# SPDX-License-Identifier: Apache-2.0 OR MIT
"""RFC 9421 HTTP Message Signatures for an AINRA presentation (D-062) — the Python statement of the profile.

The same profile as ``ainra-core``'s ``presentation`` module and ``@ainra/sdk``'s ``presentation.ts``, held to the
same answers by ``vectors/v1-presentation`` in ``make diff`` (PLAN-M34 Task 4).

The request signature is made by the RUNNING COPY's instance key; ``keyid`` names the instance credential. Covered,
exactly and in order: ``@method``, ``@authority``, ``@path``, ``content-digest`` when there is a body, and
``x-ainra-passport``. The parser accepts exactly the shape AINRA emits. Other signers' members in the same fields
(a signature agent's, D-070) are left to their own verifiers: only the ``ainra`` member is read.

The order of checks is part of the profile — it decides the reason a request wrong in several ways gets: signature
headers present → signature-input shape → alg → keyid → covered set → freshness → body digest → signature field →
signature → nonce. The nonce is asked last, and only after the signature verified, so an unauthenticated caller
cannot fill someone else's replay cache. This layer holds no state: pass ``seen`` to enforce single use.
"""

from __future__ import annotations

import base64
import re
from typing import Callable, Iterable, Sequence

from . import _b64
from ._crypto import ED25519_SIG_LEN, MLDSA65_SIG_LEN, ed25519_verify, mldsa65_verify, sha256

SIG_LABEL = "ainra"
SIG_ALG = "ainra-hybrid-v1"
PRESENTATION_HEADER = "x-ainra-passport"
MAX_AGE_SECS = 300
MAX_FUTURE_SECS = 30

# Python's \d matches any Unicode digit and its $ matches before a trailing newline; both would make this parser
# looser than the other implementations. [0-9] and fullmatch keep it to exactly one shape.
_INPUT = re.compile(
    r'ainra=\(([^)]*)\);created=([0-9]{1,15});keyid="([^"]{1,64})";alg="([^"]{1,32})";nonce="([A-Za-z0-9._~-]{1,128})"'
)
_SIG = re.compile(r"ainra=:([A-Za-z0-9+/]+={0,2}):")


def _header(headers: Sequence[tuple[str, str]], name: str) -> str | None:
    # RFC 9421 §2.1 / RFC 9110 §5.3: a field sent on several lines is one value — each line trimmed, joined by ", ".
    lines = [v.strip() for k, v in headers if k.lower() == name]
    return ", ".join(lines) if lines else None


_KEY = re.compile(r"[a-z*][a-z0-9_.*-]*")


def _member_key(m: str) -> str:
    cut = [i for i in (m.find("="), m.find(";")) if i >= 0]
    return m[: min(cut)] if cut else m


def _members(field: str) -> list[str] | None:
    """Split a ``signature-input`` or ``signature`` value into its dictionary members (RFC 9651 §3.2, D-070): at
    commas outside quoted strings and inner lists, each member trimmed of SP/HTAB. ``None`` when the field cannot be
    split without guessing. Only the structure is checked; members that are not AINRA's are not interpreted."""
    out: list[str] = []
    start, depth, quoted, escaped = 0, 0, False, False
    for i, c in enumerate(field):
        if quoted:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                quoted = False
            continue
        if c == '"':
            quoted = True
        elif c == "(":
            if depth:
                return None
            depth = 1
        elif c == ")":
            if not depth:
                return None
            depth = 0
        elif c == "," and not depth:
            out.append(field[start:i].strip(" \t"))
            start = i + 1
    if quoted or depth:
        return None
    out.append(field[start:].strip(" \t"))
    return out if all(_KEY.fullmatch(_member_key(m)) for m in out) else None


def _own_member(ms: list[str]) -> str | None | bool:
    """AINRA's member of a split field: ``None`` when it has none, ``False`` when it has more than one."""
    own = [m for m in ms if _member_key(m) == SIG_LABEL]
    return False if len(own) > 1 else (own[0] if own else None)


def content_digest(body: bytes) -> str:
    """``sha-256=:<base64>:`` — RFC 9530."""
    return "sha-256=:" + base64.b64encode(sha256(body)).decode("ascii") + ":"


def covered_components(has_body: bool) -> list[str]:
    if has_body:
        return ["@method", "@authority", "@path", "content-digest", PRESENTATION_HEADER]
    return ["@method", "@authority", "@path", PRESENTATION_HEADER]


def signature_base(method: str, authority: str, path: str, headers: Sequence[tuple[str, str]],
                   components: Iterable[str], created: int, keyid: str, nonce: str) -> str | None:
    comps = list(components)
    lines = []
    for c in comps:
        if c == "@method":
            v = method.upper()
        elif c == "@authority":
            v = authority.lower()
        elif c == "@path":
            v = path
        elif c.startswith("@"):
            return None
        else:
            v = _header(headers, c)
            if v is None:
                return None
        lines.append(f'"{c}": {v}')
    listed = " ".join(f'"{c}"' for c in comps)
    lines.append(f'"@signature-params": ({listed});created={created};keyid="{keyid}";alg="{SIG_ALG}";nonce="{nonce}"')
    return "\n".join(lines)


def _strip_quote(s: str) -> str:
    if s.startswith('"'):
        s = s[1:]
    if s.endswith('"'):
        s = s[:-1]
    return s


def _decode_signature(field: str) -> tuple[bytes, bytes] | None:
    m = _SIG.fullmatch(field)
    if not m:
        return None
    body = m.group(1).rstrip("=")
    # Canonical only — the same acceptance set as base64ct in the core: non-zero trailing bits are refused.
    raw = _b64.decode(body.replace("+", "-").replace("/", "_"))
    if raw is None or len(raw) != ED25519_SIG_LEN + MLDSA65_SIG_LEN:
        return None
    return raw[:ED25519_SIG_LEN], raw[ED25519_SIG_LEN:]


def verify_presentation(*, method: str, authority: str, path: str, headers: Sequence[tuple[str, str]],
                        body: bytes | None, iid: str, ikey_ed25519: bytes, ikey_mldsa65: bytes, now: int,
                        max_age_secs: int = MAX_AGE_SECS,
                        seen: Callable[[str], bool] | None = None) -> dict:
    """Verify the signature over a request. Returns ``{"ok": True, "nonce", "created"}`` or
    ``{"ok": False, "reason"}``. Never raises."""
    inp_field, sig_field = _header(headers, "signature-input"), _header(headers, "signature")
    if inp_field is None or sig_field is None:
        return {"ok": False, "reason": "presentation_unsigned"}
    # D-070: the fields may carry other signers' members. Read AINRA's — exactly one in each — and leave the rest.
    inputs, signatures = _members(inp_field), _members(sig_field)
    if inputs is None or signatures is None:
        return {"ok": False, "reason": "presentation_sig_invalid"}
    inp, sig = _own_member(inputs), _own_member(signatures)
    if inp is False or sig is False:
        return {"ok": False, "reason": "presentation_sig_invalid"}
    if inp is None or sig is None:
        return {"ok": False, "reason": "presentation_unsigned"}
    m = _INPUT.fullmatch(inp)
    if not m:
        return {"ok": False, "reason": "presentation_sig_invalid"}
    list_raw, created_raw, keyid, alg, nonce = m.groups()
    if alg != SIG_ALG or keyid != iid:
        return {"ok": False, "reason": "presentation_sig_invalid"}
    components = [_strip_quote(s) for s in list_raw.split(" ")] if list_raw else []
    has_body = bool(body)
    if components != covered_components(has_body):
        return {"ok": False, "reason": "presentation_sig_invalid"}
    created = int(created_raw)
    age = now - created
    if age > max_age_secs or -age > MAX_FUTURE_SECS:
        return {"ok": False, "reason": "presentation_stale"}
    if has_body and _header(headers, "content-digest") != content_digest(body):
        return {"ok": False, "reason": "presentation_sig_invalid"}
    halves = _decode_signature(sig)
    if halves is None:
        return {"ok": False, "reason": "presentation_sig_invalid"}
    base = signature_base(method, authority, path, headers, components, created, keyid, nonce)
    if base is None:
        return {"ok": False, "reason": "presentation_sig_invalid"}
    msg = base.encode("utf-8")
    if not ed25519_verify(ikey_ed25519, halves[0], msg) or not mldsa65_verify(ikey_mldsa65, halves[1], msg):
        return {"ok": False, "reason": "presentation_sig_invalid"}
    if seen is not None and seen(nonce):
        return {"ok": False, "reason": "presentation_replayed"}
    return {"ok": True, "nonce": nonce, "created": created}


def run_presentation_vector(v: dict) -> dict:
    """One ``vectors/v1-presentation`` vector, in the shape ``ainra-core`` records."""
    r = v["request"]
    headers = [(h[0], h[1]) for h in r["headers"]]
    body = _b64.decode(r["body_b64u"]) if r.get("body_b64u") is not None else None
    ik = v["instance"]["ikey"]
    seen = set(v.get("seen_nonces") or [])
    return verify_presentation(
        method=r["method"], authority=r["authority"], path=r["path"], headers=headers, body=body,
        iid=v["instance"]["iid"], ikey_ed25519=_b64.decode(ik["ed25519"]) or b"",
        ikey_mldsa65=_b64.decode(ik["mldsa65"]) or b"", now=v["now"], max_age_secs=v["max_age_secs"],
        seen=lambda n: n in seen,
    )


# ── D-065: send the bundle once, name it by digest ────────────────────────────────────────────────────────────────
# The same convention as @ainra/sdk and the edge gate: the stable part of a bundle (everything but the per-request
# proof of possession) in canonical JSON under SHA-256, written `sha-256=:…:`.

PRIME_PATH = "/.well-known/ainra-presentation"
POP_HEADER = "x-ainra-pop"
_REF = re.compile(r"sha-256=:[A-Za-z0-9+/]{43}=:")


def is_presentation_ref(value: str) -> bool:
    return isinstance(value, str) and _REF.fullmatch(value.strip()) is not None


def split_presentation(bundle: dict) -> tuple[dict, object]:
    """``(stable, pop)`` — the bundle without ``instance.pop``, and that pop (None for a passport presented directly)."""
    inst = bundle.get("instance")
    if not isinstance(inst, dict):
        return dict(bundle), None
    stable_inst = {k: v for k, v in inst.items() if k != "pop"}
    return {**bundle, "instance": stable_inst}, inst.get("pop")


def join_presentation(stable: dict, pop: object) -> dict:
    if pop is None or not isinstance(stable.get("instance"), dict):
        return dict(stable)
    return {**stable, "instance": {**stable["instance"], "pop": pop}}


def presentation_ref(bundle: dict) -> str:
    from ._canon import canon_bytes

    stable, _ = split_presentation(bundle)
    return content_digest(canon_bytes(stable))
