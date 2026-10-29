# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Signed decision records (D-079): what a gate decided, provably, after the fact.

A gate signs one record per decision with its own Ed25519 key and chains each to the one before, so anyone holding
the gate's public key can check the log end to end: an edited, deleted, reordered or inserted record is found. The
field set is closed, so there is nowhere to put a request body or personal data.

Written from D-079 and ``ainra_core::decision``, independently of the TypeScript SDK; held to
``vectors/v1-decision`` in ``make diff``. Removing records from the END of a log is invisible to the chain itself
(``vectors/v1-decision/d17``): compare the last digest with a head the gate published.
"""

from __future__ import annotations

import json

from ._b64 import decode as b64d
from ._b64 import encode as b64e
from ._canon import CanonError, canon_bytes
from ._crypto import ed25519_verify, sha256
from .link import _passport_name, jwk_thumbprint_ed25519
from .reasons import ALL as _FROZEN

DECISION_V = "ainra-decision-1"
NOT_LINKED = "not_linked"
_FIELDS = frozenset(("v", "gate", "seq", "at", "kind", "subject", "passport", "operator", "verdict", "reason",
                     "request", "status", "checkpoint", "policy", "prev", "sig"))
_OPTIONAL = frozenset(("passport", "operator", "reason", "status", "checkpoint"))
#: The request-signature refusals (D-062): a good credential on a request it did not sign is a decision too.
_PRESENTATION = frozenset(("presentation_unsigned", "presentation_sig_invalid", "presentation_stale",
                           "presentation_replayed"))


def _u64(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 2**64


def _b64n(v: object, n: int) -> bool:
    b = b64d(v)
    return b is not None and len(b) == n


def _exact(o: object, fields: tuple) -> bool:
    return isinstance(o, dict) and set(o) == set(fields)


def _parse(line: str) -> dict | None:
    """``DecisionRecord::parse_checked``: ``None`` for anything that is not a version-1 record in canonical form."""
    try:
        r = json.loads(line)
    except Exception:
        return None
    if not isinstance(r, dict) or not set(r) <= _FIELDS or not (_FIELDS - _OPTIONAL) <= set(r):
        return None
    if any(r[k] is None for k in r):  # an explicit null is not "absent" (the Rust record would refuse the line)
        return None
    for k in ("v", "gate", "kind", "subject", "verdict", "request", "prev", "sig"):
        if not isinstance(r[k], str):
            return None
    for k in ("passport", "operator", "reason"):
        if k in r and not isinstance(r[k], str):
            return None
    if not _u64(r["seq"]) or not _u64(r["at"]):
        return None
    st, cp, pol = r.get("status"), r.get("checkpoint"), r["policy"]
    if st is not None and not (_exact(st, ("uri", "issued_at", "list")) and isinstance(st["uri"], str)
                               and _u64(st["issued_at"]) and _b64n(st["list"], 32)):
        return None
    if cp is not None and not (_exact(cp, ("origin", "size", "root")) and isinstance(cp["origin"], str)
                               and _u64(cp["size"]) and _b64n(cp["root"], 32)):
        return None
    if not (_exact(pol, ("freshness", "audience")) and isinstance(pol["audience"], str)
            and pol["freshness"] in ("F1", "F2", "F3")):
        return None
    try:
        if canon_bytes(r) != line.encode("utf-8"):
            return None
    except CanonError:
        return None
    if r["v"] != DECISION_V or not _b64n(r["gate"], 32) or not _b64n(r["request"], 32) or not _b64n(r["sig"], 64):
        return None
    if not (r["seq"] == 0 and r["prev"] == "") and not _b64n(r["prev"], 32):
        return None
    if r["kind"] == "passport":
        if _passport_name(r["subject"]) is None or "passport" in r:
            return None
    elif r["kind"] == "link":
        if not _b64n(r["subject"], 32) or ("passport" in r and _passport_name(r["passport"]) is None):
            return None
    else:
        return None
    reason = r.get("reason")
    ok = ((r["verdict"] == "valid" and reason is None)
          or (r["verdict"] == "invalid" and reason == NOT_LINKED and r["kind"] == "link")
          or (r["verdict"] == "invalid" and (reason in _FROZEN or reason in _PRESENTATION)))
    if not ok:
        return None
    if "operator" in r and not (0 < len(r["operator"].encode("utf-8")) <= 63):
        return None
    return r


def signing_bytes(record: dict) -> bytes:
    """What the gate signs: the canonical record without ``sig``."""
    return canon_bytes({k: v for k, v in record.items() if k != "sig"})


def sign_decision(record: dict, gate_public: bytes, prev_line: str, sign) -> str:
    """Complete, sign and serialise one record; returns the new log line. ``v``, ``gate``, ``seq`` and ``prev`` are
    filled in from the gate key and the previous line (``""`` for the first), so a gate cannot get the chain wrong by
    hand. ``sign(msg) -> 64 bytes`` is the gate's Ed25519 signer."""
    prev = _parse(prev_line) if prev_line else None
    if prev_line and prev is None:
        raise ValueError("the previous line is not a decision record")
    rec = {k: v for k, v in record.items() if v is not None}
    rec.update(v=DECISION_V, gate=jwk_thumbprint_ed25519(gate_public), seq=prev["seq"] + 1 if prev else 0,
               prev=b64e(sha256(prev_line.encode("utf-8"))) if prev else "")
    rec["sig"] = b64e(sign(signing_bytes(rec)))
    line = canon_bytes(rec).decode("utf-8")
    if _parse(line) is None:
        raise ValueError("this record would not verify: a field is outside the vocabulary")
    return line


def verify_chain(lines: list, gate_key: bytes, anchor: dict | None = None) -> dict:
    """``{"ok": True, "count": n}`` or the first break ``{"ok": False, "index": i, "problem": p}``. Per record, in
    the core's order: schema, gate, signature, sequence, link, clock."""
    gate = jwk_thumbprint_ed25519(gate_key)
    last = dict(anchor) if anchor else None
    for index, line in enumerate(lines):
        def fail(problem: str) -> dict:
            return {"ok": False, "index": index, "problem": problem}
        r = _parse(line) if isinstance(line, str) else None
        if r is None:
            return fail("schema")
        if r["gate"] != gate:
            return fail("gate")
        if not ed25519_verify(gate_key, b64d(r["sig"]), signing_bytes(r)):
            return fail("signature")
        if r["seq"] != (last["seq"] + 1 if last else 0):
            return fail("sequence")
        if r["prev"] != (last["digest"] if last else ""):
            return fail("link")
        if last and r["at"] < last["at"]:
            return fail("clock")
        last = {"seq": r["seq"], "at": r["at"], "digest": b64e(sha256(line.encode("utf-8")))}
    return {"ok": True, "count": len(lines)}


def request_digest(method: str, authority: str, path: str, content_digest: str = "") -> str:
    """The digest a record keeps of a request: SHA-256 over the canonical ``{authority, content_digest, method, path}``
    — what the request's signature covers, never its body. Same bytes as ``ainra_core::decision::request_digest``."""
    return b64e(sha256(canon_bytes({"authority": authority, "content_digest": content_digest, "method": method,
                                    "path": path})))


class DecisionLog:
    """A gate's decision log (D-079). ``append(line)`` receives each new line (write it somewhere append-only);
    ``last_line`` resumes a log after a restart; :meth:`head` is the digest to publish. The key never leaves
    ``sign``."""

    def __init__(self, gate_public: bytes, sign, append, freshness: str = "F2", audience: str = "",
                 last_line: str = "") -> None:
        self._pub, self._sign, self._append = gate_public, sign, append
        self._policy = {"freshness": freshness, "audience": audience}
        self._last = last_line

    def record(self, decision: dict) -> str:
        line = sign_decision({**decision, "policy": self._policy}, self._pub, self._last, self._sign)
        self._append(line)
        self._last = line
        return line

    def head(self) -> str:
        return b64e(sha256(self._last.encode("utf-8"))) if self._last else ""


def run_decision_vector(v: dict) -> dict:
    key = b64d(v.get("gate_key"))
    if key is None or len(key) != 32:
        return {"ok": False, "index": 0, "problem": "schema"}
    a = v.get("anchor")
    if a is not None and not (isinstance(a, dict) and _u64(a.get("seq")) and _u64(a.get("at"))
                              and _b64n(a.get("digest"), 32)):
        return {"ok": False, "index": 0, "problem": "schema"}
    return verify_chain(v.get("lines") or [], key, a)
