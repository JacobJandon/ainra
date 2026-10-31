# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Signed decision records (D-079): what a gate decided, provably, after the fact.

A gate signs one record per decision with its own Ed25519 key and chains each to the one before, so anyone holding
the gate's public key can check the log end to end: an edited, deleted, reordered or inserted record is found. The
field set is closed, so there is nowhere to put a request body or personal data.

Written from D-079 and ``ainra_core::decision``, independently of the TypeScript SDK; held to
``vectors/v1-decision`` in ``make diff``. Removing records from the END of a log is invisible to the chain itself
(``vectors/v1-decision/d17``); a head the gate signed and a registrar logged closes that (D-081, d22–d32).
"""

from __future__ import annotations

import json

from ._b64 import decode as b64d
from ._b64 import encode as b64e
from ._canon import CanonError, canon_bytes
from ._crypto import ed25519_verify, sha256
from . import reasons as R
from ._merkle import leaf_hash, root_from_inclusion
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

    def statement(self) -> str:
        """The signed head statement for where the log stands now (D-081): hand it to a registrar's
        ``POST /decision-head`` with the gate's public key. ``""`` while the log is empty."""
        return sign_head_statement(self._last, self._pub, self._sign) if self._last else ""


# ── Logged heads (D-081) ────────────────────────────────────────────────────────────────────────────────────────────
# A gate signs a head statement — where its log stood — and a registrar appends it to its transparency log. A log
# checked against a logged head that stops short reads "truncated"; one with a different record there, "forked".

HEAD_V = "ainra-decision-head-1"
_HEAD_FIELDS = ("v", "gate", "seq", "at", "head", "sig")


class _HeadReject(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _parse_head(line: object) -> dict | None:
    if not isinstance(line, str):
        return None
    try:
        h = json.loads(line)
    except ValueError:
        return None
    if not _exact(h, _HEAD_FIELDS):
        return None
    if not all(isinstance(h[k], str) for k in ("v", "gate", "head", "sig")) or not (_u64(h["seq"]) and _u64(h["at"])):
        return None
    try:
        if canon_bytes(h).decode("utf-8") != line:
            return None
    except CanonError:
        return None
    if h["v"] != HEAD_V or not (_b64n(h["gate"], 32) and _b64n(h["head"], 32) and _b64n(h["sig"], 64)):
        return None
    return h


def head_signing_bytes(h: dict) -> bytes:
    """What the gate signs: the canonical statement without ``sig``."""
    return canon_bytes({k: v for k, v in h.items() if k != "sig"})


def _verify_head(line: object, gate_key: bytes) -> dict:
    h = _parse_head(line)
    if h is None:
        raise _HeadReject(R.SCHEMA_VIOLATION)
    if h["gate"] != jwk_thumbprint_ed25519(gate_key):
        raise _HeadReject(R.SIG_INVALID)
    if not ed25519_verify(gate_key, b64d(h["sig"]), head_signing_bytes(h)):
        raise _HeadReject(R.SIG_INVALID)
    return h


def verify_head_statement(line: str, gate_key: bytes) -> dict:
    """``{"verdict": "valid", "statement": {...}}`` when ``line`` names and was signed by ``gate_key``, else
    ``{"verdict": "invalid", "reason": r}``."""
    try:
        return {"verdict": "valid", "statement": _verify_head(line, gate_key)}
    except _HeadReject as e:
        return {"verdict": "invalid", "reason": e.reason}


def sign_head_statement(last_line: str, gate_public: bytes, sign) -> str:
    """The head statement for a log whose last line is ``last_line``, signed by the gate."""
    r = _parse(last_line)
    if r is None:
        raise ValueError("the last line is not a decision record")
    h = {"v": HEAD_V, "gate": jwk_thumbprint_ed25519(gate_public), "seq": r["seq"], "at": r["at"],
         "head": b64e(sha256(last_line.encode("utf-8")))}
    h["sig"] = b64e(sign(head_signing_bytes(h)))
    return canon_bytes(h).decode("utf-8")


def verify_head_receipt(anchors: dict, revoked_delegates: list, receipt: dict, gate_key: bytes, now: int) -> dict:
    """A registrar's receipt for a head: the statement, then that it is logged under a checkpoint the registrar's
    log key signed — the same steps, in the same order, as a link's logged-before-valid check."""
    from .verify import _decode_proof, _verify_delegate_checkpoint
    try:
        if not isinstance(receipt, dict):
            raise _HeadReject(R.SCHEMA_VIOLATION)
        h = _verify_head(receipt.get("statement"), gate_key)
        info = anchors.get(receipt.get("registrar")) if isinstance(receipt.get("registrar"), str) else None
        if info is None:
            raise _HeadReject(R.UNKNOWN_REGISTRAR)
        cp, cs = receipt.get("checkpoint"), receipt.get("checkpoint_sig")
        proof = _decode_proof(receipt.get("inclusion_proof"))
        if not isinstance(cp, dict) or not isinstance(cs, dict) or proof is None:
            raise _HeadReject(R.SCHEMA_VIOLATION)
        cp_root = b64d(cp.get("root"))
        if (cp_root is None or len(cp_root) != 32 or cs.get("mode") not in ("root", "delegate")
                or not _u64(receipt.get("leaf_index")) or not _u64(cp.get("size"))
                or not isinstance(cp.get("origin"), str)):
            raise _HeadReject(R.SCHEMA_VIOLATION)
        cp_msg = canon_bytes({"origin": cp["origin"], "root": cp["root"], "size": cp["size"]})
        log_root = b64d(info.get("log_root_key")) or b""
        if cs["mode"] == "root":
            from ._crypto import SLH_DSA_SHA2_128S_SIG_LEN, slh_dsa_sha2_128s_verify
            slh = b64d(cs.get("slh"))
            if slh is None or len(slh) != SLH_DSA_SHA2_128S_SIG_LEN or not slh_dsa_sha2_128s_verify(log_root, slh,
                                                                                                   cp_msg):
                raise _HeadReject(R.CHECKPOINT_INVALID)
        elif not _verify_delegate_checkpoint(cs, log_root, cp_msg, now, {"revoked_delegates": revoked_delegates}):
            raise _HeadReject(R.CHECKPOINT_INVALID)
        leaf = leaf_hash(receipt["statement"].encode("utf-8"))
        if root_from_inclusion(leaf, receipt["leaf_index"], cp["size"], proof) != cp_root:
            raise _HeadReject(R.NOT_LOGGED)
        return {"verdict": "valid", "statement": h}
    except _HeadReject as e:
        return {"verdict": "invalid", "reason": e.reason}


def verify_chain_to_head(lines: list, gate_key: bytes, anchor: dict | None, head: dict) -> dict:
    """:func:`verify_chain`, then — when the head's record falls in or just before this segment — that the log
    reaches it and holds exactly that record. Growth after the head holds; a log that stops short is
    ``truncated``; a different record is ``forked``."""
    if head.get("gate") != jwk_thumbprint_ed25519(gate_key):
        return {"ok": False, "index": 0, "problem": "gate"}
    r = verify_chain(lines, gate_key, anchor)
    if not r["ok"]:
        return r
    first = anchor["seq"] + 1 if anchor else 0
    if head["seq"] < first:
        if anchor and anchor["seq"] == head["seq"] and anchor["digest"] != head["head"]:
            return {"ok": False, "index": 0, "problem": "forked"}
        return r
    at = head["seq"] - first
    if at >= len(lines):
        return {"ok": False, "index": len(lines), "problem": "truncated"}
    if b64e(sha256(lines[at].encode("utf-8"))) != head["head"]:
        return {"ok": False, "index": at, "problem": "forked"}
    return r


def run_decision_vector(v: dict) -> dict:
    key = b64d(v.get("gate_key"))
    if key is None or len(key) != 32:
        return {"ok": False, "index": 0, "problem": "schema"}
    a = v.get("anchor")
    if a is not None and not (isinstance(a, dict) and _u64(a.get("seq")) and _u64(a.get("at"))
                              and _b64n(a.get("digest"), 32)):
        return {"ok": False, "index": 0, "problem": "schema"}
    lines = v.get("lines") or []
    if v.get("receipt") is not None:
        from .verifier import Verifier
        roots = v.get("roots") or {}
        gate = Verifier.from_directory(v.get("directory") or {}, roots.get("root_ed25519", ""),
                                       roots.get("root_slh", ""))
        if gate is None:
            return {"ok": False, "head": R.UNKNOWN_REGISTRAR}
        hv = gate.verify_head_receipt(v["receipt"], key, v.get("now", 0))
    elif isinstance(v.get("head"), str):
        hv = verify_head_statement(v["head"], key)
    else:
        return verify_chain(lines, key, a)
    if hv["verdict"] != "valid":
        return {"ok": False, "head": hv["reason"]}
    return verify_chain_to_head(lines, key, a, hv["statement"])
