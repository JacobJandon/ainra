# SPDX-License-Identifier: Apache-2.0 OR MIT
"""AINRA Link (D-078): who stands behind a key an agent already has, and whether that has been revoked.

A gate that has ALREADY verified a request's Ed25519 signature asks the question this module answers: which
accountable operator does this key act for, and is the link, or the operator, revoked? It attributes a genuine
request; it never makes one genuine.

Written from D-078 and the frozen order of ``ainra_core::link::verify_link``, independently of the TypeScript
SDK, and held to ``vectors/v1-link`` in ``make diff``. No I/O, no clock: the caller supplies ``now`` and every
artefact, and the trusted inputs come from a dual-root-signed directory (:meth:`Verifier.from_directory`).
"""

from __future__ import annotations

import json
import zlib

from . import reasons as R
from ._b64 import decode as b64d
from ._b64 import encode as b64e
from ._canon import CanonError, canon_bytes
from ._crypto import ED25519_SIG_LEN, MLDSA65_SIG_LEN, ed25519_verify, mldsa65_verify, sha256
from ._merkle import leaf_hash, root_from_inclusion
from .verify import FRESHNESS, MAX_CAPABILITIES, MAX_STATUS_BITS, _verify_delegate_checkpoint, _decode_proof

LINK_V = "ainra-link-1"
LINK_POP_PURPOSE = "ainra-link-pop-1"
_TOP = frozenset(("v", "registrar", "passport", "subject", "scope", "nbf", "exp", "status", "passport_status",
                  "pop", "log"))
_SUBJECT = frozenset(("kind", "alg", "thumbprint"))
_STATUSREF = frozenset(("uri", "idx"))
_LOG = frozenset(("leaf",))
#: The name grammar as the core states it (name.rs): 1–63 of a-z 0-9 '-', not starting or ending with '-'.
_MAX_LABEL = 63


class _Reject(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _u64(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 2**64


def _exact(obj: object, fields: frozenset) -> dict:
    """deny_unknown_fields + every field required — what serde does on the Rust side."""
    if not isinstance(obj, dict) or set(obj) != fields:
        raise _Reject(R.SCHEMA_VIOLATION)
    return obj


def _str(v: object) -> str:
    if not isinstance(v, str):
        raise _Reject(R.SCHEMA_VIOLATION)
    return v


def _label(s: str) -> bool:
    return (0 < len(s) <= _MAX_LABEL and all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in s)
            and not s.startswith("-") and not s.endswith("-"))


def _version(s: str) -> bool:
    parts = s.split(".")
    return 1 <= len(parts) <= 3 and all(p.isascii() and p.isdigit() and (p == "0" or p[0] != "0") for p in parts)


def _passport_name(s: str) -> tuple[str, str] | None:
    """``ainra:{registrar}:{operator}:{lineage}@{version}`` → (registrar, operator), or None."""
    if not s.startswith("ainra:") or "@" not in s:
        return None
    body, _, version = s[len("ainra:"):].rpartition("@")
    parts = body.split(":")
    if len(parts) != 3 or not all(_label(p) for p in parts) or not _version(version):
        return None
    return parts[0], parts[1]


def _parse_checked(raw: bytes) -> dict:
    """The link schema gate, in ``LinkClaims::parse_checked``'s order."""
    try:
        o = json.loads(raw.decode("utf-8"))
    except Exception:
        raise _Reject(R.SCHEMA_VIOLATION) from None
    _exact(o, _TOP)
    subject = _exact(o["subject"], _SUBJECT)
    status = _exact(o["status"], _STATUSREF)
    pstatus = _exact(o["passport_status"], _STATUSREF)
    log = _exact(o["log"], _LOG)
    for v in (o["v"], o["registrar"], o["passport"], o["pop"], subject["kind"], subject["alg"],
              subject["thumbprint"], status["uri"], pstatus["uri"], log["leaf"]):
        _str(v)
    if not isinstance(o["scope"], list) or not all(isinstance(s, str) for s in o["scope"]):
        raise _Reject(R.SCHEMA_VIOLATION)
    if not all(_u64(x) for x in (o["nbf"], o["exp"], status["idx"], pstatus["idx"])):
        raise _Reject(R.SCHEMA_VIOLATION)
    # The signed bytes must already be canonical (D-029).
    try:
        if canon_bytes(o) != raw:
            raise _Reject(R.SCHEMA_VIOLATION)
    except CanonError:
        raise _Reject(R.SCHEMA_VIOLATION) from None
    if o["v"] != LINK_V or subject["kind"] != "jwk" or subject["alg"] != "Ed25519":
        raise _Reject(R.SCHEMA_VIOLATION)
    tp, pop, leaf = b64d(subject["thumbprint"]), b64d(o["pop"]), b64d(log["leaf"])
    if tp is None or len(tp) != 32 or pop is None or len(pop) != 64 or leaf is None or len(leaf) != 32:
        raise _Reject(R.SCHEMA_VIOLATION)
    if len(o["scope"]) > MAX_CAPABILITIES or any(not s or len(s.encode("utf-8")) > 128 for s in o["scope"]):
        raise _Reject(R.SCHEMA_VIOLATION)
    # Both bits live in the one list the registrar signs.
    if status["uri"] != pstatus["uri"] or status["idx"] == pstatus["idx"]:
        raise _Reject(R.SCHEMA_VIOLATION)
    if o["nbf"] >= o["exp"]:
        raise _Reject(R.SCHEMA_VIOLATION)
    name = _passport_name(o["passport"])
    if name is None:
        raise _Reject(R.NAME_MALFORMED)
    # A registrar links only passports it issued itself.
    if name[0] != o["registrar"]:
        raise _Reject(R.SCHEMA_VIOLATION)
    o["_operator"], o["_pop"], o["_leaf"] = name[1], pop, leaf
    return o


def jwk_thumbprint_ed25519(pk: bytes) -> str:
    """RFC 7638 thumbprint of an Ed25519 key: base64url(SHA-256(``{"crv":"Ed25519","kty":"OKP","x":"…"}``))."""
    return b64e(sha256(canon_bytes({"crv": "Ed25519", "kty": "OKP", "x": b64e(pk)})))


def pop_signing_bytes(registrar: str, passport: str, thumbprint: str, nbf: int) -> bytes:
    """What the linked key signs to consent to a link (D-078). Frozen."""
    return canon_bytes({"purpose": LINK_POP_PURPOSE, "registrar": registrar, "passport": passport,
                        "thumbprint": thumbprint, "nbf": nbf})


def _authenticate_publication(info: dict, claimed_uri: str, link: dict) -> None:
    """The status publication must be the one the registrar signed (D-020), bound three ways by URI."""
    if not info.get("status_ed25519") or not info.get("status_mldsa65"):
        raise _Reject(R.STALE_STATUS)
    uri, sig_ed, sig_ml = link.get("status_uri"), link.get("status_sig_ed25519"), link.get("status_sig_mldsa65")
    if not isinstance(uri, str) or not isinstance(sig_ed, str) or not isinstance(sig_ml, str):
        raise _Reject(R.STALE_STATUS)
    if uri != info.get("status_uri") or claimed_uri != info.get("status_uri"):
        raise _Reject(R.STALE_STATUS)
    ed, ml = b64d(sig_ed), b64d(sig_ml)
    pub_ed, pub_ml = b64d(info["status_ed25519"]), b64d(info["status_mldsa65"])
    if None in (ed, ml, pub_ed, pub_ml) or len(ed) != ED25519_SIG_LEN or len(pub_ed) != 32:
        raise _Reject(R.STALE_STATUS)
    try:
        msg = canon_bytes({"bit_len": link.get("status_len"), "issued_at": link.get("status_issued_at"),
                           "status_list": link.get("status_list"), "uri": uri})
    except CanonError:
        raise _Reject(R.STALE_STATUS) from None
    if not ed25519_verify(pub_ed, ed, msg) or not mldsa65_verify(pub_ml, ml, msg):
        raise _Reject(R.STALE_STATUS)


def _unpack_status(link: dict) -> tuple[bytes, int]:
    """Decompress an AUTHENTICATED list, bounded by what it declares. Unreadable is unavailable: ``stale_status``."""
    n, z = link.get("status_len"), b64d(link.get("status_list"))
    if not _u64(n) or n > MAX_STATUS_BITS or z is None:
        raise _Reject(R.STALE_STATUS)
    need = (n + 7) // 8
    try:
        d = zlib.decompressobj()
        bits = d.decompress(z, need + 8)
        if d.unconsumed_tail or not d.eof:
            raise _Reject(R.STALE_STATUS)
    except _Reject:
        raise
    except Exception:
        raise _Reject(R.STALE_STATUS) from None
    if len(bits) < need:
        raise _Reject(R.STALE_STATUS)
    return bits, n


def _bit(bits: bytes, n: int, idx: int) -> bool:
    """Fail closed: an index at or past the list's end reads revoked, as ``StatusList::status_of`` does."""
    return idx >= n or bool((bits[idx // 8] >> (idx % 8)) & 1)


def _verify(anchors: dict, revoked_delegates: list, link: dict, presented_key: bytes, now: int,
            freshness: str, capability: str | None) -> dict:
    if not isinstance(link, dict):
        raise _Reject(R.SCHEMA_VIOLATION)
    raw = b64d(link.get("claims"))
    if raw is None:
        raise _Reject(R.SCHEMA_VIOLATION)
    c = _parse_checked(raw)
    info = anchors.get(c["registrar"])
    if info is None:
        raise _Reject(R.UNKNOWN_REGISTRAR)
    _authenticate_publication(info, c["status"]["uri"], link)
    bits, n = _unpack_status(link)
    # Every remaining field decodes, or the link is malformed.
    rsig = link.get("registrar_sig")
    if not isinstance(rsig, dict):
        raise _Reject(R.SCHEMA_VIOLATION)
    sig_ed, sig_ml = b64d(rsig.get("ed25519")), b64d(rsig.get("mldsa65"))
    cp = link.get("checkpoint")
    if sig_ed is None or sig_ml is None or not isinstance(cp, dict):
        raise _Reject(R.SCHEMA_VIOLATION)
    cp_root = b64d(cp.get("root"))
    proof = _decode_proof(link.get("inclusion_proof"))
    cs = link.get("checkpoint_sig")
    if (cp_root is None or len(cp_root) != 32 or proof is None or not isinstance(cs, dict)
            or cs.get("mode") not in ("root", "delegate")
            or not all(_u64(link.get(k)) for k in ("leaf_index", "status_issued_at"))
            or not _u64(cp.get("size")) or not isinstance(cp.get("origin"), str)):
        raise _Reject(R.SCHEMA_VIOLATION)

    # window, exact
    if now < c["nbf"]:
        raise _Reject(R.NOT_YET_VALID)
    if now >= c["exp"]:
        raise _Reject(R.EXPIRED)
    # the registrar signed exactly these bytes, with both halves of its key
    if len(sig_ed) != ED25519_SIG_LEN or len(sig_ml) != MLDSA65_SIG_LEN:
        raise _Reject(R.ALG_DOWNGRADE)
    key = info.get("issuer_key") or {}
    if not ed25519_verify(b64d(key.get("ed25519")) or b"", sig_ed, raw) or not mldsa65_verify(
            b64d(key.get("mldsa65")) or b"", sig_ml, raw):
        raise _Reject(R.SIG_INVALID)
    # the key the gate verified is the linked key, and that key consented to this link
    tp = c["subject"]["thumbprint"]
    if len(presented_key) != 32 or jwk_thumbprint_ed25519(presented_key) != tp:
        raise _Reject(R.SIG_INVALID)
    if not ed25519_verify(presented_key, c["_pop"], pop_signing_bytes(c["registrar"], c["passport"], tp, c["nbf"])):
        raise _Reject(R.SIG_INVALID)
    # scope
    if capability is not None and c["scope"] and capability not in c["scope"]:
        raise _Reject(R.CEILING_EXCEEDED)
    # status: fresh, then the link's own bit, then the operator's lineage
    age = now - link["status_issued_at"]
    if freshness not in FRESHNESS or age < 0 or age > FRESHNESS[freshness]:
        raise _Reject(R.STALE_STATUS)
    if _bit(bits, n, c["status"]["idx"]) or _bit(bits, n, c["passport_status"]["idx"]):
        raise _Reject(R.REVOKED)
    # logged before valid
    cp_msg = canon_bytes({"origin": cp["origin"], "root": cp["root"], "size": cp["size"]})
    log_root = b64d(info.get("log_root_key")) or b""
    if cs["mode"] == "root":
        from ._crypto import SLH_DSA_SHA2_128S_SIG_LEN, slh_dsa_sha2_128s_verify
        slh = b64d(cs.get("slh"))
        if slh is None or len(slh) != SLH_DSA_SHA2_128S_SIG_LEN or not slh_dsa_sha2_128s_verify(log_root, slh, cp_msg):
            raise _Reject(R.CHECKPOINT_INVALID)
    elif not _verify_delegate_checkpoint(cs, log_root, cp_msg, now, {"revoked_delegates": revoked_delegates}):
        raise _Reject(R.CHECKPOINT_INVALID)
    body = json.loads(raw.decode("utf-8"))
    del body["log"]
    if leaf_hash(canon_bytes(body)) != c["_leaf"]:
        raise _Reject(R.NOT_LOGGED)
    if root_from_inclusion(c["_leaf"], link["leaf_index"], cp["size"], proof) != cp_root:
        raise _Reject(R.NOT_LOGGED)
    cutoff = info.get("distrust_from_leaf")
    if cutoff is not None and link["leaf_index"] >= int(cutoff):
        raise _Reject(R.REGISTRAR_DISTRUSTED)
    return {"registrar": c["registrar"], "operator": c["_operator"], "passport": c["passport"],
            "scope": list(c["scope"])}


def link_from_index(index: dict, publication: dict, thumbprint: str) -> dict | None:
    """Assemble the link for one key from a registrar's link index (``GET /links``) and its signed status
    publication (``GET /status-list``). ``None`` means the key is not linked there. Assembling trusts nothing:
    :meth:`ainra.Verifier.verify_link` checks every part, so a mirror's copy is as good as the registrar's."""
    for e in index.get("links") or []:
        if isinstance(e, dict) and e.get("thumbprint") == thumbprint:
            return {
                "claims": e.get("claims"), "registrar_sig": e.get("registrar_sig"), "leaf_index": e.get("leaf_index"),
                "inclusion_proof": e.get("inclusion_proof"), "checkpoint": index.get("checkpoint"),
                "checkpoint_sig": index.get("checkpoint_sig"), "status_list": publication.get("status_list_b64"),
                "status_len": publication.get("bit_len"), "status_issued_at": publication.get("issued_at"),
                "status_uri": publication.get("uri"), "status_sig_ed25519": publication.get("sig_ed25519"),
                "status_sig_mldsa65": publication.get("sig_mldsa65"),
            }
    return None


def verify_link(anchors: dict, revoked_delegates: list, link: dict, presented_key: bytes, now: int,
                freshness: str = "F2", capability: str | None = None) -> dict:
    """``{"verdict": "valid", registrar, operator, passport, scope}`` or ``{"verdict": "invalid", "reason": …}``.

    ``anchors`` and ``revoked_delegates`` must come from an authenticated directory; use
    :meth:`ainra.Verifier.verify_link`, which supplies them. Never raises.
    """
    try:
        return {"verdict": "valid", **_verify(anchors, revoked_delegates, link, presented_key, now, freshness,
                                              capability)}
    except _Reject as e:
        return {"verdict": "invalid", "reason": e.reason}
    except Exception:
        return {"verdict": "invalid", "reason": R.SCHEMA_VIOLATION}
