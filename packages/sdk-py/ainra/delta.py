# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Signed status delta + fresh-head verification (decisions D-015, D-016).

A **delta** advances a Token Status List head by exactly one sequence. It is
authorized by BOTH the registrar's hybrid key AND a root-certified online
delegate (scope ``delta-countersign``). Two failure planes, two reasons: a
delegate-chain failure (bad/expired/wrong-scope cert, bad countersig) is
``checkpoint_invalid``; a structural or registrar-signature failure is
``stale_status`` (the head can't be advanced from trusted material → fail closed);
a missing hybrid half is ``alg_downgrade``; a present-but-invalid registrar
signature is ``sig_invalid``.

A **fresh head** (D-016) carries the head's identity + recency, delegate-signed
(scope ``fresh-head``); it fails closed on a bad/expired cert or signature
(``checkpoint_invalid``) and on future-dated or over-age timestamps
(``stale_status``, per the freshness class).

Result shape mirrors the corpus ``expect``: ``{"accept": True}`` or
``{"accept": False, "reason": <frozen reason>}``.
"""

from __future__ import annotations

from . import reasons as R
from ._b64 import decode as b64d
from ._b64 import decode_fixed as b64f
from ._canon import CanonError, canon_bytes
from ._crypto import (
    ED25519_SIG_LEN,
    MLDSA65_SIG_LEN,
    SLH_DSA_SHA2_128S_SIG_LEN,
    ed25519_verify,
    mldsa65_verify,
    slh_dsa_sha2_128s_verify,
)
from .verify import FRESHNESS, MAX_STATUS_BITS

DELTA_SCOPE = "delta-countersign"
HEAD_SCOPE = "fresh-head"


def _accept():
    return {"accept": True}


def _reject(reason):
    return {"accept": False, "reason": reason}


def _cert_ok(cert, root_slh, now, required_scope) -> bool:
    """Root-SLH-signed, in-window, correctly-scoped delegate cert."""
    if not isinstance(cert, dict):
        return False
    delegate = cert.get("delegate_ed25519")
    scopes = cert.get("scopes")
    nbf, exp = cert.get("nbf"), cert.get("exp")
    slh = b64f(cert.get("sig_slh"), SLH_DSA_SHA2_128S_SIG_LEN)
    if (
        b64f(delegate, 32) is None
        or not isinstance(scopes, list)
        or not isinstance(nbf, int)
        or not isinstance(exp, int)
        or slh is None
    ):
        return False
    try:
        msg = canon_bytes({"delegate": delegate, "exp": exp, "nbf": nbf, "scopes": scopes})
    except CanonError:
        return False
    if not slh_dsa_sha2_128s_verify(root_slh, slh, msg):
        return False
    if required_scope not in scopes:
        return False
    if now < nbf or now >= exp:
        return False
    return True


def verify_delta(v: dict) -> dict:
    """Verify one signed status delta vector."""
    try:
        return _verify_delta(v)
    except Exception:
        return _reject(R.STALE_STATUS)


def _verify_delta(v: dict) -> dict:
    now = v.get("now")
    root_slh = b64d(v.get("root_pub_slh")) or b""
    reg = v.get("registrar_pub") or {}
    reg_ed = b64d(reg.get("ed25519")) or b""
    reg_ml = b64d(reg.get("mldsa65")) or b""

    try:
        msg = canon_bytes(
            {
                "uri": v.get("uri"),
                "from_seq": v.get("from_seq"),
                "seq": v.get("seq"),
                "ts": v.get("ts"),
                "idx": v.get("idx"),
                "new_status": v.get("new_status"),
            }
        )
    except CanonError:
        return _reject(R.STALE_STATUS)

    # Registrar hybrid signature: presence/size → alg_downgrade; a present but
    # invalid signature → sig_invalid (checked before the delegate chain, so a
    # tampered body that breaks BOTH the registrar sig and the delegate
    # countersig surfaces as sig_invalid, matching the corpus).
    sig = v.get("sig_registrar") or {}
    r_ed = b64f(sig.get("ed25519"), ED25519_SIG_LEN)
    r_ml = b64f(sig.get("mldsa65"), MLDSA65_SIG_LEN)
    if r_ed is None or r_ml is None:
        return _reject(R.ALG_DOWNGRADE)
    if not ed25519_verify(reg_ed, r_ed, msg) or not mldsa65_verify(reg_ml, r_ml, msg):
        return _reject(R.SIG_INVALID)

    # Delegate chain (cert + countersignature) → checkpoint_invalid.
    if not _cert_ok(v.get("cert"), root_slh, now, DELTA_SCOPE):
        return _reject(R.CHECKPOINT_INVALID)
    delegate_pub = b64f((v.get("cert") or {}).get("delegate_ed25519"), 32) or b""
    counter = b64f(v.get("countersig_delegate"), ED25519_SIG_LEN)
    if counter is None or not ed25519_verify(delegate_pub, counter, msg):
        return _reject(R.CHECKPOINT_INVALID)

    # Structural: single-step monotone, strictly-ascending in-range indices.
    seq, from_seq = v.get("seq"), v.get("from_seq")
    if not isinstance(seq, int) or not isinstance(from_seq, int):
        return _reject(R.STALE_STATUS)
    if seq == 0 or seq != from_seq + 1:
        return _reject(R.STALE_STATUS)
    idx = v.get("idx")
    if not isinstance(idx, list):
        return _reject(R.STALE_STATUS)
    prev = -1
    for i in idx:
        if not isinstance(i, int) or i <= prev or i < 0 or i >= MAX_STATUS_BITS:
            return _reject(R.STALE_STATUS)
        prev = i

    return _accept()


def verify_head(v: dict) -> dict:
    """Verify one delegate-signed fresh-head vector."""
    try:
        return _verify_head(v)
    except Exception:
        return _reject(R.STALE_STATUS)


def _verify_head(v: dict) -> dict:
    now = v.get("now")
    root_slh = b64d(v.get("root_pub_slh")) or b""
    cert = v.get("cert") or {}

    # Delegate cert (scope fresh-head) + delegate signature → checkpoint_invalid.
    if not _cert_ok(cert, root_slh, now, HEAD_SCOPE):
        return _reject(R.CHECKPOINT_INVALID)
    try:
        msg = canon_bytes(
            {
                "uri": v.get("uri"),
                "seq": v.get("seq"),
                "ts": v.get("ts"),
                "status_hash": v.get("status_hash"),
            }
        )
    except CanonError:
        return _reject(R.CHECKPOINT_INVALID)
    delegate_pub = b64f(cert.get("delegate_ed25519"), 32) or b""
    sig = b64f(v.get("sig_delegate"), ED25519_SIG_LEN)
    if sig is None or not ed25519_verify(delegate_pub, sig, msg):
        return _reject(R.CHECKPOINT_INVALID)

    # Freshness (fail closed on future-dated or over-age) → stale_status.
    threshold = FRESHNESS.get(v.get("freshness"))
    ts = v.get("ts")
    if threshold is None or not isinstance(ts, int) or not isinstance(now, int):
        return _reject(R.STALE_STATUS)
    age = now - ts
    if age < 0 or age > threshold:
        return _reject(R.STALE_STATUS)

    return _accept()


def verify_delta_vector(v: dict) -> dict:
    """Dispatch a delta-corpus vector by its ``kind``."""
    kind = v.get("kind")
    if kind == "fresh_head":
        return verify_head(v)
    return verify_delta(v)
