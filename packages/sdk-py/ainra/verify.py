# SPDX-License-Identifier: Apache-2.0 OR MIT
"""The nine-step AINRA passport verify — independent implementation.

Consumes a presentation bundle + trust anchors + a caller-supplied ``now`` and
returns a :class:`Verdict`. Written from ``docs/AINRA_I_The_Standard.md`` §8,
``docs/AINRA_Master_Technical_Specification_v1.md`` (§8 hot path, §14 crypto,
§15 data model), the frozen reasons (``docs/reasons.json`` / D-004), and the CC2
conformance vectors as the correctness reference (their recorded verdicts are the
ground truth) — not by transliterating the Rust core or the TS SDK. Fail closed
everywhere; never raise on hostile input.

Reason precedence (earliest wins), from ``docs/reasons.json``:
schema_violation → name_malformed → unknown_registrar → not_yet_valid → expired
→ sig_invalid / alg_downgrade → ceiling_exceeded → chain_widening → chain_expired
→ stale_status → revoked → mandate_revoked → not_logged → checkpoint_invalid
"""

from __future__ import annotations

import zlib

from . import reasons as R
from ._b64 import decode as b64d
from ._b64 import decode_fixed as b64f
from ._canon import CanonError, canon_bytes, canonicalize
from ._crypto import (
    ED25519_SIG_LEN,
    MLDSA65_SIG_LEN,
    SLH_DSA_SHA2_128S_SIG_LEN,
    ed25519_verify,
    mldsa65_verify,
    sha256,
    slh_dsa_sha2_128s_verify,
)
from ._merkle import leaf_hash, root_from_inclusion
from ._name import parse_issuer, parse_subject
from .verdict import Verdict, invalid, valid

VCT = "ainra/passport/v1"
FRESHNESS = {"F1": 30, "F2": 300, "F3": 86400}
MAX_STATUS_BITS = 2**24
TIERS = frozenset(("L0", "L1", "L2", "L3", "L4"))
CLASSES = frozenset(("A1", "A2", "A3", "A4"))
CHECKPOINT_SCOPE = "checkpoint-daily"

_FORBIDDEN_KEYS = frozenset(
    (
        "score",
        "price",
        "email",
        "phone",
        "ssn",
        "dob",
        "address",
        "full_name",
        "given_name",
        "family_name",
    )
)
# Fields that reserve a future mode we cannot yet evaluate soundly (D-013):
# present ⇒ reject rather than silently honour.
_RESERVED_KEYS = frozenset(("mandates_root", "mandates_size"))


def _forbidden_present(node: object) -> bool:
    if isinstance(node, dict):
        for k, v in node.items():
            if k in _FORBIDDEN_KEYS:
                return True
            if _forbidden_present(v):
                return True
    elif isinstance(node, (list, tuple)):
        for x in node:
            if _forbidden_present(x):
                return True
    return False


def _hop_body(hop: dict) -> object:
    return {k: hop.get(k) for k in ("from", "to", "granted", "exp")}


def verify(anchors: dict, presentation: dict, now: int) -> Verdict:
    """Verify a passport presentation, returning a :class:`Verdict`."""
    try:
        return _verify(anchors, presentation, now)
    except Exception:
        # A verifier must never throw: any unforeseen structural break is an
        # invalid verdict, never a crash and never a wrong `valid`.
        return invalid(R.SCHEMA_VIOLATION)


def _verify(anchors: dict, presentation: dict, now: int) -> Verdict:
    if not isinstance(presentation, dict):
        return invalid(R.SCHEMA_VIOLATION)

    # ── Step 1: decode + schema ───────────────────────────────────────────
    claims_raw = b64d(presentation.get("claims"))
    if claims_raw is None:
        return invalid(R.SCHEMA_VIOLATION)
    try:
        import json

        claims = json.loads(claims_raw.decode("utf-8"))
    except Exception:
        return invalid(R.SCHEMA_VIOLATION)
    if not isinstance(claims, dict):
        return invalid(R.SCHEMA_VIOLATION)
    # Canonical-divergence guard (D-010): floats / non-ASCII keys / >2^53 ints.
    try:
        canonicalize(claims)
    except CanonError:
        return invalid(R.SCHEMA_VIOLATION)
    if _forbidden_present(claims):
        return invalid(R.SCHEMA_VIOLATION)
    if any(k in claims for k in _RESERVED_KEYS):
        return invalid(R.SCHEMA_VIOLATION)
    if claims.get("vct") != VCT:
        return invalid(R.SCHEMA_VIOLATION)

    # `act_chain` is NOT required. ainra-core declares it `#[serde(default)]` (passport.rs:141) — a root-issued
    # passport with no delegation may omit it entirely, and Rust and the TS SDK both accept that. This SDK
    # required it, so it rejected, with `schema_violation`, the very bundle shipped in the external verifier kit
    # (kits/verifier/sample-artifacts/bundle-valid.json, which has no act_chain). The 1009-vector corpus cannot
    # catch it: the generator always emits the field, even when empty, so the omitted case is never on the wire.
    # Found by the M30 policy-parity harness — see docs/POLICY-PARITY.md.
    required = (
        "iss", "sub", "nbf", "exp", "authority", "tier", "capabilities",
        "scope_ceiling", "keys", "status", "log",
    )
    for f in required:
        if f not in claims:
            return invalid(R.SCHEMA_VIOLATION)
    nbf, exp = claims["nbf"], claims["exp"]
    if not isinstance(nbf, int) or not isinstance(exp, int):
        return invalid(R.SCHEMA_VIOLATION)
    authority = claims["authority"]
    caps = claims["capabilities"]
    ceiling = claims["scope_ceiling"]
    act_chain = claims.get("act_chain", [])
    if not (
        isinstance(authority, dict)
        and isinstance(caps, list)
        and isinstance(ceiling, list)
        and isinstance(act_chain, list)
        and isinstance(claims.get("status"), dict)
        and isinstance(claims.get("log"), dict)
    ):
        return invalid(R.SCHEMA_VIOLATION)
    tier = claims["tier"]
    if tier not in TIERS or authority.get("class") not in CLASSES:
        return invalid(R.SCHEMA_VIOLATION)

    # prev_leaf (ADR-017): null == absent; present ⇒ strict 32 bytes.
    if "prev_leaf" in claims and claims["prev_leaf"] is not None:
        if b64f(claims["prev_leaf"], 32) is None:
            return invalid(R.SCHEMA_VIOLATION)

    # act_chain party-key count (D-011 schema gate).
    chain_keys = presentation.get("chain_keys") or []
    n_hops = len(act_chain)
    if n_hops == 0:
        if len(chain_keys) != 0:
            return invalid(R.SCHEMA_VIOLATION)
    elif len(chain_keys) != n_hops + 1:
        return invalid(R.SCHEMA_VIOLATION)

    # Identity for the verdict event (best-effort, populated as we learn it).
    sub_name = parse_subject(claims.get("sub"))
    name = claims.get("sub") if isinstance(claims.get("sub"), str) else None
    number = sub_name.number if sub_name else None
    tier_out = tier
    status_issued_at = presentation.get("status_issued_at")
    freshness_age = (
        now - status_issued_at if isinstance(status_issued_at, int) else None
    )

    def ident():
        return dict(name=name, number=number, tier=tier_out, freshness_age_s=freshness_age)

    # ── Step 2: name grammar ──────────────────────────────────────────────
    reg = parse_issuer(claims.get("iss"))
    if sub_name is None or reg is None:
        return invalid(R.NAME_MALFORMED, **ident())
    # Delegation hop endpoints must also be grammatical subject names.
    for hop in act_chain:
        if not isinstance(hop, dict):
            return invalid(R.SCHEMA_VIOLATION, **ident())
        if parse_subject(hop.get("from")) is None or parse_subject(hop.get("to")) is None:
            return invalid(R.NAME_MALFORMED, **ident())

    # ── Step 3: registrar known ───────────────────────────────────────────
    anchor = anchors.get(reg) if isinstance(anchors, dict) else None
    if not isinstance(anchor, dict):
        return invalid(R.UNKNOWN_REGISTRAR, **ident())

    # ── Step 4/5: validity window (exact; nbf inclusive, exp exclusive) ────
    if now < nbf:
        return invalid(R.NOT_YET_VALID, **ident())
    if now >= exp:
        return invalid(R.EXPIRED, **ident())

    # ── Step 6/7: hybrid signatures (issuer, then each delegation hop) ─────
    issuer_key = anchor.get("issuer_key") or {}
    iss_ed_pub = b64d(issuer_key.get("ed25519")) or b""
    iss_ml_pub = b64d(issuer_key.get("mldsa65")) or b""
    isig = presentation.get("issuer_sig") or {}
    iss_ed_sig = b64f(isig.get("ed25519"), ED25519_SIG_LEN)
    iss_ml_sig = b64f(isig.get("mldsa65"), MLDSA65_SIG_LEN)
    if iss_ed_sig is None or iss_ml_sig is None:
        return invalid(R.ALG_DOWNGRADE, **ident())
    if not ed25519_verify(iss_ed_pub, iss_ed_sig, claims_raw) or not mldsa65_verify(
        iss_ml_pub, iss_ml_sig, claims_raw
    ):
        return invalid(R.SIG_INVALID, **ident())

    hop_bodies = [canon_bytes(_hop_body(h)) for h in act_chain]
    for i, hop in enumerate(act_chain):
        p_ed = b64f(hop.get("sig_ed25519"), ED25519_SIG_LEN)
        p_ml = b64f(hop.get("sig_mldsa65"), MLDSA65_SIG_LEN)
        c_ed = b64f(hop.get("sig_child_ed25519"), ED25519_SIG_LEN)
        c_ml = b64f(hop.get("sig_child_mldsa65"), MLDSA65_SIG_LEN)
        if None in (p_ed, p_ml, c_ed, c_ml):
            return invalid(R.ALG_DOWNGRADE, **ident())
        parent = chain_keys[i]
        child = chain_keys[i + 1]
        p_ed_k = b64d(parent.get("ed25519")) or b""
        p_ml_k = b64d(parent.get("mldsa65")) or b""
        c_ed_k = b64d(child.get("ed25519")) or b""
        c_ml_k = b64d(child.get("mldsa65")) or b""
        body = hop_bodies[i]
        if not (
            ed25519_verify(p_ed_k, p_ed, body)
            and mldsa65_verify(p_ml_k, p_ml, body)
            and ed25519_verify(c_ed_k, c_ed, body)
            and mldsa65_verify(c_ml_k, c_ml, body)
        ):
            return invalid(R.SIG_INVALID, **ident())

    # ── Step 8: scope ceiling ─────────────────────────────────────────────
    ceiling_set = set(ceiling)
    if not set(caps).issubset(ceiling_set):
        return invalid(R.CEILING_EXCEEDED, **ident())

    # ── Step 9: delegation narrowing (authority may only shrink) ──────────
    allowed = ceiling_set
    for hop in act_chain:
        granted = set(hop.get("granted") or [])
        if not granted.issubset(allowed):
            return invalid(R.CHAIN_WIDENING, **ident())
        allowed = granted
    if act_chain and not set(caps).issubset(allowed):
        return invalid(R.CHAIN_WIDENING, **ident())

    # ── Step 10: delegation expiry (each hop ≤ its delegator, within now) ──
    prev_exp = exp
    for hop in act_chain:
        h_exp = hop.get("exp")
        if not isinstance(h_exp, int) or h_exp > prev_exp or now >= h_exp:
            return invalid(R.CHAIN_EXPIRED, **ident())
        prev_exp = h_exp

    # ── Step 11: status freshness (fail closed) ───────────────────────────
    fclass = presentation.get("freshness")
    threshold = FRESHNESS.get(fclass)
    if threshold is None or not isinstance(status_issued_at, int):
        return invalid(R.STALE_STATUS, **ident())
    age = now - status_issued_at
    if age < 0 or age > threshold:
        return invalid(R.STALE_STATUS, **ident())

    # ── Step 12: revocation bit ───────────────────────────────────────────
    status_len = presentation.get("status_len")
    idx = ((claims.get("status") or {}).get("status_list") or {}).get("idx")
    if not isinstance(status_len, int) or not isinstance(idx, int):
        return invalid(R.STALE_STATUS, **ident())
    if status_len > MAX_STATUS_BITS or idx < 0 or idx >= status_len:
        return invalid(R.STALE_STATUS, **ident())
    packed = b64d(presentation.get("status_list"))
    if packed is None:
        return invalid(R.STALE_STATUS, **ident())
    try:
        bits = zlib.decompressobj().decompress(packed, (MAX_STATUS_BITS // 8) + 1)
    except Exception:
        return invalid(R.STALE_STATUS, **ident())
    # FAIL CLOSED past the delivered bytes. `ainra-core` maps every out-of-range index to Revoked
    # (status.rs:136-141) and the TS SDK rejects a list shorter than its declared `bit_len`. This read
    # `else 0` — NOT revoked — so a presenter who declared a long `bit_len` and delivered a short list was
    # handed a free all-clear for every index past the bytes actually sent. Found by the M30 adversarial
    # review; the corpus cannot catch it because no vector delivers a list shorter than it declares.
    declared_bytes = (int(status_len) + 7) // 8
    if len(bits) < declared_bytes:
        return invalid(R.STALE_STATUS, **ident())
    byte_idx = idx // 8
    bit = (bits[byte_idx] >> (idx % 8)) & 1 if byte_idx < len(bits) else 1
    if bit:
        return invalid(R.REVOKED, **ident())

    # ── Step 13: mandate subtree revocation ───────────────────────────────
    mandates = claims.get("mandates")
    if isinstance(mandates, list) and mandates:
        revoked = set(presentation.get("mandate_revocations") or [])
        for m in mandates:
            if isinstance(m, dict) and m.get("id") in revoked:
                return invalid(R.MANDATE_REVOKED, **ident())

    # ── Step 14: checkpoint signature (root or delegate) ──────────────────
    # The signed checkpoint is authenticated FIRST — it establishes the trusted
    # (root, size) the inclusion proof is checked against. A checkpoint whose
    # contents were changed after signing fails here (checkpoint_invalid) before
    # its now-inconsistent size can be mistaken for a logging failure.
    checkpoint = presentation.get("checkpoint") or {}
    cp_msg = canon_bytes(checkpoint)
    log_root_slh = b64d(anchor.get("log_root_key")) or b""
    cs = presentation.get("checkpoint_sig") or {}
    mode = cs.get("mode")
    if mode == "root":
        slh = b64f(cs.get("slh"), SLH_DSA_SHA2_128S_SIG_LEN)
        if slh is None or not slh_dsa_sha2_128s_verify(log_root_slh, slh, cp_msg):
            return invalid(R.CHECKPOINT_INVALID, **ident())
    elif mode == "delegate":
        if not _verify_delegate_checkpoint(cs, log_root_slh, cp_msg, now, presentation):
            return invalid(R.CHECKPOINT_INVALID, **ident())
    else:
        return invalid(R.CHECKPOINT_INVALID, **ident())
    cp_root = b64f(checkpoint.get("root"), 32)
    size = checkpoint.get("size")
    if cp_root is None or not isinstance(size, int):
        return invalid(R.CHECKPOINT_INVALID, **ident())

    # ── Step 15: logged-before-valid (RFC 6962 inclusion to the checkpoint) ─
    log = claims["log"]
    leaf = b64f(log.get("leaf"), 32)
    if leaf is None:
        return invalid(R.NOT_LOGGED, **ident())
    body_no_log = {k: v for k, v in claims.items() if k != "log"}
    if leaf_hash(canon_bytes(body_no_log)) != leaf:
        return invalid(R.NOT_LOGGED, **ident())  # leaf doesn't bind this body
    # The credential must point at the checkpoint it proves inclusion in.
    if b64f(log.get("root"), 32) != cp_root:
        return invalid(R.NOT_LOGGED, **ident())
    proof = _decode_proof(presentation.get("inclusion_proof"))
    if proof is None or root_from_inclusion(leaf, presentation.get("leaf_index"), size, proof) != cp_root:
        return invalid(R.NOT_LOGGED, **ident())
    # D-044 graduated distrust — AFTER inclusion, and the order is load-bearing. ``leaf_index`` is only a proven
    # fact once inclusion has shown the leaf really sits there; testing the cutoff earlier would let a presenter
    # claim a low index to slip under it. Mirrors verify.rs and sdk-ts exactly.
    cutoff = anchor.get("distrust_from_leaf")
    if cutoff is not None and int(presentation.get("leaf_index") or 0) >= int(cutoff):
        return invalid(R.REGISTRAR_DISTRUSTED, **ident())
    # Each delegation hop must also prove inclusion under the same checkpoint.
    hop_proofs = presentation.get("hop_proofs") or []
    if len(hop_proofs) != n_hops:
        return invalid(R.NOT_LOGGED, **ident())
    for i, hop in enumerate(act_chain):
        h_leaf = b64f(hop.get("log_leaf"), 32)
        if h_leaf is None or h_leaf != leaf_hash(hop_bodies[i]):
            return invalid(R.NOT_LOGGED, **ident())
        hp = hop_proofs[i] or {}
        hp_proof = _decode_proof(hp.get("proof"))
        if hp_proof is None or root_from_inclusion(h_leaf, hp.get("leaf_index"), size, hp_proof) != cp_root:
            return invalid(R.NOT_LOGGED, **ident())
        if cutoff is not None and int(hp.get("leaf_index") or 0) >= int(cutoff):
            return invalid(R.REGISTRAR_DISTRUSTED, **ident())

    # 10. ADR-019 / D-047 — the instance rung, LAST and deliberately so. Everything above establishes that this
    #     passport is real, unexpired, in scope, unrevoked and logged; only then is it worth asking whether the
    #     presenter may speak for it. The ordering is what makes passport revocation kill every instance under it
    #     with ``revoked`` from step 7, rather than an instance-layer reason pointing at the container.
    inst = presentation.get("instance")
    if inst is not None:
        bad_inst = _verify_instance(inst, claims, leaf, now, presentation.get("audience") or "")
        if bad_inst is not None:
            return invalid(bad_inst, **ident())

    return valid(**ident())


#: ≤1 h instance-credential ceiling (ADR-019) — mirrors ``ainra_core::consts::INSTANCE_CRED_DEFAULT_SECS``.
INSTANCE_CRED_DEFAULT_SECS = 60 * 60
#: PoP timestamp tolerance — mirrors ``ainra_core::instance::POP_MAX_SKEW_SECS``. A FRESHNESS-layer tolerance
#: (ADR-016), never applied to a validity window: the instance window is compared exactly, like the passport's.
POP_MAX_SKEW_SECS = 30


def _instance_signing_bytes(ic: dict) -> bytes:
    """Canonical bytes the passport's control key signs.

    Field order mirrors ``InstanceCredential::signing_bytes`` in ainra-core byte-for-byte; the four-way
    differential is what keeps the three implementations honest about it.
    """
    ikey = ic.get("ikey") or {}
    return canon_bytes(
        {
            "aud": ic.get("aud"),
            "capabilities": ic.get("capabilities"),
            "exp": ic.get("exp"),
            "iid": ic.get("iid"),
            "ikey": {"ed25519": ikey.get("ed25519"), "mldsa65": ikey.get("mldsa65")},
            "nbf": ic.get("nbf"),
            "passport_leaf": ic.get("passport_leaf"),
            "sub": ic.get("sub"),
        }
    )


def _pop_signing_bytes(pop: dict) -> bytes:
    """Canonical bytes the INSTANCE key signs."""
    return canon_bytes({"aud": pop.get("aud"), "nonce": pop.get("nonce"), "ts": pop.get("ts")})


def _hybrid_ok(pub_ed, pub_ml, sig, msg: bytes) -> bool:
    """Both signatures or invalid — the same rule as every other signature in the system."""
    if pub_ed is None or pub_ml is None or not isinstance(sig, dict):
        return False
    sig_ed = b64f(sig.get("ed25519"), 64)
    sig_ml = b64d(sig.get("mldsa65"))
    if sig_ed is None or sig_ml is None:
        return False
    return ed25519_verify(pub_ed, sig_ed, msg) and mldsa65_verify(pub_ml, sig_ml, msg)


def _verify_instance(inst, claims: dict, passport_leaf: bytes, now: int, expected_aud: str):
    """The instance rung (ADR-019), fixed order, first-failure-wins.

    Returns a reason string, or ``None`` when it verifies. Order: binding -> window -> scope -> credential
    signature -> proof-of-possession. Binding first, because a credential minted for a different passport must be
    refused before any of its own claims are weighed; signature before PoP, because a PoP over a credential that
    was never validly minted proves nothing.

    Single-use of the nonce is NOT enforced here — that is caller state, and this SDK holds none by design.
    """
    if not isinstance(inst, dict):
        return R.SCHEMA_VIOLATION
    # (0) DECODE, strictly, before anything is weighed. D-029: a non-canonical base64url field is a decode
    #     failure, not a signature failure — core refuses it at the adapter gateway with ``schema_violation`` and
    #     the TS SDK does the same at ``decodePresentation``. The first version of this function returned
    #     ``instance_sig_invalid`` here and the four-way differential caught it: 985/1009, 24 disagreements, all
    #     ``instance-noncanon``. Decoding first is also what keeps the reason honest — "we could not read it" is a
    #     different fact from "it was signed by the wrong key".
    ikey = inst.get("ikey") or {}
    pop_in = inst.get("pop") or {}
    sig_in = inst.get("sig") or {}
    leaf = b64f(inst.get("passport_leaf"), 32)
    ik_ed = b64f(ikey.get("ed25519"), 32)
    ik_ml = b64d(ikey.get("mldsa65"))
    ic_sig_ed = b64f(sig_in.get("ed25519"), 64) if isinstance(sig_in, dict) else None
    ic_sig_ml = b64d(sig_in.get("mldsa65")) if isinstance(sig_in, dict) else None
    pop_sig = pop_in.get("sig") or {}
    pop_ed = b64f(pop_sig.get("ed25519"), 64) if isinstance(pop_sig, dict) else None
    pop_ml = b64d(pop_sig.get("mldsa65")) if isinstance(pop_sig, dict) else None
    if any(x is None for x in (leaf, ik_ed, ik_ml, ic_sig_ed, ic_sig_ml, pop_ed, pop_ml)):
        return R.SCHEMA_VIOLATION
    # (1) binding — belongs to the passport actually presented and proven logged.
    if inst.get("sub") != claims.get("sub") or leaf != passport_leaf:
        return R.INSTANCE_SIG_INVALID
    # (2) window — exact, no skew, plus the ceiling enforced at VERIFY and not only at issuance.
    nbf, exp = inst.get("nbf"), inst.get("exp")
    if not isinstance(nbf, int) or not isinstance(exp, int) or isinstance(nbf, bool) or isinstance(exp, bool):
        return R.INSTANCE_EXPIRED
    if exp <= nbf or exp - nbf > INSTANCE_CRED_DEFAULT_SECS:
        return R.INSTANCE_EXPIRED
    if now < nbf or now >= exp:
        return R.INSTANCE_EXPIRED
    # (3) scope — narrowing only. The intersection rule one rung down from the delegation chain.
    caps = inst.get("capabilities")
    passport_caps = claims.get("capabilities") or []
    if not isinstance(caps, list) or not all(c in passport_caps for c in caps):
        return R.INSTANCE_SCOPE_EXCEEDS
    # (4) credential signature under the PASSPORT's control key.
    pkeys = claims.get("keys") or []
    if not pkeys:
        return R.INSTANCE_SIG_INVALID
    try:
        msg = _instance_signing_bytes(inst)
    except CanonError:
        return R.INSTANCE_SIG_INVALID
    if not _hybrid_ok(
        b64f(pkeys[0].get("ed25519"), 32), b64d(pkeys[0].get("mldsa65")), inst.get("sig") or {}, msg
    ):
        return R.INSTANCE_SIG_INVALID
    # (5) proof-of-possession — audience, freshness, then the signature under the INSTANCE key.
    pop = inst.get("pop") or {}
    if inst.get("aud") != expected_aud or pop.get("aud") != expected_aud:
        return R.INSTANCE_POP_INVALID
    ts = pop.get("ts")
    if not isinstance(ts, int) or isinstance(ts, bool) or abs(ts - now) > POP_MAX_SKEW_SECS:
        return R.INSTANCE_POP_INVALID
    ikey = inst.get("ikey") or {}
    try:
        pop_msg = _pop_signing_bytes(pop)
    except CanonError:
        return R.INSTANCE_POP_INVALID
    if not _hybrid_ok(
        b64f(ikey.get("ed25519"), 32), b64d(ikey.get("mldsa65")), pop.get("sig") or {}, pop_msg
    ):
        return R.INSTANCE_POP_INVALID
    return None


def _decode_proof(items: object) -> list[bytes] | None:
    if not isinstance(items, list):
        return None
    out = []
    for x in items:
        d = b64f(x, 32)
        if d is None:
            return None
        out.append(d)
    return out


def _verify_delegate_checkpoint(cs, log_root_slh, cp_msg, now, presentation) -> bool:
    cert = cs.get("cert") or {}
    delegate_ed = cert.get("delegate_ed25519")
    delegate_ed_pub = b64f(delegate_ed, 32)
    scopes = cert.get("scopes")
    c_nbf, c_exp = cert.get("nbf"), cert.get("exp")
    cert_slh = b64f(cert.get("sig_slh"), SLH_DSA_SHA2_128S_SIG_LEN)
    if (
        delegate_ed_pub is None
        or not isinstance(scopes, list)
        or not isinstance(c_nbf, int)
        or not isinstance(c_exp, int)
        or cert_slh is None
    ):
        return False
    try:
        cert_msg = canon_bytes(
            {"delegate": delegate_ed, "exp": c_exp, "nbf": c_nbf, "scopes": scopes}
        )
    except CanonError:
        return False
    # Cert must be root-SLH-signed, in-window, correctly scoped, not revoked.
    if not slh_dsa_sha2_128s_verify(log_root_slh, cert_slh, cert_msg):
        return False
    if CHECKPOINT_SCOPE not in scopes:
        return False
    if now < c_nbf or now >= c_exp:
        return False
    from ._b64 import encode as b64e

    fingerprint = b64e(sha256(cert_msg))
    if fingerprint in (presentation.get("revoked_delegates") or []):
        return False
    # The checkpoint itself must be signed by the delegate key.
    sig_ed = b64f(cs.get("sig_ed25519"), ED25519_SIG_LEN)
    if sig_ed is None or not ed25519_verify(delegate_ed_pub, sig_ed, cp_msg):
        return False
    return True
