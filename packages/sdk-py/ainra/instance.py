# SPDX-License-Identifier: Apache-2.0 OR MIT
"""ADR-019 (D-047) — the credential a RUNNING COPY carries, from the producing side.

Two sides, and the whole point of the rung is that they run in different places:

* :func:`mint_instance_credential` runs where the passport's **control key** lives — an orchestrator, an init
  container, a sidecar the workload cannot read. That key never enters the container.
* :func:`prove_instance_possession` runs **inside** the container, with the instance key, which is the only key
  material that belongs there.

Signing is a caller-supplied callback. This SDK is a **verifier**: it holds no signing code and no key generation,
so your secrets never enter it. Pass a function that takes bytes and returns
``{"ed25519": <b64url>, "mldsa65": <b64url>}``.

Verification lives in :mod:`ainra.verify` and runs automatically as step 10 of ``verify()`` whenever a presentation
carries an ``instance`` object — you do not call it separately.
"""

from __future__ import annotations

from ._b64 import decode as b64d
from ._canon import canon_bytes

#: ADR-019 ceiling — mirrors ``ainra_core::consts::INSTANCE_CRED_DEFAULT_SECS``. A verifier enforces this
#: regardless of what a minter chose, so the clamp below is a courtesy and not the control.
INSTANCE_CRED_DEFAULT_SECS = 60 * 60


def instance_signing_bytes(ic: dict) -> bytes:
    """Canonical bytes the passport's control key signs.

    Field order mirrors ``InstanceCredential::signing_bytes`` in ainra-core byte-for-byte; the four-way
    differential over the conformance corpus is what keeps the implementations honest about it.
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


def pop_signing_bytes(pop: dict) -> bytes:
    """Canonical bytes the INSTANCE key signs."""
    return canon_bytes({"aud": pop.get("aud"), "nonce": pop.get("nonce"), "ts": pop.get("ts")})


def mint_instance_credential(
    *,
    passport_claims_b64: str,
    passport_leaf_b64: str,
    instance_public: dict,
    capabilities: list[str],
    audience: str,
    now: int,
    iid: str,
    control_sign,
    lifetime_secs: int = INSTANCE_CRED_DEFAULT_SECS,
) -> dict:
    """Mint a credential for one running copy. Run this where the CONTROL KEY lives, never in the container.

    ``passport_leaf_b64`` is the passport's ``prelog_leaf`` — the same leaf its log inclusion was proven against.
    Binding to it is what lets instance credentials go unlogged while ``logged-before-valid`` keeps deciding
    something: you cannot mint under a passport that was never logged.

    Raises ``ValueError`` on a widening capability set. The verifier would refuse it anyway, but failing here means
    the error can name the capability instead of surfacing later as a rejected request in production.
    """
    import json

    claims = b64d(passport_claims_b64)
    if claims is None:
        raise ValueError("passport_claims_b64 is not canonical base64url")
    parsed = json.loads(claims.decode("utf-8"))
    held = parsed.get("capabilities") or []
    extra = [c for c in capabilities if c not in held]
    if extra:
        raise ValueError(f"instance capabilities must narrow: {', '.join(extra)} not held by the passport")
    life = min(int(lifetime_secs), INSTANCE_CRED_DEFAULT_SECS)
    ic = {
        "sub": parsed["sub"],
        "iid": iid,
        "ikey": {"ed25519": instance_public["ed25519"], "mldsa65": instance_public["mldsa65"]},
        "nbf": int(now),
        "exp": int(now) + life,
        "capabilities": list(capabilities),
        "aud": audience,
        "passport_leaf": passport_leaf_b64,
    }
    ic["sig"] = control_sign(instance_signing_bytes(ic))
    return ic


def prove_instance_possession(*, audience: str, nonce: str, now: int, instance_sign) -> dict:
    """Produce the proof-of-possession a running copy sends with each presentation.

    A fresh ``nonce`` per presentation is the caller's responsibility. The nonce is bound into the signed bytes so
    single-use CAN be enforced; nothing here enforces it, because a replay cache is state and this SDK holds none.
    A caller that does not enforce it is exposed to replay inside the timestamp window, against this audience, by
    someone who already has the bundle — said plainly rather than left to be discovered.
    """
    pop = {"aud": audience, "nonce": nonce, "ts": int(now)}
    pop["sig"] = instance_sign(pop_signing_bytes(pop))
    return pop
