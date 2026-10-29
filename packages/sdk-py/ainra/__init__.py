# SPDX-License-Identifier: Apache-2.0 OR MIT
"""ainra — an independent Python implementation of the AINRA passport verifier.

Verify-only, offline, fail-closed, zero-telemetry. Written from the AINRA
specification and conformance vectors (not transliterated from the Rust core or
the TypeScript SDK); the differential harness proves it agrees with them
byte-for-byte on every vector's verdict and reason. See the package README and
decision D-041 for the precise independence claim and the shared cryptographic
primitives.

Quickstart::

    from ainra import Verifier
    v = Verifier.from_directory(directory, root_ed25519, root_slh)   # None unless both roots signed it
    verdict = v.verify(bundle, now)     # caller supplies `now`; no I/O
    if verdict.valid:
        ...
    else:
        print(verdict.reason)           # one of the 20 frozen reasons
"""

from __future__ import annotations

from . import reasons
from ._canon import canonicalize
from .delta import verify_delta, verify_head
from .directory import verify_directory
from .link import jwk_thumbprint_ed25519, link_from_index
from .link import pop_signing_bytes as link_pop_signing_bytes
from .instance import (
    INSTANCE_CRED_DEFAULT_SECS,
    instance_signing_bytes,
    mint_instance_credential,
    instance_cred_digest,
    pop_signing_bytes,
    prove_instance_possession,
)
from .decision import DecisionLog
from .middleware import AinraGate, AinraLinkGate, PresentationStore, ainra_gate, check_binding
from .presentation import presentation_ref, sign_presentation
from .verdict import Verdict
from .verifier import Verifier
from .verify import verify

__all__ = [
    # ADR-019 — the instance rung. Verification is automatic (step 10 of verify()); these are the PRODUCING side,
    # and they live on opposite sides of the container boundary on purpose.
    "mint_instance_credential",
    "prove_instance_possession",
    "instance_signing_bytes",
    "instance_cred_digest",
    "pop_signing_bytes",
    "INSTANCE_CRED_DEFAULT_SECS",
    # D-071 — an agent written in Python: sign each request, name the bundle it sent once by digest.
    "sign_presentation",
    "presentation_ref",
    "canonicalize",
    # D-078 — AINRA Link: who stands behind a key an agent already has (verify with Verifier.verify_link).
    "jwk_thumbprint_ed25519",
    "link_pop_signing_bytes",
    "link_from_index",
    "Verifier",
    "Verdict",
    "verify",
    "verify_delta",
    "verify_head",
    "verify_directory",
    "AinraGate",
    "AinraLinkGate",
    "DecisionLog",
    "PresentationStore",
    "check_binding",
    "ainra_gate",
    "reasons",
]

__version__ = "0.5.0"
