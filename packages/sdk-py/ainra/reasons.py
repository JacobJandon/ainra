# SPDX-License-Identifier: Apache-2.0 OR MIT
"""The 20 frozen INVALID reasons (decision D-004), in verify-precedence order.

These machine strings are frozen: they are the exact tokens the CC0 conformance
vectors reference, and they must byte-match the Rust core, the TS SDK, and the JS
CLI. Editorial glosses live in ``docs/reasons.json`` (a single source shared by
every implementation); the strings below are authoritative.
"""

from __future__ import annotations

SCHEMA_VIOLATION = "schema_violation"
NAME_MALFORMED = "name_malformed"
UNKNOWN_REGISTRAR = "unknown_registrar"
NOT_YET_VALID = "not_yet_valid"
EXPIRED = "expired"
SIG_INVALID = "sig_invalid"
ALG_DOWNGRADE = "alg_downgrade"
CEILING_EXCEEDED = "ceiling_exceeded"
CHAIN_WIDENING = "chain_widening"
CHAIN_EXPIRED = "chain_expired"
STALE_STATUS = "stale_status"
REVOKED = "revoked"
MANDATE_REVOKED = "mandate_revoked"
NOT_LOGGED = "not_logged"
#: D-044 — the registrar is accredited, but this credential was logged at/after its distrust cutoff.
REGISTRAR_DISTRUSTED = "registrar_distrusted"
CHECKPOINT_INVALID = "checkpoint_invalid"

# ADR-019 / D-047 — the instance rung. Four reasons, none reused from above: an integrator debugging a rejected
# running copy must not be handed ``expired``, which reads as "your passport ran out" when the passport is fine.
INSTANCE_EXPIRED = "instance_expired"
INSTANCE_SCOPE_EXCEEDS = "instance_scope_exceeds"
INSTANCE_SIG_INVALID = "instance_sig_invalid"
INSTANCE_POP_INVALID = "instance_pop_invalid"

# The closed set, in verify order (mirrors docs/reasons.json).
ALL = (
    SCHEMA_VIOLATION,
    NAME_MALFORMED,
    UNKNOWN_REGISTRAR,
    NOT_YET_VALID,
    EXPIRED,
    SIG_INVALID,
    ALG_DOWNGRADE,
    CEILING_EXCEEDED,
    CHAIN_WIDENING,
    CHAIN_EXPIRED,
    STALE_STATUS,
    REVOKED,
    MANDATE_REVOKED,
    NOT_LOGGED,
    REGISTRAR_DISTRUSTED,
    CHECKPOINT_INVALID,
    INSTANCE_EXPIRED,
    INSTANCE_SCOPE_EXCEEDS,
    INSTANCE_SIG_INVALID,
    INSTANCE_POP_INVALID,
)
