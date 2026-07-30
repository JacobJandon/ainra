# SPDX-License-Identifier: Apache-2.0 OR MIT
"""The verdict and the M16 verdict-event envelope (docs/PRESENTATION.md).

Every AINRA-aware surface reports a result the same way. The event fields, in
this fixed order: ``status``, ``reason``, ``name``, ``number``, ``tier``,
``freshness_age_s``. ``null`` fields appear when the bundle cannot be decoded —
the event is always well-formed.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Verdict:
    """The outcome of verification: valid, or invalid with a frozen reason."""

    valid: bool
    reason: str | None = None
    # Presentation identity, populated best-effort for the verdict event.
    name: str | None = None
    number: str | None = None
    tier: str | None = None
    freshness_age_s: int | None = None

    def as_result(self) -> dict:
        """The verdict+reason shape the differential compares against ``expect``."""
        if self.valid:
            return {"verdict": "valid"}
        return {"verdict": "invalid", "reason": self.reason}

    def event(self) -> dict:
        """The M16 verdict event, fields in their fixed order."""
        return {
            "status": "valid" if self.valid else "invalid",
            "reason": None if self.valid else self.reason,
            "name": self.name,
            "number": self.number,
            "tier": self.tier,
            "freshness_age_s": self.freshness_age_s,
        }


def valid(**identity) -> Verdict:
    return Verdict(True, None, **identity)


def invalid(reason: str, **identity) -> Verdict:
    return Verdict(False, reason, **identity)
