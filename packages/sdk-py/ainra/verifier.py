# SPDX-License-Identifier: Apache-2.0 OR MIT
"""The offline GA verifier surface (decision D-020).

``Verifier`` is a thin, pure wrapper over the frozen nine-step
:func:`ainra.verify.verify`. Two hardenings distinguish it from the raw verify,
both about *who supplies the trusted inputs*:

1. **The verifier owns the clock.** ``now`` is a caller argument; any ``now``
   field inside the presentation is ignored, so a presenter cannot backdate or
   forward-date to dodge expiry or freshness.
2. **The verifier owns the revoked-delegate set.** Revocations come only from the
   dual-root-signed directory (via :meth:`Verifier.from_directory`), never from
   the bundle, so a presenter cannot un-revoke its own delegate by omitting it.

``.verify`` never raises — any structurally broken bundle is an ``invalid``
verdict, never a crash and never a wrong ``valid``. No I/O, no telemetry.
"""

from __future__ import annotations

from .directory import verify_directory
from .verdict import Verdict, invalid
from .verify import verify as _verify


class Verifier:
    def __init__(self, anchors: dict, revoked_delegates: list | None = None) -> None:
        self._anchors = dict(anchors or {})
        self._revoked = list(revoked_delegates or [])

    @classmethod
    def from_directory(
        cls, directory: dict, root_ed25519: str, root_slh: str
    ) -> "Verifier | None":
        """Build a verifier from a directory, only if it is authentically signed.

        Returns ``None`` (no verifier) unless both ceremony-root signatures verify
        and the entries are sorted + unique — with no authentic directory, no
        registrar is trusted.
        """
        res = verify_directory(
            {"directory": directory, "root_ed25519": root_ed25519, "root_slh": root_slh}
        )
        if not res.get("accept"):
            return None
        anchors = {}
        for e in directory.get("entries", []):
            anchors[e["registrar"]] = {
                "issuer_key": {
                    "ed25519": e["issuer_ed25519"],
                    "mldsa65": e["issuer_mldsa65"],
                },
                "log_root_key": e["log_root_slh"],
            }
        return cls(anchors, directory.get("revoked_delegates", []))

    def verify(self, bundle: dict, now: int) -> Verdict:
        """Verify a presentation bundle at caller-supplied ``now``. Fail closed."""
        if not isinstance(bundle, dict):
            return invalid("schema_violation")
        # The verifier's revoked-delegate set overrides anything in the bundle.
        pres = dict(bundle)
        pres["revoked_delegates"] = self._revoked
        return _verify(self._anchors, pres, now)
