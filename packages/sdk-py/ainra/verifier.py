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

import json

from . import reasons as R
from ._b64 import decode as b64d
from ._b64 import decode_fixed as b64f
from ._canon import CanonError, canon_bytes
from ._crypto import ed25519_verify, mldsa65_verify
from .directory import verify_directory
from .verdict import Verdict, invalid
from .verify import verify as _verify


def _authenticate_status(anchors: dict, pres: dict, mandatory: bool = True) -> str | None:
    """Prove the presented status list is the one the REGISTRAR signed. Returns a reason, or None to accept.

    Mirrors `authenticateStatus` in the TS SDK: a signed publication must be present, the URI must bind three
    ways (the passport's claimed URI = the bundle's signed URI = the directory's published URI, so no other
    registrar's all-clear list can be spliced in), and the hybrid signature must verify over the canonical
    ``{bit_len, issued_at, status_list, uri}``. Every failure is ``stale_status`` — status we cannot authenticate
    is status we do not have.
    """
    claims_b64 = pres.get("claims")
    raw = b64d(claims_b64) if isinstance(claims_b64, str) else None
    if raw is None:
        return None  # a malformed bundle is the main verify path's business, not ours
    try:
        claims = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    reg = str(claims.get("iss", "")).split(":")[2] if str(claims.get("iss", "")).count(":") >= 2 else None
    info = anchors.get(reg) if reg else None
    if info is None:
        return None  # unknown registrar is the main path's business (and its own reason)
    if not info.get("status_ed25519") or not info.get("status_mldsa65"):
        # From an authenticated directory, an accredited registrar with no status key cannot have its revocations
        # authenticated → fail closed, exactly as the TS SDK does. From the raw constructor the caller supplied
        # anchors without one on purpose (the trusted-input mode) — see the note on `_anchors_authenticated`.
        return R.STALE_STATUS if mandatory else None
    uri = pres.get("status_uri")
    sig_ed, sig_ml = pres.get("status_sig_ed25519"), pres.get("status_sig_mldsa65")
    if not isinstance(uri, str) or not isinstance(sig_ed, str) or not isinstance(sig_ml, str):
        return R.STALE_STATUS
    claimed = ((claims.get("status") or {}).get("status_list") or {}).get("uri")
    if uri != info.get("status_uri") or claimed != info.get("status_uri"):
        return R.STALE_STATUS
    ed, ml = b64f(sig_ed, 64), b64d(sig_ml)
    pub_ed, pub_ml = b64f(info["status_ed25519"], 32), b64d(info["status_mldsa65"])
    if ed is None or ml is None or pub_ed is None or pub_ml is None:
        return R.STALE_STATUS
    try:
        msg = canon_bytes({
            "bit_len": pres.get("status_len"),
            "issued_at": pres.get("status_issued_at"),
            "status_list": pres.get("status_list"),
            "uri": uri,
        })
    except CanonError:
        return R.STALE_STATUS
    if not ed25519_verify(pub_ed, ed, msg) or not mldsa65_verify(pub_ml, ml, msg):
        return R.STALE_STATUS
    return None


class Verifier:
    def __init__(
        self,
        anchors: dict,
        revoked_delegates: list | None = None,
        audience: str = "",
        freshness: str = "F2",
    ) -> None:
        self._anchors = dict(anchors or {})
        self._revoked = list(revoked_delegates or [])
        #: This verifier's OWN audience (ADR-019). Empty string is the fail-closed default: a service that has
        #: not said who it is cannot be the intended recipient of anything, so it accepts no instance credential.
        self._audience = str(audience or "")
        #: This verifier's OWN status-freshness policy (F1 30s / F2 5min / F3 24h). Default F2, matching the TS
        #: SDK. A presenter must never choose this: the class bounds how long a genuine but SUPERSEDED status
        #: snapshot stays acceptable, so letting the bundle pick it lets a holder of a pre-revocation snapshot
        #: stretch the revocation window from 30 seconds to 24 hours.
        self._freshness = str(freshness or "F2")
        #: True when these anchors came from an authenticated directory (`from_directory`), which always publishes
        #: a status key per registrar. Then D-020 authentication is MANDATORY and a missing key fails closed,
        #: matching the TS SDK exactly.
        #:
        #: False for the raw constructor, where the caller supplied anchors it already trusts — the pre-D-020
        #: trusted-input mode the frozen `verify()` primitive documents. The TS SDK has no equivalent constructor,
        #: which is why this distinction has to be made explicit here rather than inherited. It is recorded as a
        #: known asymmetry in docs/POLICY-PARITY.md: a Python integrator CAN build a verifier over anchors nobody
        #: signed, and such a verifier cannot authenticate revocations. Use `from_directory` in production.
        self._anchors_authenticated = False

    @classmethod
    def from_directory(
        cls,
        directory: dict,
        root_ed25519: str,
        root_slh: str,
        audience: str = "",
        freshness: str = "F2",
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
                # These three were DROPPED here, and each drop had a consequence:
                #  * `distrust_from_leaf` (D-044) — the root's published, appealable graduated-distrust cutoff.
                #    Without it every Python verifier built the documented way treated a distrusted registrar as
                #    fully trusted.
                #  * the status key + URI (D-020) — without them the status list cannot be authenticated at all,
                #    which is what let a presenter forge an all-clear bitmap for a revoked passport.
                "distrust_from_leaf": e.get("distrust_from_leaf"),
                "status_ed25519": e.get("status_ed25519"),
                "status_mldsa65": e.get("status_mldsa65"),
                "status_uri": e.get("status_uri"),
            }
        v = cls(anchors, directory.get("revoked_delegates", []), audience, freshness)
        v._anchors_authenticated = True
        return v

    def verify(self, bundle: dict, now: int) -> Verdict:
        """Verify a presentation bundle at caller-supplied ``now``. Fail closed."""
        if not isinstance(bundle, dict):
            return invalid("schema_violation")
        # Presenter-controlled fields the verifier MUST override — the bundle's word is never the policy:
        pres = dict(bundle)
        #  * the revoked-delegate set comes from the trusted directory, not the presenter.
        pres["revoked_delegates"] = self._revoked
        #  * AUDIENCE (ADR-019). The bundle carries an `audience` field so the conformance corpus can pin
        #    audience cases deterministically — exactly as it carries `now` — and passing it through would let a
        #    presenter name its own audience and defeat audience binding entirely. The TS SDK closed this during
        #    M28; Python did not, because the fix was applied in one of the two places the rule lives. That is the
        #    defect class M29 Task 2 exists to end, and this is the last instance of it.
        pres["audience"] = self._audience
        #  * FRESHNESS CLASS. Found by the M30 policy-parity harness: this came straight off the bundle, so a
        #    presenter could advertise F3 (24 h) instead of the verifier's F2 (5 min) and have an hour-stale
        #    status accepted. The class bounds how long a genuine but SUPERSEDED snapshot stays usable, so
        #    choosing it is the receiving side's decision — exactly as the audience is. The TS SDK already
        #    overrode it; this is the same fix landing in the second place the rule lives.
        pres["freshness"] = self._freshness
        #  * MANDATE REVOCATIONS. A presenter must not be able to drop a revocation. There is no dynamic mandate
        #    feed in GA, so the authenticated set is empty — matching the TS SDK rather than trusting the wire.
        pres["mandate_revocations"] = []
        # D-020 — AUTHENTICATE THE STATUS LIST BEFORE TRUSTING A SINGLE BIT OF IT.
        # This layer did not exist in this SDK. The M5 adversarial review found the same hole in the TS wedge and
        # closed it there; Python shipped without it, so a presenter could hand over a forged all-clear bitmap and
        # have a REVOKED passport verify VALID. Demonstrated in the M30 review against the shipped middleware.
        # The frozen 9-step verify still receives status bits as a trusted input (exactly like `now`) — the
        # authentication belongs here in the GA layer, which is where TS puts it too.
        bad = _authenticate_status(self._anchors, pres, self._anchors_authenticated)
        if bad is not None:
            return invalid(bad)
        return _verify(self._anchors, pres, now)
