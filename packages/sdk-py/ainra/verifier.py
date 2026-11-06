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
from ._b64 import encode as b64e
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
    if not isinstance(claims, dict):
        return None  # not an object: the main verify path's business (schema_violation), never an exception here
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


def _authenticate_currency(anchors: dict, pres: dict, now: int, seq_seen: dict, revoked: list) -> str | None:
    """D-021 currency mode (PLAN-M51 step 1), as ``authenticateCurrency`` in the TS SDK. Returns a reason, or None.

    The bundle must carry the registrar's delegate-signed fresh head and its cert; the head must verify to the
    registrar's log root at F1, name this registrar's status URI, and hash the EXACT presented list (its text, not a
    re-encoding); and its ``seq`` may not be lower than one this verifier has already seen for that URI. A head under a
    delegate the directory revokes signs nothing, as for checkpoints. Every failure is ``stale_status``. Honest limit:
    a verifier that never sees a newer head cannot know one exists; F1 (30 s) still bounds that window.
    """
    from .delta import verify_head
    from .verify import sha256

    # The passport and its registrar first, as in Rust and TypeScript: a malformed passport or an unknown registrar is
    # the main path's business and its own reason, whatever the head looks like.
    claims_raw = b64d(pres.get("claims")) if isinstance(pres.get("claims"), str) else None
    try:
        claims = json.loads(claims_raw.decode("utf-8")) if claims_raw is not None else {}
        iss = str(claims.get("iss", "")) if isinstance(claims, dict) else ""
    except Exception:
        return None  # a malformed bundle is the main verify path's business, not ours
    info = anchors.get(iss.split(":")[2]) if iss.count(":") >= 2 else None
    if info is None:
        return None  # unknown registrar: the main path's business (and its own reason)
    fh, wc = pres.get("fresh_head"), pres.get("status_delegate_cert")
    if not isinstance(fh, dict) or not isinstance(wc, dict):
        return R.STALE_STATUS  # required in currency mode: an absent head cannot downgrade it
    seq, ts = fh.get("seq"), fh.get("ts")
    if type(seq) is not int or seq < 0 or type(ts) is not int or not isinstance(fh.get("uri"), str):
        return R.STALE_STATUS
    head = {"now": now, "root_pub_slh": info.get("log_root_key"), "cert": wc, "uri": fh["uri"], "seq": seq, "ts": ts,
            "status_hash": fh.get("status_hash"), "sig_delegate": fh.get("sig_delegate"), "freshness": "F1"}
    if not verify_head(head).get("accept"):  # the wrapper: any exception inside is stale_status, never a raise
        return R.STALE_STATUS
    try:
        cert_msg = canon_bytes({"delegate": wc.get("delegate_ed25519"), "exp": wc.get("exp"), "nbf": wc.get("nbf"),
                                "scopes": wc.get("scopes")})
        bound = sha256(canon_bytes({"bit_len": pres.get("status_len"), "status_list": pres.get("status_list"),
                                    "uri": fh["uri"]}))
    except Exception:  # CanonError, and e.g. a lone surrogate that cannot be encoded as UTF-8
        return R.STALE_STATUS
    if b64e(sha256(cert_msg)) in (revoked or []):
        return R.STALE_STATUS
    if fh["uri"] != info.get("status_uri"):
        return R.STALE_STATUS
    if b64f(fh.get("status_hash"), 32) != bound:
        return R.STALE_STATUS
    seen = seq_seen.get(fh["uri"])
    if seen is not None and seq < seen:
        return R.STALE_STATUS  # a superseded head: this verifier has already seen a newer one
    seq_seen[fh["uri"]] = seq if seen is None else max(seen, seq)
    return None


def deny_matches(e: str, sub: str) -> bool:
    """D-100: a bare id is a registrar; ``@`` makes it an exact name; otherwise it is a lineage (every version)."""
    if ":" not in e:
        parts = sub.split(":")
        return len(parts) > 1 and parts[1] == e
    if "@" in e:
        return sub == e
    return sub.startswith(e) and sub[len(e):].startswith("@")


def apply_gate_policy(verdict: Verdict, claims, directory_issued_at: int, now: int, policy: dict) -> Verdict:
    """D-100: apply a gate's own policy to the verdict it reached. Only ever turns ``valid`` into ``denied_by_policy``."""
    if not verdict.valid:
        return verdict
    max_age = policy.get("max_directory_age_s")
    if max_age is not None and now > directory_issued_at + int(max_age):
        return invalid(R.DENIED_BY_POLICY)
    try:
        sub = json.loads(b64d(claims)).get("sub", "") if isinstance(claims, str) else ""
    except Exception:  # noqa: BLE001 — a verdict was already reached on these claims; an unreadable sub matches nothing
        sub = ""
    if any(deny_matches(str(e), sub) for e in policy.get("deny") or []):
        return invalid(R.DENIED_BY_POLICY)
    return verdict


class Verifier:
    def __init__(
        self,
        anchors: dict,
        revoked_delegates: list | None = None,
        audience: str = "",
        freshness: str = "F2",
        *,
        unauthenticated_status: bool = False,
        currency: bool = False,
        policy: dict | None = None,
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
        #: True when these anchors came from an authenticated directory (`from_directory`).
        self._anchors_authenticated = False
        #: D-020 status authentication is MANDATORY unless the caller turned it off by name (D-075). A registrar
        #: whose anchor carries no status key then fails closed (`stale_status`), exactly as in the TS SDK.
        #:
        #: Until 0.4.x this constructor skipped the check whenever the anchors had no status key — "the trusted-input
        #: mode" — so the most obvious way to build a verifier in this package was one that believed any status
        #: list a presenter handed it. It was documented, and it was a default that accepts. Anchors that carry
        #: `status_ed25519`, `status_mldsa65` and `status_uri` are authenticated against, as before;
        #: `unauthenticated_status=True` is for conformance vectors and other fixtures, whose status is an input,
        #: and for nothing that decides access.
        self._status_mandatory = not unauthenticated_status
        #: D-021 currency mode (opt-in, stateful): require a fresh head bound to the presented list, and refuse a
        #: lower ``seq`` than this verifier has seen per status URI. Off by default, as in the TS SDK.
        self._currency = bool(currency)
        self._seq_seen: dict = {}
        #: D-100 — this gate's own policy: ``{"deny": [...], "max_directory_age_s": n}``, both optional. It can only
        #: turn ``valid`` into ``denied_by_policy``. ``max_directory_age_s`` is off unless set, so an offline gate keeps
        #: working on the directory it holds.
        self._policy = dict(policy or {})
        self._directory_issued_at = 0

    @classmethod
    def from_directory(
        cls,
        directory: dict,
        root_ed25519: str,
        root_slh: str,
        audience: str = "",
        freshness: str = "F2",
        currency: bool = False,
        policy: dict | None = None,
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
        v = cls(anchors, directory.get("revoked_delegates", []), audience, freshness, currency=currency, policy=policy)
        v._anchors_authenticated = True
        v._directory_issued_at = int(directory.get("issued_at") or 0)
        return v

    def verify_head_receipt(self, receipt: dict, gate_key: bytes, now: int) -> dict:
        """Check a registrar's receipt for a gate's logged decision head (D-081) against this verifier's registrars:
        the statement names and was signed by ``gate_key``, and it is logged under a checkpoint the registrar's log
        key signed. ``{"verdict": "valid", "statement": {...}}`` or ``{"verdict": "invalid", "reason": r}``."""
        from .decision import verify_head_receipt
        return verify_head_receipt(self._anchors, self._revoked, receipt, gate_key, now)

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
        bad = _authenticate_status(self._anchors, pres, self._status_mandatory)
        if bad is None and self._currency:
            bad = _authenticate_currency(self._anchors, pres, now, self._seq_seen, self._revoked)
        if bad is not None:
            return invalid(bad)
        return apply_gate_policy(_verify(self._anchors, pres, now), pres.get("claims"), self._directory_issued_at, now,
                                 self._policy)

    def verify_link(self, link: dict, presented_key: bytes, now: int, capability: str | None = None) -> dict:
        """AINRA Link (D-078): who stands behind ``presented_key``, the 32-byte Ed25519 key this gate has ALREADY
        verified the request's signature with. Uses this verifier's anchors, revoked delegates and freshness class,
        and always authenticates the status publication — a link has no fixture mode. Never raises.

        Returns ``{"verdict": "valid", "registrar", "operator", "passport", "scope"}`` or
        ``{"verdict": "invalid", "reason": ...}``. A key with no link at all is the caller's outcome ("not linked").
        """
        from .link import verify_link

        return verify_link(self._anchors, self._revoked, link, presented_key, now, self._freshness, capability)
