# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Dual-root-signed registrar directory verification (decision D-019).

The directory maps each registrar id to its hybrid issuer key, its log-checkpoint
SLH root, and its status-list signing keys, plus the epoch, issued-at, and the
revoked-delegate fingerprint list. It is signed by BOTH ceremony roots
(FROST-Ed25519 + SLH-DSA) over one canonical body. Accreditation requires **both**
signatures to verify AND the entries to be **strictly sorted + unique** — any
failure (a single bad signature, a malformed key/fingerprint, an unsorted or
duplicate entry, a tampered field) fails closed: with no authentic directory, no
registrar is known.

Result mirrors the corpus ``expect``: ``{"accept": True, "registrars": N}`` or
``{"accept": False}``.
"""

from __future__ import annotations

from ._b64 import decode as b64d
from ._b64 import decode_fixed as b64f
from ._canon import CanonError, canon_bytes
from ._crypto import ed25519_verify, slh_dsa_sha2_128s_verify

# What decides whether a directory is ACCEPTED, exactly as `ainra-core`'s `Directory::accredit` and `@ainra/sdk`
# decide it: the issuer's Ed25519 key is 32 bytes, and its ML-DSA key and the log root decode. The STATUS key is not
# part of this decision (D-073). This module used to require one, well-formed, on every entry — so a directory with
# one entry that publishes no status key was accepted by the core and by TypeScript (which then refuse that one
# registrar's passports as `stale_status`) and rejected whole by Python, which could then build no gate at all. Found
# by vectors/v1-gate on its first run (g24); the directory corpus had no such entry.
_ENTRY_STRINGS = ("registrar", "status_uri")


def _reject():
    return {"accept": False}


def verify_directory(v: dict) -> dict:
    """Verify a directory-corpus vector; return accept + registrar count."""
    try:
        return _verify_directory(v)
    except Exception:
        return _reject()


def _verify_directory(v: dict) -> dict:
    d = v.get("directory")
    if not isinstance(d, dict):
        return _reject()
    entries = d.get("entries")
    if not isinstance(entries, list):
        return _reject()

    # Structural: every entry well-formed; strictly ascending, unique registrar.
    prev = None
    for e in entries:
        if not isinstance(e, dict):
            return _reject()
        if b64f(e.get("issuer_ed25519"), 32) is None:
            return _reject()
        if b64d(e.get("issuer_mldsa65")) is None or b64d(e.get("log_root_slh")) is None:
            return _reject()
        for field in _ENTRY_STRINGS:
            if not isinstance(e.get(field), str):
                return _reject()
        reg = e["registrar"]
        if prev is not None and not (prev < reg):
            return _reject()  # unsorted or duplicate
        prev = reg

    # Every revoked-delegate fingerprint must be a canonical 32-byte value.
    revoked = d.get("revoked_delegates")
    if not isinstance(revoked, list):
        return _reject()
    for fp in revoked:
        if b64f(fp, 32) is None:
            return _reject()

    # Both root signatures over the canonical body (sig fields excluded).
    body = {k: v_ for k, v_ in d.items() if not k.startswith("sig_root")}
    try:
        msg = canon_bytes(body)
    except CanonError:
        return _reject()
    root_ed = b64d(v.get("root_ed25519")) or b""
    root_slh = b64d(v.get("root_slh")) or b""
    sig_ed = b64f(d.get("sig_root_ed25519"), 64)
    sig_slh = b64f(d.get("sig_root_slh"), 7856)
    if sig_ed is None or sig_slh is None:
        return _reject()
    if not ed25519_verify(root_ed, sig_ed, msg):
        return _reject()
    if not slh_dsa_sha2_128s_verify(root_slh, sig_slh, msg):
        return _reject()

    return {"accept": True, "registrars": len(entries)}


# ── Directory rollback (PLAN-M50) ────────────────────────────────────────────────────────────────────────────────────
# Written from ``ainra_core::directory::{accredit_at_least, DirectoryHolder}``, independently of the TypeScript SDK;
# held to ``vectors/v1-directory-epoch`` in ``make diff``. Both roots signed every old directory too, so authenticity
# cannot refuse a replayed one — only the epoch can. Authenticity is checked first, so a forged directory claiming a
# high epoch never raises the floor.

def _epoch_of(directory: dict):
    e = directory.get("epoch") if isinstance(directory, dict) else None
    return e if isinstance(e, int) and not isinstance(e, bool) and 0 <= e < 2 ** 64 else None


def verify_directory_at_least(directory: dict, root_ed25519: str, root_slh: str, min_epoch: int = 0) -> dict:
    """``{"ok": True, "epoch": e, "registrars": n}``, ``{"ok": False, "refusal": "unauthentic"}``, or
    ``{"ok": False, "refusal": "rollback", "epoch": e, "floor": f}`` for an authentic directory older than
    ``min_epoch``. The root keys are base64url, as published in ``roots.json``."""
    r = verify_directory({"directory": directory, "root_ed25519": root_ed25519, "root_slh": root_slh})
    epoch = _epoch_of(directory)
    if not r.get("accept") or epoch is None:
        return {"ok": False, "refusal": "unauthentic"}
    if epoch < min_epoch:
        return {"ok": False, "refusal": "rollback", "epoch": epoch, "floor": min_epoch}
    return {"ok": True, "epoch": epoch, "registrars": r["registrars"]}


class DirectoryHolder:
    """What a long-lived verifier keeps between directory refreshes: the highest epoch it has accepted. Hand it each
    new directory; it refuses anything older than what it already accepted. A restart starts again from ``min_epoch``
    — persisting the floor across restarts is the deployment's job."""

    def __init__(self, root_ed25519: str, root_slh: str, min_epoch: int = 0) -> None:
        self._ed, self._slh, self._floor = root_ed25519, root_slh, min_epoch

    @property
    def floor(self) -> int:
        """The epoch below which a directory is refused."""
        return self._floor

    def accept(self, directory: dict) -> dict:
        r = verify_directory_at_least(directory, self._ed, self._slh, self._floor)
        if r["ok"]:
            self._floor = r["epoch"]
        return r

    def verifier(self, directory: dict, audience: str = "", freshness: str = "F2"):
        """A ``Verifier`` built from ``directory``, only if this holder accepts it; otherwise the refusal dict."""
        r = self.accept(directory)
        if not r["ok"]:
            return r
        from .verifier import Verifier
        return Verifier.from_directory(directory, self._ed, self._slh, audience, freshness)


def run_directory_epoch_vector(v: dict) -> list:
    """One ``vectors/v1-directory-epoch`` vector: its directories, in order, to a holder starting at ``min_epoch``."""
    holder = DirectoryHolder(v.get("root_ed25519") or "", v.get("root_slh") or "", v.get("min_epoch") or 0)
    out = []
    for d in v.get("directories") or []:
        r = holder.accept(d)
        out.append({"accept": True, "epoch": r["epoch"], "registrars": r["registrars"]} if r["ok"]
                   else {"accept": False, "refusal": r["refusal"]})
    return out

