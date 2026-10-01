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
