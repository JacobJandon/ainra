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

# Exact field sizes for a well-formed entry (fail closed on any deviation).
_ENTRY_SIZES = {
    "issuer_ed25519": 32,
    "issuer_mldsa65": 1952,
    "log_root_slh": 32,
    "status_ed25519": 32,
    "status_mldsa65": 1952,
}
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
        for field, size in _ENTRY_SIZES.items():
            if b64f(e.get(field), size) is None:
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
