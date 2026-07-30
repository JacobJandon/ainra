# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Cryptographic primitives — shared audited libraries, fail-closed wrappers.

Independence note (see the package README and decision D-041): the verification
*logic* in this package is written independently from the specification and the
conformance vectors. The primitives themselves are deliberately NOT reimplemented
— reimplementing a signature scheme would be less safe, not more independent:

* **Ed25519** (32-byte key, 64-byte signature) and **ML-DSA-65 / FIPS 204**
  (1952-byte key, 3309-byte signature) come from ``cryptography`` (pyca), which
  wraps OpenSSL 3.5+.
* **SLH-DSA-SHA2-128s / FIPS 205** (32-byte key, 7856-byte signature) is not yet
  surfaced by ``cryptography``, so it is bound directly from the same OpenSSL
  ``libcrypto`` via ``ctypes`` (EVP raw-public-key verify) — an established C
  implementation used for that primitive only.
* **SHA-256** is the Python standard library ``hashlib``.

The differential (the fourth column of ``make diff``) exercises the *logic*, not
the primitives; agreement with the Rust core, the TS SDK, and the JS CLI is the
independent confirmation. Every wrapper returns ``bool`` and never raises: a
verifier fails closed, so any error, wrong size, or exception is ``False``.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

# Exact FIPS / RFC 8032 sizes — asserted as a conformance gate, matching the
# Rust core's size asserts (a deviation means a broken dependency, not a code
# change).
ED25519_PUB_LEN = 32
ED25519_SIG_LEN = 64
MLDSA65_PUB_LEN = 1952
MLDSA65_SIG_LEN = 3309
SLH_DSA_SHA2_128S_PUB_LEN = 32
SLH_DSA_SHA2_128S_SIG_LEN = 7856


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def ed25519_verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    """Verify an Ed25519 signature; fail closed on any anomaly."""
    if len(pub) != ED25519_PUB_LEN or len(sig) != ED25519_SIG_LEN:
        return False
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except Exception:
        return False


def mldsa65_verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    """Verify an ML-DSA-65 (FIPS 204) signature; fail closed on any anomaly."""
    if len(pub) != MLDSA65_PUB_LEN or len(sig) != MLDSA65_SIG_LEN:
        return False
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except Exception:
        return False


# ── SLH-DSA-SHA2-128s via OpenSSL libcrypto (ctypes) ────────────────────────
class _SlhBackend:
    """Lazy, process-wide binding to OpenSSL's SLH-DSA-SHA2-128s verify."""

    _ALG = b"SLH-DSA-SHA2-128s"

    def __init__(self) -> None:
        self._lib = None

    def _load(self):
        if self._lib is not None:
            return self._lib
        name = ctypes.util.find_library("crypto") or "libcrypto.so.3"
        lib = ctypes.CDLL(name)

        lib.EVP_PKEY_new_raw_public_key_ex.restype = ctypes.c_void_p
        lib.EVP_PKEY_new_raw_public_key_ex.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p,
            ctypes.c_char_p, ctypes.c_size_t,
        ]
        lib.EVP_PKEY_free.restype = None
        lib.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
        lib.EVP_MD_CTX_new.restype = ctypes.c_void_p
        lib.EVP_MD_CTX_new.argtypes = []
        lib.EVP_MD_CTX_free.restype = None
        lib.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]
        lib.EVP_DigestVerifyInit_ex.restype = ctypes.c_int
        lib.EVP_DigestVerifyInit_ex.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p,
            ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p,
        ]
        lib.EVP_DigestVerify.restype = ctypes.c_int
        lib.EVP_DigestVerify.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
        ]
        self._lib = lib
        return lib

    def verify(self, pub: bytes, sig: bytes, msg: bytes) -> bool:
        if len(pub) != SLH_DSA_SHA2_128S_PUB_LEN or len(sig) != SLH_DSA_SHA2_128S_SIG_LEN:
            return False
        try:
            lib = self._load()
        except Exception:
            return False
        pkey = None
        ctx = None
        try:
            pkey = lib.EVP_PKEY_new_raw_public_key_ex(
                None, self._ALG, None, pub, len(pub)
            )
            if not pkey:
                return False
            ctx = lib.EVP_MD_CTX_new()
            if not ctx:
                return False
            if lib.EVP_DigestVerifyInit_ex(ctx, None, None, None, None, pkey, None) != 1:
                return False
            return lib.EVP_DigestVerify(ctx, sig, len(sig), msg, len(msg)) == 1
        except Exception:
            return False
        finally:
            if ctx:
                lib.EVP_MD_CTX_free(ctx)
            if pkey:
                lib.EVP_PKEY_free(pkey)


_slh = _SlhBackend()


def slh_dsa_sha2_128s_verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    """Verify an SLH-DSA-SHA2-128s (FIPS 205) signature; fail closed."""
    return _slh.verify(pub, sig, msg)


def slh_available() -> bool:
    """True iff the OpenSSL SLH-DSA verify path is usable in this environment."""
    try:
        _slh._load()
        return True
    except Exception:
        return False
