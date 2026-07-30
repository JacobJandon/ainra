# SPDX-License-Identifier: Apache-2.0 OR MIT
"""The strict canonical base64url gateway (decision D-029).

Every external base64url ingestion in the verifier routes through :func:`decode`.
Python's :func:`base64.urlsafe_b64decode` is *lenient* — it silently accepts
non-zero trailing bits, standard-alphabet ("+"/"/") swaps, whitespace, and
padding. That leniency is exactly the fail-open class D-029 closes. We require a
canonical round-trip (``encode(decode(s)) == s``) plus an explicit alphabet
check, mirroring the Rust core's ``base64ct`` ``Base64UrlUnpadded`` byte-for-byte:
a value is accepted iff it is unpadded base64url whose final character's unused
low bits are all zero. Anything else is refused (returns ``None``); the caller
maps that refusal to the field-appropriate frozen reason.
"""

from __future__ import annotations

import base64

_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def decode(s: object) -> bytes | None:
    """Strictly decode a canonical unpadded base64url string.

    Returns the raw bytes, or ``None`` if ``s`` is not a canonical encoding.
    Never raises — a verifier must fail closed, not crash.
    """
    if not isinstance(s, str):
        return None
    # Reject padding, whitespace, and any non-alphabet character up front.
    for ch in s:
        if ch not in _ALPHABET:
            return None
    try:
        raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        return None
    # Canonical round-trip: catches non-zero trailing bits (a lenient decoder
    # would drop them). Identical acceptance set to base64ct Base64UrlUnpadded.
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != s:
        return None
    return raw


def encode(raw: bytes) -> str:
    """Canonical unpadded base64url encoding of ``raw``."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_fixed(s: object, length: int) -> bytes | None:
    """Strictly decode and require exactly ``length`` bytes, else ``None``."""
    raw = decode(s)
    if raw is None or len(raw) != length:
        return None
    return raw
