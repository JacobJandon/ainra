# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Deterministic canonical JSON (decisions D-003 and D-010).

The canonical form is the sorted-key, no-whitespace scheme the whole AINRA
corpus is signed and hashed over: object keys sorted, ``"key":value`` with no
spaces, scalars serialized exactly as a minimal JSON encoder would. Three input
classes are *rejected* (:class:`CanonError`) because they would diverge across a
byte-for-byte cross-language differential (D-010): floating-point numbers,
non-ASCII object keys (UTF-16 vs UTF-8 sort order disagree), and integers
outside ``[-(2**53 - 1), 2**53 - 1]`` (not exactly representable as a JS
``Number``). No conformant AINRA credential uses any of them.

This is an independent implementation written from the specification, not a port
of the Rust ``canon`` or the TypeScript ``canonicalize``; the differential
harness is what proves the three agree.
"""

from __future__ import annotations

_MAX_SAFE_INT = (2**53) - 1


class CanonError(ValueError):
    """Raised when a value cannot be canonicalized deterministically."""


def _string(s: str) -> str:
    # Minimal JSON string escaping, matching a standard JSON encoder (the same
    # set produced by JSON.stringify / serde_json): quote, backslash, the five
    # short control escapes, and \u00xx for the remaining C0 controls. Forward
    # slash is NOT escaped. Non-ASCII characters are emitted verbatim (UTF-8).
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _is_ascii(s: str) -> bool:
    return all(ord(c) < 0x80 for c in s)


def canonicalize(value: object) -> str:
    """Return the canonical JSON string for ``value`` (raises on divergent input)."""

    def enc(v: object) -> str:
        if v is None:
            return "null"
        if v is True:
            return "true"
        if v is False:
            return "false"
        if isinstance(v, float):
            # A float in the input is a divergence hazard (D-010): reject.
            raise CanonError("floats are not canonicalizable")
        if isinstance(v, int):
            if v > _MAX_SAFE_INT or v < -_MAX_SAFE_INT:
                raise CanonError("integer outside the JS-safe range")
            return str(v)
        if isinstance(v, str):
            return _string(v)
        if isinstance(v, (list, tuple)):
            return "[" + ",".join(enc(x) for x in v) + "]"
        if isinstance(v, dict):
            items = []
            for k in v:
                if not isinstance(k, str):
                    raise CanonError("object keys must be strings")
                if not _is_ascii(k):
                    raise CanonError("non-ASCII object key")
            for k in sorted(v.keys()):
                items.append(_string(k) + ":" + enc(v[k]))
            return "{" + ",".join(items) + "}"
        raise CanonError(f"uncanonicalizable value of type {type(v).__name__}")

    return enc(value)


def canon_bytes(value: object) -> bytes:
    return canonicalize(value).encode("utf-8")
