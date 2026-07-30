# SPDX-License-Identifier: Apache-2.0 OR MIT
"""The strict base64url gateway (D-029) and canonical-JSON rejection (D-010)."""

from __future__ import annotations

import base64
import unittest

from ainra._b64 import decode
from ainra._canon import CanonError, canonicalize


class TestStrictBase64(unittest.TestCase):
    def test_accepts_exactly_the_canonical_last_chars(self):
        # A three-char base64url string encodes two bytes (16 bits) out of 18,
        # so the final char carries 2 unused low bits; only the 16 last-char
        # values whose low 2 bits are zero (index ≡ 0 mod 4) round-trip
        # canonically — identical to the Rust core's base64ct Base64UrlUnpadded.
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        prefix = "AA"
        accepted = 0
        for c in alphabet:
            s = prefix + c
            raw = decode(s)
            if raw is not None:
                accepted += 1
                self.assertEqual(base64.urlsafe_b64encode(raw).rstrip(b"=").decode(), s)
        self.assertEqual(accepted, 16)

    def test_rejects_padding_whitespace_and_wrong_alphabet(self):
        self.assertIsNone(decode("AAAA="))       # padding
        self.assertIsNone(decode("AA AA"))       # whitespace
        self.assertIsNone(decode("AA+"))         # standard-alphabet '+'
        self.assertIsNone(decode("AA/"))         # standard-alphabet '/'
        self.assertIsNone(decode("AAB"))         # non-zero trailing bits (2-byte)
        self.assertIsNotNone(decode("AAAB"))     # 3 bytes, complete group — canonical
        self.assertIsNone(decode(b"AAAA"))       # not a str
        self.assertIsNone(decode(None))

    def test_accepts_a_real_key(self):
        self.assertEqual(len(decode("cJ27-6LOZcsk-KWhrlpWcRMSHGNGtVqXkcFc83oMMUg")), 32)


class TestCanonicalRejection(unittest.TestCase):
    def test_golden_sorted_no_space(self):
        self.assertEqual(
            canonicalize({"b": 1, "a": {"z": True, "y": [3, 2, 1]}}),
            '{"a":{"y":[3,2,1],"z":true},"b":1}',
        )

    def test_rejects_float(self):
        with self.assertRaises(CanonError):
            canonicalize({"x": 1.5})

    def test_rejects_non_ascii_key(self):
        with self.assertRaises(CanonError):
            canonicalize({"café": 1})

    def test_rejects_big_int(self):
        canonicalize({"n": 9007199254740991})  # 2^53 - 1 is fine
        with self.assertRaises(CanonError):
            canonicalize({"n": 9007199254740992})  # 2^53


if __name__ == "__main__":
    unittest.main()
