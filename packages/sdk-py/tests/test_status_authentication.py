# SPDX-License-Identifier: Apache-2.0 OR MIT
"""D-020 in the Python SDK: the status list must be AUTHENTICATED before a revocation bit is trusted.

This file exists because it did not. The M5 adversarial review found a presenter could forge an all-clear status
bitmap and make a REVOKED passport verify VALID; TS and Rust closed it then, and this SDK shipped without the
layer entirely. The M30 review demonstrated the bypass end to end through the shipped middleware.

WITNESS — could these fail? Each was RED against the code as it stood:
  · truncate the status list  → was VALID (out-of-range read as "not revoked"); now stale_status
  · forge an all-clear bitmap → was VALID (nothing checked the registrar's signature); now stale_status
Remove the length guard in verify.py or `_authenticate_status` in verifier.py and the matching test goes red.
"""

from __future__ import annotations

import base64
import json
import pathlib
import unittest
import zlib

from ainra import Verifier
from ainra.verify import verify as verify_primitive

ROOT = pathlib.Path(__file__).resolve().parents[3]
V1 = ROOT / "vectors" / "v1"
ART = ROOT / "kits" / "verifier" / "sample-artifacts"
_b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")  # noqa: E731


class TestStatusCannotBeForged(unittest.TestCase):
    def setUp(self) -> None:
        self.vec = json.loads((V1 / "instance-passport-revoked-0000.json").read_text())
        self.pres = self.vec["presentation"]
        self.anchors = self.vec["anchors"]
        self.now = self.pres["now"]

    def _verdict(self, pres):
        r = verify_primitive(self.anchors, pres, self.now)
        return "valid" if r.valid else r.reason

    def test_the_fixture_is_genuinely_revoked(self):
        """Otherwise the two attacks below prove nothing."""
        self.assertEqual(self._verdict(self.pres), "revoked")

    def test_a_truncated_status_list_fails_closed(self):
        """A presenter declares a long bit_len and delivers a short list.

        ainra-core maps every out-of-range index to Revoked (status.rs:136-141). This SDK read `else 0` — NOT
        revoked — handing out a free all-clear for every index past the bytes actually sent.
        """
        attack = dict(self.pres, status_list=_b64(zlib.compress(b"")))
        self.assertEqual(self._verdict(attack), "stale_status")

    def test_an_all_clear_forgery_is_refused_by_a_directory_built_verifier(self):
        """Same declared length, every bit clear — the M5 bypass.

        Driven through `from_directory`, because that is the documented production path and the only one where
        the registrar's status key is available to check against. (The raw `Verifier(anchors)` constructor is the
        pre-D-020 trusted-input mode: the caller supplied anchors it already trusts, and no status key means no
        authentication is possible. That asymmetry is deliberate, and recorded in docs/POLICY-PARITY.md.)
        """
        directory = json.loads((ART / "directory.json").read_text())
        roots = json.loads((ART / "roots.json").read_text())
        revoked = json.loads((ART / "bundle-revoked.json").read_text())
        now = json.loads((ART / "meta.json").read_text())["now"]
        v = Verifier.from_directory(directory, roots["root_ed25519"], roots["root_slh"])

        self.assertEqual(v.verify(revoked, now).reason, "revoked", "the fixture must genuinely be revoked")

        n = revoked["status_len"]
        forged = dict(revoked, status_list=_b64(zlib.compress(bytes((n + 7) // 8))))
        r = v.verify(forged, now)
        self.assertFalse(r.valid, "an all-clear forgery was accepted — the M5 bypass is open")
        self.assertEqual(r.reason, "stale_status")


class TestDirectoryPolicyIsCarried(unittest.TestCase):
    """`from_directory` dropped three fields, and each drop had a consequence."""

    def setUp(self) -> None:
        self.directory = json.loads((ART / "directory.json").read_text())
        self.roots = json.loads((ART / "roots.json").read_text())

    def test_status_key_uri_and_distrust_cutoff_all_survive(self):
        v = Verifier.from_directory(self.directory, self.roots["root_ed25519"], self.roots["root_slh"])
        self.assertIsNotNone(v)
        for reg, info in v._anchors.items():
            self.assertIn("status_ed25519", info, f"{reg}: status key dropped — revocations cannot be authenticated")
            self.assertIn("status_uri", info, f"{reg}: status URI dropped — the triple binding cannot be checked")
            self.assertIn("distrust_from_leaf", info, f"{reg}: D-044 graduated-distrust cutoff dropped")

    def test_the_shipped_verifier_kit_bundle_verifies(self):
        """The artifacts an external verifier is handed must actually verify in this SDK."""
        v = Verifier.from_directory(self.directory, self.roots["root_ed25519"], self.roots["root_slh"])
        bundle = json.loads((ART / "bundle-valid.json").read_text())
        now = json.loads((ART / "meta.json").read_text())["now"]
        r = v.verify(bundle, now)
        self.assertTrue(r.valid, f"the shipped sample bundle was refused: {r.reason}")

    def test_the_shipped_revoked_bundle_is_refused(self):
        v = Verifier.from_directory(self.directory, self.roots["root_ed25519"], self.roots["root_slh"])
        bundle = json.loads((ART / "bundle-revoked.json").read_text())
        now = json.loads((ART / "meta.json").read_text())["now"]
        r = v.verify(bundle, now)
        self.assertFalse(r.valid)
        self.assertEqual(r.reason, "revoked")


if __name__ == "__main__":
    unittest.main()
