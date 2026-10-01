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

    def test_a_decompression_bomb_is_refused(self):
        """A 64 KB header that inflates to 64 MB of zeros.

        `decompressobj.decompress(data, max_length)` TRUNCATES rather than raising, and the budget here was a flat
        2 MiB regardless of `bit_len` — so the oversize never surfaced and the huge all-clear bitmap made a REVOKED
        passport verify VALID. Found by the M30 review one layer below the short-list guard added earlier in the
        same milestone, which bounded only from below. ainra-core caps at `need + 8` (status.rs:117); so does TS.
        """
        bomb = zlib.compress(bytes(64 * 1024 * 1024))
        attack = dict(self.pres, status_list=_b64(bomb))
        self.assertEqual(self._verdict(attack), "stale_status")

    def test_an_over_long_but_small_list_is_refused(self):
        """The same rule without the amplification: more bytes than the declared length can hold."""
        n = self.pres["status_len"]
        over = zlib.compress(bytes((n + 7) // 8 + 64))
        self.assertEqual(self._verdict(dict(self.pres, status_list=_b64(over))), "stale_status")

    def test_the_honest_list_still_verifies(self):
        """Otherwise the two bounds above could be passing by refusing everything."""
        self.assertEqual(self._verdict(self.pres), "revoked")

    def test_an_all_clear_forgery_is_refused_by_a_directory_built_verifier(self):
        """Same declared length, every bit clear — the M5 bypass.

        Driven through `from_directory`, the documented production path. The plain constructor is covered by
        `TestThePlainConstructorFailsClosed` below (D-075).
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


class TestThePlainConstructorFailsClosed(unittest.TestCase):
    """D-075 — `Verifier(anchors)` used to skip status authentication whenever the anchors carried no status key.

    It was called the trusted-input mode and it was documented; it was also the first constructor anyone reaches
    for, and a verifier built that way believed whatever status list a presenter handed over. Now the default
    authenticates or refuses, and believing the bundle has to be asked for by name.

    WITNESS — could these fail? Pass `self._anchors_authenticated` to `_authenticate_status` again, as before
    D-075, and the first test goes red: both bundles read `valid`.
    """

    def setUp(self) -> None:
        self.directory = json.loads((ART / "directory.json").read_text())
        self.valid = json.loads((ART / "bundle-valid.json").read_text())
        self.revoked = json.loads((ART / "bundle-revoked.json").read_text())
        self.now = json.loads((ART / "meta.json").read_text())["now"]
        e = self.directory["entries"][0]
        self.bare = {e["registrar"]: {"issuer_key": {"ed25519": e["issuer_ed25519"], "mldsa65": e["issuer_mldsa65"]},
                                      "log_root_key": e["log_root_slh"]}}
        self.pinned = {e["registrar"]: dict(self.bare[e["registrar"]], status_ed25519=e["status_ed25519"],
                                            status_mldsa65=e["status_mldsa65"], status_uri=e["status_uri"])}

    def test_anchors_with_no_status_key_refuse_every_passport(self):
        v = Verifier(self.bare)
        self.assertEqual(v.verify(self.valid, self.now).reason, "stale_status")
        vec = json.loads((V1 / "valid-0000.json").read_text())
        r = Verifier(vec["anchors"]).verify(vec["presentation"], vec["presentation"]["now"])
        self.assertEqual(r.reason, "stale_status", "a vector's status is unsigned: the default must not believe it")

    def test_believing_the_bundle_has_to_be_asked_for_by_name(self):
        vec = json.loads((V1 / "valid-0000.json").read_text())
        v = Verifier(vec["anchors"], unauthenticated_status=True)
        self.assertTrue(v.verify(vec["presentation"], vec["presentation"]["now"]).valid)

    def test_pinned_anchors_that_carry_the_status_key_authenticate(self):
        v = Verifier(self.pinned)
        self.assertTrue(v.verify(self.valid, self.now).valid)
        self.assertEqual(v.verify(self.revoked, self.now).reason, "revoked")
        redated = dict(self.revoked, status_list=self.valid["status_list"], status_issued_at=self.now)
        self.assertEqual(v.verify(redated, self.now).reason, "stale_status")
        # ... and the opt-out does not switch authentication off where a key IS present.
        loose = Verifier(self.pinned, unauthenticated_status=True)
        self.assertEqual(loose.verify(redated, self.now).reason, "stale_status")


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
