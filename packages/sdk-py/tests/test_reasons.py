# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Every frozen reason is reachable, and the whole corpus agrees with the core.

The conformance vectors' recorded ``expect`` is the Rust core's verdict; this
test asserts the independent Python verifier reproduces it byte-for-byte on every
passport, delta, and directory vector — the same property the differential
harness enforces — and that all 15 frozen reasons are exercised.
"""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

from ainra import reasons
from ainra.delta import verify_delta_vector
from ainra.directory import verify_directory
from ainra.verify import verify

ROOT = Path(__file__).resolve().parents[3]
V1 = ROOT / "vectors" / "v1"
V1_DELTA = ROOT / "vectors" / "v1-delta"
V1_DIR = ROOT / "vectors" / "v1-directory"


def _load(d):
    for f in sorted(os.listdir(d)):
        if f.endswith(".json") and f != "manifest.json":
            yield json.loads((Path(d) / f).read_text())


class TestCorpusAgreement(unittest.TestCase):
    def test_passport_corpus(self):
        seen_reasons = set()
        count = 0
        for v in _load(V1):
            pres = v["presentation"]
            got = verify(v["anchors"], pres, pres.get("now")).as_result()
            want = v["expect"]
            want = (
                {"verdict": "valid"}
                if want["verdict"] == "valid"
                else {"verdict": "invalid", "reason": want["reason"]}
            )
            self.assertEqual(got, want, msg=v["name"])
            if got["verdict"] == "invalid":
                seen_reasons.add(got["reason"])
            count += 1
        self.assertGreater(count, 700)
        # Every frozen reason except the delta/directory-only ones is reachable
        # from the passport corpus.
        for r in reasons.ALL:
            self.assertIn(r, seen_reasons, msg=f"reason not exercised: {r}")

    def test_delta_corpus(self):
        for v in _load(V1_DELTA):
            got = verify_delta_vector(v)
            e = v["expect"]
            want = {"accept": True} if e["accept"] else {"accept": False, "reason": e["reason"]}
            self.assertEqual(got, want, msg=v["name"])

    def test_directory_corpus(self):
        for v in _load(V1_DIR):
            got = verify_directory(v)
            e = v["expect"]
            want = (
                {"accept": True, "registrars": e["registrars"]}
                if e["accept"]
                else {"accept": False}
            )
            self.assertEqual(got, want, msg=v["name"])


if __name__ == "__main__":
    unittest.main()
