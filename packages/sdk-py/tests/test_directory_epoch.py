# SPDX-License-Identifier: Apache-2.0 OR MIT
"""PLAN-M50 — a long-lived verifier keeps the highest directory epoch it accepted and never goes back. Both roots
signed the older directory too: only the epoch can refuse it."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from ainra import Verifier
from ainra.directory import DirectoryHolder, verify_directory_at_least

ROOT = Path(__file__).resolve().parents[3]


def _vec(name):
    return json.loads((ROOT / "vectors" / "v1-directory-epoch" / f"{name}.json").read_text())


class DirectoryEpochTests(unittest.TestCase):
    def test_a_holder_never_goes_back(self):
        v = _vec("e03-rollback")
        d2, d1 = v["directories"]
        holder = DirectoryHolder(v["root_ed25519"], v["root_slh"])
        self.assertIsInstance(holder.verifier(d2), Verifier)
        self.assertEqual(holder.floor, 2)
        self.assertEqual(holder.verifier(d1), {"ok": False, "refusal": "rollback", "epoch": 1, "floor": 2})
        # Genuinely signed: without a floor it would be accepted.
        self.assertTrue(verify_directory_at_least(d1, v["root_ed25519"], v["root_slh"], 0)["ok"])

    def test_a_forgery_raises_nothing(self):
        v = _vec("e07-forgery-never-raises-the-floor")
        d2, forged, d3 = v["directories"]
        holder = DirectoryHolder(v["root_ed25519"], v["root_slh"])
        self.assertTrue(holder.accept(d2)["ok"])
        self.assertEqual(holder.accept(forged), {"ok": False, "refusal": "unauthentic"})
        self.assertEqual(holder.floor, 2)
        self.assertTrue(holder.accept(d3)["ok"])
        self.assertEqual(holder.floor, 3)


if __name__ == "__main__":
    unittest.main()
