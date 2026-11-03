# SPDX-License-Identifier: Apache-2.0 OR MIT
"""PLAN-M51 — currency mode (D-021) in the Python package, held to ``vectors/v1-currency``.

Each vector is ONE currency gate's life. The Python Verifier had no currency mode before this milestone, so it
accepted a genuine pre-revocation snapshot for the whole freshness window even after it had seen the revocation (c02).
It also never checked a delegate cert's 92-day ceiling (c13 here, g30 in the gate corpus).
"""

import json
import pathlib
import unittest

from ainra.conformance import run_currency_vector, run_gate_vector

ROOT = pathlib.Path(__file__).resolve().parents[3] / "vectors"


def load(kind: str, name: str) -> dict:
    return json.loads((ROOT / kind / f"{name}.json").read_text())


class TestCurrency(unittest.TestCase):
    def test_every_currency_vector_step_by_step(self):
        files = sorted(p for p in (ROOT / "v1-currency").glob("*.json") if p.name != "manifest.json")
        self.assertGreaterEqual(len(files), 18)
        for p in files:
            v = json.loads(p.read_text())
            with self.subTest(v["name"]):
                self.assertEqual(run_currency_vector(v), v["expect"])

    def test_the_replay_is_refused_only_after_the_revocation_was_seen(self):
        v = load("v1-currency", "c02-replay-after-the-revocation-was-seen")
        self.assertEqual([r.get("reason", r["verdict"]) for r in run_currency_vector(v)],
                         ["valid", "revoked", "stale_status"])
        self.assertEqual(run_currency_vector({**v, "steps": [v["steps"][2]]}), [{"verdict": "valid"}])

    def test_a_delegate_cert_longer_than_92_days_signs_nothing(self):
        self.assertEqual(run_currency_vector(load("v1-currency", "c13-cert-longer-than-92-days")),
                         [{"verdict": "invalid", "reason": "stale_status"}])
        self.assertEqual(run_gate_vector(load("v1-gate", "g30-checkpoint-delegate-cert-too-long")),
                         {"verdict": "invalid", "reason": "checkpoint_invalid"})


if __name__ == "__main__":
    unittest.main()
