# SPDX-License-Identifier: Apache-2.0 OR MIT
"""D-073 — the gate corpus, answered by the Python ``Verifier`` as ``ainra-core`` recorded it.

``vectors/v1-gate`` is what a GATE decides: a dual-root-signed directory, a bundle exactly as a presenter sends it,
and the gate's own clock, audience and freshness class. It exists because of D-072 — a gate path that believed any
status it was handed — and every edit a presenter can make to the status material is a vector here.

WITNESS — could this fail? It did, on the corpus's first run: ``g24`` has a directory entry that publishes no status
key. The core and the TypeScript SDK accept that directory and refuse the one registrar's passports; this package
rejected the directory whole. Remove the status authentication from ``Verifier.verify`` and ``g03``–``g13`` read
``valid``.
"""

from __future__ import annotations

import json
import pathlib
import unittest

from ainra import Verifier

GATE = pathlib.Path(__file__).resolve().parents[3] / "vectors" / "v1-gate"


def run_gate_vector(v: dict) -> dict:
    gate = Verifier.from_directory(v["directory"], v["roots"]["root_ed25519"], v["roots"]["root_slh"],
                                   audience=v["audience"], freshness=v["freshness"])
    if gate is None:
        return {"verdict": "no_gate"}
    verdict = gate.verify(v["bundle"], v["now"])
    return {"verdict": "valid"} if verdict.valid else {"verdict": "invalid", "reason": verdict.reason}


class TestGateCorpus(unittest.TestCase):
    def test_every_gate_vector_reads_as_the_core_recorded_it(self):
        files = sorted(p for p in GATE.glob("*.json") if p.name != "manifest.json")
        self.assertGreaterEqual(len(files), 27)
        for path in files:
            v = json.loads(path.read_text())
            with self.subTest(v["name"]):
                self.assertEqual(run_gate_vector(v), v["expect"])

    def test_a_revoked_passport_cannot_bring_its_own_status(self):
        # The D-072 attack by name, so a reader of this file meets it without opening the corpus.
        v = json.loads((GATE / "g03-revoked-brings-an-all-clear-list.json").read_text())
        self.assertEqual(run_gate_vector(v), {"verdict": "invalid", "reason": "stale_status"})


if __name__ == "__main__":
    unittest.main()
