# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Differential runner: the fourth column of ``make diff``.

Reads a directory of conformance vectors and prints, one line per vector,
``<name>\\t<canonical-result-json>`` — the verdict+reason (passport), or the
accept+reason/registrars (delta / directory). ``tools/diff-harness/run.mjs``
spawns this once per corpus and asserts every line agrees with the vector's
recorded ``expect`` (which is the Rust core's verdict), so the Python verifier
joins the core / TS-SDK / JS-CLI differential as an independent fourth brain.

Usage:  python -m ainra._vector_runner <passport|delta|directory|presentation|gate> <dir>
"""

from __future__ import annotations

import json
import os
import sys

from .delta import verify_delta_vector
from .directory import verify_directory
from .presentation import run_presentation_vector
from .verifier import Verifier
from .verify import verify as verify_passport


def _stable(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def run(kind: str, directory: str) -> int:
    files = sorted(f for f in os.listdir(directory) if f.endswith(".json") and f != "manifest.json")
    out = []
    for f in files:
        with open(os.path.join(directory, f), encoding="utf-8") as fh:
            v = json.load(fh)
        if kind == "passport":
            pres = v["presentation"]
            result = verify_passport(v["anchors"], pres, pres.get("now")).as_result()
        elif kind == "delta":
            result = verify_delta_vector(v)
        elif kind == "directory":
            result = verify_directory(v)
        elif kind == "presentation":
            result = run_presentation_vector(v)
        elif kind == "gate":
            # D-073 — what a GATE decides: the directory against both roots, then the GA Verifier with the gate's
            # own audience and freshness class, at the gate's clock. Nothing is taken on the presenter's word.
            gate = Verifier.from_directory(v["directory"], v["roots"]["root_ed25519"], v["roots"]["root_slh"],
                                           audience=v["audience"], freshness=v["freshness"])
            if gate is None:
                result = {"verdict": "no_gate"}
            else:
                verdict = gate.verify(v["bundle"], v["now"])
                result = {"verdict": "valid"} if verdict.valid else {"verdict": "invalid", "reason": verdict.reason}
        else:
            print(f"unknown kind: {kind}", file=sys.stderr)
            return 2
        out.append(f"{v['name']}\t{_stable(result)}")
    sys.stdout.write("\n".join(out) + ("\n" if out else ""))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(run(sys.argv[1], sys.argv[2]))
