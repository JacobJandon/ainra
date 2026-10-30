# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Differential runner: the fourth column of ``make diff``.

Reads a directory of conformance vectors and prints, one line per vector,
``<name>\\t<canonical-result-json>`` — the verdict+reason (passport), or the
accept+reason/registrars (delta / directory). ``tools/diff-harness/run.mjs``
spawns this once per corpus and asserts every line agrees with the vector's
recorded ``expect`` (which is the Rust core's verdict), so the Python verifier
joins the core / TS-SDK / JS-CLI differential as an independent fourth brain.

Usage:  python -m ainra._vector_runner <passport|delta|directory|presentation|gate|link|decision> <dir>
"""

from __future__ import annotations

import json
import os
import sys

from . import conformance as C

RUN = {
    "passport": C.run_vector,
    "delta": C.run_delta_vector,
    "directory": C.run_directory_vector,
    "presentation": C.run_presentation_vector,
    "gate": C.run_gate_vector,
    "link": C.run_link_vector,
    "decision": C.run_decision_vector,
}


def _stable(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def run(kind: str, directory: str) -> int:
    if kind not in RUN:
        print(f"unknown kind: {kind}", file=sys.stderr)
        return 2
    files = sorted(f for f in os.listdir(directory) if f.endswith(".json") and f != "manifest.json")
    out = []
    for f in files:
        with open(os.path.join(directory, f), encoding="utf-8") as fh:
            v = json.load(fh)
        out.append(f"{v['name']}\t{_stable(RUN[kind](v))}")
    sys.stdout.write("\n".join(out) + ("\n" if out else ""))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(run(sys.argv[1], sys.argv[2]))
