# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Conformance adapter for the Python verifier (packages/sdk-py), fitting tools/conformance/CONTRACT.md.

Reads the runner's JSON-Lines vectors on stdin, runs the REAL ``ainra`` verifier — the same
``verify`` / ``verify_delta_vector`` / ``verify_directory`` functions the ``make diff`` fourth
column (``ainra._vector_runner``) uses — and prints one ``<name>\\t<result-json>`` line per vector.
No files, no network.

    python3 tools/conformance/adapters/py.py <passport|delta|directory>   (vectors on stdin)
"""

from __future__ import annotations

import json
import os
import sys

# Self-configure the import path to packages/sdk-py so a stranger needs no PYTHONPATH.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "packages", "sdk-py"))

from ainra.delta import verify_delta_vector  # noqa: E402
from ainra.directory import verify_directory  # noqa: E402
from ainra.verify import verify as verify_passport  # noqa: E402


def _stable(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def result(kind: str, v: dict) -> dict:
    if kind == "passport":
        pres = v["presentation"]
        return verify_passport(v["anchors"], pres, pres.get("now")).as_result()
    if kind == "delta":
        return verify_delta_vector(v)
    if kind == "directory":
        return verify_directory(v)
    raise SystemExit(f"unknown kind: {kind}")


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    kind = sys.argv[1]
    out = []
    for line in sys.stdin:
        if not line.strip():
            continue
        v = json.loads(line)
        out.append(f"{v['name']}\t{_stable(result(kind, v))}")
    sys.stdout.write("\n".join(out) + ("\n" if out else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
