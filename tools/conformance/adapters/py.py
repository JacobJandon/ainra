# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Conformance adapter for the Python verifier (packages/sdk-py), fitting tools/conformance/CONTRACT.md.

Reads the runner's JSON-Lines vectors on stdin, runs the REAL ``ainra`` verifier — the same
``ainra.conformance`` functions the ``make diff`` fourth column (``ainra._vector_runner``) uses —
and prints one ``<name>\\t<result-json>`` line per vector. No files, no network.

    python3 tools/conformance/adapters/py.py <kind>   (vectors on stdin)
"""

from __future__ import annotations

import json
import os
import sys

# Self-configure the import path to packages/sdk-py so a stranger needs no PYTHONPATH.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "packages", "sdk-py"))

from ainra._vector_runner import RUN  # noqa: E402


def _stable(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def result(kind: str, v: dict) -> dict:
    if kind not in RUN:
        raise SystemExit(f"unknown kind: {kind}")
    return RUN[kind](v)


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
