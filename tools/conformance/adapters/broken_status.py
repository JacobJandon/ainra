# SPDX-License-Identifier: Apache-2.0 OR MIT
"""A DELIBERATELY BROKEN implementation (PLAN-M50 step 3) — the proof that profile ``core`` is not enough.

The real Python verifier with ONE step removed: it never authenticates the status list, so it reads the bits a
presenter sends on the presenter's word. That is the D-072 shape, the hole that shipped in the Rust gate path, the
published MCP tool (D-074) and the published Python package (D-075) while every v1 vector stayed green: the v1 kinds
hand a verifier its status as a trusted input, so nothing in them can tell. The runner MUST pass this adapter in
profile ``core`` and fail it in profile ``full``, naming the gate vectors it gets wrong. Not shipped, not on any
conformance path — it exists only to be caught.

    python3 tools/conformance/adapters/broken_status.py <kind>   (vectors on stdin)
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "packages", "sdk-py"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ainra.verifier  # noqa: E402

ainra.verifier._authenticate_status = lambda *_args, **_kwargs: None  # ← the sabotage: every list is believed

from py import main  # noqa: E402  (the honest adapter, now driving the sabotaged verifier)

if __name__ == "__main__":
    sys.exit(main())
