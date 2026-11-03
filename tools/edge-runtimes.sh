#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make edge-runtimes — the edge gate's checks (packages/edge/runtimes/check.mjs) in Node, Deno and Bun, then the gate
# inside workerd. A runtime that is not installed is reported SKIPPED, unless REQUIRE_ALL_RUNTIMES=1 — then it is red,
# which is how CI runs it (PLAN-M50 step 7): a check that skips itself green is a check that can stop running unseen.
#
# WITNESS: REQUIRE_ALL_RUNTIMES=1 with Bun off the PATH must exit non-zero. And a runtime that IS installed and fails
# is a failure, never "SKIPPED" — the version this replaces printed SKIPPED for a failing Deno check (`a && b || echo`).
set -euo pipefail
cd "$(dirname "$0")/../packages/edge"
[ -d node_modules ] || npm install --no-audit --no-fund --silent

node runtimes/check.mjs
optional() { # optional <runtime> <command...> — run it if installed; absent is SKIPPED or, if required, red
  local rt="$1"; shift
  if command -v "$rt" >/dev/null 2>&1; then
    "$@"
  elif [ "${REQUIRE_ALL_RUNTIMES:-}" = 1 ]; then
    echo "  ✗ MISSING $rt — REQUIRE_ALL_RUNTIMES=1, so an absent runtime is a failure, not a skip" >&2
    exit 1
  else
    echo "  SKIPPED $rt (not installed)"
  fi
}
optional deno deno run --allow-read runtimes/check.mjs
optional bun bun runtimes/check.mjs
node runtimes/workerd.mjs
