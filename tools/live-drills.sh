#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make live-drills — every drill that needs a running network, on a network this script brings up (D-073).
#
# Five drills prove the identity end to end at the real clock: identity-e2e, edge-e2e, signature-agent-e2e,
# python-agent-e2e and gate-parity. Each needs the wall-clock registrar (`make live-up`) and the published directory
# (`make stage-up`), so none of them ran in CI — and gate-parity is the one that found the Rust gate path believing
# any status it was handed (D-072). A check that only runs when someone remembers to start two daemons is a check
# that mostly does not run.
#
# This starts what is missing, runs all five, prints one board, and stops only what it started. It is hermetic in
# the sense that matters: a clean checkout, the documented toolchain, no network beyond loopback.
#   LIVE_DRILLS_KEEP=1   leave the networks up afterwards
set -uo pipefail
cd "$(dirname "$0")/.."
ART="http://127.0.0.1:8091"
REG="http://127.0.0.1:4970"
started_stage=0; started_live=0
up() { curl -sf -m 2 "$1" >/dev/null 2>&1; }

if ! up "$ART/directory.json"; then
  echo "── starting the staging network (publishes the directory) ──"
  bash tools/stage.sh up >/tmp/ainra-live-drills-stage.log 2>&1 || { echo "stage-up failed:"; tail -20 /tmp/ainra-live-drills-stage.log; exit 2; }
  started_stage=1
fi
if ! up "$REG/accreditation"; then
  echo "── starting the wall-clock registrar ──"
  bash tools/live.sh up || exit 2
  started_live=1
fi
cleanup() {
  [ "${LIVE_DRILLS_KEEP:-0}" = 1 ] && return
  [ "$started_live" = 1 ] && bash tools/live.sh down >/dev/null 2>&1
  [ "$started_stage" = 1 ] && bash tools/stage.sh down >/dev/null 2>&1
}
trap cleanup EXIT

declare -a NAMES RESULTS
FAIL=0
run() { # run <name> <command...>
  local name="$1"; shift
  local log; log="$(mktemp)"
  printf '  … %-22s ' "$name"
  local start; start=$(date +%s)
  if "$@" >"$log" 2>&1; then
    printf '\r  [PASS] %-22s %s (%ss)\n' "$name" "$(grep -E ' OK[: (]' "$log" | tail -1 | cut -c1-70)" "$(( $(date +%s) - start ))"
    NAMES+=("$name"); RESULTS+=("PASS")
  else
    printf '\r  [FAIL] %-22s\n' "$name"
    grep -E '✗|FAIL|Error|error' "$log" | head -12 | sed 's/^/           /'
    NAMES+=("$name"); RESULTS+=("FAIL"); FAIL=1
  fi
  rm -f "$log"
}

echo "live drills — the identity end to end, at the real clock (TEST-ROOT)"
run "identity (node gate)"  make -s identity-e2e
run "identity (edge gate)"  make -s edge-e2e
run "signature agents"      make -s signature-agent-e2e
run "python agent"          make -s python-agent-e2e
run "gate parity"           make -s gate-parity
echo "────────────────────────────────────────────────────────────────"
if [ "$FAIL" = 0 ]; then echo "  LIVE DRILLS GREEN — ${#NAMES[@]} drills against a running network."; else echo "  LIVE DRILLS RED"; fi
exit "$FAIL"
