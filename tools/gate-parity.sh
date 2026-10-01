#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make gate-parity — any agent, any gate, one answer (D-072).
#
# Starts the three origins (Node middleware, edge gate, Python gate), then:
#   1. runs the TypeScript agent and the Python agent against each — six journeys;
#   2. runs tools/gate-parity.mjs — one battery of requests, the same answer required from all three gates.
# Stops what it started by PID. Needs the wall-clock network: `make live-up`.
set -uo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="packages/sdk-py${PYTHONPATH:+:$PYTHONPATH}"
pids=(); logs=(); names=(node edge python); urls=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; rm -f "${logs[@]}"; }
trap cleanup EXIT
start() { # start <command...>  → appends to pids/logs/urls
  local log; log="$(mktemp)"; logs+=("$log")
  "$@" >"$log" 2>&1 &
  local pid=$! port=""
  pids+=("$pid")
  for _ in $(seq 1 80); do
    port="$(sed -n 's/^LISTENING \([0-9]*\)$/\1/p' "$log")"
    [ -n "$port" ] && break
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  if [ -z "$port" ]; then echo "an origin did not start ($*):"; cat "$log"; exit 2; fi
  urls+=("http://127.0.0.1:$port")
}
start node tools/gate-origin.mjs
start node tools/gate-origin.mjs --edge
start python3 tools/gate-origin.py

rc=0
if [ "${BATTERY_ONLY:-0}" != "1" ]; then
  for i in 0 1 2; do
    for agent in ts py; do
      if [ "$agent" = ts ]; then out="$(node packages/sdk-ts/examples/agent.mjs "${urls[$i]}" 2>&1)"; else out="$(python3 packages/sdk-py/examples/agent.py "${urls[$i]}" 2>&1)"; fi
      if [ $? -eq 0 ]; then printf '  ok    %-10s agent → %-7s gate   %s checks\n' "$agent" "${names[$i]}" "$(printf '%s\n' "$out" | grep -c '^  ok ')"
      else rc=1; printf '  FAIL  %-10s agent → %-7s gate\n' "$agent" "${names[$i]}"; printf '%s\n' "$out" | grep -E 'FAIL|✗' | sed 's/^/          /'; fi
    done
  done
fi
node tools/gate-parity.mjs "node=${urls[0]}" "edge=${urls[1]}" "python=${urls[2]}" || rc=1
exit "$rc"
