#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make python-agent-e2e — an agent written in Python against the real gate, live (D-071).
#
# Starts tools/gate-origin.mjs (the Node gate, then the edge gate), runs packages/sdk-py/examples/agent.py against each,
# and stops the origin it started — by PID, never by name. Needs the wall-clock network: `make live-up`.
set -uo pipefail
cd "$(dirname "$0")/.."
rc=0
for mode in "" "--edge"; do
  log="$(mktemp)"
  node tools/gate-origin.mjs $mode >"$log" 2>&1 &
  pid=$!
  port=""
  for _ in $(seq 1 50); do
    port="$(sed -n 's/^LISTENING \([0-9]*\)$/\1/p' "$log")"
    [ -n "$port" ] && break
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  if [ -z "$port" ]; then echo "the origin did not start:"; cat "$log"; rm -f "$log"; exit 2; fi
  echo "── origin: ${mode:-@ainra/middleware} on 127.0.0.1:$port ──"
  PYTHONPATH=packages/sdk-py python3 packages/sdk-py/examples/agent.py "http://127.0.0.1:$port" || rc=1
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  rm -f "$log"
done
exit "$rc"
