#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make explorer-up [PORT=8090] / explorer-down — build + serve the AINRAscan explorer in the background.
# AINRAscan reads a LIVE public artifact contract via ?net=<url> (default: the staging artifact server on :8091).
set -uo pipefail
cd "$(dirname "$0")/.."
PORT="${PORT:-8090}"
PIDF=".explorer-pid"
CMD="${1:-up}"

if [ "$CMD" = "down" ]; then
  [ -f "$PIDF" ] && kill "$(cat "$PIDF")" 2>/dev/null || true
  pkill -f "http.server ${PORT}" 2>/dev/null || true
  rm -f "$PIDF"
  echo "explorer server stopped."
  exit 0
fi

bash tools/ainrascan.sh >/dev/null 2>&1 || true   # ensure the browser SDK bundle + explorer app are built
pkill -f "http.server ${PORT}" 2>/dev/null || true
sleep 0.2
setsid nohup python3 -m http.server "$PORT" --bind 127.0.0.1 --directory ainrascan >/dev/null 2>&1 &
echo $! > "$PIDF"
for _ in $(seq 1 25); do curl -s -o /dev/null "http://127.0.0.1:${PORT}/index.html" && break; sleep 0.2; done
echo "  AINRAscan up → http://127.0.0.1:${PORT}/?net=http://127.0.0.1:8091"
