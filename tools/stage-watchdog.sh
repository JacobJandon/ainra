#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# The staging watchdog. Restart=always catches a process that EXITED; this catches one that is ALIVE AND USELESS
# — wedged, still holding its port, answering nothing. It probes the same public read contract a consumer uses
# and restarts only what fails to answer.
#
# Deliberately quiet when healthy: a watchdog that logs every minute trains you to ignore it, so it prints one
# line per probe cycle only when something was wrong.
set -uo pipefail
cd "$(dirname "$0")/.."

ENVDIR=deploy/systemd/env
[ -d "$ENVDIR" ] || { echo "watchdog: not installed (no $ENVDIR) — run 'make stage-install'"; exit 0; }
# shellcheck disable=SC1090
for f in "$ENVDIR"/*.env; do [ -f "$f" ] && . "$f"; done

restarted=0
probe() { # probe <url> <unit> <label>
  local code
  code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$1" 2>/dev/null); [ -n "$code" ] || code=000
  if [ "$code" != "200" ]; then
    echo "watchdog: $3 not answering (HTTP $code) — restarting $2"
    systemctl --user restart "$2" 2>/dev/null || echo "watchdog: could not restart $2"
    restarted=$((restarted+1))
  fi
}

# The artifact server IS the public contract — if it is down, every consumer is down.
probe "http://127.0.0.1:${ART_PORT:-8091}/index.json"        ainra-artifacts.service            "artifact server"
# Each registrar door must serve its own accreditation.
probe "http://${REG1_ADDR:-127.0.0.1:4907}/accreditation"    ainra-registrar@registrar-07.service "registrar-07 door"
probe "http://${REG2_ADDR:-127.0.0.1:4911}/accreditation"    ainra-registrar@registrar-11.service "registrar-11 door"
# The witness answers a health path; treat any 2xx/4xx as alive (it is listening), only a connection failure is death.
wcode=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://${WIT_ADDR:-127.0.0.1:4991}/" 2>/dev/null); [ -n "$wcode" ] || wcode=000
if [ "$wcode" = "000" ]; then
  echo "watchdog: witness not listening — restarting ainra-witnessd.service"
  systemctl --user restart ainra-witnessd.service 2>/dev/null || true
  restarted=$((restarted+1))
fi

[ "$restarted" -gt 0 ] && echo "watchdog: restarted $restarted unit(s)"
exit 0
