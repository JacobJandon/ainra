#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make stage-install | stage-uninstall | stage-health
#
# Turns the staging network from "four processes that die with a terminal" into a standing service: systemd USER
# units with restart-on-failure, start-on-boot (via linger), journal logging (rotated and size-capped by systemd,
# so no logrotate config to forget), and a once-a-minute watchdog that probes the public read contract and
# restarts anything alive-but-wedged.
#
# WHAT THIS HONESTLY BUYS — read this before writing any availability claim anywhere:
#
#   The network runs whenever THIS MACHINE is powered on. No more than that.
#
# It is not "always on", and it is NOT reachable by a stranger: every daemon binds 127.0.0.1, so the public site
# at ainra.vercel.app cannot reach it and never could. This makes the network survive logout, reboot, and a
# crashed daemon — it does not make it public. A genuinely public endpoint needs a decision the operator has to
# make (see docs/PLAN-M27.md § the always-on question); nothing here provisions anything.
set -uo pipefail
cd "$(dirname "$0")/.."
REPO="$(pwd)"
UNIT_SRC=deploy/systemd
UNIT_DST="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
ENVDIR="$UNIT_SRC/env"

REG1_ADDR=127.0.0.1:4907 ; REG1_ID=registrar-07
REG2_ADDR=127.0.0.1:4911 ; REG2_ID=registrar-11
WIT_ADDR=127.0.0.1:4991
ART_PORT=8091

have_systemd() { command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; }

case "${1:-install}" in

install)
  if ! have_systemd; then
    echo "✗ no usable systemd --user session here."
    echo "  The units are still committed under $UNIT_SRC/ and work on any machine with a systemd user session."
    echo "  Without it, 'make stage-up' is the manual equivalent — and dies with your terminal, which is the"
    echo "  problem these units exist to solve."
    exit 1
  fi

  # 1. the binaries the units exec must exist BEFORE the units start, or every unit fast-restarts forever
  echo "== build the daemons =="
  cargo build --release -q -p ainra-services --bin registrar-box --bin witnessd || { echo "✗ build failed"; exit 1; }

  # 2. per-instance environment. Addresses live here, not baked into units, so a port change is one file edit.
  mkdir -p "$ENVDIR"
  { echo "REG_ADDR=$REG1_ADDR"; echo "AINRA_STAGE=1"; } > "$ENVDIR/$REG1_ID.env"
  { echo "REG_ADDR=$REG2_ADDR"; echo "AINRA_STAGE=1"; } > "$ENVDIR/$REG2_ID.env"
  { echo "WIT_ADDR=$WIT_ADDR";  echo "AINRA_STAGE=1"; } > "$ENVDIR/witness.env"
  { echo "ART_PORT=$ART_PORT";  echo "AINRA_STAGE=1"; } > "$ENVDIR/artifacts.env"
  # the write token the doors require; generated once and kept out of git
  mkdir -p stage
  [ -s stage/.issue-token ] || head -c 32 /dev/urandom | base64 | tr -d '\n=' > stage/.issue-token
  echo "AINRA_STAGE_ISSUE_TOKEN=$(cat stage/.issue-token)" >> "$ENVDIR/$REG1_ID.env"
  echo "AINRA_STAGE_ISSUE_TOKEN=$(cat stage/.issue-token)" >> "$ENVDIR/$REG2_ID.env"
  chmod 600 "$ENVDIR"/*.env stage/.issue-token

  # 3. the units themselves
  mkdir -p "$UNIT_DST"
  cp "$UNIT_SRC"/ainra-registrar@.service "$UNIT_SRC"/ainra-witnessd.service \
     "$UNIT_SRC"/ainra-artifacts.service  "$UNIT_SRC"/ainra-stage.target \
     "$UNIT_SRC"/ainra-stage-watchdog.service "$UNIT_SRC"/ainra-stage-watchdog.timer "$UNIT_DST/"
  systemctl --user daemon-reload

  # 4. survive logout and reboot. Without linger, user units stop the moment the session ends — which would leave
  #    exactly the dependency on a live terminal this is meant to remove.
  if ! loginctl show-user "$USER" -p Linger 2>/dev/null | grep -q "Linger=yes"; then
    if loginctl enable-linger "$USER" 2>/dev/null; then echo "== linger enabled (units survive logout + start at boot) =="
    else echo "!! could not enable linger — units will stop at logout. Run: sudo loginctl enable-linger $USER"; fi
  fi

  systemctl --user enable --now ainra-stage.target >/dev/null 2>&1 || true
  systemctl --user enable --now ainra-registrar@$REG1_ID.service ainra-registrar@$REG2_ID.service \
                                ainra-witnessd.service ainra-artifacts.service >/dev/null 2>&1 || true
  systemctl --user enable --now ainra-stage-watchdog.timer >/dev/null 2>&1 || true
  sleep 2

  # 5. the network needs SEEDING once — the daemons serve state, they do not invent it. Idempotent: if the
  #    contract already lists registrars, we leave the existing network alone rather than double-issuing.
  if ! curl -s -m 5 "http://127.0.0.1:$ART_PORT/index.json" 2>/dev/null | grep -q registrars; then
    echo "== seeding the network once (issue / delegate / revoke / renew / accredit / publish) =="
    bash tools/stage.sh up >/dev/null 2>&1 || echo "!! seed via stage.sh reported an error — check 'make stage-health'"
  fi

  echo
  bash "$0" health
  echo
  echo "  HONEST AVAILABILITY: the network runs whenever this machine is on — no more."
  echo "  It binds 127.0.0.1, so it is reachable from this machine only; the public site cannot reach it."
  ;;

uninstall)
  systemctl --user disable --now ainra-stage-watchdog.timer >/dev/null 2>&1 || true
  systemctl --user disable --now ainra-registrar@$REG1_ID.service ainra-registrar@$REG2_ID.service \
                                 ainra-witnessd.service ainra-artifacts.service >/dev/null 2>&1 || true
  systemctl --user disable --now ainra-stage.target >/dev/null 2>&1 || true
  rm -f "$UNIT_DST"/ainra-registrar@.service "$UNIT_DST"/ainra-witnessd.service \
        "$UNIT_DST"/ainra-artifacts.service  "$UNIT_DST"/ainra-stage.target \
        "$UNIT_DST"/ainra-stage-watchdog.service "$UNIT_DST"/ainra-stage-watchdog.timer
  systemctl --user daemon-reload 2>/dev/null || true
  echo "staging units removed. State in stage/ is untouched (delete it yourself if you meant to)."
  echo "Linger left enabled — 'loginctl disable-linger $USER' if you want that off too."
  ;;

health)
  echo "AINRA staging network — health"
  echo "────────────────────────────────────────────────────────────"
  fail=0
  probe() { # probe <label> <url> <expect-json-key>
    local code body
    body=$(curl -s -m 5 -w '\n%{http_code}' "$2" 2>/dev/null || true)
    code=$(printf '%s' "$body" | tail -1)
    if [ "$code" = "200" ]; then printf "  \033[32m[UP]\033[0m   %-22s %s\n" "$1" "$2"
    else printf "  \033[31m[DOWN]\033[0m %-22s %s  (HTTP %s)\n" "$1" "$2" "${code:-000}"; fail=1; fi
  }
  probe "artifact contract"  "http://127.0.0.1:$ART_PORT/index.json"
  probe "registrar-07 door"  "http://$REG1_ADDR/accreditation"
  probe "registrar-11 door"  "http://$REG2_ADDR/accreditation"
  wcode=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://$WIT_ADDR/" 2>/dev/null || echo 000)
  if [ "$wcode" != "000" ]; then printf "  \033[32m[UP]\033[0m   %-22s http://%s\n" "witness" "$WIT_ADDR"
  else printf "  \033[31m[DOWN]\033[0m %-22s http://%s\n" "witness" "$WIT_ADDR"; fail=1; fi

  if have_systemd; then
    echo "  ── units ──"
    for u in ainra-registrar@$REG1_ID.service ainra-registrar@$REG2_ID.service ainra-witnessd.service \
             ainra-artifacts.service ainra-stage-watchdog.timer; do
      st=$(systemctl --user is-active "$u" 2>/dev/null); [ -n "$st" ] || st=not-installed
      printf "  %-42s %s\n" "$u" "$st"
    done
    printf "  %-42s %s\n" "linger (survives logout/reboot)" \
      "$(loginctl show-user "$USER" -p Linger 2>/dev/null | cut -d= -f2 || echo unknown)"
  fi
  echo "────────────────────────────────────────────────────────────"
  if [ "$fail" = "0" ]; then echo "  ALL UP — the network answers its public read contract."
  else echo "  DEGRADED — the site's honest offline states are what a visitor should now see."; fi
  echo "  Availability: runs whenever this machine is on. Binds 127.0.0.1 — not reachable from the internet."
  exit $fail
  ;;

*) echo "usage: stage-install.sh [install|uninstall|health]"; exit 2 ;;
esac
