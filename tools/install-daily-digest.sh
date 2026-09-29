#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Install (or remove) the owner's morning page: a systemd USER timer that runs tools/daily-digest.mjs at 08:30 and
# writes ~/Desktop/ainra-today.md. Local only: it reads the repository and the send page, asks GitHub for CI status,
# and sends nothing to anyone.
#
#   bash tools/install-daily-digest.sh            install + enable (Persistent: a missed morning runs at next login)
#   bash tools/install-daily-digest.sh --remove   stop and remove it
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UNIT_DIR="$HOME/.config/systemd/user"
if [ "${1:-}" = "--remove" ]; then
  systemctl --user disable --now ainra-daily.timer 2>/dev/null || true
  rm -f "$UNIT_DIR/ainra-daily.service" "$UNIT_DIR/ainra-daily.timer"
  systemctl --user daemon-reload
  echo "removed the AINRA morning page timer"; exit 0
fi
NODE="$(command -v node)"
mkdir -p "$UNIT_DIR"
cat > "$UNIT_DIR/ainra-daily.service" <<UNIT
[Unit]
Description=AINRA morning page (~/Desktop/ainra-today.md) — reads only, sends nothing

[Service]
Type=oneshot
WorkingDirectory=$ROOT
ExecStart=$NODE $ROOT/tools/daily-digest.mjs
UNIT
cat > "$UNIT_DIR/ainra-daily.timer" <<UNIT
[Unit]
Description=Write the AINRA morning page at 08:30

[Timer]
OnCalendar=*-*-* 08:30:00
Persistent=true

[Install]
WantedBy=timers.target
UNIT
systemctl --user daemon-reload
systemctl --user enable --now ainra-daily.timer >/dev/null
systemctl --user start ainra-daily.service
echo "installed: every day at 08:30 → ~/Desktop/ainra-today.md (remove with: bash tools/install-daily-digest.sh --remove)"
systemctl --user list-timers ainra-daily.timer --no-pager | head -3
