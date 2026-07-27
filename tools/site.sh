#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make site   [SERVE=1] [PORT=8088]  — build the public static site (default; SERVE=1 serves in the foreground).
# make site-up   [PORT=8088]         — build + serve in the BACKGROUND (pid in .site-pid); one command for the demo.
# make site-down                     — stop the background server.
# The 7 HTML pages are already self-contained (no external fonts/scripts/images — nothing phones home). The build
# only refreshes the two DERIVED downloads from their CANONICAL repo sources (the reference CLI from apps/cli-node/,
# the Standard from docs/), so a visitor always downloads the real, current thing (never a stale committed copy).
set -uo pipefail
cd "$(dirname "$0")/.."
SITE=site
CMD="${1:-build}"
PORT="${PORT:-8088}"
PIDF=".site-pid"

# `down` needs no build.
if [ "$CMD" = "down" ]; then
  [ -f "$PIDF" ] && kill "$(cat "$PIDF")" 2>/dev/null || true
  pkill -f "http.server ${PORT}" 2>/dev/null || true
  rm -f "$PIDF"
  echo "site server stopped."
  exit 0
fi

set -e
command -v zip >/dev/null 2>&1 || { echo "✗ 'zip' not found — install it (see TOOLCHAIN.md), or run 'make doctor'"; exit 1; }

# 1. the Standard — canonical is docs/AINRA_I_The_Standard.md → the site's downloadable copy.
cp docs/AINRA_I_The_Standard.md "$SITE/AINRA_I_The_Standard.md"

# 2. the reference CLI — canonical is apps/cli-node/ → ainra-cli-v0.1.0.zip (packaged under ainra-cli/).
VER="$(node -e 'process.stdout.write(require("./apps/cli-node/package.json").version)')"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/ainra-cli/bin"
cp apps/cli-node/package.json apps/cli-node/README.md "$TMP/ainra-cli/"
cp apps/cli-node/bin/ainra.js "$TMP/ainra-cli/bin/"
( cd "$TMP" && zip -q -r -X "ainra-cli-v${VER}.zip" ainra-cli )
# the pages link to ainra-cli-v0.1.0.zip; keep that stable name pointing at the current build.
cp "$TMP/ainra-cli-v${VER}.zip" "$SITE/ainra-cli-v0.1.0.zip"

echo "built $SITE/ — 7 self-contained pages + refreshed downloads (CLI v${VER}, Standard $(wc -l < "$SITE/AINRA_I_The_Standard.md") lines)."
echo "  the download CLI == apps/cli-node (canonical); the Standard == docs/AINRA_I_The_Standard.md (canonical)."

# M17: keep the 4 content pages' shared header/footer in sync from site/_includes/ (one source of truth, no drift).
node tools/site-includes.mjs

# M17 Task 3 — the agent-first surface: markdown mirrors, OpenAPI specs, and the served copy of the onboarding file.
node tools/site-mirrors.mjs
node tools/openapi.mjs
cp skills.md "$SITE/skills.md"

case "$CMD" in
  up)
    pkill -f "http.server ${PORT}" 2>/dev/null || true
    sleep 0.2
    setsid nohup python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$SITE" >/dev/null 2>&1 &
    echo $! > "$PIDF"
    for _ in $(seq 1 25); do curl -s -o /dev/null "http://127.0.0.1:${PORT}/index.html" && break; sleep 0.2; done
    echo "site up → http://127.0.0.1:${PORT}/   (make site-down to stop)"
    ;;
  build|*)
    if [ "${SERVE:-0}" = "1" ]; then
      echo "serving http://127.0.0.1:${PORT}/  (Ctrl-C to stop)"
      cd "$SITE" && exec python3 -m http.server "$PORT" --bind 127.0.0.1
    fi
    ;;
esac
