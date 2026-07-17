#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make site [SERVE=1] [PORT=8088] (M11+) — build the public static site. The 8 HTML pages are already self-contained
# (no external fonts/scripts/images — nothing phones home). This step only refreshes the two DERIVED download
# artifacts from their CANONICAL repo sources, so a visitor always downloads the real, current thing (never a stale
# committed copy): the reference CLI from apps/cli-node/, and the Standard from docs/. Then optionally serves it.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v zip >/dev/null 2>&1 || { echo "✗ 'zip' not found — install it (see TOOLCHAIN.md), or run 'make doctor'"; exit 1; }
SITE=site

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

echo "built $SITE/ — 8 self-contained pages + refreshed downloads (CLI v${VER}, Standard $(wc -l < "$SITE/AINRA_I_The_Standard.md") lines)."
echo "  the download CLI == apps/cli-node (canonical); the Standard == docs/AINRA_I_The_Standard.md (canonical)."
if [ "${SERVE:-0}" = "1" ]; then
  PORT="${PORT:-8088}"
  echo "serving http://127.0.0.1:${PORT}/  (Ctrl-C to stop)"
  cd "$SITE" && exec python3 -m http.server "$PORT"
fi
