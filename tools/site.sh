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
# the release-verification guide (M24) — served so status.html's "Release integrity" link resolves.
cp RELEASE-VERIFY.md "$SITE/RELEASE-VERIFY.md"

# 2. the reference CLI — canonical is apps/cli-node/ → ainra-cli-v${VER}.zip (packaged under ainra-cli/).
# The download is ONE self-contained file: we BUNDLE the canonical source (which now signs + verifies HYBRID
# Ed25519 + ML-DSA-65, at parity with the Rust core + browser SDK) with the audited @noble ML-DSA inlined, so a
# visitor runs it with just `node` — no install, no node_modules, zero runtime deps. esbuild + @noble come from the
# SDK's install (the SDK is already hybrid); the bundle is CJS so the single file needs no ESM/require-ESM support.
VER="$(node -e 'process.stdout.write(require("./apps/cli-node/package.json").version)')"
SDK=packages/sdk-ts
[ -x "$SDK/node_modules/.bin/esbuild" ] || { echo "→ installing build-time deps (esbuild + @noble PQC) via the SDK…"; ( cd "$SDK" && npm install --prefer-offline --no-audit --no-fund --silent >/dev/null 2>&1 ); }
# let esbuild resolve @noble from the CLI entry point: link the SDK's copies into the CLI's node_modules (build-only).
mkdir -p apps/cli-node/node_modules/@noble
for p in post-quantum hashes; do ln -sfn "$(cd "$SDK/node_modules/@noble/$p" && pwd)" "apps/cli-node/node_modules/@noble/$p"; done
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/ainra-cli/bin"
cp apps/cli-node/package.json apps/cli-node/README.md "$TMP/ainra-cli/"
"$SDK/node_modules/.bin/esbuild" apps/cli-node/bin/ainra.js --bundle --platform=node --format=cjs \
  --outfile="$TMP/ainra-cli/bin/ainra.js" >/dev/null
chmod +x "$TMP/ainra-cli/bin/ainra.js"
( cd "$TMP" && zip -q -r -X "ainra-cli-v${VER}.zip" ainra-cli )
cp "$TMP/ainra-cli-v${VER}.zip" "$SITE/ainra-cli-v${VER}.zip"

echo "built $SITE/ — 7 self-contained pages + refreshed downloads (CLI v${VER}, Standard $(wc -l < "$SITE/AINRA_I_The_Standard.md") lines)."
echo "  the download CLI == apps/cli-node (canonical); the Standard == docs/AINRA_I_The_Standard.md (canonical)."

# M17: keep the 4 content pages' shared header/footer in sync from site/_includes/ (one source of truth, no drift).
node tools/site-includes.mjs

# No version drift (Task 6): AFTER the include sync, every three-part vX.Y.Z printed in a page IS the CLI version.
# The Standard is vN.N (two parts, unmatched) and passport examples use @N.N.N (no `v`, unmatched), so this catches
# ONLY a stale CLI label — in a page OR in the shared header/footer include it was just synced from.
BADVER="$(grep -rhoE 'v[0-9]+\.[0-9]+\.[0-9]+' "$SITE"/*.html 2>/dev/null | grep -vx "v${VER}" | sort -u || true)"
[ -z "$BADVER" ] || { echo "✗ site version drift: page(s) say $(echo "$BADVER" | tr '\n' ' ') but the CLI is v${VER} — one source of truth is apps/cli-node/package.json"; exit 1; }

# M17 Task 3 — the agent-first surface: markdown mirrors, OpenAPI specs, and the served copy of the onboarding file.
node tools/site-mirrors.mjs
node tools/openapi.mjs
cp skills.md "$SITE/skills.md"

# 5. the browser verifier — ainra-core compiled to WebAssembly (L5). Rebuilt from source here rather than trusted
# from the tree, so a stale artifact can never ship while the page claims it is the current core. The size ceiling
# is enforced inside the build script.
if command -v wasm-bindgen >/dev/null 2>&1; then
  bash tools/build-wasm.sh
else
  echo "  ! skipping the WebAssembly verifier — wasm-bindgen not installed; site/assets/wasm/ is left as-is."
  echo "    install: cargo install wasm-bindgen-cli --version $(grep -oP '=\K[0-9.]+' crates/ainra-wasm/Cargo.toml | head -1) --locked"
fi

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
