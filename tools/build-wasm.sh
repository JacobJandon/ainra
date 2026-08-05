#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Build the browser verifier: crates/ainra-wasm → site/assets/wasm/.
#
# Reproducible by construction — no wasm-opt, no post-processing, no vendor toolchain. `cargo build` with a pinned
# profile plus `wasm-bindgen` at a version pinned to the crate is the whole pipeline, so anyone can rebuild these
# exact bytes and compare. The size CEILING is enforced here rather than watched: a browser verifier that quietly
# grows past what a page should download is a regression whether or not anyone notices.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=site/assets/wasm
CEILING_KB=${CEILING_KB:-460}

command -v wasm-bindgen >/dev/null 2>&1 || {
  echo "wasm-bindgen not found. Install the version pinned in crates/ainra-wasm/Cargo.toml:" >&2
  echo "  cargo install wasm-bindgen-cli --version $(grep -oP '=\K[0-9.]+' crates/ainra-wasm/Cargo.toml | head -1) --locked" >&2
  exit 1
}

cargo build -p ainra-wasm --target wasm32-unknown-unknown --profile wasm-release
mkdir -p "$OUT"
wasm-bindgen --target web --no-typescript --out-dir "$OUT" \
  target/wasm32-unknown-unknown/wasm-release/ainra_wasm.wasm

WASM_KB=$(( ( $(wc -c < "$OUT/ainra_wasm_bg.wasm") + 1023 ) / 1024 ))
JS_KB=$(( ( $(wc -c < "$OUT/ainra_wasm.js") + 1023 ) / 1024 ))
echo "wasm: ${WASM_KB} KiB   glue: ${JS_KB} KiB   ceiling: ${CEILING_KB} KiB"

if [ "$WASM_KB" -gt "$CEILING_KB" ]; then
  echo "FAIL: the browser verifier is ${WASM_KB} KiB, over the ${CEILING_KB} KiB ceiling." >&2
  echo "Either justify the growth and raise CEILING_KB in this script, or find what got pulled in." >&2
  exit 1
fi
echo "WASM OK: ${WASM_KB} KiB, under the ${CEILING_KB} KiB ceiling."
