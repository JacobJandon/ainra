#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Build the EDGE gate's engine: crates/ainra-wasm with `--features edge` → packages/edge/wasm/.
#
# The same reproducible pipeline as tools/build-wasm.sh (cargo + a pinned wasm-bindgen, nothing else), with the
# gate's bindings switched on. It is a separate artifact on purpose: the browser verifier keeps its own ceiling and
# does not carry request signing or directory accreditation a page never uses. A gate loads this once per isolate,
# so its ceiling is about the platform's script limits, not a page download.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=packages/edge/wasm
CEILING_KB=${CEILING_KB:-640}
command -v wasm-bindgen >/dev/null 2>&1 || { echo "wasm-bindgen not found — see tools/build-wasm.sh" >&2; exit 1; }
cargo build -p ainra-wasm --features edge --target wasm32-unknown-unknown --profile wasm-release \
  --target-dir target/wasm-edge
mkdir -p "$OUT"
wasm-bindgen --target web --no-typescript --out-dir "$OUT" \
  target/wasm-edge/wasm32-unknown-unknown/wasm-release/ainra_wasm.wasm
WASM_KB=$(( ( $(wc -c < "$OUT/ainra_wasm_bg.wasm") + 1023 ) / 1024 ))
echo "edge wasm: ${WASM_KB} KiB   ceiling: ${CEILING_KB} KiB"
if [ "$WASM_KB" -gt "$CEILING_KB" ]; then
  echo "FAIL: the edge engine is ${WASM_KB} KiB, over the ${CEILING_KB} KiB ceiling." >&2; exit 1
fi
echo "EDGE WASM OK: ${WASM_KB} KiB, under the ${CEILING_KB} KiB ceiling."
