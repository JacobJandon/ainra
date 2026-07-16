#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Fuzz smoke. If cargo-fuzz + a nightly toolchain are present, run each target briefly; otherwise fall back to the
# in-process no-panic proptest suite (same "no crash/UB" guarantee, no nightly). Never reports a fake pass.
set -euo pipefail
cd "$(dirname "$0")/.."

if command -v cargo-fuzz >/dev/null 2>&1 && rustup toolchain list 2>/dev/null | grep -qi nightly; then
  for t in passport tsl canon; do
    echo "== cargo-fuzz $t (15s) =="
    cargo +nightly fuzz run "$t" -- -max_total_time=15
  done
  echo "fuzz smoke OK (cargo-fuzz)"
else
  echo "cargo-fuzz or nightly not installed — running in-process no-panic smoke instead."
  echo "(full soak: 'cargo install cargo-fuzz && rustup toolchain install nightly', then re-run)"
  cargo test --release -p ainra-core --test properties -- fuzz_
  echo "fuzz smoke OK (in-process no-panic proptests)"
fi
