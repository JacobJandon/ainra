#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Fuzz smoke. If cargo-fuzz + a nightly toolchain are present, run each target briefly; otherwise fall back to the
# in-process no-panic proptest suite (same "no crash/UB" guarantee, no nightly). Never reports a fake pass.
set -euo pipefail
cd "$(dirname "$0")/.."

# The newer parsers (PLAN-M51 step 5) are seeded from the published corpus itself rather than from committed copies:
# libFuzzer writes what it finds to fuzz/corpus/<target>/ (gitignored for these) and reads the vectors read-only.
seeds() {
  case "$1" in
    link) echo vectors/v1-link ;;
    decision) echo vectors/v1-decision ;;
    presentation) echo vectors/v1-presentation ;;
    directory) echo vectors/v1-directory vectors/v1-directory-epoch vectors/v1-gate vectors/v1-currency ;;
    delta) echo vectors/v1-delta ;;
  esac
}
SECS="${FUZZ_SECS:-15}"
if command -v cargo-fuzz >/dev/null 2>&1 && rustup toolchain list 2>/dev/null | grep -qi nightly; then
  for t in passport tsl canon link decision presentation directory delta; do
    echo "== cargo-fuzz $t (${SECS}s) =="
    mkdir -p "fuzz/corpus/$t"
    # shellcheck disable=SC2046
    cargo +nightly fuzz run "$t" "fuzz/corpus/$t" $(seeds "$t") -- -max_total_time="$SECS" -max_len=262144
  done
  echo "fuzz smoke OK (cargo-fuzz)"
else
  echo "cargo-fuzz or nightly not installed — running in-process no-panic smoke instead."
  echo "(full soak: 'cargo install cargo-fuzz && rustup toolchain install nightly', then re-run)"
  cargo test --release -p ainra-core --test properties -- fuzz_
  echo "fuzz smoke OK (in-process no-panic proptests)"
fi
