#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Conformance adapter for the Rust core (crates/ainra-core), fitting tools/conformance/CONTRACT.md. A thin wrapper:
# it execs `ainra-vector-gen --emit <kind>`, which reads the runner's JSON-Lines vectors on stdin and prints one
# `<name>\t<result-json>` line per vector computed by the REAL ainra-core verify path (verify / StatusDelta::verify /
# FreshHead::verify / Directory::accredit — the same functions `--check*` exercises, never a reimplementation).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BIN="$ROOT/target/release/ainra-vector-gen"
if [ ! -x "$BIN" ]; then
  echo "core adapter: build the reference generator first — cargo build --release -p ainra-vector-gen" >&2
  exit 1
fi
exec "$BIN" --emit "$1"
