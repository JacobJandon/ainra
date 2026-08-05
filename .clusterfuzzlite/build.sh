#!/bin/bash -eu
# Build every existing cargo-fuzz target for the fuzzing engine.
cd "$SRC/ainra"
cargo fuzz build -O
for t in $(cargo fuzz list); do
  cp "fuzz/target/x86_64-unknown-linux-gnu/release/$t" "$OUT/"
done
