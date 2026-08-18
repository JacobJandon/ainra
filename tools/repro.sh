#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make repro (M7) — prove the published artifact set is byte-for-byte reproducible FROM SOURCE. Build the whole set
# from scratch into a fresh EMPTY temp tree (twice), and compare against what is committed. Because the rebuild
# starts from nothing, this catches not just byte drift but ALSO orphan/planted committed files a fresh build never
# produces (the M7-review HIGH: an in-place regen would launder such files as "reproducible"). Asserts
# committed == clean-rebuild-1 == clean-rebuild-2, then writes MANIFEST.sha256 (the canonical content list).
# Covers the path-independent spec artifacts (CC0 corpus + sample book); NOT the tsc dist — see ARTIFACTS.md § reproducibility.
set -euo pipefail
cd "$(dirname "$0")/.."

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The generated locations, relative to a build root. A clean rebuild must reproduce EXACTLY this tree.
list_rel() { # $1 = root dir to enumerate, prints "<hash>␠␠<repo-relative-path>" sorted by path
  ( cd "$1" && {
      find vectors/v1 vectors/v1-delta vectors/v1-directory samples/data -type f
      for f in samples/*.svg samples/manifest.json; do [ -e "$f" ] && printf '%s\n' "$f"; done
    } | sort | tr '\n' '\0' | xargs -0 sha256sum | sort -k2 )
}

# Build the FULL artifact set from source into $1 (an empty dir), mirroring the repo-relative layout.
build_into() {
  local out="$1"
  mkdir -p "$out/samples/data"
  cargo run --release -q -p ainra-vector-gen -- --out "$out/vectors/v1" --min 500 >/dev/null 2>&1
  cargo run --release -q -p ainra-vector-gen -- --delta-out "$out/vectors/v1-delta" >/dev/null 2>&1
  cargo run --release -q -p ainra-vector-gen -- --directory-out "$out/vectors/v1-directory" >/dev/null 2>&1
  for kind in valid delegated revoked; do
    cargo run --release -q -p ainra-core --example sample_passport -- "$kind" > "$out/samples/data/sample-$kind.json"
  done
  AINRA_SAMPLES_DATA="$out/samples/data" AINRA_SAMPLES_OUT="$out/samples" node tools/render-samples.mjs >/dev/null 2>&1
}

echo "== committed set =="
A="$(list_rel .)"
A_n=$(printf '%s\n' "$A" | grep -c . || true)

echo "== clean rebuild from source (pass 1) =="
build_into "$WORK/b1"
B="$(list_rel "$WORK/b1")"

echo "== clean rebuild from source (pass 2) =="
build_into "$WORK/b2"
C="$(list_rel "$WORK/b2")"

fail=0
if [ "$A" != "$B" ]; then
  echo "!! NOT REPRODUCIBLE: the committed set differs from a clean rebuild (orphan / missing / changed byte):"
  diff <(printf '%s\n' "$A") <(printf '%s\n' "$B") | grep '^[<>]' | head -20
  fail=1
fi
if [ "$B" != "$C" ]; then
  echo "!! NON-DETERMINISTIC: two clean rebuilds differ:"
  diff <(printf '%s\n' "$B") <(printf '%s\n' "$C") | grep '^[<>]' | head
  fail=1
fi
[ "$fail" = 0 ] || { echo "repro FAILED"; exit 1; }

printf '%s\n' "$C" > MANIFEST.sha256
echo "== repro OK: committed == clean-rebuild ×2, byte-identical ($A_n files); wrote MANIFEST.sha256 =="
echo "   manifest digest: $(sha256sum MANIFEST.sha256 | cut -c1-16)…"
