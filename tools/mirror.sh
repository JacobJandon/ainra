#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make mirror — assemble a mirror directory serving EXACTLY the published artifact set listed in MANIFEST.sha256,
# preserving paths, plus a copy of the manifest itself. A mirror is any host that serves this tree; verify it with
# `make verify-mirror MIRROR=<dir>`.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-build/mirror}"
[ -f MANIFEST.sha256 ] || { echo "mirror: MANIFEST.sha256 missing — run 'make repro' first"; exit 2; }
# Guard the rm -rf: OUT must be a non-empty, relative, `..`-free scratch path (never '', '/', '.', a repo dir).
case "$OUT" in
  ""|/*|.|./|..|*/..|../*|*/../*) echo "mirror: refusing unsafe OUT '$OUT' (use a relative scratch path, e.g. build/mirror)"; exit 2 ;;
esac
case "$OUT" in
  vectors|vectors/*|samples|samples/*|crates|crates/*|packages|packages/*|tools|tools/*|docs|docs/*|services|services/*)
    echo "mirror: refusing to overwrite repo path '$OUT'"; exit 2 ;;
esac
rm -rf "$OUT"; mkdir -p "$OUT"
while read -r _hash path; do
  mkdir -p "$OUT/$(dirname "$path")"
  cp "$path" "$OUT/$path"
done < MANIFEST.sha256
cp MANIFEST.sha256 "$OUT/"
echo "mirror assembled at $OUT ($(wc -l < MANIFEST.sha256) files + MANIFEST.sha256)"
