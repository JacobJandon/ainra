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

# THE VERIFIER ANCHOR SET (M32). The manifest lists what REBUILDS reproducibly; a mirror must additionally serve
# what an offline verifier NEEDS, and those are not the same set. `make root-dark-drill` proved the difference:
# a conformance vector carries its own anchors and verified fine from a mirror, while a real issued credential —
# which carries claims, signatures and proofs but nothing about who was allowed to sign it — could not be verified
# at all, because the root-signed directory and root keys were not mirrored. The project had claimed root-dark
# verification since M1 and it was true of the corpus only.
#
# These are committed, byte-stable inputs rather than generated outputs, which is why they are copied here instead
# of being added to MANIFEST.sha256 (that file's contract is "rebuilds byte-identically twice", and these do not
# rebuild — they are ceremony products).
ANCHORS="kits/verifier/sample-artifacts"
anchor_n=0
if [ -d "$ANCHORS" ]; then
  mkdir -p "$OUT/$ANCHORS"
  for f in "$ANCHORS"/*.json; do
    [ -e "$f" ] || continue
    cp "$f" "$OUT/$ANCHORS/"; anchor_n=$((anchor_n+1))
  done
fi
[ "$anchor_n" -gt 0 ] || { echo "mirror: no verifier anchors found in $ANCHORS — a mirror without trust anchors cannot verify an issued credential"; exit 2; }

echo "mirror assembled at $OUT ($(wc -l < MANIFEST.sha256) manifest files + MANIFEST.sha256 + $anchor_n verifier anchor file(s))"
