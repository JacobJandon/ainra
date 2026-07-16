#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make verify-mirror — byte-verify a mirror directory against a manifest. Exit 0 iff every listed file is present and
# byte-identical AND the mirror serves NOTHING extra; fail closed on any missing/extra/differing byte. A relying
# party runs this against ANY mirror (ours or a third party's) using the manifest it trusts — which is reproducible
# from source via `make repro`, so the mirror's honesty is checkable without trusting the mirror OR us.
#   usage: mirror-verify.sh <mirror-dir> [manifest]   (defaults: build/mirror, MANIFEST.sha256)
set -euo pipefail
cd "$(dirname "$0")/.."
DIR="${1:-build/mirror}"
MAN="${2:-MANIFEST.sha256}"
[ -f "$MAN" ] || { echo "verify-mirror: manifest $MAN missing"; exit 2; }
[ -d "$DIR" ] || { echo "verify-mirror: mirror dir $DIR missing"; exit 2; }

fail=0; n=0
# `|| [ -n "$want" ]` so a manifest whose final line lacks a trailing newline still verifies its last entry (an
# externally-transported manifest may be newline-stripped by an editor — the M7 review's fail-open finding).
while read -r want path || [ -n "$want" ]; do
  [ -n "$want" ] || continue
  n=$((n + 1))
  # A mirror serves REGULAR files only. A symlink (even one pointing at correct bytes) is rejected — it is how a
  # mirror smuggles content from outside the served tree.
  if [ -L "$DIR/$path" ]; then echo "SYMLINK (not a regular file): $path"; fail=1; continue; fi
  if [ ! -f "$DIR/$path" ]; then echo "MISSING: $path"; fail=1; continue; fi
  got="$(sha256sum "$DIR/$path" | awk '{print $1}')"
  [ "$got" = "$want" ] || { echo "DIFFERS: $path"; fail=1; }
done < "$MAN"

# A mirror must serve EXACTLY the manifest set. Extras = any regular file OR symlink NOT in the manifest, excluding
# ONLY the top-level manifest copy (matching by full path, not basename — else a file named MANIFEST.sha256 in any
# subdir would be smuggled in unlisted, the M7 review's HIGH).
extra="$(cd "$DIR" && find . \( -type f -o -type l \) ! -path './MANIFEST.sha256' | sed 's#^\./##' | sort)"
listed="$(awk '{print $2}' "$MAN" | sort -u)"
only_in_mirror="$(comm -23 <(printf '%s\n' "$extra") <(printf '%s\n' "$listed"))"
[ -z "$only_in_mirror" ] || { echo "EXTRA (not in manifest):"; printf '%s\n' "$only_in_mirror" | head; fail=1; }

[ "$fail" = 0 ] || { echo "verify-mirror FAILED ($DIR)"; exit 1; }
echo "verify-mirror OK: $DIR is byte-identical to $MAN ($n files, no extras)"
