#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# make amendment-check-negative — prove the amendment gate rejects what it exists to reject.
#
# Three scenarios, each a real way the constitution could be edited away:
#   1. a prohibition deleted outright
#   2. a prohibition softened rather than removed ("holds no personal data" → "minimises personal data")
#   3. normative text changed with no amendment record in the same commit
#
# Every file is restored byte-for-byte and the tree is verified clean afterwards; a control that leaves the
# repository dirty has done more harm than the check does good.
set -uo pipefail
cd "$(dirname "$0")/.."

fails=0
probe() {   # probe <label> <file> <perl-expr> [--expect-record]
  local label="$1" file="$2" expr="$3" backup
  backup="$(mktemp)"; cp "$file" "$backup"
  perl -0pi -e "$expr" "$file"
  if cmp -s "$file" "$backup"; then
    echo "  ✗ $label — the mutation changed nothing; this probe tests nothing."
    fails=$((fails+1)); cp "$backup" "$file"; rm -f "$backup"; return
  fi
  if node tools/amendment-check.mjs >/dev/null 2>&1; then
    echo "  ✗ $label — amendment-check stayed GREEN"
    fails=$((fails+1))
  else
    echo "  ok  $label — rejected"
  fi
  cp "$backup" "$file"; rm -f "$backup"
  git diff --quiet -- "$file" || { echo "  ✗ $label — $file not restored"; fails=$((fails+1)); }
}

echo "amendment-negative · editing the constitution, three ways"

probe "prohibition deleted"  GOVERNANCE.md 's/computes no scores, //'
probe "prohibition softened" GOVERNANCE.md 's/holds no\npersonal data/minimises personal data where practical/'
probe "record deleted"       docs/AMENDMENTS.md 's/^## \d{4}.*$//m'

# 3. Normative text changed with no record — needs a base to diff against, so it is run against HEAD with the
#    working tree modified, which is exactly the state a commit is prepared in.
backup="$(mktemp)"; cp docs/DESIGN.md "$backup"
printf '\n<!-- probe -->\n' >> docs/DESIGN.md
if node tools/amendment-check.mjs >/dev/null 2>&1; then
  echo "  ✗ normative text changed with no record — amendment-check stayed GREEN"; fails=$((fails+1))
else
  echo "  ok  normative text changed with no record — rejected"
fi
cp "$backup" docs/DESIGN.md; rm -f "$backup"
git diff --quiet -- docs/DESIGN.md || { echo "  ✗ docs/DESIGN.md not restored"; fails=$((fails+1)); }

echo
if [ "$fails" -gt 0 ]; then
  echo "AMENDMENT-NEGATIVE FAILED — $fails scenario(s) slipped through or left the tree dirty."; exit 1
fi
echo "AMENDMENT-NEGATIVE OK: deletion, softening, record removal and unrecorded normative change are all rejected."
