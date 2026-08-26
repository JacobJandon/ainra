#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# make doctrine-negative — re-run the M32 census probes and prove `make doctrine` catches each one.
#
# Every probe below PASSED the entire board before the doctrine gate existed; that is not a hypothetical, it is
# what the census measured. So this is the rare negative control whose scenarios are the historical defects
# themselves rather than invented ones.
#
# Each probe mutates a real tracked file, runs the gate, and restores the file byte-for-byte. It fails loudly if
# the gate stays green (the check is asleep) OR if a file is left modified (the control corrupted the tree).
set -uo pipefail
cd "$(dirname "$0")/.."

fails=0
probe() {              # probe <label> <file> <sed-expression>
  local label="$1" file="$2" expr="$3" backup
  backup="$(mktemp)"; cp "$file" "$backup"
  perl -0pi -e "$expr" "$file"
  if cmp -s "$file" "$backup"; then
    echo "  ✗ $label — the mutation changed nothing; this probe tests nothing. Re-point it."
    fails=$((fails+1)); cp "$backup" "$file"; rm -f "$backup"; return
  fi
  if node tools/doctrine-check.mjs >/dev/null 2>&1; then
    echo "  ✗ $label — doctrine-check stayed GREEN while the rule was violated"
    fails=$((fails+1))
  else
    echo "  ok  $label — caught"
  fi
  cp "$backup" "$file"; rm -f "$backup"
  if ! git diff --quiet -- "$file"; then
    echo "  ✗ $label — $file was NOT restored cleanly"; fails=$((fails+1))
  fi
}

echo "doctrine-negative · the census probes, replayed against the gate that now exists"

probe "specimen label stripped"      site/get.html          's/SPECIMEN · TEST-ROOT/VERIFIED · PRODUCTION/'
probe "demo relabelled as live"      site/get.html          's/TYPE AP · SPECIMEN/TYPE AP · LIVE/'
probe "root displays a foreign mark" site/index.html        's/<body/<p>Proudly powered by Northwind — see their mark below.<\/p><body/'
probe "honest zero reworded away"    site/foundation.html   's/0 OPERATORS — GAP/INDEPENDENT WITNESS NETWORK/'
probe "footer zero reworded away"    site/_includes/footer.html 's/WITNESSES: 0/WITNESSES: ACTIVE/'
probe "DoD row hand-flipped"         docs/DOD.md            's/\| ⏳ external \(machinery ready\) \|/| ✓ |/'
probe "model promoted to measured"   docs/SCALE.md          's/honestly \[extrapolated\]/measured/'

echo
if [ "$fails" -gt 0 ]; then
  echo "DOCTRINE-NEGATIVE FAILED — $fails probe(s) went unnoticed or left the tree dirty."
  echo "A gate that does not fail on the exact defect it was written for is not a gate."
  exit 1
fi
echo "DOCTRINE-NEGATIVE OK: every census probe that once passed the whole board is now caught, and the tree is clean."
