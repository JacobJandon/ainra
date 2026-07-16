#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make freeze / make check-freeze — freeze the NORMATIVE spec docs (the contract external parties build against), so
# an unintended edit to a frozen doc is detectable. Living docs (PLAN*, DECISIONS, STATUS) are intentionally NOT
# frozen. 'write' records docs/FREEZE.sha256; 'check' fails on any drift.
set -euo pipefail
cd "$(dirname "$0")/.."
mode="${1:-check}"

# The frozen set: the Standard, the Master Technical Specification, and the design system. Byte-stable contracts.
mapfile -t DOCS < <(
  for f in docs/AINRA_I_The_Standard.md docs/AINRA_Master_Technical_Specification_v1.md docs/DESIGN.md; do
    [ -f "$f" ] && echo "$f"
  done | sort -u
)
[ "${#DOCS[@]}" -gt 0 ] || { echo "freeze: no frozen docs found"; exit 2; }
snapshot() { for f in "${DOCS[@]}"; do sha256sum "$f"; done | sort -k2; }

case "$mode" in
  write)
    snapshot > docs/FREEZE.sha256
    echo "froze ${#DOCS[@]} normative docs → docs/FREEZE.sha256"
    ;;
  check)
    [ -f docs/FREEZE.sha256 ] || { echo "check-freeze: docs/FREEZE.sha256 missing — run 'make freeze'"; exit 2; }
    if diff <(snapshot) docs/FREEZE.sha256 >/dev/null; then
      echo "check-freeze OK: all ${#DOCS[@]} frozen docs unchanged"
    else
      echo "check-freeze: FROZEN DOCS DRIFTED —"
      diff <(snapshot) docs/FREEZE.sha256 | grep '^[<>]' | head
      exit 1
    fi
    ;;
  *) echo "usage: freeze.sh {write|check}"; exit 2 ;;
esac
