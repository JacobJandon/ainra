#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# make succession-drill — can a stranger with the documented artifacts ALONE take this over?
#
# The scenario is not a disaster; it is an absence. The operator stops. Someone else clones the repository, reads
# docs/SUCCESSION.md, and follows it. Nothing else: no local state, no environment variables anyone set up, no
# knowledge that lives in one person's head.
#
# This drill runs that, from a clone in a scratch directory with a clean environment, and TIMES each step. What
# fails is the real inheritance gap — it is not a test failure, it is a discovery about the document.
#
# WITNESS: could this observe a failure? Yes, and it is designed to. It clones into a fresh directory with
# HOME/config pointed away from the operator's, so anything the repository silently depends on locally is absent
# by construction. A step that only works because of state on this machine fails here.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
REPORT_DIR="$REPO_ROOT/docs/drills"; mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/SUCCESSION-DRILL.md"

fails=0; rows=""
step() {                       # step <label> <command...>
  local label="$1"; shift
  local t0 t1 dur out rc
  t0=$(date +%s)
  out="$("$@" 2>&1)"; rc=$?
  t1=$(date +%s); dur=$((t1 - t0))
  if [ $rc -eq 0 ]; then
    printf "  ok    %-34s %4ds\n" "$label" "$dur"
    rows="$rows| $label | ✓ | ${dur}s |"$'\n'
  else
    printf "  FAIL  %-34s %4ds\n" "$label" "$dur"
    echo "$out" | tail -6 | sed 's/^/          /'
    rows="$rows| $label | ✗ | ${dur}s |"$'\n'
    fails=$((fails+1))
  fi
}

echo "succession-drill · a stranger, the documented artifacts, and nothing else"
echo "  scratch: $WORK"
START=$(date +%s)

# A CLONE of COMMITTED state, not this working tree. That distinction matters twice over: the operator's tree
# carries build caches and node_modules a successor would not have, AND uncommitted fixes are invisible here —
# which is correct, because a successor inherits what was pushed, not what was in progress. A fix must be
# committed before this drill can confirm it.
# A CLONE, not this working tree — the operator's tree carries build caches, node_modules and local config that a
# successor would not have. Cloning from the local path keeps the drill offline and still proves the property.
step "clone the repository" git clone -q "$REPO_ROOT" "$WORK/ainra"
cd "$WORK/ainra" || exit 1

# The documented first-week sequence, in order (docs/SUCCESSION.md §2).
step "1 · cold board (make preflight)"       make preflight
step "2 · artifacts rebuild + byte-verify"   bash -c "make repro && make mirror && make verify-mirror"
step "3 · network up locally"                make genesis-local
step "5 · state of the world reads"          bash -c "make genesis-status && node tools/claims.mjs"

END=$(date +%s); TOTAL=$((END - START))

{
  echo "<!-- SPDX-License-Identifier: CC-BY-4.0 -->"
  echo "# Drill — succession"
  echo
  echo "**Question.** Can a stranger holding only the repository and \`docs/SUCCESSION.md\` take this project over?"
  echo
  echo "**Method.** Clone into a scratch directory, then run the documented first-week sequence in order. No local"
  echo "state, no operator knowledge, no environment prepared in advance. Each step timed."
  echo
  echo "**Run.** $(date -u +%Y-%m-%dT%H:%M:%SZ) · total **${TOTAL}s**"
  echo
  echo "| Step | Result | Time |"
  echo "|---|---|---|"
  printf "%s" "$rows"
  echo
  if [ "$fails" -gt 0 ]; then
    echo "**Verdict: INHERITANCE GAP — $fails step(s) failed.** A step that fails here is not a broken test; it is"
    echo "something the project only does because of state on one person's machine. Fix it in the repository or in"
    echo "docs/SUCCESSION.md, then re-run."
  else
    echo "**Verdict: a stranger with the documented artifacts alone can bring this up.** Every step above ran from a"
    echo "clone with no local state and no operator knowledge."
  fi
  echo
  echo "Steps 4, 6 and 7 of \`docs/SUCCESSION.md\` are deliberately not drilled: two require the network (deploy"
  echo "credentials a successor is granted, not inherited) and one is a decision by a person. Saying which parts a"
  echo "drill does **not** cover is part of the drill."
} > "$REPORT"

echo
echo "report → docs/drills/SUCCESSION-DRILL.md   total ${TOTAL}s"
if [ "$fails" -gt 0 ]; then
  echo "SUCCESSION-DRILL FAILED — $fails inheritance gap(s). See the report."
  exit 1
fi
echo "SUCCESSION-DRILL OK: a stranger with the documented artifacts alone brought the project up in ${TOTAL}s."
