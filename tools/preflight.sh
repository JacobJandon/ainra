#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make preflight (M10) — the "clone it and it works" promise. From a fresh clone with only the documented toolchain
# (Rust 1.96 via rust-toolchain.toml, Node 22), this runs every gate a stranger would run and prints a green/red
# board. Exits nonzero if any row is red. Nothing here is faked — each row is a real command's real exit code.
#
#   make preflight              # full board
#   make preflight QUICK=1      # skip the ~long repro/soak-heavy rows for a fast sanity board
set -uo pipefail
cd "$(dirname "$0")/.."

# A newcomer's #1 failure is a missing toolchain surfacing as a cryptic error 3 minutes into a build. Catch it up front
# with a human next step instead. (`make doctor` gives the full picture + versions.)
MISSING=""
for t in rustc cargo node make; do command -v "$t" >/dev/null 2>&1 || MISSING="$MISSING $t"; done
if [ -n "$MISSING" ]; then
  echo "✗ Missing required tool(s):$MISSING"
  echo "  → Run 'make doctor' for the full environment check + how to install each. See TOOLCHAIN.md."
  exit 1
fi

QUICK="${QUICK:-0}"
LOGDIR="$(mktemp -d)"
trap 'rm -rf "$LOGDIR"' EXIT
declare -a NAMES RESULTS NOTES
FAIL=0

run() { # run <name> <note-on-pass> <command...>
  local name="$1" note="$2"; shift 2
  printf '  … %-22s ' "$name"
  local log="$LOGDIR/${name// /_}.log" start end
  start=$(date +%s 2>/dev/null || echo 0)
  if "$@" >"$log" 2>&1; then
    end=$(date +%s 2>/dev/null || echo 0)
    printf '\r  \033[32m[PASS]\033[0m %-22s %s (%ss)\n' "$name" "$note" "$((end-start))"
    NAMES+=("$name"); RESULTS+=("PASS"); NOTES+=("$note")
  else
    printf '\r  \033[31m[FAIL]\033[0m %-22s (see below)\n' "$name"
    NAMES+=("$name"); RESULTS+=("FAIL"); NOTES+=("$(tail -3 "$log" | tr '\n' ' ' | cut -c1-120)")
    FAIL=1
    echo "        ── last lines of $name ──"; tail -6 "$log" | sed 's/^/        /'
  fi
}

# Some rows need a toolchain we deliberately do NOT make a prerequisite of cloning (the WASM row needs
# wasm-bindgen-cli and a headless browser). Those SKIP loudly, naming what is missing and the command that installs
# it. A skip is never a pass: it prints in the board, it is counted, and the summary says so. CI installs the
# toolchain, so the row is genuinely enforced there — the skip is a courtesy to a stranger, not a hole in the gate.
SKIPPED=0
skip() { # skip <name> <why>
  printf '  \033[33m[SKIP]\033[0m %-22s %s\n' "$1" "$2"
  NAMES+=("$1"); RESULTS+=("SKIP"); NOTES+=("$2"); SKIPPED=$((SKIPPED+1))
}

echo "AINRA preflight — clone-and-it-works board"
echo "toolchain: $(rustc --version 2>/dev/null || echo 'rustc?') · $(node --version 2>/dev/null || echo 'node?')"
echo "────────────────────────────────────────────────────────────────"

run "fmt + clippy"       "rustfmt clean, no clippy warns" make lint-check
run "build + tests"      "release test suite"          make test
run "differential"       "4 impls agree over vectors"  make diff
run "conformance"        "runner: 3 clean, broken caught" make conformance
run "CLI hybrid"         "download: Ed25519+ML-DSA both" make cli-check
run "genesis-local"      "whole stack boots on 1 host"  make genesis-local
run "verifier kit"       "execution-bound attestation"  bash tools/verifier-kit-smoke.sh
run "ceremony dry-run"   "witness-reproducible"         bash tools/ceremony-dry-run.sh 5
run "ceremony multi"     "FROST 5-of-9 across processes" bash tools/ceremony-rehearsal-multi.sh
run "soak instrument"    "measured p95, signed report"  bash tools/soak-smoke.sh 12
run "witness quorum"     "fork refused over HTTP"       bash tools/drill-networked.sh
run "compliance probe"   "honest passes, 4 dishonest caught" bash tools/probe-drill.sh
run "one decode path"    "no duplicate bytes→core parser" node tools/one-decode-path.mjs
run "lockfile sync"      "lockfiles state their package version" node tools/lockfile-sync.mjs
run "reason contract"    "docs name every reason impls return" node tools/reasons-check.mjs
run "corpus counts"      "stated counts == vectors on disk"  node tools/corpus-check.mjs
run "instance gate"      "running copy in, unentitled out"   node tools/instance-gate-check.mjs
run "claim registry"     "every claim agrees everywhere"     node tools/claims.mjs
run "soak ingest"        "declaration reads what the soak writes" node tools/soak-ingest-check.mjs
run "no names in git"    "D-036: candidates stay out of the repo" node tools/names-check.mjs
run "cross-impl interop" "fresh sigs verify in TS + PY"   make interop
if command -v wasm-bindgen >/dev/null 2>&1 && node tools/wasm-differential.mjs --probe >/dev/null 2>&1; then
  run "browser verifier"   "whole corpus agrees in-browser" make wasm-diff
else
  skip "browser verifier" "needs wasm-bindgen-cli + a headless browser (enforced in CI; see make wasm)"
fi
run "S7 neutrality"      "no brands / no impersonation" node tools/s7-lint.mjs
run "license headers"    "SPDX on every source file"    node tools/license-check.mjs
run "status honesty"     "README == STATUS claim"       node tools/status-consistency.mjs
run "doc freeze"         "normative docs unchanged"     make check-freeze
run "MCP fidelity"       "ainra_verify ≡ SDK on vectors" make mcp-test
run "presentation shape" "CLI≡middleware≡MCP event"     make presentation-diff
run "skills replay"      "skills.md runs as written"    make skills-replay
if [ "$QUICK" != "1" ]; then
  run "reproducibility"  "artifacts rebuild byte-exact" make repro
fi

echo "────────────────────────────────────────────────────────────────"
if [ "$FAIL" = "0" ]; then
  if [ "$SKIPPED" != "0" ]; then
    echo -e "  \033[32mALL GREEN\033[0m — every gate that ran passed; \033[33m$SKIPPED skipped\033[0m for a missing optional toolchain:"
    for i in "${!NAMES[@]}"; do [ "${RESULTS[$i]}" = "SKIP" ] && echo "    – ${NAMES[$i]}: ${NOTES[$i]}"; done
  else
    echo -e "  \033[32mALL GREEN\033[0m — a stranger can clone this repo and every gate passes."
  fi
  exit 0
else
  echo -e "  \033[31mRED\033[0m — the following rows failed:"
  for i in "${!NAMES[@]}"; do [ "${RESULTS[$i]}" = "FAIL" ] && echo "    ✗ ${NAMES[$i]}: ${NOTES[$i]}"; done
  exit 1
fi
