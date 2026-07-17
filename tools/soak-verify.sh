#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make soak-verify OUT=<dir> (M10) — re-check a FINISHED soak run without trusting the runner: the report's Ed25519
# signature, the append-only hash chain, the head-hash + measurement-count binding, and that the report's own numbers
# recompute from its own log. Catches any tamper (edited line, dropped measurement, re-signed body). By default it does
# NOT gate an SLO verdict — that requires a third party to PIN the target + challenge out of band; pass SLO=<sec>
# CHALLENGE=<nonce> to run the full pinned gate (never trust the report's own threshold — D-024).
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${OUT:-out}"
LOG="$OUT/soak-log.jsonl"; REP="$OUT/soak-report.json"
if [ ! -f "$LOG" ] || [ ! -f "$REP" ]; then
  echo "usage: make soak-verify OUT=<dir with soak-log.jsonl + soak-report.json>  [SLO=60 CHALLENGE=<nonce>]"
  exit 2
fi
if [ -n "${SLO:-}" ] && [ -n "${CHALLENGE:-}" ]; then
  node kits/soak/verify-log.mjs --log "$LOG" --report "$REP" --slo-p95-sec "$SLO" --challenge "$CHALLENGE"
else
  node kits/soak/verify-log.mjs --log "$LOG" --report "$REP" --consistency-only
fi
