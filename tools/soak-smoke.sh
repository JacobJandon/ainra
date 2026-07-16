#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make soak-smoke (M9) — prove the revocation-propagation soak INSTRUMENT works end to end at smoke scale: stand up a
# real registrar, continuously issue+revoke, measure propagation from 3 vantage points into a hash-chained log,
# render the live page, emit a signed report, and independently verify the log + report. All latencies are MEASURED.
# A real 14-day / 3-region run is the same instrument with --duration-sec and regional --registrar URLs (see README).
set -euo pipefail
cd "$(dirname "$0")/.."
CYCLES="${1:-20}"
PORT="${AINRA_SOAK_PORT:-4941}"
NOW=$((1775865600 + 10 * 24 * 3600))
WORK="$(mktemp -d)"
RB=0
trap 'kill "$RB" 2>/dev/null || true; rm -rf "$WORK"' EXIT

echo "== build =="
cargo build --release -q -p ainra-services --bin registrar-box -p ainra-ceremony --bin accredit
(cd packages/sdk-ts && { [ -d node_modules ] || npm install --prefer-offline --no-audit --no-fund --silent; } && npm run build >/dev/null 2>&1)
(cd kits/soak && npm install --prefer-offline --no-audit --no-fund --silent)

echo "== start a real registrar + accredit it (root dark for the vantage points) =="
if curl -sf "http://127.0.0.1:$PORT/accreditation" >/dev/null 2>&1; then
  echo "FAIL: 127.0.0.1:$PORT already serving — kill the leftover daemon"; exit 1
fi
./target/release/registrar-box "127.0.0.1:$PORT" registrar-07 "$WORK/rb" >/dev/null 2>"$WORK/rb.err" &
RB=$!
for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$PORT/accreditation" >/dev/null 2>&1 && break; sleep 0.2; done
kill -0 "$RB" 2>/dev/null || { echo "FAIL: registrar-box died — $(tail -1 "$WORK/rb.err" 2>/dev/null)"; exit 1; }
curl -sf "http://127.0.0.1:$PORT/accreditation" > "$WORK/acc.json"
./target/release/accredit "$WORK" "$WORK/acc.json" >/dev/null

echo "== run the soak instrument: $CYCLES issue/revoke cycles × 3 vantage points =="
OUT="$WORK/out"
node kits/soak/soak.mjs --registrar "http://127.0.0.1:$PORT" --directory "$WORK/directory.json" --roots "$WORK/roots.json" \
  --now "$NOW" --vantages "local-a,local-b,local-c" --cycles "$CYCLES" --poll-ms 80 --slo-p95-sec 60 --out "$OUT"

echo "== independently verify the append-only log + the signed report =="
node kits/soak/verify-log.mjs --log "$OUT/soak-log.jsonl" --report "$OUT/soak-report.json"

echo
echo "soak-smoke OK — the instrument measures real propagation, chains it tamper-evidently, and the signed report"
echo "is reproducible from the log. A real soak: same instrument, --duration-sec $((14 * 24 * 3600)) + regional URLs."
