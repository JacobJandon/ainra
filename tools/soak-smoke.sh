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
# The collector issues a fresh single-use challenge that binds this run's log + report.
CHALLENGE="$(node -e 'console.log(require("crypto").randomBytes(16).toString("hex"))')"
node kits/soak/soak.mjs --registrar "http://127.0.0.1:$PORT" --directory "$WORK/directory.json" --roots "$WORK/roots.json" \
  --now "$NOW" --vantages "local-a,local-b,local-c" --cycles "$CYCLES" --poll-ms 80 --slo-p95-sec 60 --challenge "$CHALLENGE" --out "$OUT"

echo "== independently verify: SLO + challenge PINNED by us (not read from the report) =="
node kits/soak/verify-log.mjs --log "$OUT/soak-log.jsonl" --report "$OUT/soak-report.json" --slo-p95-sec 60 --challenge "$CHALLENGE"

echo "== ADVERSARIAL: a re-signed report claiming PASS on a BREACHING log must be REJECTED (M9 review regression) =="
# Fabricate a run: forge a log whose measurements all exceed the SLO, re-chain it, and re-sign a PASS report with a
# fresh key + the real challenge. verify-log must still FAIL because it recomputes the SLO against OUR pin.
CHALLENGE="$CHALLENGE" OUT="$OUT" node -e '
  const {createHash,generateKeyPairSync,sign}=require("crypto"); const {readFileSync,writeFileSync}=require("fs");
  const canon=(v)=>v===null||typeof v!=="object"?JSON.stringify(v):Array.isArray(v)?"["+v.map(canon).join(",")+"]":"{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+canon(v[k])).join(",")+"}";
  const sha=(b)=>createHash("sha256").update(b).digest("hex");
  // build a breaching log: 3 measurements at 999s, chained.
  let prev="genesis"; const lines=[];
  const add=(o)=>{const l={...o,prev_hash:prev}; l.this_hash=sha(canon(l)); prev=l.this_hash; lines.push(l);};
  add({ts:"t",event:"soak-start",challenge:process.env.CHALLENGE,slo_p95_sec:60});
  for(let i=0;i<3;i++) add({ts:"t",event:"measure",cycle:i,vantage:"local-a",latency_ms:999000,observed:true});
  writeFileSync(process.env.OUT+"/bad-log.jsonl", lines.map(l=>JSON.stringify(l)).join("\n")+"\n");
  const {publicKey,privateKey}=generateKeyPairSync("ed25519");
  const bodyb={kind:"ainra/soak-report/v1",challenge:process.env.CHALLENGE,measurements:3,slo:{revocation_p95_sec:60,pass:true},log_head_hash:prev};
  writeFileSync(process.env.OUT+"/bad-report.json", JSON.stringify({body:bodyb,reporter_pubkey_spki_b64:publicKey.export({type:"spki",format:"der"}).toString("base64"),sig_ed25519_b64:sign(null,Buffer.from(canon(bodyb)),privateKey).toString("base64")}));
'
if node kits/soak/verify-log.mjs --log "$OUT/bad-log.jsonl" --report "$OUT/bad-report.json" --slo-p95-sec 60 --challenge "$CHALLENGE" >/dev/null 2>&1; then
  echo "FAIL: a breaching log with a PASS report was accepted — SLO not pinned"; exit 1
else echo "  ✓ breaching-run fabrication rejected (SLO recomputed against our pin)"; fi

echo
echo "soak-smoke OK — the instrument measures real propagation, chains it tamper-evidently, and the signed report"
echo "is reproducible from the log. A real soak: same instrument, --duration-sec $((14 * 24 * 3600)) + regional URLs."
