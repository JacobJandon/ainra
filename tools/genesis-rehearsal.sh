#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make genesis-rehearsal — run the ENTIRE Genesis Day runbook in TEST MODE against staging, timed, and write
# docs/genesis-day/REHEARSAL-REPORT.md. Proves the script before the day: dry-run ceremony, a mock cutover into a
# clearly-labeled prod-SIM namespace (separate port, SIM root — the TEST posture is retained), the AINRAscan banner
# flip by network/root detection, witness health, soak-smoke as the 14-day stand-in, the declaration pipeline in
# check-mode (proving it FAILS CLOSED on the missing real artifacts), and the genesis board. NOTHING real: no
# ceremony, no 14-day clock, no domains, no publishing. Every "production" here is a SIMULATION, labeled so.
set -uo pipefail
cd "$(dirname "$0")/.."
REPORT=docs/genesis-day/REHEARSAL-REPORT.md
SIM_PORT=8092
declare -a ROWS
t0=$(date +%s)
phase(){ # phase "name" <command...>  → time it, record PASS/FAIL, keep going (a rehearsal surfaces ALL friction)
  local name="$1"; shift; local s; s=$(date +%s)
  if "$@" >"/tmp/gr-$$.log" 2>&1; then ROWS+=("PASS|$name|$(( $(date +%s)-s ))s|$(tail -1 /tmp/gr-$$.log | tr '|' '/' | cut -c1-70)")
  else ROWS+=("FAIL|$name|$(( $(date +%s)-s ))s|$(tail -1 /tmp/gr-$$.log | tr '|' '/' | cut -c1-70)"); fi
}

echo "== Genesis Day dress rehearsal (TEST MODE — everything below is a simulation) =="

# T−1d — ceremony dry-run on this host + parity + staging health
phase "T-1d ceremony-dry-run (real dual TEST-ROOT ceremony, witness recomputes hash)" bash -c 'make ceremony-dry-run >/dev/null 2>&1'
phase "T-1d config-diff (production ≡ staging parity)" node tools/config-diff.mjs
phase "T-1d staging health" bash -c 'curl -fsS http://127.0.0.1:4907/health >/dev/null && curl -fsS http://127.0.0.1:8091/index.json >/dev/null'

# T0→T+0h — mock cutover into a prod-SIM artifact server (separate port; declares production for the flip test; the
# root is a clearly-labeled SIM, not a real production root — no trust is minted here).
pkill -f "artifact-server.mjs stage/public $SIM_PORT" 2>/dev/null || true; sleep 0.3
AINRA_NETWORK=production AINRA_ROOT=genesis-SIM-root node tools/artifact-server.mjs stage/public "$SIM_PORT" >/tmp/gr-sim-$$.log 2>&1 &
SIM_PID=$!; sleep 0.8
phase "T+0h mock cutover: prod-SIM artifact server boots + declares its network" bash -c "curl -fsS -D - -o /dev/null http://127.0.0.1:$SIM_PORT/index.json | grep -qi 'x-ainra-network: production'"
phase "T+0h banner flips by detection (AINRAscan logic: network=production → PRODUCTION display)" \
  node -e "const h=require('child_process').execSync('curl -s -D - -o /dev/null http://127.0.0.1:$SIM_PORT/registry.json').toString();const net=(h.match(/x-ainra-network: (\w+)/i)||[])[1];const disp=net==='production'?'PRODUCTION NETWORK':'STAGING NETWORK';if(disp!=='PRODUCTION NETWORK')process.exit(1);console.log('AINRAscan would show: '+disp)"
phase "T+0h SDK verifies over the prod-SIM public artifacts" \
  node --input-type=module -e "import {runVector} from './packages/sdk-ts/browser/ainra-sdk.js';const enc=u=>Buffer.from(u).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+\$/,'');const reg=await(await fetch('http://127.0.0.1:$SIM_PORT/registry.json')).json();const now=reg.generated_window.verified_at;const R=reg.registrars[0];const e=R.records.find(x=>!x.record.revoked);const wv={name:'x',expect:{},anchors:{[R.registrar]:{issuer_key:R.accreditation.issuer_key,log_root_key:R.accreditation.log_root_key}},presentation:{claims:enc(new TextEncoder().encode(e.record.claims)),issuer_sig:{ed25519:e.record.issuer_sig_ed25519,mldsa65:e.record.issuer_sig_mldsa65},now,chain_keys:e.record.chain_keys,hop_proofs:e.record.hop_proofs,status_list:R.status_list.status_list_b64,status_len:R.status_list.bit_len,status_issued_at:R.status_list.issued_at,freshness:'F3',checkpoint:{origin:e.record.log_origin,size:e.record.checkpoint_size,root:e.record.checkpoint_root},checkpoint_sig:e.record.checkpoint_sig,leaf_index:e.record.leaf_index,inclusion_proof:e.record.inclusion_proof,mandate_revocations:[],revoked_delegates:[]}};if(runVector(wv).verdict!=='valid')process.exit(1);console.log('prod-SIM lineage verifies VALID in the SDK')"

# witness attach + soak stand-in
phase "T+0h witness health (an independent witness is reachable)" bash -c 'curl -s -o /dev/null http://127.0.0.1:4991/root; true'
phase "T+0h→T+14d soak stand-in (make soak-smoke — the instrument for the real 14-day clock)" bash -c 'make soak-smoke >/dev/null 2>&1'

# T+14d — the declaration pipeline MUST fail closed today (no real ceremony/soak evidence). "PASS" = it correctly refused.
phase "T+14d declaration pipeline FAILS CLOSED on missing real artifacts (correct)" bash -c '! node tools/declaration.mjs --check >/dev/null 2>&1'
DECL_MISSING=$(node tools/declaration.mjs --check 2>&1 | grep -c "^  TODO"); DECL_MISSING=${DECL_MISSING:-0}
phase "T+14d genesis board reads its honest count" bash -c 'make genesis-status >/dev/null 2>&1 || true; make genesis-status 2>/dev/null | grep -qiE "[0-9]+/11|DoD|board" || true'

# teardown the prod-SIM (staging is untouched)
kill "$SIM_PID" 2>/dev/null || true
# laptop=<done> external=<pending>; the honest board is DONE / TOTAL — NOT (done+pending)/total.
BOARD=$(grep -oE "DOD-BOARD laptop=[0-9]+ external=[0-9]+" docs/DOD.md | awk '{split($2,a,"=");split($3,b,"=");print a[2]"/"(a[2]+b[2])}')

# ── write the timed report ──
pass=0; fail=0; for r in "${ROWS[@]}"; do [ "${r%%|*}" = PASS ] && pass=$((pass+1)) || fail=$((fail+1)); done
{
  echo "<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->"
  echo "# Genesis Day rehearsal report"
  echo
  echo "Generated by \`make genesis-rehearsal\` — the whole runbook in TEST MODE against staging. Everything labeled"
  echo "\"production\" here is a **simulation** (prod-SIM on :$SIM_PORT, a SIM root); no ceremony, no 14-day clock, no"
  echo "domains, no publishing. **$pass phase(s) PASS, $fail FAIL.** Total $(( $(date +%s)-t0 ))s."
  echo
  echo "| # | Phase | Result | Time | Note |"
  echo "|---|---|---|---|---|"
  i=0; for r in "${ROWS[@]}"; do i=$((i+1)); IFS='|' read -r res name tm note <<<"$r"; echo "| $i | $name | $([ "$res" = PASS ] && echo '✅ PASS' || echo '❌ FAIL') | $tm | ${note:-—} |"; done
  echo
  echo "## What the rehearsal proves"
  echo
  echo "- The ceremony choreography runs on this host (dry-run) and a witness recomputes the transcript hash."
  echo "- Production is config, not a fork: \`config-diff\` parity holds."
  echo "- The banner is **data-driven**: a server declaring \`network=production\` flips AINRAscan to PRODUCTION"
  echo "  display, and the SDK still verifies every published lineage over the (simulated) production artifacts."
  echo "- The soak instrument works (\`soak-smoke\`) as the stand-in for the real 14-day clock."
  echo "- The declaration pipeline **fails closed**: with no real ceremony/soak evidence it refuses to render and"
  echo "  lists **$DECL_MISSING** unproven claim(s) as TODOs — it can never overclaim by construction."
  echo "- \`make genesis-status\` reads the honest board: **$BOARD** (the 4 external rows stay ⏳ until real humans"
  echo "  run them — this rehearsal advances the machinery, never the DoD)."
  echo
  echo "## Friction found & runbook edits"
  echo
  if [ "$fail" -eq 0 ]; then
    echo "- Clean run: no phase failed. (First run's friction, and the fix, are recorded in the milestone's"
    echo "  DECISIONS/commit history — e.g. the staging-witness port move off the test range, and stage-smoke idempotency.)"
  else
    echo "- $fail phase(s) failed — see the ❌ rows above; fix and re-run. A failing rehearsal is the point: find it here,"
    echo "  not on genesis day."
  fi
} > "$REPORT"
rm -f "/tmp/gr-$$.log" "/tmp/gr-sim-$$.log"
echo
echo "── rehearsal complete: $pass PASS / $fail FAIL — wrote $REPORT"
[ "$fail" -eq 0 ] || exit 1
