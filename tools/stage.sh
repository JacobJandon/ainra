#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# The AINRA STAGING network on one host — real infrastructure, real crypto, a TEST-ROOT, honest labels.
#
#   make stage-up       start 2 registrar daemons (distinct classes) + a witness + the artifact server, genesis-seed
#                       a real network over HTTP (issue / delegate / revoke / renew), publish the public artifacts.
#   make stage-status   the live board, read from the running deployment's real endpoints.
#   make stage-smoke    issue → log → verify (via the public artifact contract, in the SDK) → revoke → propagate,
#                       against the LIVE deployment; assert the contract headers. Real output.
#   make stage-down     stop everything.
#
# The network now runs under a REAL, operator-run GENESIS dual-root (FROST 5-of-9 + SLH-DSA): stage-up accredits the
# live registrars, publishes the dual-root-SIGNED directory + roots, and passports verify root-dark against it. The
# root EXISTS. What remains is the DISTRIBUTED real-world version — a publicly-recorded ceremony with independent
# custodians, >=3 external verifiers, a 14-day 3-region soak. Placeholder operators only. Zero telemetry. State in stage/.
set -uo pipefail
cd "$(dirname "$0")/.."

STAGE=stage
PUB="$STAGE/public"
REG1_ADDR=127.0.0.1:4907 ; REG1_ID=registrar-07
REG2_ADDR=127.0.0.1:4911 ; REG2_ID=registrar-11
# 4991, NOT 4891: `make drill-networked` uses 4891–4895 for its witness-quorum test, and that test fails closed on
# a leftover process on its port. Keeping the staging witness off that range lets the staging network and the test
# suite run at the same time.
WIT_ADDR=127.0.0.1:4991
ART_PORT=8091
NBF=1775865600 ; RENEW_AT=$((NBF + 5*24*3600)) ; NOW=$((NBF + 10*24*3600)) ; AUDIT_EXP=1900000000
export AINRA_STAGE=1

# --- one HTTP client (curl) with the staging write token on write calls ---
TOKEN_FILE="$STAGE/.issue-token"
post(){ curl -s -m 10 -H "Content-Type: application/json" -H "Authorization: Bearer $(cat "$TOKEN_FILE" 2>/dev/null)" -d "$2" "http://$1"; }
get(){ curl -s -m 10 "http://$1"; }

issue(){ # addr operator lineage version tier auth 'cap,cap' 'ceil,ceil' [audit] [hops-json]
  local caps ceil audit hops
  caps=$(echo "$7" | awk -F, '{for(i=1;i<=NF;i++)printf "%s\"%s\"",(i>1?",":""),$i}')
  ceil=$(echo "$8" | awk -F, '{for(i=1;i<=NF;i++)printf "%s\"%s\"",(i>1?",":""),$i}')
  audit=""; [ "${9:-}" = "audit" ] && audit=",\"audit\":{\"reference\":\"audit-$3\",\"expires\":$AUDIT_EXP}"
  hops="${10:-[]}"
  post "$1/issue" "{\"operator\":\"$2\",\"lineage\":\"$3\",\"version\":\"$4\",\"tier\":\"$5\",\"auth_class\":\"$6\",\"principal_proof\":\"deadbeef$3\",\"capabilities\":[$caps],\"scope_ceiling\":[$ceil],\"hops\":$hops$audit}" >/dev/null
}

publish(){ # fetch each daemon's public artifacts → static files with the contract path scheme
  # D-035: republish is idempotent — drop stale per-registrar artifacts first, so the published contract reflects
  # ONLY the currently-live registrars. A leftover dir from a prior onboarding (registrar-22) once inflated
  # registry.json (3 registrars / 9 issued) past the live board (2 / 8): the contract advertised a dead registrar.
  rm -rf "$PUB/registrars"
  for pair in "$REG1_ADDR:$REG1_ID" "$REG2_ADDR:$REG2_ID"; do
    local addr="${pair%:*}" d="$PUB/registrars/${pair##*:}"
    mkdir -p "$d/status" "$d/checkpoints"
    get "$addr/accreditation"        > "$d/accreditation.json"
    get "$addr/export?now=$NOW"      > "$d/export.json"
    get "$addr/status-list?now=$NOW" > "$d/status/current.json"
    get "$addr/fresh-head?now=$NOW"  > "$d/fresh-head.json"
    get "$addr/deltas?since=0"       > "$d/status/deltas.json"
    node -e 'const fs=require("fs");const e=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));const r=(e.records||[])[0]?.record;if(r){fs.writeFileSync(process.argv[2]+"/checkpoints/"+r.checkpoint_size+".json",JSON.stringify({origin:r.log_origin,size:r.checkpoint_size,root:r.checkpoint_root}))}' "$d/export.json" "$d"
  done
  # build the combined artifacts from the per-registrar exports (one pass, robust)
  NBF="$NBF" WEXP="$((NBF+366*24*3600))" NOW="$NOW" node -e '
    const fs=require("fs"); const pub=process.argv[1];
    const ids=fs.readdirSync(pub+"/registrars").filter(d=>fs.existsSync(pub+"/registrars/"+d+"/export.json"));
    const regs=ids.map(id=>JSON.parse(fs.readFileSync(pub+"/registrars/"+id+"/export.json","utf8")));
    const w={nbf:+process.env.NBF,exp:+process.env.WEXP,verified_at:+process.env.NOW};
    let issued=0,revoked=0; for(const R of regs) for(const e of R.records){issued++; if(e.record.revoked)revoked++;}
    fs.writeFileSync(pub+"/registry.json", JSON.stringify({generated_window:w, registrars:regs, totals:{registrars:regs.length,issued,revoked}}));
    fs.writeFileSync(pub+"/directory.json", JSON.stringify({network:"staging",root:"test-root",note:"Staging directory: real registrar accreditations. The production dual-root-SIGNED directory is minted at the recorded genesis ceremony (a pending DoD row) — no trust migrates from staging.",registrars:regs.map(r=>({registrar:r.registrar,accreditation:r.accreditation,root_pub_slh:r.root_pub_slh}))}));
    fs.writeFileSync(pub+"/index.json", JSON.stringify({network:"staging",root:"test-root",label:"AINRA STAGING NETWORK · TEST-ROOT",generated_window:w,registrars:ids,artifacts:{directory:"/directory.json",registry:"/registry.json",skills:"/skills.md",per_registrar:"/registrars/<id>/{accreditation,export,fresh-head,status/current,status/deltas,checkpoints/<height>}.json"},telemetry:"none"}));
  ' "$PUB"
  # M16: the agent-readable onboarding file on the public surface (repo canonical → served at /skills.md and /agents.md).
  cp skills.md "$PUB/skills.md"; cp skills.md "$PUB/agents.md"
  # M19: the network runs under a REAL genesis dual-root — publish the dual-root-SIGNED directory + roots
  # (verifiable root-dark), and relabel the contract with the root fingerprint. The root now EXISTS.
  if [ -f "$STAGE/genesis/directory.json" ]; then
    cp "$STAGE/genesis/directory.json" "$PUB/directory.json"
    cp "$STAGE/genesis/roots.json" "$PUB/roots.json"
    FP="$(node -e 'process.stdout.write(require("./"+process.argv[1]+"/genesis/roots.json").root_ed25519.slice(0,16))' "$STAGE")"
    node -e 'const fs=require("fs"),d=process.argv[1],fp=process.argv[2];const j=JSON.parse(fs.readFileSync(d+"/index.json"));j.root="genesis:"+fp;j.label="AINRA NETWORK · GENESIS ROOT "+fp+" (operator-run ceremony)";j.roots="/roots.json";j.ceremony="operator-run; public multi-custodian ceremony + external verifiers + 14d soak are the remaining real-world milestones";fs.writeFileSync(d+"/index.json",JSON.stringify(j))' "$PUB" "$FP"
  fi
  # M23 Task 4 — witness diversity: publish the witness set's SELF-DECLARED /meta into the registry the explorer reads,
  # so it can show how many independent operators (and regions) stand behind the log. Verified by no one; the key is
  # the only cryptographic fact. Today staging runs one witness — the honest count, with independent seats open.
  local wmeta; wmeta="$(get "$WIT_ADDR/meta" 2>/dev/null || echo '{}')"
  WMETA="$wmeta" WADDR="$WIT_ADDR" node -e '
    const fs=require("fs"),d=process.argv[1]; let m={}; try{m=JSON.parse(process.env.WMETA||"{}")}catch{}
    for (const f of ["registry.json","index.json"]) {
      const p=d+"/"+f; const j=JSON.parse(fs.readFileSync(p,"utf8"));
      j.witnesses = m.ed25519 ? [{ addr:process.env.WADDR, self_declared:true, ed25519:m.ed25519,
        operator:m.operator||"", region:m.region||"", note:m.note||"" }] : [];
      fs.writeFileSync(p, JSON.stringify(j));
    }
  ' "$PUB"
}

case "${1:-up}" in
up)
  mkdir -p "$STAGE" "$PUB"
  [ -f "$TOKEN_FILE" ] || openssl rand -hex 16 > "$TOKEN_FILE" 2>/dev/null || head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$TOKEN_FILE"
  export AINRA_STAGE_ISSUE_TOKEN="$(cat "$TOKEN_FILE")"
  cargo build --release -q -p ainra-services --bin registrar-box --bin witnessd -p ainra-ceremony --bin accredit
  bash tools/ainrascan.sh >/dev/null 2>&1 || true   # ensure the browser SDK bundle exists for AINRAscan-on-staging
  echo "== start the staging network (2 registrar classes + witness + artifact server) =="
  : > "$STAGE/pids"
  AINRA_STAGE=1 AINRA_STAGE_ISSUE_TOKEN="$AINRA_STAGE_ISSUE_TOKEN" ./target/release/registrar-box "$REG1_ADDR" "$REG1_ID" "$STAGE/$REG1_ID" >"$STAGE/$REG1_ID.log" 2>&1 & echo $! >> "$STAGE/pids"
  AINRA_STAGE=1 AINRA_STAGE_ISSUE_TOKEN="$AINRA_STAGE_ISSUE_TOKEN" ./target/release/registrar-box "$REG2_ADDR" "$REG2_ID" "$STAGE/$REG2_ID" >"$STAGE/$REG2_ID.log" 2>&1 & echo $! >> "$STAGE/pids"
  ./target/release/witnessd "$WIT_ADDR" deploy/staging-witness.config.json >"$STAGE/witness.log" 2>&1 & echo $! >> "$STAGE/pids"
  sleep 1.2
  echo "== genesis-seed a real network over HTTP (issue / delegate / revoke / renew) =="
  issue "$REG1_ADDR" acme    invoicing   4.2.1 L3 A2 "read:invoices,sign:invoice" "read:invoices,sign:invoice,read:payments" audit
  issue "$REG1_ADDR" acme    data-export 2.0.0 L2 A2 "export:data" "export:data"
  issue "$REG1_ADDR" globex  fraud-scan  1.4.2 L3 A2 "read:transactions,flag:transaction" "read:transactions,flag:transaction" audit
  issue "$REG1_ADDR" acme    support-bot 1.0.0 L1 A2 "read:tickets" "read:tickets,reply:ticket" no \
        '[{"from":"ainra:registrar-07:acme:owner@1.0.0","to":"ainra:registrar-07:acme:support-desk@1.0.0","granted":["read:tickets","reply:ticket"]},{"from":"ainra:registrar-07:acme:support-desk@1.0.0","to":"ainra:registrar-07:acme:support-bot@1.0.0","granted":["read:tickets"]}]'
  issue "$REG2_ADDR" operator-03 scheduler   2.2.0 L2 A2 "read:calendar,book:slot" "read:calendar,book:slot,cancel:slot"
  issue "$REG2_ADDR" operator-05 notifier    3.0.1 L1 A2 "send:notification" "send:notification"
  issue "$REG2_ADDR" operator-03 crawler     0.9.0 L0 A1 "fetch:public" "fetch:public"
  post "$REG1_ADDR/revoke" "{\"sub\":\"ainra:$REG1_ID:acme:data-export@2.0.0\",\"now\":$NOW}" >/dev/null
  post "$REG2_ADDR/revoke" "{\"sub\":\"ainra:$REG2_ID:operator-03:crawler@0.9.0\",\"now\":$NOW}" >/dev/null
  post "$REG2_ADDR/renew"  "{\"sub\":\"ainra:$REG2_ID:operator-03:scheduler@2.2.0\",\"new_version\":\"2.3.0\",\"now\":$RENEW_AT}" >/dev/null
  echo "== accredit the network under a REAL genesis dual-root (FROST 5-of-9 + SLH-DSA) =="
  mkdir -p "$STAGE/genesis"
  get "$REG1_ADDR/accreditation" > "$STAGE/genesis/acc-$REG1_ID.json"
  get "$REG2_ADDR/accreditation" > "$STAGE/genesis/acc-$REG2_ID.json"
  ./target/release/accredit "$STAGE/genesis" "$STAGE/genesis/acc-$REG1_ID.json" "$STAGE/genesis/acc-$REG2_ID.json"
  ROOT_FP="$(node -e 'process.stdout.write(require("./"+process.argv[1]+"/genesis/roots.json").root_ed25519.slice(0,16))' "$STAGE")"
  export AINRA_ROOT="genesis:$ROOT_FP"
  echo "== publish the public artifacts (the contract read surface) =="
  publish
  AINRA_STAGE=1 node tools/artifact-server.mjs "$PUB" "$ART_PORT" >"$STAGE/artifact.log" 2>&1 & echo $! >> "$STAGE/pids"
  sleep 0.6
  echo
  echo "  AINRA STAGING NETWORK · TEST-ROOT is up:"
  echo "    registrar $REG1_ID   http://$REG1_ADDR   (write-auth: bearer token in $TOKEN_FILE)"
  echo "    registrar $REG2_ID   http://$REG2_ADDR"
  echo "    witness              http://$WIT_ADDR"
  echo "    public artifacts     http://127.0.0.1:$ART_PORT/   (CORS, contract headers — what AINRAscan/mirrors read)"
  echo "    → AINRAscan on staging:  http://localhost:8090/?net=http://127.0.0.1:$ART_PORT"
  echo "    → make stage-status | make stage-smoke | make stage-down"
  ;;
down)
  if [ -f "$STAGE/pids" ]; then while read -r p; do kill "$p" 2>/dev/null; done < "$STAGE/pids"; rm -f "$STAGE/pids"; fi
  pkill -f "artifact-server.mjs $PUB" 2>/dev/null || true
  echo "staging network stopped."
  ;;
publish) publish; echo "republished."; ;;
status)
  echo "AINRA STAGING BOARD · TEST-ROOT  ($(date -u +%H:%M:%SZ))"
  echo "────────────────────────────────────────────────────────────"
  for pair in "$REG1_ADDR:$REG1_ID" "$REG2_ADDR:$REG2_ID"; do
    h=$(get "${pair%:*}/health"); up=$([ -n "$h" ] && echo UP || echo DOWN)
    printf "  registrar %-14s %-4s  %s\n" "${pair##*:}" "$up" "$(echo "$h" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const j=JSON.parse(s);console.log(`records=${j.records} status_seq=${j.status_seq} write_auth=${j.write_auth}`)}catch{console.log("")}})' 2>/dev/null)"
  done
  w=$(get "$WIT_ADDR/root" 2>/dev/null); printf "  witness %-16s %s\n" "$WIT_ADDR" "$([ -n "$w" ] && echo 'UP (open seat — see deploy/witness-quickstart.md)' || echo DOWN)"
  a=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$ART_PORT/index.json"); printf "  artifact server %-9s HTTP %s  (banner: X-AINRA-Network: staging)\n" ":$ART_PORT" "$a"
  echo "────────────────────────────────────────────────────────────"
  echo "  labels: STAGING · TEST-ROOT · placeholder operators · zero telemetry"
  ;;
smoke) exec bash tools/stage-smoke.sh ;;
*) echo "usage: stage.sh {up|down|publish|status|smoke}"; exit 2 ;;
esac
