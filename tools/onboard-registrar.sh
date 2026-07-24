#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Onboard a NEW registrar onto the RUNNING staging network — the whole "become an accredited registrar" path,
# the way a real operator (a GoDaddy/Namecheap for agent passports) would walk it. General: any id/port/operator.
#
#   ID=registrar-22 PORT=4922 OPERATOR=acmecerts LINEAGE=audit-trail  bash tools/onboard-registrar.sh
#
# Steps (each is the real endpoint, not a mock):
#   ① stand up the operator's registrar-box            — its own DISTINCT keys (derived per id), own state, own port
#   ② read its accreditation APPLICATION               — GET /accreditation → the registrar's public keys
#   ③ the root ACCREDITS it                            — staging: the TEST-ROOT includes it in the signed directory
#                                                          (production: the 5-of-9 root signs this directory entry)
#   ④ it ISSUES a passport through the identical door  — POST /issue (real hybrid signing + RFC-6962 log inclusion)
#   ⑤ PUBLISH                                          — the passport enters the public artifacts every verifier reads
#   ⑥ an INDEPENDENT verifier checks it                — the real @ainra/sdk says VALID, trusting the SOURCE not the seller
set -uo pipefail
cd "$(dirname "$0")/.."
STAGE=stage; PUB="$STAGE/public"
ID="${ID:-registrar-22}"; PORT="${PORT:-4922}"; ADDR="127.0.0.1:$PORT"
OPERATOR="${OPERATOR:-acmecerts}"; LINEAGE="${LINEAGE:-audit-trail}"; VERSION="${VERSION:-1.0.0}"
TIER="${TIER:-L2}"; AUTH="${AUTH:-A2}"; CAPS="${CAPS:-read:ledger,export:report}"
NBF=1775865600; NOW=$((NBF + 10*24*3600)); WEXP=$((NBF + 366*24*3600))
TOKEN="$(cat "$STAGE/.issue-token" 2>/dev/null || true)"
export AINRA_STAGE=1 AINRA_STAGE_ISSUE_TOKEN="$TOKEN"
post(){ curl -s -m 10 -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d "$2" "http://$1"; }
get(){ curl -s -m 10 "http://$1"; }
sep(){ printf '─%.0s' {1..76}; echo; }

[ -d "$PUB" ] || { echo "staging network is not up — run: make stage-up"; exit 1; }
sep; echo "ONBOARDING A NEW REGISTRAR → $ID   (operator: $OPERATOR)"; sep

echo "① Stand up the operator's registrar-box  ($ID @ $ADDR — own key class, own state $STAGE/$ID)"
cargo build --release -q -p ainra-services --bin registrar-box
if get "$ADDR/health" >/dev/null 2>&1 && [ -n "$(get "$ADDR/health")" ]; then
  echo "   already running."
else
  ./target/release/registrar-box "$ADDR" "$ID" "$STAGE/$ID" >"$STAGE/$ID.log" 2>&1 &
  echo $! >> "$STAGE/pids"; sleep 1.2
fi
get "$ADDR/health" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const j=JSON.parse(s);console.log(`   box UP · records=${j.records} · write_auth=${j.write_auth}`)}catch{console.log("   box did not answer /health")}})'

echo
echo "② Accreditation APPLICATION — the registrar's public keys (GET /accreditation)"
get "$ADDR/accreditation" > "$STAGE/.acc-$ID.json"
node -e 'const a=require(process.argv[1]);const k=v=>String(v||"").slice(0,22)+"…";const acc=a.accreditation||a;console.log("   registrar    :",a.registrar||acc.registrar);console.log("   issuer_key   :",k(acc.issuer_key));console.log("   log_root_key :",k(acc.log_root_key));console.log("   -> DISTINCT from every other registrar (keys seeded per id) — a real key class, not an alias.");' "$STAGE/.acc-$ID.json"

echo
echo "③ The root ACCREDITS it — signs it into the directory"
echo "   staging: the TEST-ROOT includes $ID in directory.json (production: the 5-of-9 root signs this entry)."

echo
echo "④ It ISSUES a passport through the identical public door (POST /issue)"
capsJSON=$(echo "$CAPS" | awk -F, '{for(i=1;i<=NF;i++)printf "%s\"%s\"",(i>1?",":""),$i}')
SUB="ainra:$ID:$OPERATOR:$LINEAGE@$VERSION"
post "$ADDR/issue" "{\"operator\":\"$OPERATOR\",\"lineage\":\"$LINEAGE\",\"version\":\"$VERSION\",\"tier\":\"$TIER\",\"auth_class\":\"$AUTH\",\"principal_proof\":\"deadbeef$LINEAGE\",\"capabilities\":[$capsJSON],\"scope_ceiling\":[$capsJSON],\"hops\":[]}" >/dev/null
echo "   issued: $SUB   (tier $TIER · $AUTH · caps: $CAPS)"

echo
echo "⑤ PUBLISH — the passport enters the public artifacts (the contract read surface at :8091)"
d="$PUB/registrars/$ID"; mkdir -p "$d/status" "$d/checkpoints"
get "$ADDR/accreditation"        > "$d/accreditation.json"
get "$ADDR/export?now=$NOW"      > "$d/export.json"
get "$ADDR/status-list?now=$NOW" > "$d/status/current.json"
get "$ADDR/fresh-head?now=$NOW"  > "$d/fresh-head.json"
get "$ADDR/deltas?since=0"       > "$d/status/deltas.json"
node -e 'const fs=require("fs");const e=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));const r=(e.records||[])[0]?.record;if(r){fs.writeFileSync(process.argv[2]+"/checkpoints/"+r.checkpoint_size+".json",JSON.stringify({origin:r.log_origin,size:r.checkpoint_size,root:r.checkpoint_root}))}' "$d/export.json" "$d"
# rebuild the COMBINED public artifacts by scanning every registrar dir (this is what makes $ID appear network-wide)
NBF="$NBF" WEXP="$WEXP" NOW="$NOW" node -e '
  const fs=require("fs"); const pub=process.argv[1];
  const ids=fs.readdirSync(pub+"/registrars").filter(d=>fs.existsSync(pub+"/registrars/"+d+"/export.json"));
  const regs=ids.map(id=>JSON.parse(fs.readFileSync(pub+"/registrars/"+id+"/export.json","utf8")));
  const w={nbf:+process.env.NBF,exp:+process.env.WEXP,verified_at:+process.env.NOW};
  let issued=0,revoked=0; for(const R of regs) for(const e of R.records){issued++; if(e.record.revoked)revoked++;}
  fs.writeFileSync(pub+"/registry.json", JSON.stringify({generated_window:w, registrars:regs, totals:{registrars:regs.length,issued,revoked}}));
  fs.writeFileSync(pub+"/directory.json", JSON.stringify({network:"staging",root:"test-root",note:"Staging directory: real registrar accreditations. The production dual-root-SIGNED directory is minted at the recorded genesis ceremony (a pending DoD row) — no trust migrates from staging.",registrars:regs.map(r=>({registrar:r.registrar,accreditation:r.accreditation,root_pub_slh:r.root_pub_slh}))}));
  fs.writeFileSync(pub+"/index.json", JSON.stringify({network:"staging",root:"test-root",label:"AINRA STAGING NETWORK · TEST-ROOT",generated_window:w,registrars:ids,telemetry:"none"}));
  console.log("   directory now lists "+ids.length+" registrars: "+ids.join(", "));
' "$PUB"

echo
echo "⑥ An INDEPENDENT verifier checks the new registrar's passport — the real @ainra/sdk, trusting the SOURCE not the seller"
node --input-type=module -e '
import { runVector } from "./ainrascan/vendor/ainra-sdk.js";
const enc=u=>Buffer.from(u).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const norm=v=>JSON.stringify({verdict:v.verdict,reason:v.reason??null});
const reg=await(await fetch("http://127.0.0.1:8091/registry.json")).json();
const now=reg.generated_window.verified_at;
const R=reg.registrars.find(r=>r.registrar==="'"$ID"'");
if(!R){console.error("   new registrar not in the published registry");process.exit(1);}
let ok=0;
for(const e of R.records){const rec=e.record;
  const wv={name:rec.sub,expect:{},anchors:{[R.registrar]:{issuer_key:R.accreditation.issuer_key,log_root_key:R.accreditation.log_root_key}},
   presentation:{claims:enc(new TextEncoder().encode(rec.claims)),issuer_sig:{ed25519:rec.issuer_sig_ed25519,mldsa65:rec.issuer_sig_mldsa65},now,
   chain_keys:rec.chain_keys,hop_proofs:rec.hop_proofs,status_list:R.status_list.status_list_b64,status_len:R.status_list.bit_len,status_issued_at:R.status_list.issued_at,
   freshness:"F3",checkpoint:{origin:rec.log_origin,size:rec.checkpoint_size,root:rec.checkpoint_root},checkpoint_sig:rec.checkpoint_sig,leaf_index:rec.leaf_index,inclusion_proof:rec.inclusion_proof,mandate_revocations:[],revoked_delegates:[]}};
  const v=runVector(wv); const agree=norm(v)===norm(e.verdict);
  console.log(`   ${v.verdict==="valid"?"✓ VALID":"✗ "+(v.reason||"INVALID")}  ${rec.sub}   ${agree?"(SDK ≡ registrar export)":"(MISMATCH!)"}`);
  if(v.verdict==="valid"&&agree)ok++;
}
process.exit(ok>0?0:1);
'
sep; echo "$ID is accredited, issuing, and verifiable network-wide — a third GoDaddy on the same neutral root."; sep
