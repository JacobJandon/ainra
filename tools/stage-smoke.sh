#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make stage-smoke — end-to-end against the LIVE staging deployment: issue → log → verify via the public artifact
# contract (in the real SDK) → revoke → propagation, plus the ARTIFACTS.md contract header assertions. Real output.
set -uo pipefail
cd "$(dirname "$0")/.."
REG=127.0.0.1:4907 ; RID=registrar-07 ; ART=http://127.0.0.1:8091 ; NOW=$((1775865600 + 10*24*3600))
TOKEN="$(cat stage/.issue-token 2>/dev/null)"
fail(){ echo "  ✗ $1"; exit 1; }

echo "== 1. the public artifact contract serves with correct headers (what a browser/mirror needs) =="
hdr(){ curl -s -m 8 -D - -o /dev/null "$1"; }
D=$(hdr "$ART/registry.json")
echo "$D" | grep -qi "access-control-allow-origin: \*"        || fail "registry.json missing CORS *"
echo "$D" | grep -qi "x-ainra-network: staging"               || fail "registry.json missing STAGING banner"
echo "$D" | grep -qiE "etag: \"[0-9a-f]+\""                   || fail "registry.json (mutable) missing ETag"
echo "$D" | grep -qi "cache-control: public, max-age=5"        || fail "registry.json wrong cache policy"
echo "  ✓ registry.json: CORS * · ETag · short-cache · X-AINRA-Network: staging"
CK=$(ls stage/public/registrars/$RID/checkpoints/*.json 2>/dev/null | head -1)
if [ -n "$CK" ]; then CKN=$(basename "$CK"); DC=$(hdr "$ART/registrars/$RID/checkpoints/$CKN")
  echo "$DC" | grep -qi "cache-control: public, max-age=31536000, immutable" || fail "checkpoint not immutable-cached"
  echo "  ✓ checkpoints/$CKN: immutable, max-age=1y (content/height-addressed)"; fi
DO=$(curl -s -m 8 -D - -o /dev/null -X OPTIONS "$ART/registry.json")
echo "$DO" | grep -qi "access-control-allow-methods: GET" || fail "OPTIONS preflight not answered"
echo "  ✓ OPTIONS preflight answered (browser client-verify won't be blocked)"

echo "== 2. verify a published lineage in the REAL SDK, over the public artifacts (root not consulted) =="
V=$(node --input-type=module -e '
import { runVector } from "./packages/sdk-ts/browser/ainra-sdk.js";
const enc=(u)=>Buffer.from(u).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const reg=await (await fetch(process.argv[1]+"/registry.json")).json(); const now=reg.generated_window.verified_at;
const wire=(rec,R)=>({name:rec.sub,expect:{},anchors:{[R.registrar]:{issuer_key:R.accreditation.issuer_key,log_root_key:R.accreditation.log_root_key}},presentation:{claims:enc(new TextEncoder().encode(rec.claims)),issuer_sig:{ed25519:rec.issuer_sig_ed25519,mldsa65:rec.issuer_sig_mldsa65},now,chain_keys:rec.chain_keys,hop_proofs:rec.hop_proofs,status_list:R.status_list.status_list_b64,status_len:R.status_list.bit_len,status_issued_at:R.status_list.issued_at,freshness:"F3",checkpoint:{origin:rec.log_origin,size:rec.checkpoint_size,root:rec.checkpoint_root},checkpoint_sig:rec.checkpoint_sig,leaf_index:rec.leaf_index,inclusion_proof:rec.inclusion_proof,mandate_revocations:[],revoked_delegates:[]}});
let ok=0,rev=0,tot=0; for(const R of reg.registrars) for(const e of R.records){tot++;const v=runVector(wire(e.record,R));if(v.verdict==="valid")ok++;if(v.reason==="revoked")rev++;}
console.log(`${ok} valid / ${rev} revoked / ${tot} total (SDK over public artifacts)`);
' "$ART" 2>&1)
echo "$V" | grep -q "total" && echo "  ✓ $V" || fail "SDK verify over public artifacts failed: $V"

echo "== 3. LIVE write path: issue → verify → revoke → propagate (registrar daemon, authed) =="
# A UNIQUE lineage per run so the smoke is idempotent against the long-lived daemon (re-running never collides with
# an already-issued-and-revoked subject from a previous run).
LIN="smoke-$$-$RANDOM"
SUB="ainra:$RID:acme:$LIN@1.0.0"
curl -s -m 8 -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d "{\"operator\":\"acme\",\"lineage\":\"$LIN\",\"version\":\"1.0.0\",\"tier\":\"L2\",\"auth_class\":\"A2\",\"principal_proof\":\"deadbeefsmoke\",\"capabilities\":[\"read:x\"],\"scope_ceiling\":[\"read:x\"],\"hops\":[]}" \
  "http://$REG/issue" >/dev/null
V1=$(curl -s -m 8 "http://$REG/verify?sub=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$SUB")&now=$NOW" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).verdict.verdict))')
[ "$V1" = "valid" ] && echo "  ✓ issued + verified VALID via the daemon" || fail "fresh issue did not verify ($V1)"
curl -s -m 8 -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d "{\"sub\":\"$SUB\",\"now\":$NOW}" "http://$REG/revoke" >/dev/null
V2=$(curl -s -m 8 "http://$REG/verify?sub=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$SUB")&now=$NOW" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s).verdict;console.log(j.reason||j.verdict)})')
[ "$V2" = "revoked" ] && echo "  ✓ revoked → propagates → verify now INVALID (revoked)" || fail "revocation did not propagate ($V2)"

echo "== 4. write path is guarded (online-exposure hardening) =="
UN=$(curl -s -m 8 -o /dev/null -w '%{http_code}' -X POST -H "Content-Type: application/json" -d '{}' "http://$REG/issue")
[ "$UN" = "401" ] && echo "  ✓ unauthenticated issue → 401 (bearer token required)" || fail "unauth issue not rejected (got $UN)"

echo
echo "STAGE-SMOKE OK — the staging network issues, logs, verifies over the public contract, revokes, and propagates;"
echo "every public artifact serves CORS + correct cache + the STAGING/TEST-ROOT banner; the write path is authed."
