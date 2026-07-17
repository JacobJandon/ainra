#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make verifier-triple-drill (M10) — prove the §29 "≥3 external verifiers" flow works at smoke scale, exactly as the
# real event would: the maintainer mints THREE distinct challenges; three SEPARATE verifier environments (fresh temp
# dirs, fresh keys) each verify their own fresh corpus and emit a signed attestation; the collector accepts all three
# under DISTINCT keys and rejects a hand-authored one. This is a DRY RUN — these three are simulated on one host and do
# NOT count as real external verifiers (real ones are three separately-vetted people on three machines; see
# GENESIS-CHECKLIST §3). It proves the machinery, unfakeably.
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${AINRA_TRIPLE_PORT:-4971}"
NOW=$((1775865600 + 10 * 24 * 3600))

echo "== build SDK + registrar/accredit bins =="
(cd packages/sdk-ts && { [ -d node_modules ] || npm install --prefer-offline --no-audit --no-fund --silent; } && npm run build >/dev/null 2>&1)
cargo build --release -q -p ainra-services --bin registrar-box -p ainra-ceremony --bin accredit
(cd kits/verifier && npm install --prefer-offline --no-audit --no-fund --silent)

WORK="$(mktemp -d)"; RB=0
trap 'kill "$RB" 2>/dev/null || true; rm -rf "$WORK"' EXIT

echo "== maintainer: one registrar, accredited root-dark =="
if curl -sf "http://127.0.0.1:$PORT/accreditation" >/dev/null 2>&1; then echo "FAIL: port $PORT busy"; exit 1; fi
./target/release/registrar-box "127.0.0.1:$PORT" registrar-07 "$WORK/rb" >/dev/null 2>"$WORK/rb.err" &
RB=$!
for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$PORT/accreditation" >/dev/null 2>&1 && break; sleep 0.2; done
kill -0 "$RB" 2>/dev/null || { echo "FAIL: registrar-box died — $(tail -1 "$WORK/rb.err")"; exit 1; }

declare -a ATT KEYS
for i in 1 2 3; do
  echo "== verifier #$i: fresh challenge + fresh environment =="
  CDIR="$WORK/challenge-$i"; SECRET="$WORK/secret-$i.json"; OUT="$WORK/att-$i.json"
  mkdir -p "$CDIR"
  curl -sf "http://127.0.0.1:$PORT/accreditation" > "$WORK/acc.json"
  ./target/release/accredit "$CDIR" "$WORK/acc.json" >/dev/null
  NONCE="$(node -e 'console.log(require("crypto").randomBytes(16).toString("hex"))')"
  node kits/verifier/mint-challenge.mjs --registrar "http://127.0.0.1:$PORT" --now "$NOW" --count 8 \
    --out "$CDIR" --secret "$SECRET" --nonce "$NONCE" >/dev/null
  # a SEPARATE verifier environment: its own key is generated inside verify-kit per run
  node kits/verifier/verify-kit.mjs --challenge "$NONCE" --challenge-dir "$CDIR" --out "$OUT" >/dev/null
  node kits/verifier/check-attestation.mjs --attestation "$OUT" --challenge "$NONCE" --secret "$SECRET" >/dev/null \
    && echo "  ✓ verifier #$i attestation ACCEPTED (execution-bound)" || { echo "FAIL: verifier #$i rejected"; exit 1; }
  ATT+=("$OUT")
  KEYS+=("$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).body.verifier_pubkey_spki_b64)' "$OUT")")
done

echo "== the three attestations must be under DISTINCT verifier keys =="
UNIQ=$(printf '%s\n' "${KEYS[@]}" | sort -u | wc -l)
[ "$UNIQ" -eq 3 ] && echo "  ✓ 3 distinct verifier keys" || { echo "FAIL: only $UNIQ distinct keys — not 3 independent verifiers"; exit 1; }

echo "== a hand-authored attestation (never ran the SDK) must be REJECTED under verifier #1's challenge =="
NONCE1="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).nonce)' "$WORK/secret-1.json")"
FORGE="$WORK/forge.json"
CANON="kits/verifier/sample-artifacts" NONCE="$NONCE1" FORGE="$FORGE" node -e '
  const {readFileSync,writeFileSync}=require("fs"); const {createHash,generateKeyPairSync,sign}=require("crypto");
  const canon=(v)=>v===null||typeof v!=="object"?JSON.stringify(v):Array.isArray(v)?"["+v.map(canon).join(",")+"]":"{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+canon(v[k])).join(",")+"}";
  const sha=(f)=>createHash("sha256").update(readFileSync(process.env.CANON+"/"+f,"utf8")).digest("hex");
  const {publicKey,privateKey}=generateKeyPairSync("ed25519");
  const body={kind:"ainra/verifier-attestation/v1",challenge:process.env.NONCE,execution_bound:false,
    verifier_pubkey_spki_b64:publicKey.export({type:"spki",format:"der"}).toString("base64"),sdk:"forged",now:1,
    artifacts_sha256:{"directory.json":sha("directory.json"),"roots.json":sha("roots.json"),"bundle-valid.json":sha("bundle-valid.json"),"bundle-revoked.json":sha("bundle-revoked.json")},
    verdicts:{valid:"valid",revoked:"invalid:revoked",forged:"invalid:stale_status"},challenge_now:null,challenge_corpus_sha256:null,challenge_verdicts:null};
  writeFileSync(process.env.FORGE, JSON.stringify({body, sig_ed25519_b64: sign(null,Buffer.from(canon(body)),privateKey).toString("base64")}));
'
if node kits/verifier/check-attestation.mjs --attestation "$FORGE" --challenge "$NONCE1" --secret "$WORK/secret-1.json" >/dev/null 2>&1; then
  echo "FAIL: hand-authored attestation accepted"; exit 1
else echo "  ✓ hand-authored forgery REJECTED"; fi

echo
echo "verifier-triple-drill OK — 3 distinct execution-bound attestations accepted, forgery rejected."
echo "The REAL event: 3 separately-vetted people run 'make verify-as-external' on 3 machines with 3 challenges you mint."
