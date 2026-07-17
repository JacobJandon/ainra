#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make verifier-operator-drill (M11) — prove the OPERATOR loop for real external verifiers, end to end, exactly as the
# maintainer would run it: mint a per-party challenge → the party verifies with the published SDK only → collect +
# check their attestation → a durable evidence/verifier/<party>.json → `make genesis-status` counts it. Three
# CLEARLY-LABELLED DRY-RUN parties (they do NOT count as real external verifiers — real ones are real strangers on real
# machines; see GENESIS-CHECKLIST §3). Also proves a hand-authored attestation is rejected and writes no evidence.
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${AINRA_OPERATOR_PORT:-4991}"
NOW=$((1775865600 + 10 * 24 * 3600))

echo "== build SDK + bins =="
(cd packages/sdk-ts && { [ -d node_modules ] || npm install --prefer-offline --no-audit --no-fund --silent; } && npm run build >/dev/null 2>&1)
cargo build --release -q -p ainra-services --bin registrar-box -p ainra-ceremony --bin accredit
(cd kits/verifier && npm install --prefer-offline --no-audit --no-fund --silent)

WORK="$(mktemp -d)"; RB=0
trap 'kill "$RB" 2>/dev/null || true; rm -rf "$WORK"' EXIT
OPS="$WORK/ops"; EV="$WORK/evidence"; mkdir -p "$OPS" "$EV"

echo "== operator: stand up a registrar (the root the parties verify) =="
if curl -sf "http://127.0.0.1:$PORT/accreditation" >/dev/null 2>&1; then echo "FAIL: port $PORT busy"; exit 1; fi
./target/release/registrar-box "127.0.0.1:$PORT" registrar-07 "$WORK/rb" >/dev/null 2>"$WORK/rb.err" &
RB=$!
for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$PORT/accreditation" >/dev/null 2>&1 && break; sleep 0.2; done
kill -0 "$RB" 2>/dev/null || { echo "FAIL: registrar-box died — $(tail -1 "$WORK/rb.err")"; exit 1; }

PARTIES="dryrun-alice dryrun-bob dryrun-carol"   # ← clearly labelled DRY-RUN; NOT counted as real external verifiers
for P in $PARTIES; do
  echo "== operator: mint a challenge for '$P' =="
  CDIR="$OPS/$P/challenge"; mkdir -p "$CDIR"
  curl -sf "http://127.0.0.1:$PORT/accreditation" > "$WORK/acc.json"
  ./target/release/accredit "$CDIR" "$WORK/acc.json" >/dev/null
  N="$(node -e 'console.log(require("crypto").randomBytes(16).toString("hex"))')"
  node kits/verifier/mint-challenge.mjs --registrar "http://127.0.0.1:$PORT" --now "$NOW" --count 8 \
    --party "$P" --ops-dir "$OPS" --nonce "$N" >/dev/null
  # the answer key must have landed under the (gitignored) ops dir and NOT be in the challenge sent to the party
  [ -f "$OPS/$P/answer-key.json" ] || { echo "FAIL: no answer key for $P"; exit 1; }
  [ -f "$CDIR/answer-key.json" ] && { echo "FAIL: answer key leaked into the challenge sent to $P"; exit 1; }

  echo "== party '$P' (separate machine, published SDK only): verify + attest =="
  node kits/verifier/verify-kit.mjs --challenge "$N" --challenge-dir "$CDIR" --out "$WORK/att-$P.json" >/dev/null

  echo "== operator: check '$P' attestation → durable evidence =="
  node kits/verifier/check-attestation.mjs --attestation "$WORK/att-$P.json" --challenge "$N" \
    --secret "$OPS/$P/answer-key.json" --party "$P" --evidence-out "$EV/verifier/$P.json" >/dev/null
  [ -f "$EV/verifier/$P.json" ] || { echo "FAIL: no evidence written for $P"; exit 1; }
  # the evidence file must NOT contain the secret answer key
  grep -q '"expected"' "$EV/verifier/$P.json" && { echo "FAIL: evidence for $P contains the answer key"; exit 1; }
  echo "  ✓ $P onboarded → evidence/verifier/$P.json (no secret inside)"
done

echo "== the board reads the three durable evidence files =="
BOARD="$(node tools/genesis-board/board.mjs --evidence "$EV" --html "$WORK/board.html" | sed 's/\x1b\[[0-9;]*m//g')"
echo "$BOARD" | grep -E "external verifiers|criteria proven" | sed 's/^/  /'
echo "$BOARD" | grep -q "3/3 distinct valid" && echo "  ✓ board counts 3/3 distinct external verifiers → row ✅" || { echo "FAIL: board did not count 3/3"; exit 1; }

echo "== a hand-authored attestation (never ran the SDK) is REJECTED and writes NO evidence =="
N1="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).nonce)' "$OPS/dryrun-alice/answer-key.json")"
FORGE="$WORK/forge.json"
CANON="kits/verifier/sample-artifacts" NONCE="$N1" FORGE="$FORGE" node -e '
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
if node kits/verifier/check-attestation.mjs --attestation "$FORGE" --challenge "$N1" --secret "$OPS/dryrun-alice/answer-key.json" --party dryrun-mallory --evidence-out "$EV/verifier/dryrun-mallory.json" >/dev/null 2>&1; then
  echo "FAIL: forged attestation accepted"; exit 1
fi
[ -f "$EV/verifier/dryrun-mallory.json" ] && { echo "FAIL: forged attestation wrote evidence"; exit 1; }
echo "  ✓ forged attestation rejected — no evidence written"

echo
echo "verifier-operator-drill OK — the operator loop works end to end on 3 dry-run parties (board reads 3 distinct"
echo "evidence files), and a forgery is refused. The REAL three come from real strangers via outreach/EXTERNAL-VERIFIER-CALL.md."
