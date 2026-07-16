#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make verifier-kit-smoke (M9) — prove the External Verifier Kit works end to end AND is EXECUTION-BOUND: a stranger,
# using ONLY the published @ainra/sdk, verifies a genuine passport root-dark, rejects a revoked + a forged one, AND
# correctly verifies a FRESH challenge corpus (K bundles whose revocation state we minted secretly). We then collect
# their signed attestation and confirm it WITHOUT trusting their word — the decisive gate being that their verdicts on
# the fresh bundles match our private answer key (a party who never verified must guess all K). Exits nonzero on any
# failure. Regression for the M9 review: a hand-authored / conformance-only / wrong-answer attestation MUST be rejected.
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${AINRA_VERIFIER_PORT:-4951}"
NOW=$((1775865600 + 10 * 24 * 3600))

echo "== build the published SDK (@ainra/sdk) + the registrar/accredit bins =="
(cd packages/sdk-ts && { [ -d node_modules ] || npm install --prefer-offline --no-audit --no-fund --silent; } && npm run build >/dev/null 2>&1)
cargo build --release -q -p ainra-services --bin registrar-box -p ainra-ceremony --bin accredit

echo "== install the verifier kit (SDK-only dependency) =="
(cd kits/verifier && npm install --prefer-offline --no-audit --no-fund --silent)

WORK="$(mktemp -d)"
RB=0
trap 'kill "$RB" 2>/dev/null || true; rm -rf "$WORK"' EXIT
OUT="$WORK/verifier-attestation.json"
CHALDIR="$WORK/challenge"          # PUBLIC — handed to the verifier
SECRET="$WORK/challenge-secret.json"  # PRIVATE — the maintainer's answer key
mkdir -p "$CHALDIR"

echo "== maintainer: stand up a real registrar + accredit it (root dark) =="
if curl -sf "http://127.0.0.1:$PORT/accreditation" >/dev/null 2>&1; then
  echo "FAIL: 127.0.0.1:$PORT already serving — kill the leftover daemon"; exit 1
fi
./target/release/registrar-box "127.0.0.1:$PORT" registrar-07 "$WORK/rb" >/dev/null 2>"$WORK/rb.err" &
RB=$!
for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$PORT/accreditation" >/dev/null 2>&1 && break; sleep 0.2; done
kill -0 "$RB" 2>/dev/null || { echo "FAIL: registrar-box died — $(tail -1 "$WORK/rb.err" 2>/dev/null)"; exit 1; }
curl -sf "http://127.0.0.1:$PORT/accreditation" > "$WORK/acc.json"
./target/release/accredit "$CHALDIR" "$WORK/acc.json" >/dev/null   # writes challenge/directory.json + challenge/roots.json

echo "== maintainer: mint a FRESH challenge corpus (secret coin-flip revocations) + private answer key =="
CHALLENGE="$(node -e 'console.log(require("crypto").randomBytes(16).toString("hex"))')"
node kits/verifier/mint-challenge.mjs --registrar "http://127.0.0.1:$PORT" --now "$NOW" --count 8 \
  --out "$CHALDIR" --secret "$SECRET" --nonce "$CHALLENGE"

echo "== verifier (stranger): verify sample corpus root-dark + the fresh challenge, emit a signed attestation =="
node kits/verifier/verify-kit.mjs --out "$OUT" --challenge "$CHALLENGE" --challenge-dir "$CHALDIR"

echo "== collect: confirm the attestation without trusting the verifier — decisive gate is the answer key =="
node kits/verifier/check-attestation.mjs --attestation "$OUT" --challenge "$CHALLENGE" --secret "$SECRET"

echo "== ADVERSARIAL: forged / conformance-only / wrong-answer attestations must be REJECTED (M9 review regressions) =="
# (a) THE EXACT COMMITTED-FORGERY the review found: hand-author a conformance-only body from PUBLIC data + the issued
#     challenge + a fresh key, never running the SDK. Before the fix this printed "ran the real SDK … VALID"; now the
#     execution-binding gate (step 4) rejects it because execution_bound=false.
FORGED="$WORK/forged-conformance.json"
CANON="kits/verifier/sample-artifacts" CHALLENGE="$CHALLENGE" FORGED="$FORGED" node -e '
  const {readFileSync,writeFileSync}=require("fs"); const {createHash,generateKeyPairSync,sign}=require("crypto");
  const canon=(v)=>v===null||typeof v!=="object"?JSON.stringify(v):Array.isArray(v)?"["+v.map(canon).join(",")+"]":"{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+canon(v[k])).join(",")+"}";
  const sha=(f)=>createHash("sha256").update(readFileSync(process.env.CANON+"/"+f,"utf8")).digest("hex");
  const {publicKey,privateKey}=generateKeyPairSync("ed25519");
  const body={kind:"ainra/verifier-attestation/v1",challenge:process.env.CHALLENGE,execution_bound:false,
    verifier_pubkey_spki_b64:publicKey.export({type:"spki",format:"der"}).toString("base64"),sdk:"i-never-imported-it",now:1,
    artifacts_sha256:{"directory.json":sha("directory.json"),"roots.json":sha("roots.json"),"bundle-valid.json":sha("bundle-valid.json"),"bundle-revoked.json":sha("bundle-revoked.json")},
    verdicts:{valid:"valid",revoked:"invalid:revoked",forged:"invalid:stale_status"},
    challenge_now:null,challenge_corpus_sha256:null,challenge_verdicts:null};
  writeFileSync(process.env.FORGED, JSON.stringify({body, sig_ed25519_b64: sign(null,Buffer.from(canon(body)),privateKey).toString("base64")}));
'
if node kits/verifier/check-attestation.mjs --attestation "$FORGED" --challenge "$CHALLENGE" --secret "$SECRET" >/dev/null 2>&1; then
  echo "FAIL: a hand-authored conformance-only attestation was accepted — execution not bound"; exit 1
else echo "  ✓ hand-authored conformance-only forgery rejected (never verified the fresh challenge)"; fi

# (b) a WRONG-ANSWER execution-bound attestation: take the genuine one, flip every challenge verdict, re-sign with a
#     fresh key (a guesser who never verified). Must be rejected by the answer-key gate.
WRONG="$WORK/wrong-answers.json"
SECRET="$SECRET" OUT="$OUT" WRONG="$WRONG" node -e '
  const {readFileSync,writeFileSync}=require("fs"); const {generateKeyPairSync,sign}=require("crypto");
  const canon=(v)=>v===null||typeof v!=="object"?JSON.stringify(v):Array.isArray(v)?"["+v.map(canon).join(",")+"]":"{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+canon(v[k])).join(",")+"}";
  const att=JSON.parse(readFileSync(process.env.OUT,"utf8")); const body={...att.body};
  body.challenge_verdicts=body.challenge_verdicts.map(v=>v==="valid"?"invalid:revoked":"valid"); // flip every answer
  const {publicKey,privateKey}=generateKeyPairSync("ed25519");
  body.verifier_pubkey_spki_b64=publicKey.export({type:"spki",format:"der"}).toString("base64");
  writeFileSync(process.env.WRONG, JSON.stringify({body, sig_ed25519_b64: sign(null,Buffer.from(canon(body)),privateKey).toString("base64")}));
'
if node kits/verifier/check-attestation.mjs --attestation "$WRONG" --challenge "$CHALLENGE" --secret "$SECRET" >/dev/null 2>&1; then
  echo "FAIL: an execution-bound attestation with wrong challenge answers was accepted — answer key not enforced"; exit 1
else echo "  ✓ wrong-answer forgery rejected (verdicts did not match the private answer key)"; fi

# (c) the genuine attestation replayed under a DIFFERENT challenge → REJECTED (non-replayable).
if node kits/verifier/check-attestation.mjs --attestation "$OUT" --challenge "different-challenge" --secret "$SECRET" >/dev/null 2>&1; then
  echo "FAIL: attestation accepted under the wrong challenge — replayable"; exit 1
else echo "  ✓ wrong-challenge replay rejected"; fi

# (d) missing the answer key entirely → the collector must refuse to certify (fail closed, not fail open).
if node kits/verifier/check-attestation.mjs --attestation "$OUT" --challenge "$CHALLENGE" >/dev/null 2>&1; then
  echo "FAIL: attestation certified without the answer key — execution unverifiable but accepted"; exit 1
else echo "  ✓ refuses to certify without the private answer key"; fi

echo
echo "verifier-kit-smoke OK — an EXECUTION-BOUND attestation (correct verdicts on a fresh, unpublished challenge) is"
echo "valid; hand-authored, wrong-answer, replayed, and answer-key-less attestations all fail closed."
