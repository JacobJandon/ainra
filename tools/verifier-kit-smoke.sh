#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make verifier-kit-smoke (M9) — prove the External Verifier Kit works end to end: a stranger, using ONLY the
# published @ainra/sdk, verifies a genuine passport root-dark, rejects a revoked one and a forged one, and emits a
# signed attestation that we then collect and confirm WITHOUT trusting their word. Exits nonzero if any step fails.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== build the published SDK (@ainra/sdk) =="
(cd packages/sdk-ts && { [ -d node_modules ] || npm install --prefer-offline --no-audit --no-fund --silent; } && npm run build >/dev/null 2>&1)

echo "== install the verifier kit (SDK-only dependency) =="
(cd kits/verifier && npm install --prefer-offline --no-audit --no-fund --silent)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
OUT="$WORK/verifier-attestation.json"
# The maintainer issues a fresh single-use CHALLENGE per verifier (here, random). The attestation is bound to it.
CHALLENGE="$(node -e 'console.log(require("crypto").randomBytes(16).toString("hex"))')"

echo "== run the kit: verify root-dark + reject revoked + reject forged (challenge $CHALLENGE) =="
node kits/verifier/verify-kit.mjs --out "$OUT" --challenge "$CHALLENGE"

echo "== collect: verify the attestation without trusting the verifier =="
node kits/verifier/check-attestation.mjs --attestation "$OUT" --challenge "$CHALLENGE"

echo "== ADVERSARIAL: forged attestations must be REJECTED (M9 review regressions) =="
# (a) empty corpus + correct challenge, signed with a fresh key (attacker never ran the SDK) → must be REJECTED.
FORGED="$WORK/forged.json"
CHALLENGE="$CHALLENGE" FORGED="$FORGED" node -e '
  const {generateKeyPairSync, sign} = require("crypto"); const {writeFileSync} = require("fs");
  const canon = (v)=>v===null||typeof v!=="object"?JSON.stringify(v):Array.isArray(v)?"["+v.map(canon).join(",")+"]":"{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+canon(v[k])).join(",")+"}";
  const {publicKey,privateKey}=generateKeyPairSync("ed25519");
  const body={kind:"ainra/verifier-attestation/v1",challenge:process.env.CHALLENGE,verifier_pubkey_spki_b64:publicKey.export({type:"spki",format:"der"}).toString("base64"),sdk:"forged",now:1776729600,artifacts_sha256:{},verdicts:{valid:"valid",revoked:"invalid:revoked",forged:"invalid:stale_status"}};
  writeFileSync(process.env.FORGED, JSON.stringify({body, sig_ed25519_b64: sign(null, Buffer.from(canon(body)), privateKey).toString("base64")}));
'
if node kits/verifier/check-attestation.mjs --attestation "$FORGED" --challenge "$CHALLENGE" >/dev/null 2>&1; then
  echo "FAIL: an attestation with an EMPTY corpus was accepted — fail-open"; exit 1
else echo "  ✓ empty-corpus forgery rejected (never ran the SDK → no valid attestation)"; fi
# (b) the genuine attestation replayed against a DIFFERENT challenge → REJECTED (non-replayable).
if node kits/verifier/check-attestation.mjs --attestation "$OUT" --challenge "different-challenge" >/dev/null 2>&1; then
  echo "FAIL: attestation accepted under the wrong challenge — replayable"; exit 1
else echo "  ✓ wrong-challenge replay rejected"; fi

echo
echo "verifier-kit-smoke OK — a challenge-bound attestation is valid; empty-corpus + replayed forgeries fail closed."
