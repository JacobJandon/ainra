#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make verify-as-external CHALLENGE=<dir> [OUT=<file>] (M10) — the ONE command a stranger runs to become external
# verifier #N. Point it at the challenge corpus the maintainer sent you; it verifies the sample corpus root-dark AND
# your fresh challenge bundles with only @ainra/sdk, and writes a signed attestation you send back. No maintainer
# help, no data leaves your machine, ≤10 min. See kits/verifier/QUICKSTART.md.
set -euo pipefail
cd "$(dirname "$0")/.."
CHALLENGE="${CHALLENGE:-}"
OUT="${OUT:-verifier-attestation.json}"
if [ -z "$CHALLENGE" ] || [ ! -f "$CHALLENGE/challenge.json" ]; then
  echo "usage: make verify-as-external CHALLENGE=<dir the maintainer sent you> [OUT=<file>]"
  echo "  (the dir must contain challenge.json, directory.json, roots.json and the bundle-*.json files)"
  echo "  To TRY the whole loop end-to-end on your own machine instead, run:  make verifier-kit-smoke"
  exit 2
fi
NONCE="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).nonce)' "$CHALLENGE/challenge.json")"

echo "== build the published SDK (@ainra/sdk) + install the kit (SDK-only) =="
(cd packages/sdk-ts && { [ -d node_modules ] || npm install --prefer-offline --no-audit --no-fund --silent; } && npm run build >/dev/null 2>&1)
(cd kits/verifier && npm install --prefer-offline --no-audit --no-fund --silent)

echo "== verify sample corpus root-dark + your fresh challenge (nonce $NONCE) =="
node kits/verifier/verify-kit.mjs --challenge "$NONCE" --challenge-dir "$CHALLENGE" --out "$OUT"

echo
echo "✓ wrote $OUT — send THIS FILE back to the maintainer (nothing else left your machine)."
echo "  They confirm it without trusting you:  check-attestation.mjs --attestation $OUT --challenge $NONCE --secret <their answer key>"
