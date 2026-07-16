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

echo "== run the kit: verify root-dark + reject revoked + reject forged =="
node kits/verifier/verify-kit.mjs --out "$OUT"

echo "== collect: verify the attestation without trusting the verifier =="
node kits/verifier/check-attestation.mjs --attestation "$OUT"

echo
echo "verifier-kit-smoke OK — a stranger can produce a valid, self-verifying attestation with only @ainra/sdk."
