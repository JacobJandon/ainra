#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# `make conformance` (M24 Task 2) — prove the conformance runner BOTH ways, offline:
#   1. the three in-repo verdict implementations (Rust core, TS SDK, Python) each pass the FULL public corpus CLEAN,
#      all reporting the SAME corpus hash;
#   2. a deliberately broken implementation FAILS with named divergences (a conformance tool that cannot fail is
#      theatre); and
#   3. the self-attestation roundtrip works: an implementer signs their own report with their OWN ephemeral key and
#      a re-checker accepts it only after the runner re-runs clean.
# No network. See docs/conformance/PROGRAMME.md and tools/conformance/CONTRACT.md.
set -uo pipefail
cd "$(dirname "$0")/../.."

RUN="node tools/conformance/run.mjs"
ATTEST="node tools/conformance/attest.mjs"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAIL=0

echo "── AINRA conformance ────────────────────────────────────────────────"
echo "The root publishes the corpus + runner and certifies no one. This target"
echo "proves the runner detects conformance AND nonconformance."
echo ""

# 1. The three genuine corpus-verdict implementations MUST pass clean (exit 0).
clean() { # clean <label> <impl-command...>
  local label="$1"; shift
  printf '  %-26s ' "$label"
  if $RUN --impl "$*" --name "$label" --version 0.3.0 --out "$TMP/$label.json" >"$TMP/$label.log" 2>&1; then
    grep -E '→ PASS' "$TMP/$label.log" | sed 's/^/    /'
  else
    echo "FAILED (expected clean pass):"; sed 's/^/      /' "$TMP/$label.log"; FAIL=1
  fi
}
echo "clean adapters (must PASS, full corpus, 0 divergences):"
clean "ainra-core"    bash tools/conformance/adapters/core.sh
clean "ainra-sdk-ts"  node tools/conformance/adapters/sdk.mjs
clean "ainra-sdk-py"  python3 tools/conformance/adapters/py.py
echo ""

# 2. The broken implementation MUST fail (nonzero) with named divergences — proof the runner catches nonconformance.
echo "broken adapter (must FAIL with named divergences):"
if $RUN --impl "node tools/conformance/adapters/broken.mjs" --name broken-skips-validity-window --version 0.0.0 \
      --out "$TMP/broken.json" >"$TMP/broken.log" 2>&1; then
  echo "    ✗ ERROR — the broken adapter PASSED. The runner failed to detect nonconformance."; FAIL=1
else
  ndiv="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).divergences.length)' "$TMP/broken.json")"
  echo "    ✓ broken adapter correctly FAILED — $ndiv named divergence(s), e.g.:"
  grep -E 'DIVERGENCE' "$TMP/broken.log" | head -2 | sed 's/^/      /'
fi
echo ""

# 3. Self-attestation roundtrip with an ephemeral IMPLEMENTER key (never committed): sign own report, re-check it.
echo "self-attestation (implementer signs own results; a re-checker re-runs to verify):"
if command -v ssh-keygen >/dev/null 2>&1; then
  ssh-keygen -t ed25519 -N "" -C "impl@example.org" -f "$TMP/impl-key" >/dev/null 2>&1
  $ATTEST generate --report "$TMP/ainra-sdk-ts.json" --key "$TMP/impl-key" --identity impl@example.org \
        --out "$TMP/attestation.json" >"$TMP/attest-gen.log" 2>&1
  if $ATTEST verify --attestation "$TMP/attestation.json" --allowed-signers "$TMP/attestation.json.allowed_signers" \
        --identity impl@example.org --impl "node tools/conformance/adapters/sdk.mjs" \
        --report "$TMP/ainra-sdk-ts.json" >"$TMP/attest-verify.log" 2>&1; then
    grep -E 'ACCEPTED' "$TMP/attest-verify.log" | sed 's/^ */    /'
  else
    echo "    ✗ attestation verify failed:"; sed 's/^/      /' "$TMP/attest-verify.log"; FAIL=1
  fi
else
  echo "    (skipped — ssh-keygen not on PATH; install OpenSSH to exercise self-attestation)"
fi

echo "─────────────────────────────────────────────────────────────────────"
if [ "$FAIL" = "0" ]; then
  echo "  ✓ conformance OK — runner passes the 3 real impls clean, catches the broken one, attestation round-trips."
  exit 0
else
  echo "  ✗ conformance FAILED — see above."
  exit 1
fi
