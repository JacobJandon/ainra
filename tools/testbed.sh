#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# M5 testbed — compose the REAL components end to end and prove the 5-line verify wedge:
#   1. start the live registrar-box daemon (real keys, real log, real status)
#   2. run the ceremony `accredit` over its published /accreditation → dual-root-signed directory + roots
#   3. issue a passport, fetch its /present bundle, verify it with `ainra-verify` (the CI/edge step) → VALID
#   4. REVOKE the passport, re-fetch the bundle, verify again → INVALID (revoked) — the gate fails closed
# Every artifact is real; nothing is asserted by narration. Exits nonzero if any step misbehaves.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${AINRA_TESTBED_PORT:-4903}"
NOW=$((1775865600 + 10*24*3600))     # inside the demo delegate-cert window (2026-04-21)
WORK="$(mktemp -d)"
DATA="$WORK/rb-data"
trap 'kill "${RB_PID:-0}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

echo "== build =="
cargo build --release -p ainra-services --bin registrar-box -p ainra-ceremony --bin accredit || {
  echo "FAIL: cargo build for the testbed daemons failed"; exit 1; }
# a restored CI cache can leave stale fingerprints with the workspace bins pruned: cargo says Finished,
# the file does not exist. Gate on the artifact and self-heal with a targeted clean rebuild.
if [ ! -x ./target/release/registrar-box ] || [ ! -x ./target/release/accredit ]; then
  echo "note: cargo reported fresh but bins are missing (pruned cache) — clean-rebuilding the two packages"
  cargo clean --release -p ainra-services -p ainra-ceremony
  cargo build --release -p ainra-services --bin registrar-box -p ainra-ceremony --bin accredit || {
    echo "FAIL: clean rebuild failed"; exit 1; }
  [ -x ./target/release/registrar-box ] || { echo "FAIL: registrar-box still missing after clean rebuild"; exit 1; }
fi
# subshell: a failed SDK build must never shift the script's cwd (a && cd ../.. chain stranded us in
# packages/sdk-ts, making every later ./target/... path silently wrong — the CI "vanishing binary")
( cd packages/sdk-ts && { [ -d node_modules ] || npm install --prefer-offline --no-audit --no-fund --silent; } \
  && npm run build ) >/dev/null 2>&1 || { echo "FAIL: @ainra/sdk build (needed for the verify step)"; exit 1; }

echo "== 1. start registrar-box on 127.0.0.1:$PORT =="
./target/release/registrar-box "127.0.0.1:$PORT" registrar-07 "$DATA" >"$WORK/rb.out" 2>"$WORK/rb.err" &
RB_PID=$!
# slow shared runners: wait up to 120s and FAIL LOUDLY with full diagnostics if the daemon never binds or died
for i in $(seq 1 240); do
  curl -sf "http://127.0.0.1:$PORT/accreditation" >/dev/null 2>&1 && break
  kill -0 "$RB_PID" 2>/dev/null || break   # daemon died — stop waiting
  sleep 0.5
done
curl -sf "http://127.0.0.1:$PORT/accreditation" >/dev/null 2>&1 || {
  echo "FAIL: registrar-box never came up on :$PORT"
  kill -0 "$RB_PID" 2>/dev/null && echo "  daemon state: still running (pid $RB_PID) — bind/port problem" || echo "  daemon state: EXITED"
  ls -la ./target/release/registrar-box 2>&1 | sed 's/^/  bin: /'
  [ -s "$WORK/rb.err" ] && sed 's/^/  rb.err: /' "$WORK/rb.err" || echo "  rb.err: (empty)"
  [ -s "$WORK/rb.out" ] && tail -5 "$WORK/rb.out" | sed 's/^/  rb.out: /' || echo "  rb.out: (empty)"
  exit 1; }

echo "== 2. accredit its keys into a dual-root-signed directory =="
curl -sf "http://127.0.0.1:$PORT/accreditation" > "$WORK/acc.json"
./target/release/accredit "$WORK" "$WORK/acc.json"

SUB="ainra:registrar-07:acme:invoicing@1.0.0"
echo "== 3. issue $SUB, fetch its presentation bundle, verify =="
curl -sf -X POST "http://127.0.0.1:$PORT/issue" \
  -d '{"operator":"acme","lineage":"invoicing","version":"1.0.0","tier":"L3","auth_class":"A2","principal_proof":"deadbeef7f3a2c1d","capabilities":["read:invoices"],"scope_ceiling":["read:invoices"],"audit":{"reference":"audit-acme-invoicing","expires":1900000000},"hops":[]}' >/dev/null
curl -sf "http://127.0.0.1:$PORT/present?sub=$SUB&now=$NOW" > "$WORK/bundle.json"
echo -n "   verdict: "; node tools/ainra-verify.mjs --directory "$WORK/directory.json" --roots "$WORK/roots.json" --bundle "$WORK/bundle.json" --now "$NOW"

echo "== 4. revoke, re-fetch, verify again (must be INVALID) =="
curl -sf -X POST "http://127.0.0.1:$PORT/revoke" -d "{\"sub\":\"$SUB\",\"now\":$NOW}" >/dev/null
curl -sf "http://127.0.0.1:$PORT/present?sub=$SUB&now=$NOW" > "$WORK/bundle-revoked.json"
if node tools/ainra-verify.mjs --directory "$WORK/directory.json" --roots "$WORK/roots.json" --bundle "$WORK/bundle-revoked.json" --now "$NOW" --quiet 2>/dev/null; then
  echo "   FAIL: revoked passport verified VALID"; exit 1
else
  echo "   verdict: INVALID (revoked) — the gate fails closed, as it must"
fi

echo "== 4b. ADVERSARIAL: a malicious presenter forges an all-clear status to un-revoke (must STILL be INVALID) =="
# This is the exact bypass the M5 review found: the status list is presenter-supplied, so a hostile presenter takes
# the revoked bundle and rewrites its bitmap to all-clear. The status list is now AUTHENTICATED against the
# registrar's directory-published key (D-020), so the forged bits no longer match the signature → fail closed.
for MODE in clear strip swap-uri; do
  node tools/forge-status.mjs --in "$WORK/bundle-revoked.json" --out "$WORK/bundle-forged.json" --now "$NOW" --mode "$MODE" 2>/dev/null
  if node tools/ainra-verify.mjs --directory "$WORK/directory.json" --roots "$WORK/roots.json" --bundle "$WORK/bundle-forged.json" --now "$NOW" --quiet 2>/dev/null; then
    echo "   FAIL: forged ($MODE) status verified VALID — REVOCATION BYPASS"; exit 1
  else
    echo "   forge=$MODE → INVALID (status authentication holds)"
  fi
done

echo "== 5. verify latency (TTFV: the cost is LOCAL CPU, once per relationship; the root does zero) =="
echo -n "   "; node tools/ainra-verify.mjs --directory "$WORK/directory.json" --roots "$WORK/roots.json" --bundle "$WORK/bundle.json" --now "$NOW" --bench 20000

echo
echo "testbed OK — live registrar accredited into a signed directory; 5-line verify accepts a real passport and"
echo "rejects a revoked one. This is the wedge: local, offline, ~5 lines, no network fee to verify."
