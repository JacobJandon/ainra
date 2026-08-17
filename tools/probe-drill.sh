#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make probe-drill (D-046) — prove the compliance probe works, in the only way that counts: run it against an honest
# registrar and against four dishonest ones, and require the right verdict from each.
#
# The positive run alone would prove nothing. A probe that always says COMPLIANT says COMPLIANT about a registrar
# suppressing revocations too — so the four controls are the deliverable and the honest run is the baseline.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${AINRA_PROBE_PORT:-4951}"
PROXY="${AINRA_PROBE_PROXY_PORT:-4952}"
NOW=$((1775865600 + 10 * 24 * 3600))
WORK="$(mktemp -d)"
RB=0; PX=0
cleanup() {
  [ "$PX" -ne 0 ] && kill "$PX" 2>/dev/null || true
  [ "$RB" -ne 0 ] && kill "$RB" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build =="
cargo build --release -q -p ainra-services --bin registrar-box -p ainra-ceremony --bin accredit
(cd packages/sdk-ts && { [ -d node_modules ] || npm install --prefer-offline --no-audit --no-fund --silent; } && npm run build >/dev/null 2>&1)
(cd kits/probe && npm install --prefer-offline --no-audit --no-fund --silent)

echo "== stand up a real registrar (staging: the public door is open) + accredit it =="
if curl -sf "http://127.0.0.1:$PORT/accreditation" >/dev/null 2>&1; then
  echo "FAIL: 127.0.0.1:$PORT already serving — kill the leftover daemon"; exit 1
fi
# A write token, so P0 has something real to be refused BY. Never passed to the probe. The variable name matters:
# with no token configured the registrar's write door is OPEN (local-dev default), and P0 caught exactly that when
# this driver first ran with the name spelled wrong. The check found a real open door on its first outing.
AINRA_STAGE=1 AINRA_STAGE_ISSUE_TOKEN="$(node -e 'console.log(require("crypto").randomBytes(16).toString("hex"))')" \
  ./target/release/registrar-box "127.0.0.1:$PORT" registrar-07 "$WORK/rb" >/dev/null 2>"$WORK/rb.err" &
RB=$!
for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$PORT/accreditation" >/dev/null 2>&1 && break; sleep 0.2; done
kill -0 "$RB" 2>/dev/null || { echo "FAIL: registrar-box died — $(tail -1 "$WORK/rb.err" 2>/dev/null)"; exit 1; }
curl -sf "http://127.0.0.1:$PORT/accreditation" > "$WORK/acc.json"
./target/release/accredit "$WORK" "$WORK/acc.json" >/dev/null

# Grow the log past a single leaf, deliberately. In a one-leaf tree a correct inclusion proof is EMPTY and the root
# IS the leaf, so the probe's "delete the proof" control (P2d) cannot fail there and honestly reports itself SKIPPED.
# The drill exists to exercise the strong version, so it puts real siblings in the tree first — and the drop-log
# sabotage below only bites for the same reason.
for _ in 1 2; do
  curl -sf -X POST "http://127.0.0.1:$PORT/demo/issue" -H 'content-type: application/json' \
    -d '{"operator":"tidewater","lineage":"warehouse"}' >/dev/null || { echo "FAIL: could not grow the log"; exit 1; }
done
echo "   log grown to $(curl -sf "http://127.0.0.1:$PORT/health" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(String(JSON.parse(s).records)))') records"

run_probe() { # run_probe <url> <outdir>
  node kits/probe/probe.mjs --registrar "$1" --directory "$WORK/directory.json" --roots "$WORK/roots.json" \
    --now "$NOW" --slo-revocation-sec 60 --poll-ms 80 --timeout-sec 20 --out "$2"
}

echo
echo "== POSITIVE · the honest registrar must come back COMPLIANT =="
if ! run_probe "http://127.0.0.1:$PORT" "$WORK/honest"; then
  echo "FAIL: the probe called an honest registrar non-compliant"; exit 1
fi
node -e '
const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
if (r.verdict !== "COMPLIANT") { console.error("FAIL: verdict " + r.verdict); process.exit(1); }
if (r.measured.revocation_visible_ms === null) { console.error("FAIL: no revocation latency was measured"); process.exit(1); }
const ids = r.checks.filter(c => c.pass).map(c => c.id);
for (const need of ["P0","P1","P2a","P2b","P2c","P2d","P3","P4","P5"]) {
  if (!ids.includes(need)) { console.error("FAIL: " + need + " did not pass on the honest registrar"); process.exit(1); }
}
// The tree was grown on purpose above, so nothing may be skipped here. A skip in this run means the driver stopped
// exercising the strong control and the board would go green on a thinner test than it claims to run.
if (r.skipped.length) { console.error("FAIL: skipped " + r.skipped.map(s => s.id).join(",") + " — the log was supposed to be multi-leaf"); process.exit(1); }
console.log("  ✓ all " + ids.length + " checks passed · revocation visible in " + (r.measured.revocation_visible_ms/1000).toFixed(3) + "s · seq " + r.measured.status_seq.start + " → " + r.measured.status_seq.end);
' "$WORK/honest/probe-report.json"

# ── the four dishonest registrars ────────────────────────────────────────────────────────────────────────────────
# Each: stand up the proxy, run the probe, require a non-zero exit AND require the named check to be the one that
# failed. "It failed" is not enough — a probe that fails for the wrong reason is a probe that will pass for the wrong
# reason later.
control() { # control <mode> <expected-verdict> <check-that-must-fail>
  local mode="$1" want="$2" must="$3"
  echo
  echo "== NEGATIVE · sabotage = $mode · expect $want with $must failing =="
  node kits/probe/dishonest-registrar.mjs --upstream "http://127.0.0.1:$PORT" --port "$PROXY" --sabotage "$mode" >"$WORK/px-$mode.log" 2>&1 &
  PX=$!
  for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$PROXY/health" >/dev/null 2>&1 && break; sleep 0.2; done
  set +e
  run_probe "http://127.0.0.1:$PROXY" "$WORK/$mode" >"$WORK/probe-$mode.log" 2>&1
  local rc=$?
  set -e
  kill "$PX" 2>/dev/null || true; PX=0
  sed -n '1,40p' "$WORK/probe-$mode.log" | sed 's/^/     /'
  if [ "$rc" -eq 0 ]; then
    echo "FAIL: the probe passed a registrar that was $mode — it cannot observe this failure, so it is decoration"
    exit 1
  fi
  node -e '
  const [f, want, must] = process.argv.slice(1);
  const r = JSON.parse(require("fs").readFileSync(f, "utf8"));
  if (r.verdict !== want) { console.error("FAIL: verdict " + r.verdict + ", wanted " + want); process.exit(1); }
  const failed = r.checks.filter(c => !c.pass).map(c => c.id);
  if (!failed.includes(must) && !(want === "INVALID-RUN" && r.aborted)) {
    console.error("FAIL: " + must + " did not fail; failures were [" + failed.join(",") + "]"); process.exit(1);
  }
  console.log("  ✓ caught: " + r.verdict + " · failed [" + failed.join(",") + "]" + (r.aborted ? " · ABORTED: " + r.aborted.slice(0, 90) + "…" : ""));
  ' "$WORK/$mode/probe-report.json" "$want" "$must"
}

control open-write-door    INVALID-RUN    P0
control drop-log           NON-COMPLIANT  P2a
control suppress-revocation NON-COMPLIANT P3
control rewind-seq         NON-COMPLIANT  P5

echo
echo "probe-drill PASS: the probe passes an honest registrar and catches all four dishonest ones"
echo "  · open-write-door    → the run is voided, not scored: a probe with write access is a self-report"
echo "  · drop-log           → logged-before-valid is enforced by the verifier, not by the registrar's word"
echo "  · suppress-revocation → a 200 on /revoke means nothing; only what a stranger can observe counts"
echo "  · rewind-seq         → a history that moves backwards is refused from outside as well as inside (D-045)"
