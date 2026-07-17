#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make genesis-board-demo (M10) — prove the genesis board turns REAL artifacts into ✅ and refuses fakes. It produces
# genuine evidence end to end (3 execution-bound verifier attestations, a TEST-ROOT ceremony transcript, one soak
# region-run), renders the board, and asserts: the verifier + ceremony rows go ✅ from real signature-checked artifacts,
# the soak row stays ⏳ (1 region, day 0 of 14 — the board will NOT fake it), and tampering an attestation drops the
# verifier count. This is a demo of the MACHINERY; the real board runs on real strangers' evidence.
set -euo pipefail
cd "$(dirname "$0")/../.."
PORT="${AINRA_BOARD_PORT:-4983}"
NOW=$((1775865600 + 10 * 24 * 3600))

echo "== build SDK + bins =="
(cd packages/sdk-ts && { [ -d node_modules ] || npm install --prefer-offline --no-audit --no-fund --silent; } && npm run build >/dev/null 2>&1)
cargo build --release -q -p ainra-services --bin registrar-box -p ainra-ceremony --bin accredit --bin ceremony
(cd kits/verifier && npm install --prefer-offline --no-audit --no-fund --silent)
(cd kits/soak && npm install --prefer-offline --no-audit --no-fund --silent)

WORK="$(mktemp -d)"; RB=0
trap 'kill "$RB" 2>/dev/null || true; rm -rf "$WORK"' EXIT
EV="$WORK/evidence"; mkdir -p "$EV/verifiers" "$EV/ceremony" "$EV/soak/local-a"

echo "== stand up a registrar =="
if curl -sf "http://127.0.0.1:$PORT/accreditation" >/dev/null 2>&1; then echo "FAIL: port $PORT busy"; exit 1; fi
./target/release/registrar-box "127.0.0.1:$PORT" registrar-07 "$WORK/rb" >/dev/null 2>"$WORK/rb.err" &
RB=$!
for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$PORT/accreditation" >/dev/null 2>&1 && break; sleep 0.2; done
kill -0 "$RB" 2>/dev/null || { echo "FAIL: registrar died"; exit 1; }

echo "== 3 external verifiers → 3 execution-bound attestations (real evidence) =="
for i in 1 2 3; do
  CDIR="$WORK/chal-$i"; mkdir -p "$CDIR"
  curl -sf "http://127.0.0.1:$PORT/accreditation" > "$WORK/acc.json"
  ./target/release/accredit "$CDIR" "$WORK/acc.json" >/dev/null
  N="$(node -e 'console.log(require("crypto").randomBytes(16).toString("hex"))')"
  node kits/verifier/mint-challenge.mjs --registrar "http://127.0.0.1:$PORT" --now "$NOW" --count 8 --out "$CDIR" --secret "$WORK/sec-$i.json" --nonce "$N" >/dev/null
  node kits/verifier/verify-kit.mjs --challenge "$N" --challenge-dir "$CDIR" --out "$WORK/att-$i.json" >/dev/null
  mkdir -p "$EV/verifiers/v$i"
  cp "$WORK/att-$i.json" "$EV/verifiers/v$i/attestation.json"
  cp "$WORK/sec-$i.json" "$EV/verifiers/v$i/secret.json"
done

echo "== a TEST-ROOT ceremony transcript (real hash) =="
./target/release/ceremony "$WORK/cer" >/dev/null 2>&1
cp "$WORK/cer/transcript.json" "$WORK/cer/transcript.sha256" "$EV/ceremony/"

echo "== one soak region-run (real measured report) =="
DIRSRC="$WORK/chal-1"
node kits/soak/soak.mjs --registrar "http://127.0.0.1:$PORT" --directory "$DIRSRC/directory.json" --roots "$DIRSRC/roots.json" \
  --now "$NOW" --vantages "local-a,local-b,local-c" --cycles 10 --poll-ms 80 --slo-p95-sec 60 --challenge "soakdemo" --out "$WORK/soak-out" >/dev/null 2>&1 || true
cp "$WORK/soak-out/soak-report.json" "$WORK/soak-out/soak-log.jsonl" "$EV/soak/local-a/"

echo "== render the board from the real evidence =="
BOARD="$(node tools/genesis-board/board.mjs --evidence "$EV" --html "$WORK/board.html" | sed 's/\x1b\[[0-9;]*m//g')"
echo "$BOARD" | grep -E "verifiers|ceremony|soak|criteria proven" | sed 's/^/  /'

echo "== assertions =="
echo "$BOARD" | grep -q "3/3 distinct valid" && echo "  ✓ 3/3 verifier attestations verified → row ✅" || { echo "FAIL: verifier row not 3/3"; exit 1; }
echo "$BOARD" | grep -qE "✅  Recorded in-person ceremony" && echo "  ✓ ceremony transcript verified → row ✅" || { echo "FAIL: ceremony row not ✅"; exit 1; }
echo "$BOARD" | grep -qE "⏳  14-day" && echo "  ✓ soak row stays ⏳ (1 region, day 0 of 14 — board refuses to fake it)" || { echo "FAIL: soak row should be ⏳"; exit 1; }

echo "== refuse a FAKE: tamper one attestation → the board must drop it =="
node -e 'const f=process.argv[1];const a=JSON.parse(require("fs").readFileSync(f));a.body.challenge_verdicts=a.body.challenge_verdicts.map(()=>"valid");require("fs").writeFileSync(f,JSON.stringify(a))' "$EV/verifiers/v3/attestation.json"
BOARD2="$(node tools/genesis-board/board.mjs --evidence "$EV" --html "$WORK/board2.html" | sed 's/\x1b\[[0-9;]*m//g')"
echo "$BOARD2" | grep -q "2/3 distinct valid" && echo "  ✓ tampered attestation refused → 2/3 (row back to ⏳)" || { echo "FAIL: tampered attestation not refused"; exit 1; }

echo
echo "genesis-board-demo OK — real artifacts drive the board to ✅, the soak row is not faked, a tampered attestation is refused."
