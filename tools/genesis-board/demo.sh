#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make genesis-board-demo (M10) — prove the genesis board turns REAL artifacts into ✅ and refuses fakes. It produces
# genuine evidence end to end (3 execution-bound verifier attestations, a TEST-ROOT ceremony transcript, one soak
# region-run), renders the board, and asserts: the verifier + ceremony rows go ✅ from real signature-checked artifacts,
# the soak row stays ⏳ (1 region, day 0 of 14 — the board will NOT fake it), and tampering an attestation drops the
# verifier count. This is a demo of the MACHINERY; the real board runs on real strangers' evidence.
set -euo pipefail
# M35: this drill runs at the fixed genesis instant on purpose — it is HERMETIC, and a reproducible clock is
# what makes it reproducible. The daemon now defaults to the wall clock, so pinning is stated, not assumed.
export AINRA_CLOCK=pinned
# Its registrar writes with no token (mint-challenge issues through /issue). Since M35 the daemon refuses that unless
# asked — and only on loopback. This demo went red when that landed and nothing ran it (found in PLAN-M50 step 5).
export AINRA_OPEN_WRITES=1
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

# ── PLAN-M50 step 5: the witness row and the outside-rebuild row, computed from evidence ─────────────────────────
echo "== witness cosignatures: only distinct outside keys over ONE log-signed checkpoint count =="
mkdir -p "$EV/anchors" "$EV/cosignatures" "$EV/rebuild"
cp "$WORK/chal-1/directory.json" "$WORK/chal-1/roots.json" "$EV/anchors/"
SUB="$(curl -sf "http://127.0.0.1:$PORT/records" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(encodeURIComponent(JSON.parse(s).records[0].sub)))')"
curl -sf "http://127.0.0.1:$PORT/present?sub=$SUB&now=$NOW" > "$WORK/bundle.json"
cosign() { # cosign <key-name> <file-name> [moved] — a witness cosignature with the named key; `moved` cosigns a checkpoint the log never signed
  node -e '
  const fs = require("fs"), c = require("crypto");
  const [bundle, keyFile, out, now, moved] = process.argv.slice(1);
  if (!fs.existsSync(keyFile)) fs.writeFileSync(keyFile, c.generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }));
  const priv = c.createPrivateKey(fs.readFileSync(keyFile));
  const b = JSON.parse(fs.readFileSync(bundle, "utf8"));
  const cp = { origin: b.checkpoint.origin, size: b.checkpoint.size + (moved ? 1 : 0), root: b.checkpoint.root };
  const msg = JSON.stringify({ origin: cp.origin, root: cp.root, size: cp.size }); // canonical: keys sorted, no spaces
  fs.writeFileSync(out, JSON.stringify({ witness_key: c.createPublicKey(priv).export({ format: "jwk" }).x, checkpoint: cp,
    checkpoint_sig: b.checkpoint_sig, cosignature: c.sign(null, Buffer.from(msg), priv).toString("base64url"), observed_at: Number(now) }));
  ' "$WORK/bundle.json" "$WORK/wk-$1.pem" "$EV/cosignatures/$2.json" "$NOW" "${3:-}"
}
board() { node tools/genesis-board/board.mjs --evidence "$EV" --html "$WORK/b.html" "$@" | sed 's/\x1b\[[0-9;]*m//g'; }
expect() { # expect <label> <pattern> <board output>
  if echo "$3" | grep -qE "$2"; then echo "  ✓ $1"; else echo "FAIL: $1 — wanted /$2/"; echo "$3" | grep -E "witnesses|rebuild" | sed 's/^/      /'; exit 1; fi
}
for i in 1 2 3; do cosign a "a$i"; done
expect "three cosignatures from ONE key are one witness → 1/3, row ⏳" "⏳  Independent witnesses.* 1/3 independent" "$(board)"
cosign b b1; cosign c c1 moved
expect "a cosignature over a checkpoint the log never signed is rejected → 2/3" "⏳  Independent witnesses.* 2/3 .*1 rejected" "$(board)"
rm "$EV/cosignatures/c1.json"; cosign c c2
expect "three distinct outside keys over the log-signed checkpoint → 3/3, row ✅" "✅  Independent witnesses.* 3/3 independent" "$(board)"
CX="$(node -e 'const c=require("crypto");console.log(c.createPublicKey(c.createPrivateKey(require("fs").readFileSync(process.argv[1]))).export({format:"jwk"}).x)' "$WORK/wk-c.pem")"
printf '{"witness_ed25519":["%s"],"rebuild_spki":[]}' "$CX" > "$WORK/project-keys.json"
expect "the same three, with one key the project's own → 2/3, row ⏳" "⏳  Independent witnesses.* 2/3 .*1 under project keys" "$(board --project-keys "$WORK/project-keys.json")"
expect "an unreadable project key list counts nothing" "⏳  Independent witnesses.*unreadable" "$(board --project-keys "$WORK/no-such-file.json")"

echo "== an outside rebuild: a signed statement whose manifest digest matches the tag =="
TAG="$(git describe --tags --abbrev=0)"
git show "$TAG:MANIFEST.sha256" | sort -r > "$WORK/manifest-other-locale.txt" # the same lines in another order
node tools/genesis-board/rebuild-statement.mjs --tag "$TAG" --key "$WORK/rk.pem" --keygen --builder "demo rebuilder" \
  --manifest "$WORK/manifest-other-locale.txt" --out "$EV/rebuild/outsider.json" >/dev/null
expect "a matching statement, written under another locale's order → row ✅" "✅  An outsider rebuilds.* 1 outside rebuilder" "$(board)"
RX="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).body.builder_pubkey_spki_b64)' "$EV/rebuild/outsider.json")"
printf '{"witness_ed25519":[],"rebuild_spki":["%s"]}' "$RX" > "$WORK/project-keys-r.json"
expect "the same statement under a project key → row ⏳" "⏳  An outsider rebuilds.* 0 outside rebuilder.*1 rejected" "$(board --project-keys "$WORK/project-keys-r.json")"
git show "$TAG:MANIFEST.sha256" | awk 'NR==1{c=substr($0,1,1); $0=(c=="0"?"1":"0") substr($0,2)} 1' > "$WORK/manifest-wrong.txt" # one hash digit off
node tools/genesis-board/rebuild-statement.mjs --tag "$TAG" --key "$WORK/rk.pem" --builder "demo rebuilder" \
  --manifest "$WORK/manifest-wrong.txt" --out "$EV/rebuild/outsider.json" >/dev/null
expect "a statement whose rebuild produced a different artifact → row ⏳" "⏳  An outsider rebuilds.* 0 outside rebuilder.*1 rejected" "$(board)"

echo
echo "genesis-board-demo OK — real artifacts drive the board to ✅, the soak row is not faked, a tampered attestation is refused,"
echo "  witness and rebuild rows move only on verified outside evidence."
