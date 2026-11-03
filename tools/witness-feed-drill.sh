#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make witness-feed-drill (PLAN-M51 witness work) — a stranger's witness, end to end, against a real registrar:
# three witnessd processes configured the way kits/witness tells an operator to (a random key file, a state file,
# the root-signed directory), each fed by kits/witness/submit.mjs from the registrar's /witness-feed, and the genesis
# board counting what they signed. Then the failures that matter, each required to happen:
#
#   * a log that grew is cosigned again only with a consistency proof (the feed supplies it), and refused without;
#   * a restarted witness remembers where it was: a replayed older checkpoint is refused, not cosigned on first sight;
#   * a witness on a public address refuses to start with no key file, with only a `seed` phrase, or with no
#     directory (its key would be computable, or its log keys whoever's reached it first);
#   * a loopback witness without a directory is not locked to a key that never verified anything;
#   * a tampered cosignature is not counted by the board;
#   * a witness on the wall clock judges the cert at ITS time, whatever `now` a caller sends.
#
# WITNESS (could this fail?): each bullet above was the behaviour before this change — the key derived from the
# address, no state, a key overwritten by every request, no feed — and the drill asserts its opposite.
set -euo pipefail
export AINRA_CLOCK=pinned    # hermetic: registrar and witnesses on the fixed genesis clock
export AINRA_OPEN_WRITES=1   # the registrar's writes come from this script, on loopback
cd "$(dirname "$0")/.."

PORT="${AINRA_FEED_PORT:-4955}"
WBASE="${AINRA_FEED_WITNESS_PORT:-4956}"
NOW=$((1775865600 + 10 * 24 * 3600))
WORK="$(mktemp -d)"
PIDS=()
PORT2=$((WBASE + 6))
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; exit 1; }
ok() { echo "  ✓ $*"; }
json() { node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const v=JSON.parse(s);const r=process.argv[1].split(".").reduce((o,k)=>o?.[k],v);process.stdout.write(r===undefined?"":String(r))})' "$1"; }
up() { for _ in $(seq 1 60); do curl -sf "$1" >/dev/null 2>&1 && return 0; sleep 0.2; done; return 1; }

echo "== build =="
cargo build --release -q -p ainra-services --bin registrar-box --bin witnessd -p ainra-ceremony --bin accredit
(cd packages/sdk-ts && { [ -d node_modules ] || npm install --prefer-offline --no-audit --no-fund --silent; } && npm run build >/dev/null 2>&1)

echo "== a registrar, accredited into a root-signed directory =="
for p in "$PORT" "$PORT2" $(seq "$WBASE" $((WBASE + 5))); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then fail "127.0.0.1:$p already serving"; fi
done
AINRA_STAGE=1 ./target/release/registrar-box "127.0.0.1:$PORT" registrar-07 "$WORK/rb" >/dev/null 2>"$WORK/rb.err" &
PIDS+=($!)
up "http://127.0.0.1:$PORT/accreditation" || fail "registrar did not start: $(tail -1 "$WORK/rb.err")"
curl -sf "http://127.0.0.1:$PORT/accreditation" >"$WORK/acc.json"
./target/release/accredit "$WORK" "$WORK/acc.json" >/dev/null
issue() { curl -sf -X POST "http://127.0.0.1:$PORT/demo/issue" -H 'content-type: application/json' -d '{"lineage":"feed"}' >/dev/null; }
issue; issue

witness() { # witness <n> [extra config json] — start witness n on WBASE+n with the operator's config
  local n="$1" extra="${2:-}"
  node -e '
  const [work, n, extra] = process.argv.slice(1);
  const c = { key_file: `${work}/w${n}.key`, state_file: `${work}/w${n}.state`, directory: `${work}/directory.json`,
    roots: `${work}/roots.json`, operator: `drill witness ${n}` };
  require("fs").writeFileSync(`${work}/w${n}.json`, JSON.stringify(extra ? { ...c, ...JSON.parse(extra) } : c));
  ' "$WORK" "$n" "$extra"
  ./target/release/witnessd "127.0.0.1:$((WBASE + n))" "$WORK/w$n.json" >"$WORK/w$n.log" 2>&1 &
  PIDS+=($!)
  up "http://127.0.0.1:$((WBASE + n))/key" || fail "witness $n did not start: $(tail -1 "$WORK/w$n.log")"
}
submit() { # submit <n> <out>
  node kits/witness/submit.mjs --registrar "http://127.0.0.1:$PORT" --witness "http://127.0.0.1:$((WBASE + $1))" \
    --out "$2" --now "$NOW"
}

echo "== three operators' witnesses: key file, state file, the directory =="
for n in 0 1 2; do witness "$n"; done
[ "$(stat -c %a "$WORK/w0.key")" = 600 ] && ok "each witness made its own random key, owner-only (0600)" || fail "key file mode $(stat -c %a "$WORK/w0.key")"
[ "$(curl -sf "http://127.0.0.1:$WBASE/info" | json log_keys_from_directory)" = true ] && ok "log keys come from the directory" || fail "witness did not pin keys from the directory"
mkdir -p "$WORK/ev/anchors" "$WORK/ev/cosignatures"
cp "$WORK/directory.json" "$WORK/roots.json" "$WORK/ev/anchors/"
for n in 0 1 2; do submit "$n" "$WORK/ev/cosignatures/w$n.json" | sed 's/^/    /'; done
curl -sf "http://127.0.0.1:$PORT/witness-feed" >"$WORK/feed-old.json"
BOARD="$(node tools/genesis-board/board.mjs --evidence "$WORK/ev" --html "$WORK/b.html" | sed 's/\x1b\[[0-9;]*m//g')"
echo "$BOARD" | grep -qE "✅  Independent witnesses.* 3/3 independent" && ok "the board counts three independent witnesses over one log-signed checkpoint" \
  || { echo "$BOARD" | grep -i witness; fail "board did not count 3/3"; }

echo "== the log grows: a witness cosigns again only with a consistency proof =="
issue
NOPROOF="$(node -e '
fetch(process.argv[1] + "/witness-feed").then((r) => r.json()).then((f) => fetch(process.argv[2] + "/consider", { method: "POST",
  body: JSON.stringify({ origin: f.checkpoint.origin, size: f.checkpoint.size, root_b64: f.checkpoint.root,
  checkpoint_sig: f.checkpoint_sig, consistency_proof_b64: [], now: Number(process.argv[3]) }) })).then((r) => r.json())
  .then((v) => process.stdout.write(v.outcome));
' "http://127.0.0.1:$PORT" "http://127.0.0.1:$((WBASE + 1))" "$NOW")"
[ "$NOPROOF" = refused_fork ] && ok "the grown log WITHOUT a consistency proof is refused ($NOPROOF)" || fail "growth without proof: $NOPROOF"
OUT="$(submit 0 "$WORK/ev/cosignatures/w0-grown.json")"
echo "$OUT" | grep -q "^cosigned: .*consistency proven" && ok "grown log cosigned with the feed's consistency proof" || fail "growth: $OUT"

echo "== a restarted witness remembers =="
SEEN_BEFORE="$(curl -sf "http://127.0.0.1:$WBASE/seen" | json ainra-log/registrar-07.size)"
kill "${PIDS[1]}"; wait "${PIDS[1]}" 2>/dev/null || true
for _ in $(seq 1 40); do (exec 3<>"/dev/tcp/127.0.0.1/$WBASE") 2>/dev/null || break; sleep 0.1; done
witness 0
SEEN_AFTER="$(curl -sf "http://127.0.0.1:$WBASE/seen" | json ainra-log/registrar-07.size)"
[ -n "$SEEN_BEFORE" ] && [ "$SEEN_BEFORE" = "$SEEN_AFTER" ] && ok "after a restart it still knows size $SEEN_AFTER" || fail "seen before $SEEN_BEFORE, after $SEEN_AFTER"
REPLAY="$(node -e '
const f = JSON.parse(require("fs").readFileSync(process.argv[1]));
fetch(process.argv[2] + "/consider", { method: "POST", body: JSON.stringify({ origin: f.checkpoint.origin, size: f.checkpoint.size,
  root_b64: f.checkpoint.root, checkpoint_sig: f.checkpoint_sig, consistency_proof_b64: [], now: Number(process.argv[3]) }) })
  .then((r) => r.json()).then((v) => process.stdout.write(v.outcome));
' "$WORK/feed-old.json" "http://127.0.0.1:$WBASE" "$NOW")"
[ "$REPLAY" = refused_regression ] && ok "the older checkpoint, replayed after the restart, is refused ($REPLAY)" || fail "replay after restart: $REPLAY"

echo "== a witness on a public address refuses to start unless its key and its log keys are its own =="
public_refuses() { # public_refuses <label> <config json> <expected word in the refusal>
  printf '%s' "$2" >"$WORK/pub.json"
  set +e
  timeout 5 ./target/release/witnessd "0.0.0.0:$((WBASE + 3))" "$WORK/pub.json" >"$WORK/public.log" 2>&1
  local rc=$?
  set -e
  [ "$rc" = 2 ] && grep -q "$3" "$WORK/public.log" && ok "refused (exit 2): $1" || fail "public bind, $1: exit $rc · $(cat "$WORK/public.log")"
}
public_refuses "no key file — an address-derived key is computable by anyone" '{}' key_file
public_refuses "only a seed phrase — computable by anyone who reads the config" '{"seed":"change-me"}' key_file
public_refuses "no directory — log keys would be whoever's reached it first" \
  "{\"key_file\":\"$WORK/pub.key\",\"state_file\":\"$WORK/pub.state\"}" directory

echo "== a loopback witness without a directory is not locked to a key that verified nothing =="
witness 3 '{"directory":"","roots":""}'
BOGUS="$(node -e 'console.log(Buffer.alloc(32, 7).toString("base64url"))')"
FIRST="$(node -e '
const [reg, wit, bogus, now] = process.argv.slice(1);
(async () => {
  const f = await (await fetch(reg + "/witness-feed")).json();
  const body = (key) => JSON.stringify({ origin: f.checkpoint.origin, size: f.checkpoint.size, root_b64: f.checkpoint.root,
    checkpoint_sig: f.checkpoint_sig, consistency_proof_b64: [], log_root_key_b64: key, now: Number(now) });
  const acc = await (await fetch(reg + "/accreditation")).json();
  const a = await (await fetch(wit + "/consider", { method: "POST", body: body(bogus) })).json();
  const b = await (await fetch(wit + "/consider", { method: "POST", body: body(acc.log_root_key) })).json();
  process.stdout.write(a.outcome + " " + b.outcome);
})();
' "http://127.0.0.1:$PORT" "http://127.0.0.1:$((WBASE + 3))" "$BOGUS" "$NOW")"
[ "$FIRST" = "refused_unsigned cosigned_first_sight" ] && ok "a junk key first locks nothing; the log's own key then verifies ($FIRST)" || fail "first-key lock: $FIRST"

echo "== a tampered cosignature is not counted =="
node -e 'const f=process.argv[1];const e=JSON.parse(require("fs").readFileSync(f));e.cosignature=Buffer.alloc(64,1).toString("base64url");require("fs").writeFileSync(f,JSON.stringify(e))' "$WORK/ev/cosignatures/w2.json"
BOARD2="$(node tools/genesis-board/board.mjs --evidence "$WORK/ev" --html "$WORK/b2.html" | sed 's/\x1b\[[0-9;]*m//g')"
echo "$BOARD2" | grep -qE "⏳  Independent witnesses.* 2/3 .*1 rejected" && ok "the board drops it: 2/3, row ⏳" || { echo "$BOARD2" | grep -i witness; fail "tampered cosignature counted"; }

echo "== on the wall clock: the cert is judged at the witness's time, whatever a caller sends =="
mkdir -p "$WORK/wall"
env -u AINRA_CLOCK AINRA_STAGE=1 ./target/release/registrar-box "127.0.0.1:$PORT2" registrar-07 "$WORK/wall/rb" >/dev/null 2>"$WORK/wall/rb.err" &
PIDS+=($!)
up "http://127.0.0.1:$PORT2/accreditation" || fail "wall-clock registrar did not start: $(tail -1 "$WORK/wall/rb.err")"
curl -sf "http://127.0.0.1:$PORT2/accreditation" >"$WORK/wall/acc.json"
./target/release/accredit "$WORK/wall" "$WORK/wall/acc.json" >/dev/null
curl -sf -X POST "http://127.0.0.1:$PORT2/demo/issue" -H 'content-type: application/json' -d '{"lineage":"wall"}' >/dev/null
printf '{"key_file":"%s/w5.key","state_file":"%s/w5.state","directory":"%s/directory.json","roots":"%s/roots.json"}' \
  "$WORK/wall" "$WORK/wall" "$WORK/wall" "$WORK/wall" >"$WORK/wall/w5.json"
env -u AINRA_CLOCK ./target/release/witnessd "127.0.0.1:$((WBASE + 5))" "$WORK/wall/w5.json" >"$WORK/wall/w5.log" 2>&1 &
PIDS+=($!)
up "http://127.0.0.1:$((WBASE + 5))/key" || fail "wall-clock witness did not start"
OUT="$(node kits/witness/submit.mjs --registrar "http://127.0.0.1:$PORT2" --witness "http://127.0.0.1:$((WBASE + 5))" --out "$WORK/wall/ev.json")"
echo "$OUT" | grep -q '^cosigned_first_sight' && ok "a wall-clock witness cosigns a wall-clock registrar's checkpoint, no --now" || fail "wall clock: $OUT"
IGNORED="$(node -e '
fetch(process.argv[1] + "/witness-feed").then((r) => r.json()).then((f) => fetch(process.argv[2] + "/consider", { method: "POST",
  body: JSON.stringify({ origin: f.checkpoint.origin, size: f.checkpoint.size, root_b64: f.checkpoint.root,
  checkpoint_sig: f.checkpoint_sig, consistency_proof_b64: [], now: 1 }) })).then((r) => r.json()).then((v) => process.stdout.write(v.outcome));
' "http://127.0.0.1:$PORT2" "http://127.0.0.1:$((WBASE + 5))")"
[ "$IGNORED" = cosigned ] && ok "a caller's now=1 (before the cert's window) is ignored: $IGNORED" || fail "caller clock honoured: $IGNORED"

echo
echo "witness-feed-drill PASS — a witness configured as kits/witness says, fed by the registrar, counted by the board; and it fails safe."
