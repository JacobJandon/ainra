#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# make ctl-drill — does the read-only control room raise the alarm it exists for? (PLAN-M52 steps 1–2)
#
# Contracts are built from the signed directories in vectors/v1-directory-epoch (epochs 1, 2 and three different
# epoch-3 directories, all under one pair of test roots), archived with `ainra directory archive`, and then broken one
# way at a time. Each broken contract must make `ainra ctl status` exit 1 with the alarm NAMED; the honest one must
# exit 0. The archive's own refusals are checked too.
#
# WITNESS: the rollback case is run twice — with the memory of the honest run, and with the memory deleted. With it,
# ctl must alarm; without it, the same self-consistent old contract must pass. If both alarmed, the memory would not
# be what catches a rollback; if both passed, nothing would.
set -uo pipefail
cd "$(dirname "$0")/.."

cargo build --release -q -p ainra-cli-rs || exit 2
A=./target/release/ainra
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
fail=0
pass() { echo "  ok    $1"; }
bad()  { echo "  ✗     $1"; fail=1; }

# the signed directories, by name
node -e '
const fs = require("fs"), V = "vectors/v1-directory-epoch/", out = process.argv[1];
const e01 = JSON.parse(fs.readFileSync(V + "e01-newer-each-time.json", "utf8"));
const e08 = JSON.parse(fs.readFileSync(V + "e08-withdrawn-registrar-replayed.json", "utf8"));
fs.writeFileSync(out + "/roots.json", JSON.stringify({ root_ed25519: e01.root_ed25519, root_slh: e01.root_slh }));
e01.directories.forEach((d, i) => fs.writeFileSync(`${out}/d${i + 1}.json`, JSON.stringify(d)));
fs.writeFileSync(out + "/d3-other.json", JSON.stringify(e08.directories[0]));   // a different authentic epoch 3
' "$W" || exit 2

# contract <name> <epochs to archive…> — the current directory is the last archived one
contract() {
  local c="$W/$1"; shift; mkdir -p "$c"
  cp "$W/roots.json" "$c/roots.json"
  for d in "$@"; do "$A" directory archive "$W/$d.json" --roots "$W/roots.json" --into "$c" >/dev/null || return 1; done
  cp "$W/${!#}.json" "$c/directory.json"
  echo '{"registrars":[]}' > "$c/registry.json"
  node -e '
    const fs = require("fs"), c = process.argv[1];
    const d = JSON.parse(fs.readFileSync(c + "/directory.json", "utf8"));
    for (const e of d.entries) {
      fs.mkdirSync(`${c}/registrars/${e.registrar}`, { recursive: true });
      fs.writeFileSync(`${c}/registrars/${e.registrar}/export.json`, JSON.stringify({ status_seq: 5,
        records: [{ checkpoint_size: 10, checkpoint_root: "rootA" }, { checkpoint_size: 12, checkpoint_root: "rootB" }] }));
    }' "$c"
}
edit() { node -e "const fs=require('fs'),p=process.argv[1];const v=JSON.parse(fs.readFileSync(p,'utf8'));($2)(v);fs.writeFileSync(p,JSON.stringify(v))" "$1"; }

# expect <label> <exit> <alarm text or -> <ctl args…>
expect() {
  local label="$1" want="$2" text="$3"; shift 3
  local out rc; out=$("$A" ctl status "$@" --max-age 999999999999 2>&1); rc=$?
  if [ "$rc" != "$want" ]; then bad "$label — exit $rc, wanted $want"; echo "$out" | sed 's/^/        /' | head -20; return; fi
  if [ "$text" != "-" ] && ! grep -q "ALARM.*$text" <<<"$out"; then bad "$label — no '$text' alarm"; echo "$out" | sed 's/^/        /' | head -20; return; fi
  pass "$label"
}

echo "ctl-drill · the control room must alarm, by name, on each way a contract can lie"
contract honest d1 d2 d3 || { bad "archiving three signed epochs"; exit 1; }
S="$W/seen.json"
expect "an honest contract: no alarm, memory written"                     0 -           --net "$W/honest" --roots "$W/roots.json" --state "$S"
expect "the same contract again: still no alarm"                          0 -           --net "$W/honest" --roots "$W/roots.json" --state "$S"

# rollback: an old but self-consistent contract, served under the same name
contract old d1 d2
rm -rf "$W/honest-saved"; mv "$W/honest" "$W/honest-saved"; cp -r "$W/old" "$W/honest"
expect "rollback to epoch 2 after epoch 3 was seen"                       1 "rollback"  --net "$W/honest" --roots "$W/roots.json" --state "$S"
expect "WITNESS: the same rollback with the memory deleted passes"        0 -           --net "$W/honest" --roots "$W/roots.json" --state "$W/fresh.json"
rm -rf "$W/honest"; mv "$W/honest-saved" "$W/honest"

# equivocation: a second, different authentic directory at epoch 3, in a contract that is consistent with itself —
# only the memory of the first epoch 3 can tell
contract equiv d1 d2 d3-other
sed "s#\"$W/honest\##\"$W/equiv\##g" "$S" > "$W/seen-equiv.json"
expect "equivocation: another signed epoch 3 than the one seen"           1 "equivocation" --net "$W/equiv" --roots "$W/roots.json" --state "$W/seen-equiv.json"

# the epoch index
contract skip d1 d3
expect "an index that skips epoch 2"                                      1 "skips"     --net "$W/skip" --roots "$W/roots.json" --state "$W/s1.json"
cp -r "$W/honest" "$W/lie"; edit "$W/lie/epochs.json" 'v=>{v.epochs[1].digest="00".repeat(32)}'
expect "an index that lies about epoch 2's digest"                        1 "digest"    --net "$W/lie" --roots "$W/roots.json" --state "$W/s2.json"
cp -r "$W/honest" "$W/gone"; rm "$W/gone/epochs/2.json"
expect "an index that lists an epoch it does not serve"                   1 "not served" --net "$W/gone" --roots "$W/roots.json" --state "$W/s3.json"

# registrars, against the memory of the honest run
REG=$(node -e 'const d=require(process.argv[1]);console.log(d.entries[0].registrar)' "$W/honest/directory.json")
for case in shrink fork seq; do
  cp -r "$W/honest" "$W/$case"
  sed "s#\"$W/honest\##\"$W/$case\##g" "$S" > "$W/seen-$case.json"     # the same memory, for the copy's name
done
edit "$W/shrink/registrars/$REG/export.json" 'v=>{v.records=[{checkpoint_size:9,checkpoint_root:"rootA"}]}'
expect "a registrar's log shrinks"                                        1 "shrank"    --net "$W/shrink" --roots "$W/roots.json" --state "$W/seen-shrink.json"
edit "$W/fork/registrars/$REG/export.json" 'v=>{v.records[1].checkpoint_root="rootX"}'
expect "a registrar's log forks (same size, another root)"                1 "forked"    --net "$W/fork" --roots "$W/roots.json" --state "$W/seen-fork.json"
edit "$W/seq/registrars/$REG/export.json" 'v=>{v.status_seq=4}'
expect "a registrar's status sequence goes back"                          1 "status sequence" --net "$W/seq" --roots "$W/roots.json" --state "$W/seen-seq.json"

# mirrors, pinned roots, staleness, an unsigned directory
cp -r "$W/honest" "$W/mirror"; echo '{"registrars":[1]}' > "$W/mirror/registry.json"
expect "a mirror that serves other bytes"                                 1 "mirror"    --net "$W/honest" --mirror "$W/mirror" --roots "$W/roots.json" --state "$W/s4.json"
expect "a mirror that serves the same bytes"                              0 -           --net "$W/honest" --mirror "$W/honest" --roots "$W/roots.json" --state "$W/s5.json"
node -e 'const fs=require("fs");const r=JSON.parse(fs.readFileSync(process.argv[1]));r.root_slh=r.root_slh.slice(0,-4)+"AAAA";fs.writeFileSync(process.argv[2],JSON.stringify(r))' "$W/roots.json" "$W/other-roots.json"
expect "a contract whose roots are not the pinned ones"                   1 "roots"     --net "$W/honest" --roots "$W/other-roots.json" --state "$W/s6.json"
out=$("$A" ctl status --net "$W/honest" --roots "$W/roots.json" --state "$W/s7.json" --max-age 60 2>&1); rc=$?
[ "$rc" = 1 ] && grep -q "ALARM.*stale directory" <<<"$out" && pass "a directory older than the published cadence" || bad "a directory older than the published cadence (exit $rc)"
cp -r "$W/honest" "$W/forged"; edit "$W/forged/directory.json" 'v=>{v.issued_at+=1}'
expect "a directory whose bytes no longer match its signatures"           1 "does not verify" --net "$W/forged" --roots "$W/roots.json" --state "$W/s8.json"

# the archive's own refusals
mkdir -p "$W/arch"
"$A" directory archive "$W/d2.json" --roots "$W/roots.json" --into "$W/arch" >/dev/null || bad "archive epoch 2"
"$A" directory archive "$W/d1.json" --roots "$W/roots.json" --into "$W/arch" >/dev/null 2>&1 && bad "archive accepted an older epoch" || pass "the archive refuses an epoch older than its last"
"$A" directory archive "$W/d3.json" --roots "$W/roots.json" --into "$W/arch" >/dev/null || bad "archive epoch 3"
"$A" directory archive "$W/d3-other.json" --roots "$W/roots.json" --into "$W/arch" >/dev/null 2>&1 && bad "archive accepted a second epoch 3" || pass "the archive refuses a second, different directory at an archived epoch"
"$A" directory archive "$W/forged/directory.json" --roots "$W/roots.json" --into "$W/arch2" >/dev/null 2>&1 && bad "archive accepted an unsigned directory" || pass "the archive refuses a directory that does not verify"

if [ "$fail" = 0 ]; then echo "CTL-DRILL OK — every lie raised its alarm by name, the honest contract raised none, and the memory is what catches a rollback"; exit 0; fi
echo "CTL-DRILL FAILED"; exit 1
