#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# make epoch-log-drill — the witnessed epoch log (PLAN-M52 step 10, D-097): does a witness refuse a split view, and
# does the control room alarm on a log that lies?
#
# Contracts are built from the signed directories in vectors/v1-directory-epoch (epochs 1, 2, 3 and a different,
# equally authentic epoch 3), archived with `ainra directory archive`, exactly as `make ctl-drill` builds them.
#
# WITNESS (each must hold, or this drill fails):
#   · a witness cosigns a log of 1 epoch, then its growth to 3;
#   · shown a different epoch 3 than the one it cosigned, the same witness REFUSES (split view), and `ctl`, holding its
#     memory of the first epoch 3, ALARMS (equivocation);
#   · a log that shrank is refused; a leaf whose directory does not verify under both roots is refused by `log` and
#     by the witness;
#   · a cosignature is accepted into the contract only if it verifies; a forged one is refused, and when served
#     anyway `ctl` alarms; a served head that is not the head the epochs make makes `ctl` alarm;
#   · two witnesses with their own keys on the current head are counted, and `ctl` names a pinned witness missing;
#   · with the witness's memory deleted, the equivocating epoch 3 is cosigned — the memory is what refuses it.
set -uo pipefail
cd "$(dirname "$0")/.."

cargo build --release -q -p ainra-cli-rs || exit 2
A=./target/release/ainra
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
fail=0
pass() { echo "  ok    $1"; }
bad()  { echo "  ✗     $1"; fail=1; }
# want <label> <exit> <text or -> <command…>
want() {
  local label="$1" code="$2" text="$3"; shift 3
  local out rc; out=$("$@" 2>&1); rc=$?
  if [ "$rc" != "$code" ]; then bad "$label — exit $rc, wanted $code"; echo "$out" | sed 's/^/        /' | head -12; return; fi
  if [ "$text" != "-" ] && ! grep -q -- "$text" <<<"$out"; then bad "$label — no '$text'"; echo "$out" | sed 's/^/        /' | head -12; return; fi
  pass "$label"
}

node -e '
const fs = require("fs"), V = "vectors/v1-directory-epoch/", out = process.argv[1];
const e01 = JSON.parse(fs.readFileSync(V + "e01-newer-each-time.json", "utf8"));
const e08 = JSON.parse(fs.readFileSync(V + "e08-withdrawn-registrar-replayed.json", "utf8"));
fs.writeFileSync(out + "/roots.json", JSON.stringify({ root_ed25519: e01.root_ed25519, root_slh: e01.root_slh }));
e01.directories.forEach((d, i) => fs.writeFileSync(`${out}/d${i + 1}.json`, JSON.stringify(d)));
fs.writeFileSync(out + "/d3-other.json", JSON.stringify(e08.directories[0]));
' "$W" || exit 2

contract() {  # contract <name> <epochs…> — what ctl reads: roots, the current directory, the archive, a registry
  local c="$W/$1"; shift; mkdir -p "$c"
  cp "$W/roots.json" "$c/roots.json"
  for d in "$@"; do "$A" directory archive "$W/$d.json" --roots "$W/roots.json" --into "$c" >/dev/null || return 1; done
  cp "$W/${!#}.json" "$c/directory.json"
  echo '{"registrars":[]}' > "$c/registry.json"
}
ctl() { "$A" ctl status --roots "$W/roots.json" --max-age 999999999999 "$@"; }
R="$W/roots.json" K="$W/w1.key" S="$W/w1.state"

echo "epoch-log-drill · a witnessed log of directory epochs (D-097)"
contract one d1 && contract three d1 d2 d3 && contract two d1 d2 && contract equiv d1 d2 d3-other || { bad "building contracts"; exit 1; }

want "the log of three epochs: head computed"                               0 "size 3"        "$A" directory log --net "$W/three" --roots "$R" --write "$W/three"
want "witness 1 cosigns the log at 1 epoch (a new key is made, 0600)"      0 "cosigned"      "$A" directory witness --net "$W/one" --roots "$R" --key "$K" --state "$S" --out "$W/c1.json"
[ "$(stat -c %a "$K")" = "600" ] && pass "the new witness key is owner-only" || bad "the witness key is $(stat -c %a "$K"), not 600"
want "witness 1 cosigns its growth to 3 epochs"                             0 "cosigned"      "$A" directory witness --net "$W/three" --roots "$R" --key "$K" --state "$S" --out "$W/c3.json"
want "witness 1 refuses a log that shrank to 2"                             1 "shrank"        "$A" directory witness --net "$W/two" --roots "$R" --key "$K" --state "$S"
want "witness 1 refuses a different epoch 3 (split view)"                   1 "split view"    "$A" directory witness --net "$W/equiv" --roots "$R" --key "$K" --state "$S"

# ctl, holding the memory of the honest epoch 3, shown the other one
ctl --net "$W/three" --state "$W/ctl.json" >/dev/null 2>&1
sed "s#\"$W/three\##\"$W/equiv\##g" "$W/ctl.json" > "$W/ctl-equiv.json"
want "ctl alarms on the other epoch 3 (equivocation)"                       1 "equivocation"  ctl --net "$W/equiv" --state "$W/ctl-equiv.json"

# a leaf whose directory does not verify
cp -r "$W/three" "$W/forged"
node -e 'const fs=require("fs"),p=process.argv[1];const d=JSON.parse(fs.readFileSync(p,"utf8"));const k=Object.keys(d).find(k=>/sig/i.test(k)&&typeof d[k]==="string")||"root_sig_slh";const s=String(d[k]);d[k]=(s[0]==="A"?"B":"A")+s.slice(1);fs.writeFileSync(p,JSON.stringify(d))' "$W/forged/epochs/2.json"
want "log refuses a leaf whose directory does not verify"                   1 "does not verify" "$A" directory log --net "$W/forged" --roots "$R"
want "witness refuses it too"                                               1 "does not verify" "$A" directory witness --net "$W/forged" --roots "$R" --key "$W/w9.key" --state "$W/w9.state"

# cosignatures into the contract, and what ctl makes of them
K1=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).witness_key)' "$W/c3.json")
want "witness 2 (its own key) cosigns the log at 3 epochs"                  0 "cosigned"      "$A" directory witness --net "$W/three" --roots "$R" --key "$W/w2.key" --state "$W/w2.state" --out "$W/c3b.json"
want "both cosignatures are taken into the contract"                        0 "3 cosignature" "$A" directory log --net "$W/three" --roots "$R" --write "$W/three" --add-cosig "$W/c1.json" --add-cosig "$W/c3.json" --add-cosig "$W/c3b.json"
want "ctl: the served head is the head the epochs make"                     0 "as served"     ctl --net "$W/three" --state "$W/ctl2.json" --epoch-witness "$K1"
want "ctl: witnesses on the current head are counted"                       0 "2 witness(es) on the current head" ctl --net "$W/three" --state "$W/ctl2.json"
want "ctl names a pinned witness that did not cosign"                       0 "1 of 2 pinned" ctl --net "$W/three" --state "$W/ctl2.json" --epoch-witness "$K1" --epoch-witness "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
node -e 'const fs=require("fs"),p=process.argv[1],q=process.argv[2];const c=JSON.parse(fs.readFileSync(p,"utf8"));const s=c.sig;c.sig=(s[0]==="A"?"B":"A")+s.slice(1);fs.writeFileSync(q,JSON.stringify(c))' "$W/c3.json" "$W/forged-cosig.json"
want "a forged cosignature is refused at the door"                          1 "does not verify" "$A" directory log --net "$W/three" --roots "$R" --write "$W/three" --add-cosig "$W/forged-cosig.json"
cp -r "$W/three" "$W/lying"
node -e 'const fs=require("fs"),p=process.argv[1],f=process.argv[2];const v=JSON.parse(fs.readFileSync(p,"utf8"));v.cosignatures.push(JSON.parse(fs.readFileSync(f,"utf8")));fs.writeFileSync(p,JSON.stringify(v))' "$W/lying/epoch-log-cosignatures.json" "$W/forged-cosig.json"
want "ctl alarms on a forged cosignature served anyway"                     1 "epoch-log cosignature" ctl --net "$W/lying" --state "$W/ctl3.json"
cp -r "$W/three" "$W/lying-head"
node -e 'const fs=require("fs"),p=process.argv[1];const v=JSON.parse(fs.readFileSync(p,"utf8"));v.root="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";fs.writeFileSync(p,JSON.stringify(v))' "$W/lying-head/epoch-log.json"
want "ctl alarms on a served head the epochs do not make"                   1 "epoch-log.json says" ctl --net "$W/lying-head" --state "$W/ctl4.json"

# the memory is load-bearing
want "WITNESS: with its memory deleted, the witness cosigns the other epoch 3" 0 "cosigned"   "$A" directory witness --net "$W/equiv" --roots "$R" --key "$K" --state "$W/forgot.state" --out "$W/c-equiv.json"
if cmp -s <(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).root)' "$W/c3.json") <(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).root)' "$W/c-equiv.json"); then
  bad "the two epoch-3 histories made the same root"
else
  pass "and the two cosignatures, by one key, name two different roots for size 3 — evidence anyone can check"
fi

if [ "$fail" = 0 ]; then echo "EPOCH-LOG DRILL OK — a witness refuses a split view and a forged leaf; ctl alarms on a lying head and a forged cosignature"; else echo "EPOCH-LOG DRILL FAILED"; exit 1; fi
