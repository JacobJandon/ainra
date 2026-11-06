#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# make sign-epoch-rehearsal — one directory change, from request to published epoch, across nine custodian processes
# (PLAN-M52 steps 5–8). TEST-ROOT: every root key here is a rehearsal key made in this run and thrown away after it.
#
#   1. Nine `dkg-participant` custodians run a FROST 5-of-9 DKG, each in its own home; an SLH-DSA root key is made
#      with `slh-root` (a 0600 file). Those two public keys are the pinned roots.
#   2. Two registrars file ACCREDIT requests, signed with their own keys (proof of possession), with the Standard §3
#      prerequisites as file digests and test_root: true. Epoch 1 is proposed, checked, signed by five custodians and
#      the SLH root, assembled and archived (`ainra directory archive`).
#   3. Each refusal of step 5 is shown by its check id against epoch 1.
#   4. registrar-07 revokes its own delegate and registrar-11 distrusts itself from a leaf (two self-requests). Epoch 2
#      is proposed; another party re-derives it; each signing custodian fetches it from two mirrors onto its own
#      home, re-derives the digest from ITS copy, and signs only that. Five shares aggregate; the SLH root signs; the
#      directory is assembled; a transcript and its SHA-256 are written; `ainra directory publish` puts it in the
#      contract; `ainra ctl status` reads a two-epoch history with no alarm and `ainra ctl diff 1 2` shows the change.
#   5. Each refusal of step 6 is shown on a draft epoch 3 (proposed and checked, never signed).
#
# WITNESS (each must be red on the defect it names, or this script fails):
#   · a coordinator who hands the custodians a DIFFERENT but internally consistent proposal is refused: the digest of
#     each custodian's own fetched copy differs from the coordinator's;
#   · two mirrors serving different copies are refused by the custodian;
#   · four shares cannot aggregate;
#   · a directory with only one root signature is refused by assemble AND by publish;
#   · one changed byte in the transcript fails its hash check (kits/ceremony/verify-transcript.mjs, and publish);
#   · publish refuses: an epoch that is not the archive's last + 1, an authentic epoch 2 that is not the approved
#     proposal's digest, and an authentic epoch 2 that no transcript names.
# Showing it red: disable the custodian's comparison of its own digest with the coordinator's (in a scratch copy of
# this file, run with AINRA_ROOT pointing at the repository), and the first witness fails.
set -uo pipefail
ROOT="${AINRA_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT" || exit 2

cargo build --release -q -p ainra-cli-rs --bin ainra || exit 2
cargo build --release -q -p ainra-ceremony --bin dkg-participant --bin slh-root || exit 2
A="$ROOT/target/release/ainra"; P="$ROOT/target/release/dkg-participant"; SLH="$ROOT/target/release/slh-root"
command -v sha256sum >/dev/null 2>&1 || { echo "✗ sha256sum not found"; exit 2; }
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
LOG="$W/log"; : > "$LOG"
fail=0
pass() { echo "  ok    $1"; }
bad()  { echo "  ✗     $1"; fail=1; }
die()  { echo "  ✗     $1"; echo "        ── last lines of the log ──"; tail -15 "$LOG" | sed 's/^/        /'; exit 1; }
b64u_hex()  { node -e 'process.stdout.write(Buffer.from(process.argv[1],"hex").toString("base64url"))' "$1"; }
b64u_file() { node -e 'process.stdout.write(require("fs").readFileSync(process.argv[1]).toString("base64url"))' "$1"; }
fresh()     { head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
edit()      { node -e "const fs=require('fs'),p=process.argv[1];const v=JSON.parse(fs.readFileSync(p,'utf8'));($2)(v);fs.writeFileSync(p,JSON.stringify(v,null,2))" "$1"; }
# Recompute a proposal's signing_bytes_sha256 the way a careful forger would (canonical JSON of the four signed fields),
# so that only the invariant under test is broken.
reseal() { node -e '
  const fs=require("fs"),c=require("crypto"),p=process.argv[1],v=JSON.parse(fs.readFileSync(p,"utf8"));
  const canon=(x)=>Array.isArray(x)?"["+x.map(canon).join(",")+"]":x&&typeof x==="object"?"{"+Object.keys(x).sort().map(k=>JSON.stringify(k)+":"+canon(x[k])).join(",")+"}":JSON.stringify(x);
  const d=v.directory;v.signing_bytes_sha256=c.createHash("sha256").update(canon({entries:d.entries,epoch:d.epoch,issued_at:d.issued_at,revoked_delegates:d.revoked_delegates})).digest("hex");
  fs.writeFileSync(p,JSON.stringify(v,null,2))' "$1"; }

# refused <label> <check id> <command…> — must exit 1 and name the check
refused() {
  local label="$1" id="$2"; shift 2
  local out rc; out=$("$@" 2>&1); rc=$?
  if [ "$rc" = 1 ] && grep -qF "REFUSED [$id]" <<<"$out"; then pass "$label — refused [$id]"
  else bad "$label — wanted REFUSED [$id], got exit $rc"; echo "$out" | sed 's/^/        /' | head -6; fi
}
accepted() {
  local label="$1"; shift
  local out rc; out=$("$@" 2>&1); rc=$?
  if [ "$rc" = 0 ]; then pass "$label"; else bad "$label — exit $rc"; echo "$out" | sed 's/^/        /' | head -6; fi
}

NOW=$(date +%s)
T_FILE1=$((NOW - 7200)); T_EPOCH1=$((NOW - 3600)); T_FILE2=$((NOW - 1800)); T_EPOCH2=$((NOW - 600)); T_EPOCH3=$((NOW - 60))
echo "sign-epoch-rehearsal · TEST-ROOT · one change from request to published epoch, nine custodian processes"

# ── 1. the roots ────────────────────────────────────────────────────────────────────────────────────────────────────
N=9; T=5; BOX="$W/postbox"; mkdir -p "$BOX"
SEED="$(fresh)"
dkg_round() {
  local mode="$1" seed="${2:-}" pids=() ok=0
  for K in $(seq 1 "$N"); do "$P" "$mode" "$K" "$N" "$T" "$BOX" "$W/home-$K" $seed >>"$LOG" 2>&1 & pids+=($!); done
  for p in "${pids[@]}"; do wait "$p" || ok=1; done
  [ "$ok" = 0 ] || die "a custodian failed in $mode"
}
dkg_round dkg1 "$SEED"; dkg_round dkg2; dkg_round dkg3
[ "$(cat "$BOX"/group/*.pub | sort -u | wc -l | tr -d ' ')" = 1 ] || die "the custodians disagree on the group key"
GROUP_HEX="$(cat "$BOX/group/1.pub")"
pass "nine custodians, nine homes: one FROST $T-of-$N group key ${GROUP_HEX:0:16}…"
mkdir -p "$W/slh"
SLH_PUB=$("$SLH" keygen "$W/slh/root.key" 2>>"$LOG") || die "slh-root keygen"
[ "$(stat -c %a "$W/slh/root.key")" = 600 ] && pass "SLH-DSA TEST-ROOT key in a 0600 file" || bad "the SLH key file is not 0600"
cp "$W/slh/root.key" "$W/slh/loose.key"; chmod 644 "$W/slh/loose.key"
"$SLH" pub "$W/slh/loose.key" >/dev/null 2>&1 && bad "slh-root used a key file others can read" || pass "slh-root refuses a key file others can read"
node -e 'require("fs").writeFileSync(process.argv[1],JSON.stringify({root_ed25519:process.argv[2],root_slh:process.argv[3]},null,2)+"\n")' \
  "$W/roots.json" "$(b64u_hex "$GROUP_HEX")" "$SLH_PUB"

# ── the ceremony, as each custodian runs it ─────────────────────────────────────────────────────────────────────────
# Mirrors are directories the coordinator does not control; the frozen (R4) digest is published by the steward and
# matched by an independent party. A custodian copies the proposal (and epoch N) from BOTH mirrors onto its own home,
# refuses if the copies differ, re-derives it with check-proposal from its own copies, takes the message from its own
# copy with sign-request, and refuses unless that digest equals the frozen one AND the coordinator's packet.
custodian_derive() {  # custodian_derive <K> <proposal name> <base name or -> <frozen sha> <coordinator's sha>
  local K="$1" name="$2" base="$3" frozen="$4" packet="$5" h="$W/home-$1/fetched"
  rm -rf "$h"; mkdir -p "$h/a" "$h/b"
  cp "$W/mirror-a/$name" "$h/a/"; cp "$W/mirror-b/$name" "$h/b/"
  cmp -s "$h/a/$name" "$h/b/$name" || { echo "custodian $K refuses: the two mirrors serve different copies of $name"; return 1; }
  local args=()
  if [ "$base" != - ]; then
    cp "$W/mirror-a/$base" "$h/a/"; cp "$W/mirror-b/$base" "$h/b/"
    cmp -s "$h/a/$base" "$h/b/$base" || { echo "custodian $K refuses: the mirrors disagree on epoch N"; return 1; }
    args=(--base "$h/a/$base" --roots "$W/roots.json")
  fi
  "$A" directory check-proposal "$h/a/$name" "${args[@]}" >>"$LOG" 2>&1 || { echo "custodian $K refuses: check-proposal fails on its own copy"; return 1; }
  "$A" directory sign-request "$h/a/$name" > "$h/sign-request.txt" || return 1
  local own; own=$(sed -n 's/^sha256 //p' "$h/sign-request.txt")
  [ "$own" = "$frozen" ] || { echo "custodian $K refuses: its own copy's digest ${own:0:16}… is not the frozen ${frozen:0:16}…"; return 1; }
  [ "$own" = "$packet" ] || { echo "custodian $K refuses: its own copy's digest ${own:0:16}… is not the coordinator's ${packet:0:16}…"; return 1; }
  head -1 "$h/sign-request.txt" > "$W/home-$K/msg.hex"
  echo "custodian $K reads aloud ${own:0:16}… and signs"
}
QUORUM="1 3 5 7 9"
# frost_sign <out b64 var file> — the quorum commits and signs over each custodian's OWN msg.hex; aggregate.
frost_sign() {
  local hex; hex=$(cat "$W/home-1/msg.hex")
  rm -rf "$BOX/sign"; local s; s="$(fresh)"   # fresh nonces every round: a nonce is never reused across messages
  for K in $QUORUM; do "$P" commit "$K" "$BOX" "$W/home-$K" "$s" >>"$LOG" 2>&1 || return 1; done
  for K in $QUORUM; do "$P" sign "$K" "$BOX" "$W/home-$K" "$(cat "$W/home-$K/msg.hex")" >>"$LOG" 2>&1 || return 1; done
  "$P" aggregate "$BOX" "$hex" >>"$LOG" 2>&1 || return 1
  b64u_file "$BOX/signature.bin" > "$1"
}
publish_to_mirrors() { mkdir -p "$W/mirror-a" "$W/mirror-b"; for f in "$@"; do cp "$f" "$W/mirror-a/"; cp "$f" "$W/mirror-b/"; done; }

# ── 2. epoch 1 ──────────────────────────────────────────────────────────────────────────────────────────────────────
mkdir -p "$W/reg" "$W/req" "$W/prereq"
for r in 07 11 23; do "$A" init "$W/reg/registrar-$r" "registrar-$r" --seed "7$r" >>"$LOG" 2>&1 || die "init registrar-$r"; done
"$A" init "$W/reg/impostor-07" registrar-07 --seed 999 >>"$LOG" 2>&1 || die "init the impostor"   # a thief's fresh keys, same name
for f in agreement independence monitor audit; do echo "TEST-ROOT rehearsal artifact ($f) — not a real document" > "$W/prereq/$f.txt"; done
node -e '
  const fs=require("fs"),c=require("crypto"),d=process.argv[1],h=(f)=>c.createHash("sha256").update(fs.readFileSync(d+"/"+f)).digest("hex");
  const a=(f)=>({file:f,sha256:h(f)});
  fs.writeFileSync(process.argv[2],JSON.stringify({prerequisites:{agreement:a("agreement.txt"),independence_attestation:a("independence.txt"),
    competitor_monitor:a("monitor.txt"),audit:{...a("audit.txt"),date:"2026-11-04"}}}))' "$W/prereq" "$W/prereq/evidence.json"
for r in 07 11; do
  "$A" directory request ACCREDIT --registrar "$W/reg/registrar-$r" --filed-at "$T_FILE1" --evidence "$W/prereq/evidence.json" --test-root --out "$W/req/acc-$r.json" >>"$LOG" 2>&1 || die "request ACCREDIT $r"
  "$A" accredit "$W/reg/registrar-$r" > "$W/req/accreditation-$r.json" 2>>"$LOG"
  accepted "ACCREDIT registrar-$r: proof of possession of every key, §3 prerequisites, TEST-ROOT, keys as served" \
    "$A" directory check-request "$W/req/acc-$r.json" --accreditation "$W/req/accreditation-$r.json"
done
"$A" directory propose --request "$W/req/acc-07.json" --request "$W/req/acc-11.json" --issued-at "$T_EPOCH1" --out "$W/p1.json" >>"$LOG" 2>&1 || die "propose epoch 1"
F1=$("$A" directory sign-request "$W/p1.json" | sed -n 's/^sha256 //p')
publish_to_mirrors "$W/p1.json"
for K in $QUORUM; do custodian_derive "$K" p1.json - "$F1" "$F1" >>"$LOG" 2>&1 || die "custodian $K on epoch 1"; done
frost_sign "$W/p1.ed" || die "FROST signing of epoch 1"
"$SLH" sign "$W/slh/root.key" "$(cat "$W/home-1/msg.hex")" > "$W/p1.slh" 2>>"$LOG" || die "SLH signing of epoch 1"
"$A" directory assemble "$W/p1.json" --sig-ed25519 "$(cat "$W/p1.ed")" --sig-slh "$(cat "$W/p1.slh")" --roots "$W/roots.json" --out "$W/d1.json" >>"$LOG" 2>&1 || die "assemble epoch 1"
C="$W/contract"; mkdir -p "$C"
cp "$W/roots.json" "$C/roots.json"; echo '{"registrars":[]}' > "$C/registry.json"
"$A" directory archive "$W/d1.json" --roots "$W/roots.json" --into "$C" >>"$LOG" 2>&1 || die "archive epoch 1"
cp "$W/d1.json" "$C/directory.json"
pass "epoch 1: two ACCREDIT requests → proposal → 5 of 9 shares + SLH → assembled → archived"
# the rehearsal signs the epoch vectors, whose issued_at is fixed; read them at that clock, not today's (D-094 cadence)
NOW_D1=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).issued_at)' "$W/d1.json")
accepted "ctl status reads epoch 1 with no alarm (memory written)" "$A" ctl status --net "$C" --roots "$W/roots.json" --state "$W/seen.json" --now "$NOW_D1"

# ── 3. step 5: each refusal by name, against epoch 1 ────────────────────────────────────────────────────────────────
D1=(--directory "$C/directory.json" --roots "$W/roots.json")
"$A" directory request ACCREDIT --registrar "$W/reg/registrar-23" --filed-at "$T_FILE2" --evidence "$W/prereq/evidence.json" --test-root --out "$W/req/acc-23.json" >>"$LOG" 2>&1
"$A" accredit "$W/reg/registrar-23" > "$W/req/accreditation-23.json" 2>>"$LOG"
accepted "ACCREDIT of a new registrar-23 against epoch 1" "$A" directory check-request "$W/req/acc-23.json" "${D1[@]}" --accreditation "$W/req/accreditation-23.json"
cp "$W/req/acc-23.json" "$W/req/acc-23-nopop.json"; edit "$W/req/acc-23-nopop.json" 'v=>{delete v.proofs}'
refused "a new key without proof of possession" proof-of-possession "$A" directory check-request "$W/req/acc-23-nopop.json" "${D1[@]}"
cp "$W/req/acc-23.json" "$W/req/acc-23-other.json"; edit "$W/req/acc-23-other.json" 'v=>{v.proofs.possession.log_root_slh=JSON.parse(require("fs").readFileSync(process.argv[1].replace("acc-23-other","acc-07"),"utf8")).proofs.possession.log_root_slh}'
refused "a log root proof made over another request" proof-of-possession "$A" directory check-request "$W/req/acc-23-other.json" "${D1[@]}"
refused "keys that differ from the served /accreditation" accreditation-match "$A" directory check-request "$W/req/acc-23.json" "${D1[@]}" --accreditation "$W/req/accreditation-11.json"
"$A" directory request ACCREDIT --registrar "$W/reg/registrar-23" --filed-at "$T_FILE2" --test-root --out "$W/req/acc-23-bare.json" >>"$LOG" 2>&1
refused "an ACCREDIT without the Standard §3 prerequisites" prerequisites "$A" directory check-request "$W/req/acc-23-bare.json" "${D1[@]}"
"$A" directory request ACCREDIT --registrar "$W/reg/registrar-23" --filed-at "$T_FILE2" --evidence "$W/prereq/evidence.json" --out "$W/req/acc-23-real.json" >>"$LOG" 2>&1
refused "an ACCREDIT without test_root while no legal entity exists" test-root-only "$A" directory check-request "$W/req/acc-23-real.json" "${D1[@]}"
"$A" directory request ACCREDIT --registrar "$W/reg/impostor-07" --filed-at "$T_FILE2" --evidence "$W/prereq/evidence.json" --test-root --out "$W/req/acc-imp.json" >>"$LOG" 2>&1
refused "an ACCREDIT that changes an accredited registrar's keys (moves trust)" moves-trust "$A" directory check-request "$W/req/acc-imp.json" "${D1[@]}"
"$A" directory request REGISTRAR_KEY_ROLL --registrar "$W/reg/registrar-07" --filed-at "$T_FILE2" --out "$W/req/roll.json" >>"$LOG" 2>&1
refused "REGISTRAR_KEY_ROLL while its model is undecided" moves-trust "$A" directory check-request "$W/req/roll.json" "${D1[@]}"
"$A" directory request ROOT_KEY_ROLL --subject root --filer steward --filed-at "$T_FILE2" --out "$W/req/rootroll.json" >>"$LOG" 2>&1
refused "ROOT_KEY_ROLL (its own track)" root-key-roll "$A" directory check-request "$W/req/rootroll.json" "${D1[@]}"
"$A" directory request WITHDRAW --registrar "$W/reg/impostor-07" --filed-at "$T_FILE2" --out "$W/req/wd-imp.json" >>"$LOG" 2>&1
refused "a self-WITHDRAW signed by a key that is not the current one" self-signature "$A" directory check-request "$W/req/wd-imp.json" "${D1[@]}"
"$A" directory request REVOKE_DELEGATE --registrar "$W/reg/impostor-07" --filed-at "$T_FILE2" --out "$W/req/rd-imp.json" >>"$LOG" 2>&1
refused "a REVOKE_DELEGATE of a delegate the registrar's log root never signed" delegate-owned "$A" directory check-request "$W/req/rd-imp.json" "${D1[@]}"
"$A" directory request DISTRUST_FROM_LEAF --subject registrar-11 --filer monitor-01 --leaf 5 --filed-at "$T_FILE2" --out "$W/req/adv-none.json" >>"$LOG" 2>&1
refused "an adverse request with no compliance record" adverse-notice-chain "$A" directory check-request "$W/req/adv-none.json" "${D1[@]}"
mkrecord() {  # mkrecord <out> <networks…> — the ladder at D-094 item 11's numbers: notice 1, notice 2 fifteen days
  # later, a cure window closing 31 days after notice 1, then one reproduction per network given
  node -e '
    const [out,now,...nets]=process.argv.slice(1),t=Number(now),d=86400,h=(i)=>String(i).repeat(64).slice(0,64),n1=t-70*d;
    const reps=nets.map((n,i)=>({vantage:"vp-"+i,network:n,at:t-60000+i,report_sha256:h(i+3)}));
    require("fs").writeFileSync(out,JSON.stringify({compliance:{notices:[{n:1,at:n1,sha256:h(1)},{n:2,at:n1+15*d,sha256:h(2)}],
      cure_window_ends:n1+31*d,reproductions:reps}}))' "$@"
}
mkrecord "$W/req/one.json" "$NOW" net-a;         mkrecord "$W/req/same.json" "$NOW" net-a net-a;  mkrecord "$W/req/two.json" "$NOW" net-a net-b
for e in one same two; do "$A" directory request DISTRUST_FROM_LEAF --subject registrar-11 --filer monitor-01 --leaf 5 --filed-at "$T_FILE2" --evidence "$W/req/$e.json" --out "$W/req/adv-$e.json" >>"$LOG" 2>&1; done
refused "an adverse request reproduced from one vantage point" adverse-vantage "$A" directory check-request "$W/req/adv-one.json" "${D1[@]}"
refused "an adverse request reproduced twice from one network" adverse-vantage "$A" directory check-request "$W/req/adv-same.json" "${D1[@]}"
accepted "an adverse request with a full compliance record (two vantage points, distinct networks)" "$A" directory check-request "$W/req/adv-two.json" "${D1[@]}"
# D-096: the record a monitor really files is the one kits/probe/notice.mjs writes from probe reports. Run its ladder
# over three cycles of reports from two networks (notice 1, notice 2 fifteen days later, the breach record after the
# 30-day cure window) and hand the evidence it writes to the checker; and a record whose cure window is 20 days long.
node --input-type=module -e '
  const [, , mod, nowArg, outOk, outEarly] = process.argv; const { step, evidence, fresh, DAY } = await import(mod); const now = Number(nowArg), T0 = now - 50 * DAY;
  const rep = (id, net, at) => { const report = { registrar_id: "registrar-11", vantage: { id, network: net }, ran_at: new Date(at * 1000).toISOString(),
    verdict: "NON-COMPLIANT", checks: [{ id: "P3", pass: false }] }; return { report, sha256: String(at % 10) .repeat(64).slice(0, 63) + id.slice(-1) }; };
  let L = fresh("registrar-11"); for (const d of [0, 15, 32]) L = step(L, [rep("vp-a", "net-1", T0 + d * DAY), rep("vp-b", "net-2", T0 + d * DAY + 60)], T0 + d * DAY).state;
  if (L.stage !== "breach") { console.error("the ladder did not reach the breach record: " + L.stage); process.exit(1); }
  const fs = await import("node:fs"); fs.writeFileSync(outOk, JSON.stringify(evidence(L, "DISTRUST_FROM_LEAF", now)));
  const early = evidence(L, "DISTRUST_FROM_LEAF", now); early.compliance.cure_window_ends = early.compliance.notices[0].at + 20 * DAY;
  fs.writeFileSync(outEarly, JSON.stringify(early));
' rehearsal "$PWD/kits/probe/notice.mjs" "$NOW" "$W/req/ladder.json" "$W/req/ladder-early.json"
for e in ladder ladder-early; do "$A" directory request DISTRUST_FROM_LEAF --subject registrar-11 --filer monitor-01 --leaf 5 --filed-at "$T_FILE2" --evidence "$W/req/$e.json" --out "$W/req/adv-$e.json" >>"$LOG" 2>&1; done
accepted "a DISTRUST_FROM_LEAF whose evidence is the record kits/probe/notice.mjs wrote from three cycles of probe reports" "$A" directory check-request "$W/req/adv-ladder.json" "${D1[@]}"
refused "the same record with a 20-day cure window (D-094: at least 30)" adverse-notice-chain "$A" directory check-request "$W/req/adv-ladder-early.json" "${D1[@]}"
# D-098: the root's emergency stop. Two homes made from registrar-11's own seed, each issued a different passport, are
# a registrar running two divergent copies of its log: one key, two histories at one size. Their signed checkpoints
# are the proof; the request carrying it skips the ladder. The same checkpoint twice is not a fork.
mkdir -p "$W/fork"
for x in a b; do "$A" init "$W/fork/$x" registrar-11 --seed 711 >>"$LOG" 2>&1 || die "init fork-$x"; done
"$A" issue "$W/fork/a" --operator acme --lineage alpha --version 1.0.0 >>"$LOG" 2>&1 && "$A" issue "$W/fork/b" --operator globex --lineage beta --version 1.0.0 >>"$LOG" 2>&1 || die "issue into the two copies"
for x in a b; do sub=$("$A" list "$W/fork/$x" 2>/dev/null | grep -o 'ainra:registrar-11:[^ ]*' | head -1); "$A" present "$W/fork/$x" "$sub" > "$W/fork/$x.json" 2>>"$LOG" || die "present fork-$x"; done
node -e '
  const fs = require("fs"), [a, b, out, same] = process.argv.slice(1);
  const cp = (f) => { const r = JSON.parse(fs.readFileSync(f, "utf8")); return { checkpoint: { origin: r.log_origin, size: r.checkpoint_size, root: r.checkpoint_root }, checkpoint_sig: r.checkpoint_sig }; };
  fs.writeFileSync(out, JSON.stringify({ compliance: { fork_proof: { a: cp(a), b: cp(b) } } }));
  fs.writeFileSync(same, JSON.stringify({ compliance: { fork_proof: { a: cp(a), b: cp(a) } } }));
' "$W/fork/a.json" "$W/fork/b.json" "$W/req/fork.json" "$W/req/fork-same.json"
for e in fork fork-same; do "$A" directory request DISTRUST_FROM_LEAF --subject registrar-11 --filer monitor-01 --leaf 1 --filed-at "$T_FILE2" --evidence "$W/req/$e.json" --out "$W/req/adv-$e.json" >>"$LOG" 2>&1; done
accepted "an emergency DISTRUST_FROM_LEAF carrying a real fork of registrar-11's log (no notice, no cure, no reproductions)" "$A" directory check-request "$W/req/adv-fork.json" "${D1[@]}"
refused "the same request with one checkpoint twice (not a fork)" adverse-proof "$A" directory check-request "$W/req/adv-fork-same.json" "${D1[@]}"

# ── 4. epoch 2: two self-requests, proposed, re-derived, signed by custodians from their own copies, published ──────
"$A" directory request REVOKE_DELEGATE --registrar "$W/reg/registrar-07" --filed-at "$T_FILE2" --out "$W/req/rd-07.json" >>"$LOG" 2>&1 || die "request REVOKE_DELEGATE"
"$A" directory request DISTRUST_FROM_LEAF --registrar "$W/reg/registrar-11" --leaf 1000 --filed-at "$T_FILE2" --out "$W/req/dl-11.json" >>"$LOG" 2>&1 || die "request DISTRUST_FROM_LEAF"
accepted "REVOKE_DELEGATE filed by registrar-07, signed by its current issuer key" "$A" directory check-request "$W/req/rd-07.json" "${D1[@]}"
accepted "DISTRUST_FROM_LEAF filed by registrar-11 about itself" "$A" directory check-request "$W/req/dl-11.json" "${D1[@]}"
cp "$W/req/rd-07.json" "$W/req/rd-07-swapped.json"; edit "$W/req/rd-07-swapped.json" 'v=>{v.proofs.filer=JSON.parse(require("fs").readFileSync(process.argv[1].replace("rd-07-swapped","dl-11"),"utf8")).proofs.filer}'
refused "a self-request carrying another registrar's signature" self-signature "$A" directory check-request "$W/req/rd-07-swapped.json" "${D1[@]}"
"$A" directory propose --base "$C/directory.json" --roots "$W/roots.json" --request "$W/req/rd-07.json" --request "$W/req/dl-11.json" --issued-at "$T_EPOCH2" --out "$W/p2.json" >>"$LOG" 2>&1 || die "propose epoch 2"
F2=$("$A" directory sign-request "$W/p2.json" | sed -n 's/^sha256 //p')
mkdir -p "$W/independent"; cp "$W/p2.json" "$C/epochs/1.json" "$W/independent/"
IND=$("$A" directory check-proposal "$W/independent/p2.json" --base "$W/independent/1.json" --roots "$W/roots.json" | sed -n 's/^  signing bytes SHA-256 //p')
[ -n "$IND" ] && [ "$IND" = "$F2" ] && pass "R4: another party re-derives epoch 2 from epoch 1 and the requests alone — the same digest ${F2:0:16}…" || bad "the independent re-derivation does not match ($IND vs $F2)"
cp "$C/epochs/1.json" "$W/epoch-1.json"
publish_to_mirrors "$W/p2.json" "$W/epoch-1.json"
# The coordinator's DIFFERENT, internally consistent proposal: the same requests, one second later.
"$A" directory propose --base "$C/directory.json" --roots "$W/roots.json" --request "$W/req/rd-07.json" --request "$W/req/dl-11.json" --issued-at "$((T_EPOCH2 + 1))" --out "$W/p2-evil.json" >>"$LOG" 2>&1 || die "propose the other epoch 2"
accepted "the coordinator's other epoch 2 passes check-proposal on its own (it is self-consistent)" "$A" directory check-proposal "$W/p2-evil.json" --base "$C/directory.json" --roots "$W/roots.json"
EVIL=$("$A" directory sign-request "$W/p2-evil.json" | sed -n 's/^sha256 //p')
refusals=0
for K in $QUORUM; do custodian_derive "$K" p2.json epoch-1.json "$F2" "$EVIL" >>"$LOG" 2>&1 || refusals=$((refusals + 1)); done
[ "$refusals" = 5 ] && pass "WITNESS: handed a different, self-consistent proposal by the coordinator, all 5 custodians refuse (their own copy's digest differs)" \
  || bad "WITNESS: only $refusals of 5 custodians refused the coordinator's different proposal"
cp "$W/p2-evil.json" "$W/mirror-b/p2.json"
custodian_derive 1 p2.json epoch-1.json "$F2" "$F2" >>"$LOG" 2>&1 && bad "WITNESS: a custodian signed although the two mirrors disagree" \
  || pass "WITNESS: two mirrors serving different copies — the custodian refuses"
cp "$W/p2.json" "$W/mirror-b/p2.json"
for K in $QUORUM; do custodian_derive "$K" p2.json epoch-1.json "$F2" "$F2" >>"$LOG" 2>&1 || die "custodian $K on the honest epoch 2"; done
pass "each of the 5 signing custodians fetched epoch 2 from two mirrors and derived ${F2:0:16}… from its own copy"
frost_sign "$W/p2.ed" || die "FROST signing of epoch 2"
mv "$BOX/sign/share-9.bin" "$W/share-9.bin"
"$P" aggregate "$BOX" "$(cat "$W/home-1/msg.hex")" >>"$LOG" 2>&1 && bad "WITNESS: four shares produced a signature" || pass "WITNESS: four shares cannot aggregate"
mv "$W/share-9.bin" "$BOX/sign/share-9.bin"
"$SLH" sign "$W/slh/root.key" "$(cat "$W/home-1/msg.hex")" > "$W/p2.slh" 2>>"$LOG" || die "SLH signing of epoch 2"
refused "WITNESS: assemble with only the FROST signature" assemble-both-roots "$A" directory assemble "$W/p2.json" --sig-ed25519 "$(cat "$W/p2.ed")" --sig-slh "" --roots "$W/roots.json" --out "$W/d2-x.json"
refused "WITNESS: assemble with the SLH signature of epoch 1" assemble-both-roots "$A" directory assemble "$W/p2.json" --sig-ed25519 "$(cat "$W/p2.ed")" --sig-slh "$(cat "$W/p1.slh")" --roots "$W/roots.json" --out "$W/d2-x.json"
"$A" directory assemble "$W/p2.json" --sig-ed25519 "$(cat "$W/p2.ed")" --sig-slh "$(cat "$W/p2.slh")" --roots "$W/roots.json" --out "$W/d2.json" >>"$LOG" 2>&1 || die "assemble epoch 2"
pass "epoch 2 assembled: both root signatures verify over the proposal's signing bytes"

# the transcript, and its hash for witnesses to recompute
PD2=$("$A" directory sign-request "$W/p2.json" | sed -n 's/^proposal //p')
node -e '
  const fs=require("fs"),[out,w,pd,sha,ind]=process.argv.slice(1),d=JSON.parse(fs.readFileSync(w+"/d2.json","utf8")),r=JSON.parse(fs.readFileSync(w+"/roots.json","utf8"));
  const checks=[1,3,5,7,9].map((k)=>{const t=fs.readFileSync(`${w}/home-${k}/fetched/sign-request.txt`,"utf8");
    return {custodian:k,own_copy_sha256:/^sha256 (.*)$/m.exec(t)[1],mirrors_agree:true,read_aloud:sha.slice(0,16)};});
  fs.writeFileSync(out,JSON.stringify({kind:"ainra/epoch-ceremony-transcript/v1-TESTROOT",
    label:"TEST-ROOT rehearsal (make sign-epoch-rehearsal), not a real ceremony",epoch:d.epoch,base_epoch:d.epoch-1,
    proposal_digest:pd,signing_bytes_sha256:sha,independent_check:ind,root_ed25519:r.root_ed25519,root_slh:r.root_slh,
    custodians:9,threshold:5,signers:[1,3,5,7,9],custodian_checks:checks,
    sig_root_ed25519:d.sig_root_ed25519,sig_root_slh:d.sig_root_slh},null,2)+"\n")' "$W/transcript.json" "$W" "$PD2" "$F2" "$IND"
(cd "$W" && sha256sum transcript.json > transcript.sha256)
accepted "the transcript recomputes to its published SHA-256 (kits/ceremony/verify-transcript.mjs)" node kits/ceremony/verify-transcript.mjs --transcript "$W/transcript.json" --sha256 "$W/transcript.sha256"
cp "$W/transcript.json" "$W/transcript-flipped.json"
node -e 'const fs=require("fs"),p=process.argv[1],b=fs.readFileSync(p);const i=b.indexOf("signers");b[i]=b[i]^1;fs.writeFileSync(p,b)' "$W/transcript-flipped.json"
node kits/ceremony/verify-transcript.mjs --transcript "$W/transcript-flipped.json" --sha256 "$W/transcript.sha256" >>"$LOG" 2>&1 \
  && bad "WITNESS: a transcript with one changed byte passed its hash check" || pass "WITNESS: one changed byte in the transcript fails its hash check"

# ── step 8: publish, and each refusal ───────────────────────────────────────────────────────────────────────────────
PUB=(--roots "$W/roots.json" --into "$C")
cp "$W/d2.json" "$W/d2-one.json"; edit "$W/d2-one.json" 'v=>{v.sig_root_slh=""}'
refused "WITNESS: publish a directory with only one root signature" publish-both-roots "$A" directory publish "$W/d2-one.json" "${PUB[@]}" --proposal "$W/p2.json" --transcript "$W/transcript.json"
refused "publish an epoch that is not the archive's last + 1 (epoch 1 again)" publish-next-epoch "$A" directory publish "$W/d1.json" "${PUB[@]}" --proposal "$W/p1.json" --transcript "$W/transcript.json"
# An authentic epoch 2 that was never approved: the rehearsal plays a colluding quorum and signs the other proposal.
for K in $QUORUM; do cp "$W/p2-evil.json" "$W/home-$K/p2-evil.json"; "$A" directory sign-request "$W/home-$K/p2-evil.json" | head -1 > "$W/home-$K/msg.hex"; done
frost_sign "$W/evil.ed" || die "FROST signing of the other epoch 2"
"$SLH" sign "$W/slh/root.key" "$(cat "$W/home-1/msg.hex")" > "$W/evil.slh" 2>>"$LOG" || die "SLH signing of the other epoch 2"
"$A" directory assemble "$W/p2-evil.json" --sig-ed25519 "$(cat "$W/evil.ed")" --sig-slh "$(cat "$W/evil.slh")" --roots "$W/roots.json" --out "$W/d2-evil.json" >>"$LOG" 2>&1 || die "assemble the other epoch 2"
refused "publish an authentic epoch 2 that is not the approved proposal's digest" publish-approved "$A" directory publish "$W/d2-evil.json" "${PUB[@]}" --proposal "$W/p2.json" --transcript "$W/transcript.json"
refused "publish an authentic epoch 2 that no transcript names" publish-transcript "$A" directory publish "$W/d2-evil.json" "${PUB[@]}" --proposal "$W/p2-evil.json" --transcript "$W/transcript.json"
refused "WITNESS: publish with a transcript that fails its published SHA-256" publish-transcript "$A" directory publish "$W/d2.json" "${PUB[@]}" --proposal "$W/p2.json" --transcript "$W/transcript-flipped.json" --transcript-sha256 "$W/transcript.sha256"
[ "$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).epochs.length)' "$C/epochs.json")" = 1 ] \
  && pass "after every refusal the archive still holds epoch 1 only" || bad "a refused publish changed the archive"
accepted "publish epoch 2: both roots, the approved digest, a transcript naming it" "$A" directory publish "$W/d2.json" "${PUB[@]}" --proposal "$W/p2.json" --transcript "$W/transcript.json" --transcript-sha256 "$W/transcript.sha256"
NOW_D2=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).issued_at)' "$W/d2.json")
out=$("$A" ctl status --net "$C" --roots "$W/roots.json" --state "$W/seen.json" --now "$NOW_D2" 2>&1); rc=$?
[ "$rc" = 0 ] && grep -q "epoch history: 2 epoch(s)" <<<"$out" && grep -q "CTL OK" <<<"$out" \
  && pass "ainra ctl status: a two-epoch history, no alarm, memory moved forward from epoch 1" || { bad "ctl status after publish (exit $rc)"; echo "$out" | sed 's/^/        /' | head -20; }
out=$("$A" ctl diff 1 2 --net "$C" 2>&1)
grep -q "+ revoked delegate" <<<"$out" && grep -q "changed      registrar-11: distrust_from_leaf" <<<"$out" \
  && pass "ainra ctl diff 1 2: the revoked delegate and registrar-11's cutoff" || { bad "ctl diff 1 2"; echo "$out" | sed 's/^/        /'; }
node -e 'const e=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).epochs[1];process.exit(e.proposal&&e.ceremony&&e.proposal.path==="proposals/2.json"?0:1)' "$C/epochs.json" \
  && pass "epochs.json records epoch 2's proposal and ceremony transcript" || bad "epochs.json does not name epoch 2's proposal and transcript"

# ── 5. step 6: each proposal refusal by name, on a draft epoch 3 (never signed) ─────────────────────────────────────
"$A" directory request DISTRUST_FROM_LEAF --registrar "$W/reg/registrar-07" --leaf 50 --filed-at "$T_EPOCH2" --out "$W/req/dl-07.json" >>"$LOG" 2>&1
"$A" directory propose --base "$C/directory.json" --roots "$W/roots.json" --request "$W/req/dl-07.json" --issued-at "$T_EPOCH3" --out "$W/p3.json" >>"$LOG" 2>&1 || die "propose epoch 3"
B2=(--base "$C/directory.json" --roots "$W/roots.json")
accepted "the honest draft of epoch 3 re-derives from epoch 2" "$A" directory check-proposal "$W/p3.json" "${B2[@]}"
variant() { cp "$W/p3.json" "$W/p3-$1.json"; edit "$W/p3-$1.json" "$2"; [ "${3:-}" = reseal ] && reseal "$W/p3-$1.json"; echo "$W/p3-$1.json"; }
refused "a skipped epoch (3 → 4)"                       proposal-epoch            "$A" directory check-proposal "$(variant skip 'v=>{v.epoch=4;v.directory.epoch=4}' reseal)" "${B2[@]}"
refused "an entry dropped without a WITHDRAW"           proposal-no-drop          "$A" directory check-proposal "$(variant drop 'v=>{v.directory.entries=v.directory.entries.filter(e=>e.registrar!=="registrar-11")}' reseal)" "${B2[@]}"
refused "a field outside the frozen schema"             proposal-schema           "$A" directory check-proposal "$(variant field 'v=>{v.directory.entries[0].approvers=["k1","k2"]}')" "${B2[@]}"
refused "a distrust cutoff lifted"                      proposal-cutoff           "$A" directory check-proposal "$(variant lift 'v=>{for(const e of v.directory.entries)if(e.registrar==="registrar-11")delete e.distrust_from_leaf}' reseal)" "${B2[@]}"
refused "a distrust cutoff moved later"                 proposal-cutoff           "$A" directory check-proposal "$(variant later 'v=>{for(const e of v.directory.entries)if(e.registrar==="registrar-11")e.distrust_from_leaf=2000}' reseal)" "${B2[@]}"
refused "a revoked delegate removed"                    proposal-revocations-kept "$A" directory check-proposal "$(variant unrevoke 'v=>{v.directory.revoked_delegates=[]}' reseal)" "${B2[@]}"
refused "a diff that does not match"                    proposal-diff             "$A" directory check-proposal "$(variant diff 'v=>{v.diff[0].change="~ nothing changes"}')" "${B2[@]}"
refused "a signing-bytes digest that does not match"    proposal-digest           "$A" directory check-proposal "$(variant digest 'v=>{v.signing_bytes_sha256="0".repeat(64)}')" "${B2[@]}"
refused "an endpoint moved in a self-consistent directory" proposal-rederive         "$A" directory check-proposal "$(variant swap 'v=>{v.directory.entries[0].status_uri="status://elsewhere/1"}' reseal)" "${B2[@]}"
refused "sign-request on a proposal whose digest lies"  proposal-digest           "$A" directory sign-request "$W/p3-digest.json"

echo
if [ "$fail" = 0 ]; then
  echo "SIGN-EPOCH-REHEARSAL OK — TEST-ROOT. A change went request → check → proposal → 5-of-9 + SLH signature → publish,"
  echo "  every custodian signed only what it derived from its own copy, and each refusal of PLAN-M52 steps 5–8 was shown by name."
  exit 0
fi
echo "SIGN-EPOCH-REHEARSAL FAILED"; exit 1
