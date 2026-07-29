#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make witness-check (M23 Task 4) — the witness kit v2 smoke + a TIMED outsider-onboarding rehearsal.
#
# Proves the single-binary `witnessd` runs from a ONE-FILE config, serves its operator's SELF-DECLARED metadata at
# /info (verified by no one; the key is the only cryptographic fact), aliases /root→/key, stays back-compatible with
# the bare-address form, and — the whole point — still REFUSES A FORK in a quorum. Also times the full "clone →
# running witness" path, which the kit README claims is under ten minutes.
set -euo pipefail
cd "$(dirname "$0")/.."
BIN=target/release/witnessd
ADDR="127.0.0.1:4995"; ADDR2="127.0.0.1:4996"
command -v curl >/dev/null || { echo "✗ curl not found"; exit 1; }

t0=$(date +%s)
echo "== build the single witnessd binary =="
cargo build --release -q -p ainra-services --bin witnessd
t_build=$(( $(date +%s) - t0 ))

json() { node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{process.stdout.write(String(JSON.parse(s)[process.argv[1]]))}catch{process.stdout.write("")}})' "$1"; }
pids=(); cleanup(){ for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }; trap cleanup EXIT
fail=0; ok(){ if eval "$2"; then echo "  ✓ $1"; else echo "  ✗ $1"; fail=1; fi; }

echo "== boot witnessd from a ONE-FILE config =="
"$BIN" "$ADDR" kits/witness/witness.config.json >/tmp/witness-v2.log 2>&1 & pids+=($!)
for _ in $(seq 1 50); do curl -sf "http://$ADDR/root" >/dev/null 2>&1 && break; sleep 0.1; done
t_boot=$(( $(date +%s) - t0 ))

INFO=$(curl -sS "http://$ADDR/info")
ok "/info is self-declared"          "[ \"$(printf '%s' "$INFO" | json self_declared)\" = 'true' ]"
ok "/info carries the operator claim" "[ -n \"$(printf '%s' "$INFO" | json operator)\" ]"
ok "/info carries a region claim"     "[ -n \"$(printf '%s' "$INFO" | json region)\" ]"
KINFO=$(printf '%s' "$INFO" | json ed25519)
KROOT=$(curl -sS "http://$ADDR/root" | json ed25519)
KKEY=$(curl -sS "http://$ADDR/key" | json ed25519)
ok "/root aliases /key"               "[ \"$KROOT\" = \"$KKEY\" ] && [ -n \"$KROOT\" ]"
ok "the /info key IS the witness key" "[ \"$KINFO\" = \"$KROOT\" ]"

echo "== back-compat: the bare-address form still runs (no config) =="
"$BIN" "$ADDR2" >/tmp/witness-v2-nocfg.log 2>&1 & pids+=($!)
for _ in $(seq 1 50); do curl -sf "http://$ADDR2/root" >/dev/null 2>&1 && break; sleep 0.1; done
NC=$(curl -sS "http://$ADDR2/info")
ok "bare-address /info still self-declared, key present, operator empty" \
   "[ \"$(printf '%s' "$NC" | json self_declared)\" = 'true' ] && [ -n \"$(printf '%s' "$NC" | json ed25519)\" ] && [ -z \"$(printf '%s' "$NC" | json operator)\" ]"

echo "== the point of a witness: a quorum still REFUSES A FORK =="
bash tools/drill-networked.sh 5 3 >/tmp/witness-fork.log 2>&1 \
  && ok "networked quorum certifies the honest head and refuses the fork" "grep -qiE 'refus|not certified' /tmp/witness-fork.log" \
  || { echo "  ✗ drill-networked failed"; tail -5 /tmp/witness-fork.log; fail=1; }

echo
echo "onboarding timing (this machine): build ${t_build}s · clone→running witness ${t_boot}s  (kit claim: < 10 min / 600 s)"
[ "$t_boot" -lt 600 ] && echo "  ✓ under the 10-minute onboarding bar" || { echo "  ✗ onboarding exceeded 10 min"; fail=1; }
[ "$fail" -eq 0 ] && echo "✓ witness kit v2 smoke PASSED" || { echo "✗ witness kit v2 smoke FAILED"; exit 1; }
