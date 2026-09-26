#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# make live-up · live-down · live-status — a registrar that KEEPS TIME, with the public door open (M35).
#
# The staging network (`make stage-up`) is a reproducible reference world pinned to 2026-04-21, and says so. This is
# the other thing: the same registrar on the WALL CLOCK, renewing its delegates before they lapse and presenting
# every passport against the current checkpoint. It is what a stranger's agent should actually talk to, and what
# `make identity-e2e` proves end to end.
#
# It is still TEST-ROOT. The registrar id is `registrar-07`, whose issuer key derives from its id, so it is the key
# the published directory already accredits: verifiers need no new genesis to trust it. The state is fresh and
# lives in live/ (gitignored). Nothing here is production, and nothing here claims to be.
set -uo pipefail
cd "$(dirname "$0")/.."

PORT="${LIVE_PORT:-4970}"
ID="${LIVE_ID:-registrar-07}"
DIR="live/$ID"
URL="http://127.0.0.1:$PORT"
PIDF="live/$ID.pid"
LOG="live/$ID.log"

up() {
  mkdir -p live
  if curl -sf -m 2 "$URL/accreditation" >/dev/null 2>&1; then echo "live registrar already up · $URL"; return 0; fi
  cargo build --release -q -p ainra-services --bin registrar-box || { echo "build failed"; exit 1; }
  # Writes (/issue, /revoke, /renew) need a bearer token — the registrar refuses them otherwise (M35). The token is
  # generated here, kept 0600 in live/ (gitignored), and never printed. The public demo door needs none: it is
  # rate-limited and mints only specimens.
  TOKF="live/.issue-token"
  if [ ! -s "$TOKF" ]; then (umask 077; head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$TOKF"); fi
  # AINRA_CLOCK=wall is also the default; it is stated here so nobody has to know that.
  AINRA_STAGE=1 AINRA_CLOCK=wall AINRA_STAGE_ISSUE_TOKEN="$(cat "$TOKF")" \
    setsid ./target/release/registrar-box "127.0.0.1:$PORT" "$ID" "$DIR" \
    >"$LOG" 2>&1 </dev/null &
  echo $! >"$PIDF"
  for _ in $(seq 1 50); do curl -sf -m 1 "$URL/accreditation" >/dev/null 2>&1 && break; sleep 0.2; done
  if ! curl -sf -m 2 "$URL/accreditation" >/dev/null 2>&1; then
    echo "live registrar did not come up — log:"; tail -5 "$LOG"; exit 1
  fi
  echo "live registrar up · $URL · wall clock · public door open · TEST-ROOT"
  grep -E "re-certified|RELOADED" "$LOG" | sed 's/^/  /' || true
}

down() {
  if [ -f "$PIDF" ] && kill "$(cat "$PIDF")" 2>/dev/null; then echo "live registrar stopped"; else echo "live registrar was not running"; fi
  rm -f "$PIDF"
}

status() {
  if ! curl -sf -m 2 "$URL/accreditation" >/dev/null 2>&1; then echo "live registrar DOWN · $URL"; return 1; fi
  NOW=$(date +%s)
  echo "live registrar UP · $URL · checked at the real clock ($NOW)"
  # The check the pinned boards could never make: the delegate that signs a presentation issued NOW, read from a
  # real presentation rather than from the registrar's own description of itself.
  SUB=$(curl -sf -m 3 "$URL/records" | python3 -c 'import json,sys; r=json.load(sys.stdin); r=r if isinstance(r,list) else r.get("records",[]); print(r[0]["sub"] if r else "")' 2>/dev/null)
  if [ -z "$SUB" ]; then echo "  no passports issued yet — run make identity-e2e"; return 0; fi
  curl -sf -m 3 "$URL/present?sub=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$SUB")&now=$NOW" | python3 -c '
import json,sys,time
b=json.load(sys.stdin)
def window(o):
    if isinstance(o,dict):
        if isinstance(o.get("nbf"),int) and isinstance(o.get("exp"),int): return o["nbf"],o["exp"]
        for v in o.values():
            w=window(v)
            if w: return w
nbf,exp=window(b.get("checkpoint_sig",{})) or (0,0)
now=int(time.time())
ok=nbf<=now<=exp
d=lambda t: time.strftime("%Y-%m-%d",time.gmtime(t))
verdict = "OK" if ok else "EXPIRED - presentations will not verify"
print(f"  checkpoint delegate {d(nbf)} → {d(exp)} · {(exp-now)//86400} days left · {verdict}")
sys.exit(0 if ok else 1)
'
}

case "${1:-up}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "usage: tools/live.sh up|down|status"; exit 2 ;;
esac
