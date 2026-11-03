#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# ONE COMMAND TO BE A WITNESS.
#
#   bash kits/witness/be-a-witness.sh [--port 4991] [--operator "Your Institution"] [--region EU] [--contact "…"]
#                                     [--directory directory.json --roots roots.json] [--home ~/.ainra-witness]
#
# Your witness's key and memory live in --home (default ~/.ainra-witness): a random key made on first start (0600),
# and the state that lets it refuse a fork after a restart. Keep that folder; it IS your witness. Every log's key comes
# from the root-signed directory: --directory/--roots if you pass them, otherwise the copy published at
# https://ainra.org/net/ (fetched once, kept in --home). A public witness without a directory refuses to start.
#
# It builds the daemon if needed, starts it, waits until it answers, proves it works against this repository's own
# fork drill, and prints the exact candidacy JSON to commit — the file the intake CI already probes. Nothing is
# provisioned, nothing is uploaded, no account is created, and nothing leaves the machine.
#
# WHY THIS EXISTS. Witnessing is the control that makes the split-view guarantee real, and it has ZERO operators.
# The engineering has been finished and rehearsed for months; what stood between a willing stranger and a running
# witness was: install a Rust toolchain, find the right cargo invocation, copy a config, learn what to put in it,
# work out how to prove it works, then work out what to submit. Six steps and a reading task. That is not a
# security property, it is friction, and friction is the thing we could actually fix.
#
# WITNESS (the question this project asks of every check): could this script report success while leaving the
# operator with a witness that does not work? It requires YOUR daemon to stay up and answer `/key`, `/seen` and
# `/info` (with the same key), and it runs the fork drill — which starts its OWN witnesses from the same binary, so it
# proves the code you are running refuses a fork. Your daemon's own first cosignature comes from
# `kits/witness/submit.mjs` against a real registrar; this script never feeds it a throwaway log, because a log it
# has seen once is a log it is held to.
set -uo pipefail
CALLER="$PWD"
cd "$(dirname "$0")/../.."
abs() { case "$1" in /*|"") printf '%s' "$1" ;; *) printf '%s/%s' "$CALLER" "$1" ;; esac; }

PORT=4991; OPERATOR=""; REGION=""; CONTACT="public issue thread — no email needed"; ID=""
HOMEDIR="${AINRA_WITNESS_HOME:-$HOME/.ainra-witness}"; DIRECTORY=""; ROOTS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --operator) OPERATOR="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --contact) CONTACT="$2"; shift 2 ;;
    --id) ID="$2"; shift 2 ;;
    --home) HOMEDIR="$2"; shift 2 ;;
    --directory) DIRECTORY="$2"; shift 2 ;;
    --roots) ROOTS="$2"; shift 2 ;;
    -h|--help) sed -n '3,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1"; exit 2 ;;
  esac
done
START=$(date +%s)

echo "== 1/4 · build the daemon (one binary, no runtime dependencies) =="
if [ ! -x ./target/release/witnessd ]; then
  command -v cargo >/dev/null 2>&1 || { echo "  cargo not found — install Rust (https://rustup.rs), then re-run this script."; exit 2; }
  cargo build --release -q -p ainra-services --bin witnessd || { echo "  build failed"; exit 1; }
fi
echo "  ./target/release/witnessd ready"

HOMEDIR="$(abs "$HOMEDIR")"; DIRECTORY="$(abs "$DIRECTORY")"; ROOTS="$(abs "$ROOTS")"
echo "== 2/4 · start it on 0.0.0.0:$PORT (key and memory in $HOMEDIR) =="
if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
  echo "  port $PORT is already in use — stop the old witness first (or pass --port)"; exit 1
fi
mkdir -p "$HOMEDIR" && chmod 700 "$HOMEDIR"
if [ -n "$DIRECTORY" ] || [ -n "$ROOTS" ]; then
  [ -f "$DIRECTORY" ] && [ -f "$ROOTS" ] || { echo "  --directory and --roots must both name files"; exit 2; }
  cp "$DIRECTORY" "$HOMEDIR/directory.json"; cp "$ROOTS" "$HOMEDIR/roots.json"
elif [ ! -f "$HOMEDIR/directory.json" ] || [ ! -f "$HOMEDIR/roots.json" ]; then
  echo "  fetching the published root-signed directory (https://ainra.org/net/) — the witness verifies it before use"
  curl -sSf https://ainra.org/net/directory.json -o "$HOMEDIR/directory.json" \
    && curl -sSf https://ainra.org/net/roots.json -o "$HOMEDIR/roots.json" \
    || { echo "  could not fetch it — pass --directory and --roots"; exit 1; }
fi
CFG="$HOMEDIR/witness.json"
node -e '
const [cfg, home, op, region, contact] = process.argv.slice(1);
const fs = require("fs");
const c = { key_file: `${home}/witness.key`, state_file: `${home}/witness.state`,
  ...(fs.existsSync(`${home}/directory.json`) ? { directory: `${home}/directory.json`, roots: `${home}/roots.json` } : {}),
  operator: op, region, contact, note: "self-declared; verified by no one — the key is the only cryptographic fact" };
fs.writeFileSync(cfg, JSON.stringify(c, null, 2) + "\n");
' "$CFG" "$HOMEDIR" "${OPERATOR:-unnamed operator}" "${REGION:-unspecified}" "$CONTACT"
echo "  log keys: from the root-signed directory in $HOMEDIR"
./target/release/witnessd "0.0.0.0:$PORT" "$CFG" >/tmp/witnessd-$PORT.log 2>&1 &
WPID=$!
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$PORT/key" >/dev/null 2>&1 && break; sleep 0.2; done
if ! curl -sf "http://127.0.0.1:$PORT/key" >/dev/null 2>&1; then
  echo "  the daemon did not answer — log:"; tail -5 "/tmp/witnessd-$PORT.log"; kill "$WPID" 2>/dev/null; exit 1
fi
KEY=$(curl -sf "http://127.0.0.1:$PORT/key" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const j=JSON.parse(s);process.stdout.write(j.ed25519||j.key||"")}catch{process.stdout.write("")}})')
echo "  answering · key ${KEY:0:16}…"

kill -0 "$WPID" 2>/dev/null || { echo "  the daemon exited — log:"; tail -5 "/tmp/witnessd-$PORT.log"; exit 1; }
SEEN=$(curl -sf "http://127.0.0.1:$PORT/seen" || true)
[ -n "$SEEN" ] || { echo "  the daemon does not answer /seen — is this an old witnessd build?"; kill "$WPID" 2>/dev/null; exit 1; }
INFOKEY=$(curl -sf "http://127.0.0.1:$PORT/info" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{process.stdout.write(JSON.parse(s).ed25519||"")}catch{}})')
[ -n "$KEY" ] && [ "$INFOKEY" = "$KEY" ] || { echo "  /info and /key disagree (or are empty) — not a usable witness"; kill "$WPID" 2>/dev/null; exit 1; }
echo "== 3/4 · prove this witness code refuses a fork (the drill runs its own witnesses from the same binary) =="
if ! make drill-networked >/tmp/witness-drill-$PORT.log 2>&1; then
  echo "  the fork drill FAILED — this witness is not usable yet:"; tail -6 "/tmp/witness-drill-$PORT.log"
  kill "$WPID" 2>/dev/null; exit 1
fi
echo "  honest head certified · injected fork refused — $(grep -c . /tmp/witness-drill-$PORT.log >/dev/null && echo 'drill green')"

ELAPSED=$(( $(date +%s) - START ))
SUGGEST="${ID:-$(echo "${OPERATOR:-witness}" | tr '[:upper:] ' '[:lower:]-' | tr -cd 'a-z0-9-' | cut -c1-24)}"
echo
echo "== 4/4 · you are a witness. Total elapsed: ${ELAPSED}s =="
echo
echo "Your endpoint must be reachable from the internet for the intake CI to probe it. Then commit this file as"
echo "evidence/witness/${SUGGEST:-your-id}.json and open a PR — CI checks the shape and probes /key and /info:"
echo
cat <<JSON
{
  "candidate_id": "${SUGGEST:-your-id}",
  "endpoint": "https://<your-public-hostname>",
  "operator": "${OPERATOR:-Your Institution}",
  "jurisdiction": "${REGION:-EU}",
  "contact": "$CONTACT",
  "production": false,
  "notes": "witnessd, own infrastructure. Key ${KEY:0:16}…"
}
JSON
echo
echo "Your first cosignature (and every one after it, on a schedule) comes from a real registrar:"
echo "  node kits/witness/submit.mjs --registrar <registrar-url> --witness http://127.0.0.1:$PORT \\"
echo "       --out evidence/cosignatures/${SUGGEST:-your-id}.json"
echo
echo "The daemon is running as PID $WPID on port $PORT. Stop it with: kill $WPID. Keep $HOMEDIR."
echo "Nothing was uploaded and no account was created. A candidacy confers no standing until the charter"
echo "process constitutes it — and a witness the root operates is not an independent witness and is never counted."
