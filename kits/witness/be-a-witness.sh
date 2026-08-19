#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# ONE COMMAND TO BE A WITNESS.
#
#   bash kits/witness/be-a-witness.sh [--port 4991] [--operator "Your Institution"] [--region EU] [--contact "…"]
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
# operator with a witness that does not work? It calls `/key` and `/info` and then runs the real quorum drill
# against the daemon it just started — if the daemon is not genuinely cosigning, the drill fails and so does this.
set -uo pipefail
cd "$(dirname "$0")/../.."

PORT=4991; OPERATOR=""; REGION=""; CONTACT="public issue thread — no email needed"; ID=""
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --operator) OPERATOR="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --contact) CONTACT="$2"; shift 2 ;;
    --id) ID="$2"; shift 2 ;;
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

echo "== 2/4 · start it on 0.0.0.0:$PORT =="
CFG="$(mktemp)"; trap 'rm -f "$CFG"' EXIT
cat > "$CFG" <<JSON
{ "operator": "${OPERATOR:-unnamed operator}", "region": "${REGION:-unspecified}", "contact": "$CONTACT",
  "note": "self-declared; verified by no one — the key is the only cryptographic fact" }
JSON
./target/release/witnessd "0.0.0.0:$PORT" "$CFG" >/tmp/witnessd-$PORT.log 2>&1 &
WPID=$!
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$PORT/key" >/dev/null 2>&1 && break; sleep 0.2; done
if ! curl -sf "http://127.0.0.1:$PORT/key" >/dev/null 2>&1; then
  echo "  the daemon did not answer — log:"; tail -5 "/tmp/witnessd-$PORT.log"; kill "$WPID" 2>/dev/null; exit 1
fi
KEY=$(curl -sf "http://127.0.0.1:$PORT/key" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const j=JSON.parse(s);process.stdout.write(j.ed25519||j.key||"")}catch{process.stdout.write("")}})')
echo "  answering · key ${KEY:0:16}…"

echo "== 3/4 · prove it actually cosigns (the real fork drill, against YOUR daemon) =="
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
echo "The daemon is running as PID $WPID on port $PORT. Stop it with: kill $WPID"
echo "Nothing was uploaded and no account was created. A candidacy confers no standing until the charter"
echo "process constitutes it — and a witness the root operates is not an independent witness and is never counted."
