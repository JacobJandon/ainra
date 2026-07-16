#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make drill-networked (M9 / D-021 transport) — run N SEPARATELY-OPERATED witnessd processes on different ports, then
# have a relying party talk to them over HTTP: submit the honest log's checkpoints, collect cosignatures, and show an
# injected fork REFUSED by the networked quorum. The threshold k stays the relying party's argument, never fetched.
set -euo pipefail
cd "$(dirname "$0")/.."
N="${1:-5}"
K="${2:-3}"
BASE_PORT="${AINRA_WITNESS_PORT:-4891}"
declare -a PIDS=()
declare -a ADDRS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

echo "== build =="
cargo build --release -q -p ainra-services --bin witnessd --bin witness-quorum-drill

echo "== start $N witnessd processes (each an independent witness, distinct key) =="
for i in $(seq 0 $((N - 1))); do
  PORT=$((BASE_PORT + i))
  ADDR="127.0.0.1:$PORT"
  if curl -sf "http://$ADDR/key" >/dev/null 2>&1; then echo "FAIL: $ADDR already serving — kill leftover witnessd"; exit 1; fi
  ./target/release/witnessd "$ADDR" >/dev/null 2>/dev/null &
  PIDS+=($!)
  ADDRS+=("$ADDR")
done
# wait for readiness + liveness (a fresh witness must actually be up, not a stale one)
for idx in "${!ADDRS[@]}"; do
  A="${ADDRS[$idx]}"
  for _ in $(seq 1 40); do curl -sf "http://$A/key" >/dev/null 2>&1 && break; sleep 0.1; done
  kill -0 "${PIDS[$idx]}" 2>/dev/null || { echo "FAIL: witnessd $A did not start"; exit 1; }
done

echo "== relying party (k=$K) drives the networked quorum over HTTP =="
./target/release/witness-quorum-drill "$K" "${ADDRS[@]}"

echo
echo "drill-networked OK — $N independently-operated witnesses over HTTP; an injected fork was refused by the quorum;"
echo "k stayed the relying party's argument (D-021 closed to a deployable transport). See kits/witness/README.md."
