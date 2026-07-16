#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make genesis-local (M8 / MTS §29 / N9) — boot the WHOLE AINRA world on one laptop, all real, and write a
# transcript. Composes every layer: dual-root ceremony over TWO registrar classes → issue + log (logged-before-
# valid) → a stranger's 5-line SDK verify with the root DARK → revoke + re-verify INVALID → forged all-clear
# rejected → an injected log fork caught by the witness QUORUM (not us). Exits nonzero if any stage misbehaves;
# nothing is asserted by narration — every verdict is the real tool's exit code.
set -euo pipefail
cd "$(dirname "$0")/.."

NOW=$((1775865600 + 10 * 24 * 3600)) # inside the demo delegate-cert window (2026-04-21)
OUT="${1:-genesis-out}"
WORK="$(mktemp -d)"
P1=4931
P2=4932
declare -a PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

verify() { # $1=bundle → prints VALID/INVALID via the REAL sdk verifier (root dark: only directory + roots)
  if node tools/ainra-verify.mjs --directory "$OUT/directory.json" --roots "$OUT/roots.json" \
    --bundle "$1" --now "$NOW" --quiet 2>/dev/null; then echo VALID; else echo INVALID; fi
}

echo "== build =="
cargo build --release -q -p ainra-services --bin registrar-box -p ainra-ceremony --bin accredit
(cd packages/sdk-ts && npm run build >/dev/null 2>&1)
rm -rf "$OUT"
mkdir -p "$OUT"

echo "== 1. ceremony: TWO registrar classes → dual-root-signed directory (FROST 5-of-9 + SLH-DSA) =="
# Pre-flight: refuse to run if anything already answers our ports — else a STALE leftover daemon would silently
# serve the whole run and mask a regression in the freshly-built binary (M8 review MEDIUM: false green).
for port in $P1 $P2; do
  if curl -sf "http://127.0.0.1:$port/accreditation" >/dev/null 2>&1; then
    echo "FAIL: 127.0.0.1:$port is already serving — kill the leftover daemon (this run must use THIS build)"; exit 1
  fi
done
start_rb() { # $1=port $2=id $3=datadir → launches the FRESH binary, keeps its stderr (so a bind panic is visible)
  ./target/release/registrar-box "127.0.0.1:$1" "$2" "$3" >/dev/null 2>"$WORK/$2.err" &
  local pid=$!
  PIDS+=("$pid")
  for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$1/accreditation" >/dev/null 2>&1 && break; sleep 0.2; done
  # The FRESH child MUST still be alive — if it died on bind (EADDRINUSE) while a stale daemon answered, catch it.
  kill -0 "$pid" 2>/dev/null || { echo "FAIL: registrar-box '$2' (pid $pid) died — $(cat "$WORK/$2.err" 2>/dev/null | tail -1)"; exit 1; }
}
start_rb "$P1" registrar-07 "$WORK/rb1"
start_rb "$P2" registrar-02 "$WORK/rb2"
curl -sf "http://127.0.0.1:$P1/accreditation" >"$WORK/acc1.json"
curl -sf "http://127.0.0.1:$P2/accreditation" >"$WORK/acc2.json"
./target/release/accredit "$OUT" "$WORK/acc1.json" "$WORK/acc2.json"

echo "== 2. each registrar issues a passport (logged-before-valid) =="
SUB1="ainra:registrar-07:acme:invoicing@1.0.0"
SUB2="ainra:registrar-02:globex:payments@1.0.0"
curl -sf -X POST "http://127.0.0.1:$P1/issue" \
  -d '{"operator":"acme","lineage":"invoicing","version":"1.0.0","tier":"L3","auth_class":"A2","principal_proof":"deadbeef7f3a2c1d","capabilities":["read:invoices"],"scope_ceiling":["read:invoices"],"hops":[]}' >/dev/null
curl -sf -X POST "http://127.0.0.1:$P2/issue" \
  -d '{"operator":"globex","lineage":"payments","version":"1.0.0","tier":"L3","auth_class":"A2","principal_proof":"cafef00d12345678","capabilities":["read:ledger"],"scope_ceiling":["read:ledger"],"hops":[]}' >/dev/null
curl -sf "http://127.0.0.1:$P1/present?sub=$SUB1&now=$NOW" >"$OUT/bundle-07.json"
curl -sf "http://127.0.0.1:$P2/present?sub=$SUB2&now=$NOW" >"$OUT/bundle-02.json"

echo "== 3. a stranger's 5-line SDK (root DARK) verifies both → VALID =="
V07="$(verify "$OUT/bundle-07.json")"
V02="$(verify "$OUT/bundle-02.json")"
echo "   registrar-07 → $V07 · registrar-02 → $V02"
[ "$V07" = VALID ] && [ "$V02" = VALID ] || { echo "FAIL: a freshly-issued passport did not verify"; exit 1; }

echo "== 4. revoke registrar-07's lineage → re-verify INVALID; forged all-clear rejected =="
curl -sf -X POST "http://127.0.0.1:$P1/revoke" -d "{\"sub\":\"$SUB1\",\"now\":$NOW}" >/dev/null
curl -sf "http://127.0.0.1:$P1/present?sub=$SUB1&now=$NOW" >"$OUT/bundle-07-revoked.json"
VREV="$(verify "$OUT/bundle-07-revoked.json")"
[ "$VREV" = INVALID ] || { echo "FAIL: revoked passport verified VALID"; exit 1; }
node tools/forge-status.mjs --in "$OUT/bundle-07-revoked.json" --out "$WORK/forged.json" --now "$NOW" --mode clear 2>/dev/null
VFORGE="$(verify "$WORK/forged.json")"
[ "$VFORGE" = INVALID ] || { echo "FAIL: a forged all-clear status verified VALID"; exit 1; }
echo "   revoked → $VREV · forged all-clear → $VFORGE (fails closed)"

echo "== 5. an injected log fork is caught by the witness QUORUM (not us) =="
DRILL="$(cargo run --release -q -p ainra-services --bin pipeline-demo 2>&1)"
echo "$DRILL" | grep -q "the fork cannot gather a quorum" || { echo "FAIL: the quorum did not catch the fork"; exit 1; }
FORKLINE="$(echo "$DRILL" | grep 'INJECTED FORK' | tail -1 | sed 's/^ *//')"
echo "   $FORKLINE"

echo "== 6. transcript + artifact hashes =="
NOW="$NOW" V07="$V07" V02="$V02" VREV="$VREV" VFORGE="$VFORGE" OUT="$OUT" FORKLINE="$FORKLINE" \
  python3 - <<'PY'
import json, hashlib, os, glob
out = os.environ["OUT"]
def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()
roots = json.load(open(f"{out}/roots.json"))
directory = json.load(open(f"{out}/directory.json"))
artifacts = {os.path.relpath(p, out): sha(p) for p in sorted(glob.glob(f"{out}/*.json"))}
transcript = {
    "note": "AINRA genesis-local — the whole stack on one laptop, all real (MTS §29 / N9). Verdicts are the real tools'.",
    "now": int(os.environ["NOW"]),
    "root_ed25519": roots["root_ed25519"],
    "root_slh": roots["root_slh"],
    "epoch": directory["epoch"],
    "registrars": [e["registrar"] for e in directory["entries"]],
    "results": {
        "registrar-07_valid": os.environ["V07"],
        "registrar-02_valid": os.environ["V02"],
        "registrar-07_after_revoke": os.environ["VREV"],
        "registrar-07_forged_all_clear": os.environ["VFORGE"],
        "witness_quorum_fork": os.environ["FORKLINE"],
    },
    "artifacts_sha256": artifacts,
}
open(f"{out}/transcript.json", "w").write(json.dumps(transcript, indent=2, sort_keys=True) + "\n")
print(f"   wrote {out}/transcript.json — {len(directory['entries'])} registrars, {len(artifacts)} artifacts hashed")
PY

echo
echo "genesis-local OK — the whole AINRA world booted on one laptop:"
echo "  · dual-root ceremony over TWO registrar classes → a signed directory a stranger trust-anchors"
echo "  · both passports logged-before-valid, verified VALID by a 5-line SDK with the root DARK"
echo "  · revocation + a forged all-clear both fail closed"
echo "  · an injected log fork caught by a witness quorum, not by us"
echo "  · full transcript + artifact hashes in $OUT/ (reproducible; see 'make repro' + 'make verify-mirror')"
