#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make ceremony-dry-run (M9) — rehearse the OPERATOR CHOREOGRAPHY of the genesis ceremony across N "separate
# machines" (separate working dirs), run the REAL dual-root ceremony (FROST 5-of-9 + SLH-DSA, TEST-ROOT), and prove
# an independent WITNESS recomputes the transcript hash + confirms every custodian's commit-reveal. It also proves
# the ceremony FAILS LOUDLY when a custodian's step is skipped. TEST-ROOT material only — the real recorded ceremony
# with air-gapped shares is documented in kits/ceremony/RUNBOOK.md.
set -euo pipefail
cd "$(dirname "$0")/.."
N="${1:-5}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DRY="$WORK/dry-run"
mkdir -p "$DRY"

echo "== $N custodians each commit on their own machine (TEST-ROOT commit-reveal) =="
for K in $(seq 1 "$N"); do
  node kits/ceremony/operator.mjs --id "$K" --out "$DRY"
done
# coordinator sanity: refuse to proceed if any custodian did not commit (a skipped step, caught before signing).
have=$(ls "$DRY"/operator-*.json 2>/dev/null | wc -l)
[ "$have" -eq "$N" ] || { echo "FAIL: only $have/$N custodians committed — coordinator refuses to proceed"; exit 1; }

echo "== coordinator: run the REAL dual-root ceremony (FROST 5-of-9 + SLH-DSA, TEST-ROOT) =="
cargo run --release -q -p ainra-ceremony --bin ceremony -- "$WORK/ceremony" >/dev/null 2>&1
cp "$WORK/ceremony/transcript.json" "$WORK/ceremony/transcript.sha256" "$DRY/"
CTHASH="$(tr -d '[:space:]' < "$DRY/transcript.sha256")"
DRY="$DRY" CTHASH="$CTHASH" N="$N" python3 - <<'PY'
import json, os
json.dump({"kind": "ainra/ceremony-manifest/v1-TESTROOT",
           "required_operators": int(os.environ["N"]),
           "ceremony_transcript_sha256": os.environ["CTHASH"]},
          open(os.path.join(os.environ["DRY"], "ceremony-manifest.json"), "w"), indent=2)
PY

echo "== an INDEPENDENT witness recomputes the transcript hash + verifies every custodian =="
node kits/ceremony/witness.mjs --dir "$DRY"

echo "== NEGATIVE: skip a custodian → the witness MUST fail loudly =="
BAD="$WORK/bad"
cp -r "$DRY" "$BAD"
rm -f "$BAD/operator-$N.json"
if node kits/ceremony/witness.mjs --dir "$BAD" >/dev/null 2>&1; then
  echo "FAIL: witness passed with a skipped custodian — fail-loud is broken"; exit 1
else
  echo "  ✓ witness correctly refused the ceremony missing custodian $N"
fi

echo "== NEGATIVE: paper over a no-show by COPYING another custodian's part → the witness MUST fail loudly =="
# A file count alone would be fooled by `cp operator-1.json operator-N.json` (still N files). The witness must catch
# it: the copy carries operator_id 1 (≠ N) AND reuses custodian 1's public key (not a distinct signer).
DUP="$WORK/dup"
cp -r "$DRY" "$DUP"
cp "$DUP/operator-1.json" "$DUP/operator-$N.json"
if node kits/ceremony/witness.mjs --dir "$DUP" >/dev/null 2>&1; then
  echo "FAIL: witness accepted a custodian's part copied over a no-show — quorum is forgeable by file count"; exit 1
else
  echo "  ✓ witness correctly refused a duplicated custodian part (mislabeled operator_id + reused key)"
fi

echo
echo "ceremony-dry-run OK — choreography rehearses; the transcript is witness-reproducible; a skipped step (or a"
echo "copied part) fails loudly. TEST-ROOT only. The real recorded ceremony (air-gapped shares) is in kits/ceremony/RUNBOOK.md."
