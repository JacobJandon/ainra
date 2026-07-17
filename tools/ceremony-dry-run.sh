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

echo "== an OUTSIDER recomputes the published transcript hash from PUBLIC BYTES alone (+ coordinator checklist) =="
# A real coordinator ticks ceremony-checklist.json on camera; here we tick a TEST-ROOT copy to exercise the check.
DRY="$DRY" node -e '
  const {readFileSync,writeFileSync}=require("fs");
  const cl=JSON.parse(readFileSync("kits/ceremony/ceremony-checklist.json","utf8"));
  cl.steps.forEach((s)=>{ s.done=true; s.evidence="dry-run (camera-mark N/A)"; }); cl.test_root=true; cl.ceremony_id="DRYRUN";
  writeFileSync(process.env.DRY+"/ceremony-checklist.json", JSON.stringify(cl,null,2)+"\n");
'
node kits/ceremony/verify-transcript.mjs --transcript "$DRY/transcript.json" --sha256 "$DRY/transcript.sha256" --checklist "$DRY/ceremony-checklist.json"

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

echo "== NEGATIVE: one physical key aliased via base64 padding to fake a distinct signer → the witness MUST fail loudly =="
# The sharper version of the copy attack (M9 review): re-sign custodian 1's key into slot N under a NON-canonical
# base64 string (drop the '=' padding). It decodes to the SAME key, so it is NOT a distinct signer — the witness must
# reject it even though the raw strings differ. Uses only custodian 1's PUBLIC data, but a genuine attacker would hold
# the key; here we prove the *check* catches the alias regardless of who holds it.
ALIAS="$WORK/alias"
cp -r "$DRY" "$ALIAS"
DRY="$DRY" N="$N" ALIAS="$ALIAS" node -e '
  const {readFileSync,writeFileSync}=require("fs");
  // Take custodian 1s record; strip the trailing "=" from its pubkey base64 (still decodes to the identical key),
  // relabel it operator_id N, and drop the signature (the witness must reject on the DUPLICATE-KEY check BEFORE it
  // ever trusts a signature — a key alias is not a distinct signer even with a perfect signature).
  const one=JSON.parse(readFileSync(process.env.DRY+"/operator-1.json","utf8"));
  const b={...one.body, operator_id:Number(process.env.N), pubkey_spki_b64:one.body.pubkey_spki_b64.replace(/=+$/,"")};
  writeFileSync(process.env.ALIAS+"/operator-"+process.env.N+".json", JSON.stringify({body:b, sig_ed25519_b64:one.sig_ed25519_b64},null,2)+"\n");
'
if node kits/ceremony/witness.mjs --dir "$ALIAS" >/dev/null 2>&1; then
  echo "FAIL: witness accepted a base64-padding alias of an existing key as a distinct custodian — quorum forgeable"; exit 1
else
  echo "  ✓ witness correctly refused a base64-aliased duplicate key (canonicalized key identity)"
fi

echo
echo "ceremony-dry-run OK — choreography rehearses; the transcript is witness-reproducible; a skipped step (or a"
echo "copied part) fails loudly. TEST-ROOT only. The real recorded ceremony (air-gapped shares) is in kits/ceremony/RUNBOOK.md."
