#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# make site-net — publish the staging network's read contract into site/net/, and stamp WHEN.
#
# The site ships a copy of the contract so the record browses on any static host, not only next to a running
# network. That copy needs a publication date, and it cannot borrow one from the data: `generated_window.verified_at`
# is `seed.rs::VERIFY_NOW`, a pinned constant the staging network computes its validity window against. It is the
# same number in a record published today and one published a year ago — reading it as an age says "110 days old"
# about a file that is byte-identical to what the network is serving this second. So the stamp is written here, at
# the moment of copying, by the thing doing the copying.
#
#   make site-net          refresh site/net/ from a reachable contract and stamp site/net/published.json
#   make site-net-check    is the committed copy still what the network serves? (needs a running network)
#
# --check never writes and never guesses: no network, no verdict.
set -uo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-publish}"
SRC="${AINRA_CONTRACT:-http://127.0.0.1:8091}"
DEST="site/net"
FILES="index.json registry.json directory.json roots.json"

fetch_to() { curl -fsS -m 10 "$SRC/$1" -o "$2" 2>/dev/null; }

probe=$(curl -s -m 10 -o /dev/null -w '%{http_code}' "$SRC/index.json" 2>/dev/null)
[ -n "$probe" ] || probe=000
if [ "$probe" != "200" ]; then
  echo "site-net: no contract at $SRC (HTTP $probe) — run 'make stage-install' or 'make stage-all' first."
  echo "site-net: refusing to $MODE against a network that is not answering."
  exit 2
fi

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
for f in $FILES; do
  fetch_to "$f" "$TMP/$f" || { echo "site-net: contract answered but did not serve $f — aborting"; exit 2; }
done

# Each registrar's own tree travels with the record, and every file in it must be a JSON document the network
# actually served. Until 2026-11-04 only accreditation.json was refreshed here, so the published
# registrars/registrar-07/status/current.json stayed the 3 August list — revoking another passport than the
# 17 August registry.json beside it did — and ainra.org served the two together for months.
REG_FILES="accreditation.json export.json fresh-head.json status/current.json status/deltas.json"
json_ok() { [ -s "$1" ] && node -e 'JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"))' "$1" 2>/dev/null; }
for reg in $(node -e 'for (const r of JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).registrars||[]) console.log(r)' "$TMP/index.json"); do
  mkdir -p "$TMP/registrars/$reg/status" "$TMP/registrars/$reg/checkpoints"
  for f in $REG_FILES; do
    { fetch_to "registrars/$reg/$f" "$TMP/registrars/$reg/$f" && json_ok "$TMP/registrars/$reg/$f"; } \
      || { echo "site-net: $reg's $f is missing, empty or not JSON on the network — refusing to $MODE over it"; exit 2; }
  done
  cp_name=$(node -e 'const r=(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).records||[])[0]?.record;if(r)console.log(r.checkpoint_size)' "$TMP/registrars/$reg/export.json")
  if [ -n "$cp_name" ]; then
    { fetch_to "registrars/$reg/checkpoints/$cp_name.json" "$TMP/registrars/$reg/checkpoints/$cp_name.json" && json_ok "$TMP/registrars/$reg/checkpoints/$cp_name.json"; } \
      || { echo "site-net: $reg's checkpoints/$cp_name.json is not served — refusing to $MODE over it"; exit 2; }
  fi
done
TREE=$(cd "$TMP" && find registrars -type f | sort)

if [ "$MODE" = "check" ]; then
  drift=0
  for f in $FILES $TREE; do
    if ! cmp -s "$TMP/$f" "$DEST/$f"; then echo "site-net: DRIFT — site/net/$f differs from what $SRC serves now"; drift=1; fi
  done
  for f in $(cd "$DEST" && find registrars -type f 2>/dev/null | sort); do
    [ -f "$TMP/$f" ] || { echo "site-net: DRIFT — site/net/$f is published but the network no longer serves it"; drift=1; }
  done
  # The byte-comparison above proves the published copy matches what the ARTIFACT SERVER serves. It does NOT prove
  # the REGISTRAR can still present the passports that record describes — and those are different machines with
  # different state. This gate said "byte-identical" for days while the registrar had regressed behind the record
  # after a restart and answered `unknown subject` for a passport the record listed. The artifact server serves
  # files from disk; the registrar serves from its own reloaded state. A record nobody can honour is not a record.
  reg_drift=0
  first_sub=$(curl -s -m 10 "$SRC/registry.json" 2>/dev/null \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const r=JSON.parse(s);for(const R of r.registrars||[])for(const e of R.records||[]){const x=e.record?.sub||e.sub;if(x){console.log(x);process.exit(0)}}}catch{}})' 2>/dev/null)
  if [ -n "$first_sub" ]; then
    REG_URL="${AINRA_REG:-http://127.0.0.1:4907}"
    body=$(curl -s -m 10 "$REG_URL/present?sub=$(node -e 'process.stdout.write(encodeURIComponent(process.argv[1]))' "$first_sub")&now=1776729600" 2>/dev/null)
    case "$body" in
      *'"claims"'*) echo "site-net: registrar can present a sampled subject from the record" ;;
      *) echo "site-net: DRIFT — the record lists a subject the registrar cannot present:"
         echo "site-net:   subject : $first_sub"
         echo "site-net:   answer  : $(printf '%s' "$body" | head -c 120)"
         echo "site-net: the registrar has regressed behind the published record (restart without its state?)."
         reg_drift=1 ;;
    esac
  fi
  if [ "$drift" -eq 0 ] && [ "$reg_drift" -ne 0 ]; then exit 1; fi
  if [ "$drift" -eq 0 ]; then
    echo "site-net OK: the published record is byte-identical to the running network ($(echo $FILES $TREE | wc -w) files)"
  else
    echo "site-net: the published record no longer matches the network — run 'make site-net' to republish"
    exit 1
  fi
  exit 0
fi

# PLAN-M52 step 1: keep every epoch — before anything is copied, so a refusal leaves the published copy as it was.
# The archive refuses anything unsigned, an older epoch, and a second directory at an archived epoch, so a republish
# can only add to the history, never rewrite it.
[ -x target/release/ainra ] || cargo build --release -q -p ainra-cli-rs
./target/release/ainra directory archive "$TMP/directory.json" --roots "$TMP/roots.json" --into "$DEST" \
  || { echo "site-net: the directory the network serves cannot join the epoch history — refusing to publish it"; exit 1; }
for f in $FILES; do cp "$TMP/$f" "$DEST/$f"; done
# The per-registrar trees, whole: a stamped index over stale leaves would be worse than no stamp at all.
rm -rf "$DEST/registrars"; cp -r "$TMP/registrars" "$DEST/registrars"

NOW=$(date -u +%s)
ROOT=$(curl -s -m 10 -D- -o /dev/null "$SRC/registry.json" 2>/dev/null | grep -i '^x-ainra-root:' | tr -d '\r' | awk '{print $2}')
NETW=$(curl -s -m 10 -D- -o /dev/null "$SRC/registry.json" 2>/dev/null | grep -i '^x-ainra-network:' | tr -d '\r' | awk '{print $2}')
{
  printf '{\n  "published_at": %s,\n  "published_at_iso": "%s",\n' "$NOW" "$(date -u -d "@$NOW" +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "network": "%s",\n  "root": "%s",\n' "${NETW:-staging}" "${ROOT:-test-root}"
  printf '  "note": "When this copy of the read contract was taken from the network. NOT generated_window.verified_at, which is a pinned staging constant and says nothing about age.",\n'
  printf '  "sha256": {\n'
  i=0; n=$(echo $FILES | wc -w)
  for f in $FILES; do
    i=$((i+1)); h=$(sha256sum "$DEST/$f" | awk '{print $1}')
    printf '    "%s": "%s"%s\n' "$f" "$h" "$([ "$i" -lt "$n" ] && echo ,)"
  done
  printf '  }\n}\n'
} > "$DEST/published.json"

echo "site-net: published $(echo $FILES | wc -w) files from $SRC — stamped $(date -u -d "@$NOW" +%Y-%m-%dT%H:%M:%SZ)"
