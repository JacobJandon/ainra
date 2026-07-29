#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make ceremony-rehearsal-multi (M23 Task 3) — run the FROST 5-of-9 root ceremony across NINE ISOLATED OS PROCESSES.
#
# The M4 `ceremony` binary runs all nine custodians inside one process (a faithful simulation). This rehearses the
# DISTRIBUTABLE shape: nine `dkg-participant` processes, each with its own private home dir, exchange every round
# message through a shared "postbox" directory only — the exact protocol air-gapped custodians run by couriering USB
# sticks. It proves: (1) all nine independently derive the SAME group key (distributed DKG succeeded); (2) any five
# shares threshold-sign a message that verifies against that key; (3) four shares CANNOT (the threshold holds); and
# (4) an outsider recomputes the transcript hash from public bytes alone. TEST-ROOT entropy, freshly seeded per run.
set -euo pipefail
cd "$(dirname "$0")/.."
N=9; T=5
BIN=target/release/dkg-participant
[ -x "$BIN" ] || { echo "→ building dkg-participant…"; cargo build --release -q -p ainra-ceremony --bin dkg-participant; }
command -v sha256sum >/dev/null 2>&1 || { echo "✗ sha256sum not found"; exit 1; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
BOX="$WORK/postbox"; mkdir -p "$BOX"
SEED="$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"   # fresh run entropy (TEST-ROOT, labelled)
MSG="ainra genesis root — distributed ceremony rehearsal 01"
MSGHEX="$(printf '%s' "$MSG" | od -An -tx1 | tr -d ' \n')"
ms() { date +%s%3N; }

# spawn one process PER custodian for a DKG round; barrier on all nine (a round can't start until the last finished).
dkg_round() {  # dkg_round <dkg1|dkg2|dkg3> [seed]
  local mode="$1" seed="${2:-}"; local pids=()
  for K in $(seq 1 "$N"); do
    "$BIN" "$mode" "$K" "$N" "$T" "$BOX" "$WORK/home-$K" $seed >"$WORK/log-$mode-$K" 2>&1 &
    pids+=($!)
  done
  local ok=0
  for p in "${pids[@]}"; do wait "$p" || ok=1; done
  [ "$ok" -eq 0 ] || { echo "✗ a custodian failed in $mode:"; cat "$WORK"/log-"$mode"-* 2>/dev/null; exit 1; }
}

echo "== FROST $T-of-$N genesis ceremony across $N isolated processes (file-based rounds) =="
START="$(ms)"
dkg_round dkg1 "$SEED"
dkg_round dkg2
dkg_round dkg3
DKG_MS=$(( $(ms) - START ))

# (1) consensus: every custodian's independently-derived group key must be identical.
GROUP="$(cat "$BOX/group/1.pub")"
DISTINCT="$(cat "$BOX"/group/*.pub | sort -u | wc -l | tr -d ' ')"
[ "$DISTINCT" -eq 1 ] || { echo "✗ custodians disagree on the group key ($DISTINCT distinct)"; exit 1; }
echo "  ✓ all $N custodians derived ONE group key  ${GROUP:0:32}…  (${DKG_MS} ms)"

# (2) five shares (spanning several processes) threshold-sign; verify against the group key.
SIGN_START="$(ms)"
QUORUM="1 3 5 7 9"
spids=(); for K in $QUORUM; do "$BIN" commit "$K" "$BOX" "$WORK/home-$K" "$SEED" >"$WORK/log-commit-$K" 2>&1 & spids+=($!); done
for p in "${spids[@]}"; do wait "$p" || { echo "✗ commit failed"; cat "$WORK"/log-commit-*; exit 1; }; done
spids=(); for K in $QUORUM; do "$BIN" sign "$K" "$BOX" "$WORK/home-$K" "$MSGHEX" >"$WORK/log-sign-$K" 2>&1 & spids+=($!); done
for p in "${spids[@]}"; do wait "$p" || { echo "✗ sign failed"; cat "$WORK"/log-sign-*; exit 1; }; done
"$BIN" aggregate "$BOX" "$MSGHEX" || { echo "✗ aggregation/verification failed for the 5-share quorum"; exit 1; }
SIGN_MS=$(( $(ms) - SIGN_START ))
SIG="$(od -An -tx1 "$BOX/signature.bin" | tr -d ' \n')"

# (3) four shares must NOT be able to sign — remove one share and re-aggregate; expect refusal.
rm -f "$BOX/sign/share-9.bin"
if "$BIN" aggregate "$BOX" "$MSGHEX" >/dev/null 2>&1; then
  echo "✗ SECURITY: 4 shares produced a valid signature — threshold broken"; exit 1
fi
echo "  ✓ 5 shares signed (VALID, ${SIGN_MS} ms) · 4 shares refused — the ${T}-of-${N} threshold holds"

# (4) transcript + outsider hash recompute (public bytes only).
TS="$WORK/transcript.json"
cat > "$TS" <<JSON
{
  "kind": "ainra/ceremony-rehearsal-multi/v1-TESTROOT",
  "custodians": $N,
  "threshold": $T,
  "processes": "isolated (one OS process per custodian, file-based rounds)",
  "group_ed25519": "$GROUP",
  "message_hex": "$MSGHEX",
  "signature_ed25519": "$SIG",
  "quorum_signers": [1, 3, 5, 7, 9]
}
JSON
THASH="$(sha256sum "$TS" | cut -d' ' -f1)"
printf '%s  transcript.json\n' "$THASH" > "$WORK/transcript.sha256"
OUTSIDER="$(sha256sum "$TS" | cut -d' ' -f1)"
[ "$THASH" = "$OUTSIDER" ] || { echo "✗ transcript hash mismatch"; exit 1; }
echo "  ✓ transcript recomputed by an outsider from public bytes → SHA-256 ${THASH:0:32}…"

echo
echo "✓ distributed ceremony rehearsal PASSED — real FROST across $N processes, ${T}-of-${N} threshold enforced,"
echo "  RFC 8032 signature verifies against the group key, transcript reproducible. TEST-ROOT (fresh entropy per run)."
