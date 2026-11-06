#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# make remote-ceremony-drill — the remote emergency ceremony, rehearsed and timed (PLAN-M53 step 4, D-101).
#
# Five custodians of a TEST-ROOT FROST 5-of-9 root sign an emergency epoch digest without ever being on a network:
# every custodian step runs in its own process with NO network interface (`unshare --net`), with its own home (its
# key share and nonces) and its own postbox. Only frames (kits/ceremony/remote.mjs: base45 text, QR- or USB-ready)
# cross between the custodians and a relay that nobody trusts. The DKG itself is the in-person ceremony (D-094 item 4)
# and is not timed; what is timed is the emergency path: commit, relay, sign, relay, aggregate.
#
# WITNESS (each must hold, or this drill fails):
#   · a custodian process cannot reach any network (a connection attempt from inside fails);
#   · five offline custodians produce a root signature that verifies (dkg-participant aggregate verifies it);
#   · the relay sees only public files: packing a custodian's nonces is refused;
#   · one character changed by the relay is refused as altered in transit; a frame from another session is refused;
#   · a relay that swaps one custodian's commitment for another gets no signature (FROST refuses the aggregate);
#   · a custodian whose signing package differs (it signed another message) is caught when the relay merges packages.
# The measured times are machine time only — no person carried media or read a digest aloud — and are reported as such.
set -uo pipefail
cd "$(dirname "$0")/.."
cargo build --release -q -p ainra-ceremony --bin dkg-participant || exit 2
P="$PWD/target/release/dkg-participant"; RM="node $PWD/kits/ceremony/remote.mjs"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
NS=(unshare --user --map-root-user --net)
fail=0; pass() { echo "  ok    $1"; }; bad() { echo "  ✗     $1"; fail=1; }
ms() { date +%s%3N; }
hexrand() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }

echo "remote-ceremony-drill · five offline custodians, one untrusted relay, frames only (TEST-ROOT)"

# 0 · isolation. Where unprivileged network namespaces are blocked (many CI runners and containers), the custodian
# steps run without one and the drill says so: every other witness still runs, and the frames are still the only path
# between custodians and relay. Isolation is proven wherever the namespace can be made.
if "${NS[@]}" true 2>/dev/null; then
  if "${NS[@]}" timeout 5 node -e 'const s=require("net").connect(443,"1.1.1.1");s.on("connect",()=>process.exit(1));s.on("error",()=>process.exit(0));' 2>/dev/null; then
    pass "a custodian process has no network: a connection attempt from inside fails"
  else bad "a custodian process reached a network from inside its namespace"; exit 1; fi
else
  NS=(); echo "  ·     network namespaces are not available on this machine: custodian steps run without one (isolation not proven HERE; the frames are still the only path)"
fi

# 1 · the in-person DKG (not timed): nine custodians, a 5-of-9 group key
BOX="$W/dkg"; SEED=$(hexrand)
for r in dkg1 dkg2 dkg3; do for K in 1 2 3 4 5 6 7 8 9; do
  if [ $r = dkg1 ]; then "$P" $r $K 9 5 "$BOX" "$W/home-$K" "$SEED" >/dev/null || exit 2; else "$P" $r $K 9 5 "$BOX" "$W/home-$K" >/dev/null || exit 2; fi
done; done
mkdir -p "$W/relay" && cp -r "$BOX/group" "$W/relay/"   # the relay holds only the public group key
SESSION="EMERG-$(date +%Y%m%d)-$(hexrand | cut -c1-6 | tr a-f A-F)"
MSG=$(printf 'emergency epoch · DISTRUST_FROM_LEAF registrar-11 at leaf 1 · TEST-ROOT drill' | sha256sum | cut -d' ' -f1)
Q="1 3 5 7 9"; mkdir -p "$W/usb"
for K in $Q; do mkdir -p "$W/desk-$K"; done

# 2 · the emergency signature, timed
T0=$(ms)
NSEED=$(hexrand)
for K in $Q; do  # round 1, each custodian offline: a commitment; the nonce stays in its home
  "${NS[@]}" "$P" commit $K "$W/desk-$K" "$W/home-$K" "$NSEED" >/dev/null || { bad "custodian $K could not commit"; exit 1; }
  "${NS[@]}" $RM pack "$W/desk-$K" "$SESSION" "$W/usb/$K-r1.frames" "sign/commit-$K.bin" >/dev/null || { bad "custodian $K could not pack"; exit 1; }
done
T1=$(ms)
$RM unpack "$W/relay" "$SESSION" "$W"/usb/*-r1.frames >/dev/null || { bad "the relay could not unpack round 1"; exit 1; }
$RM pack "$W/relay" "$SESSION" "$W/usb/r1-all.frames" $(for K in $Q; do printf 'sign/commit-%s.bin ' $K; done) >/dev/null
T2=$(ms)
for K in $Q; do  # round 2, each offline: take every commitment, sign its OWN copy of the message
  "${NS[@]}" $RM unpack "$W/desk-$K" "$SESSION" "$W/usb/r1-all.frames" >/dev/null || { bad "custodian $K refused the relay's commitments"; exit 1; }
  "${NS[@]}" "$P" sign $K "$W/desk-$K" "$W/home-$K" "$MSG" >/dev/null || { bad "custodian $K could not sign"; exit 1; }
  "${NS[@]}" $RM pack "$W/desk-$K" "$SESSION" "$W/usb/$K-r2.frames" "sign/share-$K.bin" "sign/pkg.bin" >/dev/null || exit 1
done
T3=$(ms)
$RM unpack "$W/relay" "$SESSION" "$W"/usb/*-r2.frames >/dev/null || { bad "the relay could not merge round 2"; exit 1; }
if "$P" aggregate "$W/relay" "$MSG" >/dev/null 2>&1; then pass "five offline custodians, frames only: the root signature verifies"; else bad "the aggregate did not verify"; fi
T4=$(ms)
FRAMES=$(cat "$W"/usb/*.frames | wc -l); BYTES=$(cat "$W"/usb/*.frames | wc -c); LONGEST=$(cat "$W"/usb/*.frames | awk '{ if (length > m) m = length } END { print m }')
echo "  ·     machine time: round 1 $((T1-T0)) ms · relay $((T2-T1)) ms · round 2 $((T3-T2)) ms · aggregate $((T4-T3)) ms · total $((T4-T0)) ms"
echo "  ·     crossed the gap: $FRAMES frame(s), $BYTES bytes, the longest $LONGEST characters (one QR code each)"

# 3 · what the relay cannot do
$RM pack "$W/home-1" "$SESSION" "$W/x.frames" "nonces.bin" >/dev/null 2>&1 && bad "a custodian's nonces were packed" || pass "the relay sees only public files: packing a custodian's nonces is refused"
# one character of a payload changed so the frame still decodes, to different bytes: the digest must catch it
node -e '
  const fs = require("fs"), [inp, out] = process.argv.slice(1), lines = fs.readFileSync(inp, "utf8").split("\n");
  const m = lines[0].match(/^((?:[^/]*\/){6})(.*)$/), plen = +lines[0].split("/")[5], body = m[2].slice(plen);
  const k = Math.floor(body.length / 6) * 3, A = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:", c = body[k];
  const swapped = body.slice(0, k) + (c === "0" ? "1" : "0") + body.slice(k + 1);   // the low digit of a triple: never overflows
  lines[0] = m[1] + m[2].slice(0, plen) + swapped; fs.writeFileSync(out, lines.join("\n"));
' "$W/usb/1-r1.frames" "$W/usb-alt.frames"
mkdir -p "$W/scratch1"; out=$($RM unpack "$W/scratch1" "$SESSION" "$W/usb-alt.frames" 2>&1)
if grep -q "altered in transit" <<<"$out" && [ -z "$(ls -A "$W/scratch1")" ]; then pass "one character changed in transit is refused, and nothing is written"; else bad "an altered frame was accepted ($out)"; fi
mkdir -p "$W/scratch2"; out=$($RM unpack "$W/scratch2" "EMERG-OTHER" "$W/usb/1-r1.frames" 2>&1); grep -q "from session" <<<"$out" && pass "a frame from another session is refused" || bad "a frame from another session was accepted"

# a relay that swaps custodian 3's commitment for one from another run: FROST refuses the aggregate
SW="$W/swap"; mkdir -p "$SW/relay" "$SW/usb"; cp -r "$BOX/group" "$SW/relay/"
NSEED2=$(hexrand)
for K in $Q; do mkdir -p "$SW/desk-$K"; cp -r "$W/home-$K" "$SW/home-$K"
  "${NS[@]}" "$P" commit $K "$SW/desk-$K" "$SW/home-$K" "$NSEED2" >/dev/null; "${NS[@]}" $RM pack "$SW/desk-$K" "$SESSION" "$SW/usb/$K-r1.frames" "sign/commit-$K.bin" >/dev/null; done
$RM unpack "$SW/relay" "$SESSION" "$SW"/usb/*-r1.frames >/dev/null
mkdir -p "$SW/other"; cp -r "$W/home-3" "$SW/home-3x"; "$P" commit 3 "$SW/other" "$SW/home-3x" "$(hexrand)" >/dev/null; cp "$SW/other/sign/commit-3.bin" "$SW/relay/sign/commit-3.bin"
$RM pack "$SW/relay" "$SESSION" "$SW/usb/r1-all.frames" $(for K in $Q; do printf 'sign/commit-%s.bin ' $K; done) >/dev/null
for K in $Q; do "${NS[@]}" $RM unpack "$SW/desk-$K" "$SESSION" "$SW/usb/r1-all.frames" >/dev/null 2>&1; "${NS[@]}" "$P" sign $K "$SW/desk-$K" "$SW/home-$K" "$MSG" >/dev/null 2>&1; "${NS[@]}" $RM pack "$SW/desk-$K" "$SESSION" "$SW/usb/$K-r2.frames" "sign/share-$K.bin" "sign/pkg.bin" >/dev/null 2>&1; done
$RM unpack "$SW/relay" "$SESSION" "$SW"/usb/*-r2.frames >/dev/null 2>&1
"$P" aggregate "$SW/relay" "$MSG" >/dev/null 2>&1 && bad "a swapped commitment still produced a signature" || pass "a relay that swaps a commitment gets no signature (FROST refuses the aggregate)"

# a custodian that signed another message: its signing package differs, and the relay's merge refuses it
OD="$W/odd"; mkdir -p "$OD/relay" "$OD/usb"; cp -r "$BOX/group" "$OD/relay/"; NSEED3=$(hexrand)
for K in $Q; do mkdir -p "$OD/desk-$K"; cp -r "$W/home-$K" "$OD/home-$K"; "${NS[@]}" "$P" commit $K "$OD/desk-$K" "$OD/home-$K" "$NSEED3" >/dev/null; "${NS[@]}" $RM pack "$OD/desk-$K" "$SESSION" "$OD/usb/$K-r1.frames" "sign/commit-$K.bin" >/dev/null; done
$RM unpack "$OD/relay" "$SESSION" "$OD"/usb/*-r1.frames >/dev/null; $RM pack "$OD/relay" "$SESSION" "$OD/usb/r1-all.frames" $(for K in $Q; do printf 'sign/commit-%s.bin ' $K; done) >/dev/null
OTHER=$(printf 'some other message' | sha256sum | cut -d' ' -f1)
for K in $Q; do m=$MSG; [ $K = 7 ] && m=$OTHER; "${NS[@]}" $RM unpack "$OD/desk-$K" "$SESSION" "$OD/usb/r1-all.frames" >/dev/null; "${NS[@]}" "$P" sign $K "$OD/desk-$K" "$OD/home-$K" "$m" >/dev/null; "${NS[@]}" $RM pack "$OD/desk-$K" "$SESSION" "$OD/usb/$K-r2.frames" "sign/share-$K.bin" "sign/pkg.bin" >/dev/null; done
out=$($RM unpack "$OD/relay" "$SESSION" "$OD"/usb/*-r2.frames 2>&1); grep -q "different bytes" <<<"$out" && pass "a custodian who signed another message is caught when the relay merges the packages" || bad "two different signing packages were merged"

if [ $fail = 0 ]; then echo "REMOTE-CEREMONY DRILL OK — five offline custodians signed through an untrusted relay; the relay could neither read a secret nor alter a round"; else echo "REMOTE-CEREMONY DRILL FAILED"; exit 1; fi
