#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make miri — run the interpreter over the code that reads ATTACKER-CONTROLLED BYTES, and only that code.
#
# WHY THIS IS A LIST AND NOT `cargo miri test -p ainra-core --lib`
#
# It was exactly that for months, and it never once finished. Miri interprets; it does not execute. Anything that
# hashes or signs in a loop runs orders of magnitude slower, and ainra-core's suite is full of both — SLH-DSA
# delegate certs, ML-DSA hybrid signatures, exhaustive Merkle consistency pairs. The job had no `timeout-minutes`,
# so every run walked into GitHub's 6-hour ceiling and was killed. GitHub reports that kill as `cancelled`, which
# reads like a person cancelled it rather than "this check is broken", and that is how it stayed invisible across
# 40 consecutive runs. MEASURED, not guessed:
#
#   whole lib               > 900s  KILLED — never completes
#   merkle:: (whole module) > 1200s KILLED — consistency_all_size_pairs hashes over every size pair
#   status:: (whole module) > 600s  KILLED — dies inside delta_bad_delegate_countersig (SLH-DSA cert build)
#
# So the list below is the honest scope: the byte-handling code, which is what miri is for and what the original
# job comment actually named. Signature and hashing THROUGHPUT is not a UB question — the fuzzer
# (clusterfuzzlite, address sanitizer, in the same workflow) covers those paths at execution speed, which is the
# right instrument for them.
#
# WHAT THIS ACTUALLY DEFENDS, given ainra-core is `#![forbid(unsafe_code)]`
#
# The crate cannot contain UB of its own — `forbid` cannot even be locally overridden, which is why an attempt to
# inject a use-after-free here does not compile. Miri interprets the whole call graph, so what it is really
# watching is the UNSAFE CODE IN THE DEPENDENCIES these parsers drive: flate2's zlib decompressor on
# attacker-shaped bytes (status::larger_bitstring_roundtrips), serde_json, and the crypto crates. Plus it is a
# tripwire for the day someone relaxes the forbid.
#
# CONTROLS (run before this was committed — a check never seen failing is decoration):
#   · a filter matching zero tests    → FAIL, exit 1   (libtest calls that "ok. 0 passed"; we do not)
#   · a deliberately failing test     → FAIL, exit 1, with the panic shown
#
# If you are about to "fix" this by pointing miri back at the whole suite: it will pass locally for as long as you
# are willing to wait, and it will be killed in CI. Add tests to the list instead.
set -uo pipefail
cd "$(dirname "$0")/.."

export MIRIFLAGS="${MIRIFLAGS:--Zmiri-disable-isolation}"
# name::prop_round_trip is a proptest. Its default 256 cases cost 667s under the interpreter; 16 cases cost 46s and
# find the same class of defect, because miri is checking that the parser is SOUND on each input, not searching for
# a failing one. Searching is the fuzzer's job.
export PROPTEST_CASES="${PROPTEST_CASES:-16}"

# Each entry is a libtest filter. Module-wide where the whole module is feasible; individual tests where it is not,
# with the reason on the line — so a future reader can see the exclusion is measured rather than arbitrary.
FILTERS=(
  "b64::"                                            # base64url decode — canonical-only, rejects non-canonical tails
  "canon::"                                          # canonical JSON — integer/keys/whitespace handling
  "name::"                                           # the name grammar, incl. homoglyph rejection (proptest capped)
  "passport::"                                       # the passport parser itself: the first thing to touch a stranger's bytes
  # Per-test entries carry the `::tests::` segment because libtest filters are SUBSTRING matches against the full
  # path. `merkle::empty_and_single` matches nothing — the test is `merkle::tests::empty_and_single` — and libtest
  # reports a filter that matches nothing as "ok. 0 passed", exit 0. Seven such filters were written during the
  # sizing pass and every one printed a green line while measuring nothing. Hence the zero-match guard below.
  "merkle::tests::empty_and_single"                          # merkle:: whole-module is KILLED (>1200s): the
  "merkle::tests::known_two_leaf_root"                       # exhaustive size-pair and all-leaves tests never finish
  "status::tests::pack_roundtrip_lsb_first"                  # status:: whole-module is KILLED (>600s) inside the
  "status::tests::status_resolution_and_fail_closed_past_end" # SLH-DSA delta/fresh-head cert tests. These four are
  "status::tests::freshness_fails_closed"                    # the bit-packing and bounds handling — the UB surface
  "status::tests::larger_bitstring_roundtrips"
)

# NOT included, and why — every one of these was measured, not assumed:
#
#   whole lib                                > 900s  KILLED
#   merkle::                                 >1200s  KILLED   (consistency_all_size_pairs)
#   merkle::tests::build_then_verify_all_leaves > 600s KILLED
#   status::                                 > 600s  KILLED   (delta_bad_delegate_countersig — SLH-DSA cert build)
#   verify::                                 > 600s  KILLED   (builds whole presentations: SLH-DSA + ML-DSA)
#
# `verify::` being absent is not a coverage hole. Its UB surface is the decoders it calls — b64, canon, passport,
# and the status bit operations — and all four are above. What `verify::` adds on top is signature verification,
# which is arithmetic in audited crates, not hand-rolled byte handling.

echo "miri — undefined behaviour in the byte-handling code"
echo "  MIRIFLAGS=$MIRIFLAGS · PROPTEST_CASES=$PROPTEST_CASES · ${#FILTERS[@]} filters"
echo "────────────────────────────────────────────────────────────────"

fail=0
total_start=$(date +%s)
for f in "${FILTERS[@]}"; do
  start=$(date +%s)
  out=$(cargo +nightly miri test -p ainra-core --lib -- "$f" 2>&1); rc=$?
  end=$(date +%s)
  res=$(printf '%s' "$out" | grep -E '^test result:' | tail -1)
  # A filter that matches NOTHING passes libtest with "0 passed" — silently measuring nothing. That is the same
  # class of defect this whole exercise is about, so it is a failure here.
  passed=$(printf '%s' "$res" | sed -n 's/^test result: ok\. \([0-9]*\) passed.*/\1/p')
  if [ "$rc" -ne 0 ]; then
    printf '  FAIL  %-52s %3ss\n' "$f" "$((end-start))"
    printf '%s\n' "$out" | tail -25 | sed 's/^/        /'
    fail=1
  elif [ -z "$passed" ] || [ "$passed" -eq 0 ]; then
    printf '  FAIL  %-52s %3ss  filter matched NO tests — it is measuring nothing\n' "$f" "$((end-start))"
    fail=1
  else
    printf '  ok    %-52s %3ss  %s tests\n' "$f" "$((end-start))" "$passed"
  fi
done
total_end=$(date +%s)

echo "────────────────────────────────────────────────────────────────"
if [ "$fail" -ne 0 ]; then
  echo "miri: FAILED after $((total_end-total_start))s"
  exit 1
fi
echo "miri OK: no undefined behaviour in the byte-handling code ($((total_end-total_start))s total)"
