<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# M26 — the ml-dsa advisory, taken properly

One advisory, closed end to end: scoped honestly, fixed, proven against evidence the vulnerable crate did not
produce, deployed to the surface that actually serves it, and then the *class* of failure closed behind it.

## Task 0 — the exposure, scoped before it was fixed

`RUSTSEC-2025-0144` / `GHSA-hcp2-x6j4-29j7`: `decompose()` used a hardware division instruction to compute
`r1.0 / TwoGamma2::U32`. The division is reached through `high_bits()` and `low_bits()` on values derived from the
secret key components **s2** (`(&w - &cs2).low_bits()`) and **t0** (`Hint::new()`).

**It is a signing-side leak.** Verification consumes only public inputs — public key, signature, message — so a
verifier has no secret for the timing to leak. That is the honest scope, and it is written down in
[`SECURITY-ADVISORIES.md`](../SECURITY-ADVISORIES.md) with the code paths that put us on each side of the line.

**Scoping is not softening.** The signing side is real and it is ours: registrar issuance, the ceremony delegates,
and the CLI all sign. The fix was taken in full.

## Task 1 — ground truth from outside our own corpus

The 745 conformance vectors were generated *by* the vulnerable crate, so they cannot adjudicate a change to it.
Before touching the dependency, NIST's own ML-DSA-65 answers were wired in as
[`vectors/nist/ml-dsa-65-fips204-kat.json`](../vectors/nist/ml-dsa-65-fips204-kat.json), driven by
[`crates/ainra-core/tests/fips204_kat.rs`](../crates/ainra-core/tests/fips204_kat.rs):

* **keyGen** — a seed expands to the byte-exact public and secret key NIST specifies.
* **sigGen** — deterministic signing reproduces NIST's signature byte for byte. Not "a valid signature", *the* signature.
* **sigVer** — 15 cases, **12 of them negative**. A verifier that accepts everything passes the positives and fails here.

**0.0.4 passed every KAT.** Had it failed, that would have been a far larger finding than the timing leak, and the
instruction was to stop and report. It did not.

## Task 2 — the upgrade, proven

`ml-dsa 0.0.4 → 0.1.1`. Upstream fix: Barrett reduction replaces the operand-dependent division.

The API break is seed-first (`SigningKey::from_seed`; `sign_deterministic` moved to `ExpandedSigningKey`). Key
derivation is **preserved** — checked, not hoped: 0.0.4's `key_gen(rng)` filled a 32-byte xi and ran FIPS 204
Algorithm 6, and 0.1's `from_seed` is the same algorithm, so drawing the seed ourselves yields byte-identical keys
for a given seeded CSPRNG. That is what keeps a reproducible corpus reproducible across a crypto upgrade.

| # | Proof | Result |
|---|---|---|
| (a) | FIPS 204 KATs on the new crate | **3/3** — keyGen, byte-exact sigGen, sigVer incl. 12 negatives |
| (b) | Every existing vector still verifies | **745 + 17 + 9** reproduce their recorded verdicts · **0 vector files changed** |
| (c) | Four-way differential | **745/745 · 10/10 · 4/4 · 17/17 · 9/9** · py **745/745 · 17/17 · 9/9** |
| (d) | Fresh signatures cross-checked | TS **3/3**, PY **3/3**, both refuse a flipped bit |
| (e) | Reproducibility + board | `repro` byte-identical ×2 (790 files, digest `ace6366e60fe74e5…`) · clean-clone board **ALL GREEN 22/22** |

**(c) is a genuine interop cross-check, not an echo.** `ainra-core` uses RustCrypto `ml-dsa`; `sdk-ts` and
`cli-node` use `@noble/post-quantum`; `sdk-py` uses OpenSSL through `cryptography.hazmat`. Three independent
ML-DSA implementations agreeing.

**(b) needed care.** The regenerated corpus came out **byte-identical** — Barrett reduction computes the same
value the division did — which makes "the vectors still pass" an easy test to pass. That is why (d) exists:
[`tools/interop-verify.mjs`](../tools/interop-verify.mjs) signs genuinely novel material under a seed the corpus
has never used and has the other two implementations check it. **No vector was ever regenerated to clear a red.**

### A dependency removed, decided on evidence

`getrandom` is a **default** feature of ml-dsa 0.1. It broke the `wasm32-unknown-unknown` build outright and is
dead weight — key derivation goes through our own seed, so ml-dsa's RNG is never reached. Set
`default-features = false, features = ["alloc"]`; getrandom is now **absent from the verify path**.

This was carried as *unproven* for a session: `make repro` aborted once (SIGABRT) with the change in place. Re-run
alone on an idle machine it passed **twice**, byte-identical, same digest. The abort was **contention** — a
clean-clone board was building concurrently with repro's two clean rebuilds. Had it reproduced, the change would
have been reverted: a smaller dependency surface is not worth an unreproducible build.

## Task 3 — shipped where it is actually served

Pushing is not deploying. The live site serves a WASM verifier built from this crate, and `ainra.vercel.app`
deploys from a **separate** repo via `tools/export-site.sh`.

```
before deploy   live wasm sha256  7d060806795a4654   ← pre-upgrade
after  deploy   live wasm sha256  819e47a4d9f390b7   ← matches local, byte for byte
                HTTP 200 · 379037 bytes
```

Driven in a real browser against production: engine **`ainra-core`**, clean specimen **VALID**, forged signature
**`sig_invalid`**, **zero page errors**.

## Task 4 — closing the class, not just the bug

Three checks in this repository had never once done their job, and each looked healthy from a distance:

| Check | Appeared to be | Actually was |
|---|---|---|
| `scorecard` | a published OpenSSF score | `ossf/scorecard-action@v2` is not a tag — never resolved, never published |
| `clusterfuzzlite` | continuous parser fuzzing | failed at *build* every run — never fuzzed one input |
| `cargo-audit` | advisories gated | short-circuited on an unmaintained notice, hiding the ml-dsa vulnerability |

A red job reads as "the check found something". Two of those three meant "the check never ran".

### Every security job now has a proof it CAN go green

| Job | Proof it passes | Proof it can fail |
|---|---|---|
| `cargo-audit` | exit 0, 143 crates scanned, clean with the documented ignore | ignore removed → exit 1, `RUSTSEC-2023-0089`, `1 denied warning found!` |
| `clusterfuzzlite` | all three targets build **and run**: `canon` 2,819,057 · `passport` 2,365,037 · `tsl` 589,127 executions in 21 s each, no crashes | a build failure is the failure mode it had for its whole life |
| `scorecard` | run `31102308487` completes after the SHA pin | previously failed at action resolution on every push |
| `browser verifier` | 745/745 in a headless browser | `make wasm-diff-negative` — one flipped bit → 744/745, exit 1 |
| `cross-impl interop` | TS 3/3, PY 3/3 | `make interop-negative` — one corrupted byte → exit 1 |
| `one decode path` | 46 Rust files scanned, clean | a planted duplicate parser is caught, and was |

### Other structural fixes

* **56 action refs pinned to commit SHAs, 0 floating**, across all 8 workflows. Pinned-Dependencies is itself one
  of the checks Scorecard scores, so this is both the fix and a point on the thing being fixed.
* **`cargo-audit` reports everything before it gates.** An informational pass that always succeeds runs first, so
  the whole picture reaches the log; the deny-pass is the gate. One notice can never hide another again.
* **The rule is written into [`CONTRIBUTING.md`](../CONTRIBUTING.md)** — *a check that has never passed does not
  exist* — with the interop harness's vacuous comparison as the worked example.

### The worked example, because it is the sharpest one

`tools/interop-verify.mjs` shipped comparing `verifyHybrid`'s result against `"ok"`. That function returns
**`null`** on success. The positive check reported every genuine signature as rejected — loud, and caught
immediately. The negative control compared `=== "ok"`, a value that can never occur, so it reported
**"3/3 flipped-bit refused" while testing nothing** — silent, and nearly missed.

The loud half is not the lesson. **A negative control that cannot fire is indistinguishable from one that passes.**

## Task 5 — closed publicly

`SECURITY.md` commits every finding to a public post-mortem and a pinning vector. This is the first to arrive
through that process; the post-mortem is in that file, and **the FIPS 204 KAT suite is the pinning vector** — it
would have caught a functional regression in either direction, and it now runs on every board.

## Release

`v0.3.1`, with the full board at the release commit in [`docs/releases/v0.3.1-board.md`](releases/v0.3.1-board.md).
**Not tagged and not published here** — those are the maintainer's buttons.
