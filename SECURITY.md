<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Security Policy

AINRA is security-critical infrastructure: it is a **root of trust**. We treat it that way.

## Our posture
- **Fail closed, everywhere.** Any ambiguity, any error, any missing signature → reject. A verifier that returns
  `valid` on error, or crashes instead of rejecting, is a critical bug.
- **Both signatures or invalid · logged-before-valid** are load-bearing invariants, not options.
- **Adversarial review at every milestone.** Each milestone is put through a multi-agent attack→verify→synthesize
  review that tries to break its invariants; confirmed findings are fixed before the milestone is called done, and
  recorded in `docs/DECISIONS.md` (e.g. the M5 status-list revocation-bypass, the M6 threshold-downgrade, the M7
  reproducibility orphan-laundering, the M8 identical-registrar-keys). If you can defeat an invariant, we want it.

## What is in scope (high value)
- Making a **revoked** or **forged** passport verify `VALID` (a revocation bypass).
- Defeating **both-signatures-or-invalid** (an algorithm downgrade that verifies).
- Making an **unlogged** credential verify (breaking logged-before-valid).
- Getting an equivocating **fork** past the witness quorum, or lowering the relying party's threshold `k`.
- A **directory / mirror** that verifies while serving tampered or non-reproducible bytes.
- A **DoS** in the verify path (unbounded allocation, an uncatchable crash) reachable pre-authentication.
- Any **telemetry / phone-home** in `ainra-core` or a shipped SDK (that is a privacy defect, N7).

## What is out of scope (known, documented)
- The **local-by-default dev daemons** (`registrar-box`, `witnessd`, …) bind `127.0.0.1`, carry no auth, and use
  permissive CORS. Transport security (TLS), authn/z, and rate-limiting are **deployment** concerns (reverse proxy),
  documented as such in the kit READMEs and `docs/STATUS.md`. A "no auth on the local daemon" report is not a finding.
- The **external DoD events** (recorded ceremony, ≥3 external verifiers, 14-day/3-region soak) are pending real-world
  events, honestly tracked in `docs/DOD.md` — not vulnerabilities.

## Reporting a vulnerability

**Do not open a public issue.** Use the repository's **private security advisory** channel — it needs no email
address on either side, which matches our no-PII stance (D-036: the root collects no personal data, and that
includes yours):

> **[Report a vulnerability privately](https://github.com/JacobJandon/ainra/security/advisories/new)**
> (repository → Security → Advisories → *Report a vulnerability*)

Include:
- a description and the impact,
- a concrete reproduction — the exact bundle / directory / input, or a failing `make` invocation. **A failing
  conformance vector is the ideal report**: we can add it to the corpus verbatim and it becomes a permanent test,
- your assessment of severity.

### What we promise, honestly

We are **pre-institution**: an operator-run project, not yet a staffed foundation. So the commitment is what one
maintainer can actually keep, not a corporate SLA:

| | Commitment |
|---|---|
| Acknowledgement | within **5 business days** — if you hear nothing by then, the channel failed; open a *non-exploit* public issue saying only "unacknowledged advisory, please check" |
| Triage verdict | within **14 days** of acknowledgement (confirmed / not-a-finding / needs-more-info) |
| Fix + disclosure | coordinated with you; we do not sit on confirmed exploitable findings |
| Credit | you are credited unless you prefer anonymity |

After the genesis ceremony this becomes a custodian/board responsibility with a real response body; this table is
updated then, not before (see `GOVERNANCE.md`).

### What a fix looks like here (the promise that matters)

Every fixed security bug in this project has received the same treatment, and yours will too:

1. **A pinning vector.** The bug becomes a permanent entry in the CC0 conformance corpus, so all four
   implementations are tested against it forever and no future refactor can silently reintroduce it.
2. **A public post-mortem.** The finding, the root cause, and the fix are written into `docs/DECISIONS.md` as a
   numbered decision, and into `CHANGELOG.md` under the release that fixed it — by name, in the open.
3. **No quiet patches.** We publicly own fixed security bugs; hiding them would be the opposite of a trust root.

The historical examples in "Our posture" above are exactly that record: each one is a vector in the corpus and a
decision in the log. That is the standard your report will be held to — and the reason a good report here is
permanent, not just patched.

## Post-mortem: RUSTSEC-2025-0144 — timing side-channel in `ml-dsa` (fixed in v0.3.1)

The first finding to arrive through the process above, written up to the standard that section promises.

**What it was.** `ml-dsa` ≤ 0.1.0-rc.2 computed `r1.0 / TwoGamma2::U32` in `decompose()` with a hardware division
instruction. Division timing is operand-dependent, and `decompose()` is reached through `high_bits()` /
`low_bits()` on values derived from the secret key components **s2** and **t0**. Upstream advisory:
[GHSA-hcp2-x6j4-29j7](https://github.com/RustCrypto/signatures/security/advisories/GHSA-hcp2-x6j4-29j7),
6.4 medium, published 2025-12-12.

**Blast radius, stated honestly.** This is a **signing-side** leak. Verification consumes only public inputs — the
public key, the signature, the message — so a relying party running the verifier has no secret for the timing to
expose. The signing side is ours and is real: registrar issuance, ceremony delegates, and the CLI all sign. The
scoping did not soften the fix; `ml-dsa` was taken to 0.1.1, where Barrett reduction replaces the division.

**Why our CI did not catch it, which is the more useful half.** `cargo-audit` ran on every push and was *red* —
but `--deny warnings` stops at the first denied finding, and that was an **unmaintained** notice on
`atomic-polyfill`, a transitive crate of the signing-side FROST dependency. The real vulnerability sat behind it,
unreported, in a **direct dependency of the verify path**. A gate that stops at the first problem can hide a worse
one behind a lesser one.

Two neighbouring checks turned out never to have run at all: `scorecard` referenced an action tag that does not
exist (`ossf/scorecard-action@v2`), and `clusterfuzzlite` — "continuous fuzzing on the parsers" — failed at
*build* on every run and had never fuzzed a single input. Both read as ordinary red jobs.

**What changed.**

* `ml-dsa` 0.0.4 → 0.1.1. `getrandom` dropped from the verify path entirely along the way (it was a default
  feature, unreachable in our use, and it broke the WebAssembly build).
* **The pinning vector is the FIPS 204 KAT suite** — NIST's own ML-DSA-65 keyGen / sigGen / sigVer answers
  ([`vectors/nist/ml-dsa-65-fips204-kat.json`](vectors/nist/ml-dsa-65-fips204-kat.json), 15 sigVer cases of which
  12 are negative). Our own vectors could not adjudicate this: they were generated *by* the vulnerable crate.
  The KATs are independent of it in both directions, and they now run on every board.
* `cargo-audit` reports **every** advisory before it gates, so one notice can never hide another again.
* All **56** GitHub Actions references pinned to commit SHAs.
* `CONTRIBUTING.md` gained the rule these three failures taught: **a check that has never passed does not exist**,
  with a worked example of a negative control that passed while testing nothing.

**Not fixed by us:** nothing here was reported by an outside researcher — this was found by reading our own red
CI honestly. Full workings: [`docs/_archive/plans/PLAN-M26.md`](docs/_archive/plans/PLAN-M26.md) and
[`SECURITY-ADVISORIES.md`](SECURITY-ADVISORIES.md).

## Verifying what you run
You do not have to trust us: the SDK is byte-differential-tested against the Rust core over the public CC0 vectors
(`make diff`), every published artifact is byte-reproducible from source (`make repro`), and any mirror is
byte-verifiable root-dark (`make verify-mirror`). If your build disagrees with the vectors, that itself is a report.
