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

## Post-mortem: the Rust gate path believed any status it was handed (D-072, fixed before first release)

The second finding written up to this standard, and the first we found in our own code rather than a dependency's.

**What it was.** A presentation carries the registrar's status list — the revocation bitmap — and when it was
issued. Both come from the presenter, and they mean nothing until the registrar's signature over exactly those
values verifies under the status key the signed directory publishes (D-020). `@ainra/sdk` and the Python package
have checked that signature since they had a verifier. The Rust gate path — `credential_json` / `gate_json` in
`ainra-adapter`, which is what `@ainra/edge` and `ainra verify-request` run — did not check it at all. Its wire struct
did not declare the signature fields, so they were silently dropped on the way in.

**What it allowed.** Measured on the live test network: an agent whose passport had just been revoked presented
the bundle from before its revocation with `status_issued_at` set to the current second. The Node gate and the
Python gate answered `403 stale_status`. The edge gate answered `201`, stored the bundle, and allowed the signed
requests that followed. At that gate a revoked party could switch its own revocation off, for as long as it liked,
by editing one integer; an all-clear list of its own making worked too.

**Blast radius, stated honestly.** `@ainra/edge` has never been published to a registry, and `verify-request` is in
no released binary; nothing on npm or PyPI and no release artifact was affected. The repository is public, so anyone
running the edge gate from a checkout between 2026-09-29 (D-068, when that gate landed) and the fix was exposed. The
browser "Try it" panel uses fixture semantics on specimen records and is not a gate.

**Why nothing caught it, which is the more useful half.**

* Every check that compared the Rust path with the others used *honest* bundles — valid, revoked, an hour later.
  A verifier that ignores a signature agrees with one that checks it on everything an honest party sends.
* The edge tests did contain one "forged" bundle, and it was refused — because the edit happened to break the
  list's compression. The test asserted `403` and never asked the reason. A refusal for the wrong reason is a pass
  that proves nothing.
* `docs/POLICY-PARITY.md` explained why the Rust core needed no column in the policy harness: its `Presentation` is
  a struct literal, so no field can be defaulted. True of the core, and beside the point: the code that *fills* that
  struct for a gate decides where each value comes from.
* The conformance corpus could not see it by construction. A vector's status is a fixture input with no signature.
* The five drills that exercise real gates against a real registrar ran only when someone had started two daemons
  by hand, and none of them sent the same request to more than one gate.

**How it was found.** By building the check that was missing: the three gates behind real sockets, one battery of
requests, the same status and reason required from each (`make gate-parity`). It went red on its first run.

**What changed.**

* Rust gates call `verify_gate`, which authenticates the status against the directory's status key before anything
  is decompressed, in the order `@ainra/sdk` applies; the trust object carries the status authorities and one
  without them is refused whole. One definition of the signed bytes now lives in the core.
* **The pinning vectors are a new corpus family, [`vectors/v1-gate`](vectors/v1-gate)**: 27 gate vectors — a
  dual-root-signed directory, a bundle as a presenter sends it, and the gate's own clock, audience and freshness
  class. Every edit a presenter can make to the status material is one of them, and so is the attack itself (`g03`).
  The Rust core, the TypeScript SDK, the Python package and the edge WebAssembly build must agree on all of them in
  `make diff` and their own tests. With the fix removed, twelve read differently. On its first run this corpus found
  a further disagreement (a directory entry with no status key: Python rejected the whole directory).
* `make policy-parity` has a column for the Rust gate path.
* `make live-drills` brings up a network and runs the five live drills; CI runs it on every push.
* What authentication does not close is written into the corpus rather than left to be assumed: a genuine earlier
  publication of the same passport is accepted until it is older than the verifier's freshness class (`g18`, `g19`).

## Post-mortem: the published MCP tool believed the bundle (D-074, fixed in 0.5.0)

**What it was.** `ainra_verify` in `@ainra/mcp` 0.4.1 ran the conformance corpus's runner (`runVector`) over
the bundle it was handed. A conformance vector is self-contained on purpose: it carries its own clock, freshness
class, status list and revoked-delegate list, and the runner believes them. The tool overrode only the audience.

**What it allowed.** An agent asking the tool whether to trust a counterparty got the counterparty's own answer. On
the signed sample bundles: the revoked one carrying an all-clear status list with no signature read `valid`; a
status an hour old advertising the laxest freshness class read `valid`; and the tool had no clock of its own, so a
bundle stayed "fresh" — and unexpired — for as long as it said so.

**Blast radius, stated honestly.** This one is published: npm `@ainra/mcp` 0.4.1, the only version there, since
2026-09-19. Anyone who used
`ainra_verify` on a presentation received from another party, to decide anything, was exposed for the whole of that
time. `@ainra/sdk`'s `Verifier`, `@ainra/middleware` and the Python package were not affected. We have no telemetry
(by design), so we cannot say whether anyone was.

**Why nothing caught it.** `make mcp-test` proved the tool byte-identical to the SDK on the corpus — and it was. The
test held the tool to the wrong function. "The wrapper agrees with the thing it wraps" says nothing when the thing
wrapped is a test runner. It was found the same day as D-072, by asking of every published surface the question D-072
had just taught: who supplies the clock, the class and the status?

**What changed.** The tool takes a signed directory and roots and decides as a gate does, with the caller's clock,
class and audience, and returns a `decision`. Replaying a vector is a separate mode that must be asked for by name
and decides nothing; the old calling convention is refused with an explanation rather than answered. **The pinning
vectors are `vectors/v1-gate`** — the tool is held to all 27 gate vectors in `make mcp-test`.

**The same class, once more (D-075).** The Python package's plain constructor, `ainra.Verifier(anchors)`, skipped
status authentication whenever the anchors carried no status key — on PyPI through 0.4.x. It was documented as a
"trusted-input mode"; it was also the constructor the quickstart opened with. `Verifier.from_directory`, the
documented production path, was not affected. The plain constructor now fails closed, and believing the bundle has to
be asked for by name. If you build a Python verifier from raw anchors, move to `from_directory` or add the status key
to the anchors.

**What you should do.** If you run `@ainra/mcp` 0.4.1 and rely on `ainra_verify` for a trust decision:
upgrade to 0.5.0 when it is published, and until then verify with `@ainra/sdk`'s `Verifier` directly.

## Verifying what you run
You do not have to trust us: the SDK is byte-differential-tested against the Rust core over the public CC0 vectors
(`make diff`), every published artifact is byte-reproducible from source (`make repro`), and any mirror is
byte-verifiable root-dark (`make verify-mirror`). If your build disagrees with the vectors, that itself is a report.
