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

## Verifying what you run
You do not have to trust us: the SDK is byte-differential-tested against the Rust core over the public CC0 vectors
(`make diff`), every published artifact is byte-reproducible from source (`make repro`), and any mirror is
byte-verifiable root-dark (`make verify-mirror`). If your build disagrees with the vectors, that itself is a report.
