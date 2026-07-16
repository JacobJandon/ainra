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
**Do not open a public issue.** Email **security@ainra.example** (replace with the project's real contact before
launch) with:
- a description and impact,
- a concrete reproduction (the exact bundle / directory / input, or a failing `make` invocation),
- your assessment of severity.

We aim to acknowledge within a few business days and to coordinate a fix + disclosure timeline with you. We credit
reporters unless you prefer to remain anonymous.

## Verifying what you run
You do not have to trust us: the SDK is byte-differential-tested against the Rust core over the public CC0 vectors
(`make diff`), every published artifact is byte-reproducible from source (`make repro`), and any mirror is
byte-verifiable root-dark (`make verify-mirror`). If your build disagrees with the vectors, that itself is a report.
