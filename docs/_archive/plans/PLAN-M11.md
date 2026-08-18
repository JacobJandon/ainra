<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN — M11: public-operational (plumbing, durability, operator tooling)

M11 makes the repo safe to *operate* in public: CI that actually runs on the host, a proper front desk for
strangers, verifiable releases, a smooth operator loop for real external verifiers, and a repo that survives a
newcomer's first hostile hour. No new protocol. Prime directives bind (nothing fake, no third-party names anywhere
incl. commit messages, zero telemetry, both-or-invalid, logged-before-valid, no bespoke crypto, never weaken a test;
MTS wins; log D-026…). Do NOT push, create the public repo, run a real ceremony/soak, or fabricate results — prepare
to the exact edge of public and stop.

## Task 1 — CI that runs on the host
- Validate `.github/workflows/ci.yml` runs on push + PR with the full gate set (already: fmt/clippy/test --release,
  differential, wedge, drill/testbed/genesis-local, repro+verify-mirror, fuzz, S7/license/status/freeze/N7, gitleaks).
- Add a dedicated **`audit`** job running `make audit` on every PR (secret/S7/license parity with the local command).
- Decide repro-in-CI: keep on PR in its own parallel job with `timeout-minutes` (regressions caught pre-merge) +
  add a nightly `schedule`; add `timeout-minutes` to every job. Log the decision (D-026).
- Encode the release-test trap inline (done); pin toolchains explicitly (rust 1.96 via toolchain file + action; Node 22).
- Parameterize the README CI badge `<owner>` to one obvious spot; document the exact pre-push checklist in PUBLISH-AUDIT.md.

## Task 2 — Community health files
- `.github/ISSUE_TEMPLATE/`: security-adjacent-bug (routes to SECURITY.md, no public disclosure), bug report,
  spec/vector-discrepancy (conformance is claimed against public vectors → first-class report). `config.yml` links.
- `.github/PULL_REQUEST_TEMPLATE.md`: tests added · `make preflight` green · no third-party names · SPDX header ·
  decision logged if behavior changed · DCO sign-off.
- Confirm CONTRIBUTING (DCO + gates), CODE_OF_CONDUCT, SECURITY consistent with STATUS.md. No FUNDING file (no neutral
  entity/target yet — omit rather than invent).

## Task 3 — Release hygiene
- `CHANGELOG.md` mapping releases → milestone ladder (M1–M11) + D-0xx, honestly noting the fixed security bugs
  (CRITICAL revocation bypass, base64-alias quorum forgery, attestation-execution correction).
- `scripts/release.sh` (`make release`): refuse a dirty tree or red preflight; run preflight; regenerate + check
  `MANIFEST.sha256`; build the reference CLI artifact; print a signable checksum manifest.
- Document the downloader's verify-a-release path (fetch artifact + manifest, check hashes, signature when wired).

## Task 4 — Operator tooling for real external verifiers (highest-leverage ⏳ row)
- `mint-challenge.mjs`: per-named-party fresh corpus + private answer key stored under a per-party id, gitignored
  (assert ignored); print the party the exact command + the file to send back.
- `check-attestation.mjs --secret`: validate signature + answer key + forge-probability (2⁻ᴷ); emit durable
  `evidence/verifier/<party>.json` the board reads; refuse hand-authored/wrong-key with a clear reason.
- `kits/verifier/OPERATOR.md`: onboard one verifier cold (mint → send → receive → check → board increments); D-024
  honest-scope verbatim.
- Acceptance: 3 labelled dry-run parties (NOT counted) minted + completed with the published SDK + checked; board
  reads 3 distinct evidence files; a forged attestation rejected.

## Task 5 — Durability
- `TOOLCHAIN.md` (exact Rust/Node/make/system-lib versions) + `make doctor` (check env, print what's missing).
- Error-message audit on golden paths (preflight, genesis-local, verifier kit): human next step, not a stack trace.
- Extend `status-consistency` to also fail if the genesis board's ✅/⏳ counts drift from `docs/DOD.md`.
- Re-confirm LICENSE/SPDX/THIRD-PARTY pass after everything.

## Working method
Per task: implement → run the gate, paste real output. Ambiguity → stricter reading, log D-0xx. Acceptance: fresh-clone
`make preflight` green; CI valid + would run green (syntax + review + pre-push checklist); community/release files
present + consistent; operator loop works on dry-run parties + board reads evidence; newcomers get a human next step.
End with the honest board, the pre-push checklist, and confirmation that only recruiting real people remains.
