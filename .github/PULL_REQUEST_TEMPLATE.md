<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] **Tests added/updated** for the change (and existing tests were **not** weakened — a red test is fixed, never deleted or loosened).
- [ ] **`make preflight` is green** locally (build+test, differential, genesis-local, kit smokes, S7, license, repro).
- [ ] **`make audit` is green** (no secret, no third-party/company name in code, fixtures, docs, or **commit messages**).
- [ ] Every new source file carries the **`SPDX-License-Identifier: Apache-2.0 OR MIT`** header.
- [ ] If behavior changed, a decision is logged in **`docs/DECISIONS.md`** (D-0xx) and, if it touches the verify path or a normative doc, the **MTS wins** and the deviation is noted.
- [ ] No telemetry / network / clock added to `ainra-core` or a shipped SDK (N7).
- [ ] **DCO sign-off**: every commit is signed off (`git commit -s`) — see [CONTRIBUTING.md](../CONTRIBUTING.md). We use the DCO, not a CLA.

## Security

- [ ] This PR does **not** introduce a way for a revoked or forged passport to verify VALID, weaken the both-signatures-or-invalid or logged-before-valid rules, or add bespoke crypto. (If it might, stop and read [SECURITY.md](../SECURITY.md) first.)

<!-- Reviewers: the CI `audit`, `hygiene`, `reproducibility`, and `integration` jobs must be green before merge. -->
