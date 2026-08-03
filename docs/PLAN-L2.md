<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# L2 — operational scaffolding for a public root

Follows L1 (docs/PLAN-L1.md). Three moves: audit L1 from evidence and finish/park it; build the
security/community/intake scaffolding a public trust root owes the strangers it invites; make releases
and the site self-serve. Prime directives bind: nothing fake · fail closed · full-output checks ·
zero telemetry · the DoD table untouched (intake pipelines define HOW rows flip; they never flip them).
Platform config files naming the host are plumbing and allowed; S7 continues to govern prose.

## Task 0 — L1 state, verified from evidence (2026-08-03)

| L1 phase | State | Evidence (command output) |
|---|---|---|
| Tags | **DONE** | `git tag -l` → v0.2.0, v0.2.0 · `git verify-tag` both: `Good "git" signature for dev@ainra.local with ED25519 key SHA256:xMs+…9Us` · derefs: v0.2.0→`5ae1b12`, v0.3.0→`af3c869` == the RELEASING.md pins |
| Public repo | **DONE** | `git remote -v` → github.com/JacobJandon/ainra · local HEAD `7dbe468` == `git ls-remote origin main` · **anonymous** `git clone --depth 1` of the public URL succeeded at the same HEAD |
| Stranger Test | **DONE (proven)** | `docs/releases/stranger-test-2026-07-31.md` — credential-less container, anonymous clone, 18/18 ALL GREEN; re-proven since by the public nightly CI board (scheduled run success 2026-08-02) |
| Platform releases | **DONE** | `gh release list` → v0.3.0 (signed, provenance+SBOM) + v0.2.0 (signed externally at its pin); Latest marker corrected to v0.3.0 this session |
| npm publish | **PARKED (credentials)** | `registry.npmjs.org/@ainra/sdk` and `/@ainra/middleware` → `{"error":"Not found"}` — unpublished; dry-runs green per L1. Resume: see the L2 resume list |
| PyPI publish | **PARKED (credentials)** | `pypi.org/pypi/ainra/json` → HTTP 404 — unpublished; wheel+sdist twine-check PASSED per L1. Resume: see the L2 resume list |
| outreach/ready/ | **DONE (nothing sent)** | 43 files: 3× (challenge/ + ONE-PAGER + EMAIL-DRAFT), custodian-packet/, witness/, SOAK-REALITY-CHECK.md, README.md |

## Session log

| L2 task | State | Notes |
|---|---|---|
| 0 — audit | DONE | table above; stray QA PNGs removed from the repo root; release Latest marker fixed |
| 1 — security & community scaffolding | in progress | |
| 2 — intake pipelines | pending | |
| 3 — release automation | pending | |
| 4 — site live | pending | |
| 5 — roadmap + closure | pending | |
