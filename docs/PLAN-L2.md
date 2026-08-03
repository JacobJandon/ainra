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
| 1 — scaffolding | DONE (`e66ed48`) | SECURITY.md → real private-advisory channel (no placeholder email, D-036 no-PII), honest pre-institution response table, pinning-vector + public-post-mortem promise · CONTRIBUTING.md → conformance-first rule · verifier-divergence + spec-question issue templates (absorbed the stale 3-impl vector template) · GOVERNANCE.md + MAINTAINERS.md (operator-run today, custodians at ceremony, constituencies after) |
| 2 — intake pipelines | DONE (`df38c3e`,`8df28bd`) | `tools/intake-check.mjs` public-half checker — proven pass + malformed-fail + tamper-fail · `tools/witness-probe.mjs` — proven reachable-pass + unreachable-fail-closed · `evidence/README.md` + verifier/witness templates · `witnesses/candidates.json` (candidate≠production) · `.github/workflows/intake.yml` on submission PRs · wired into skills.md + llms.txt (also fixed the stale "three implementations"→four) · **never flips a DoD row** (private answer-key check stays with the maintainer) |
| 3 — release automation | DONE (`951a3bf`) | `.github/workflows/release.yml` on `vX.Y.Z`: one-release-rule gate → reproducible rebuild + provenance + SBOM + manifest → draft release with board link; signature stays a maintainer step (D-042, key never in CI). **PROVEN**: pushed labeled `v0.0.0-ci-test` (no board) → CI **REFUSED** at the gate (`Release REFUSED — no board evidence … no full board from a clean clone ⇒ no release`); throwaway tag + would-be release deleted from local + remote |
| 4 — site live | DONE (`9d686e6`) | Pages enabled via API (Actions source, HTTPS enforced); deploy workflow re-enabled + first deploy green. **Live: https://jacobjandon.github.io/ainra/** — all pages + agent surfaces (llms.txt, skills index, OpenAPI ×6, .md mirrors, the Standard) 200 over HTTPS; browser QA 5 pages 0 console errors, honest live-data fallback renders. Live URL propagated → README + package metadata (homepage/repository) + outreach one-pagers. `ainra.org` stays the declared canonical (owner's domain call) |
| 5 — roadmap + closure | DONE | ROADMAP.md (shipped + the three rows with flip conditions: verifiers **0/3**, ceremony not held, soak not started, witness candidacies **0**) linked from README; closing board run from a clean clone at HEAD (evidence below); resume list below |

## Resume list (each one paste away — none blocks the rest)

- **npm publish** (PARKED, needs credentials): `npm login` then `cd packages/sdk-ts && npm publish --access public --provenance`; rewrite `@ainra/sdk` `file:`→`^0.3.0` in middleware, then `cd ../middleware && npm publish --access public --provenance`. `@ainra/mcp` stays unpublished (not standalone).
- **PyPI publish** (PARKED, needs credentials): `cd packages/sdk-py && python -m build && TWINE_USERNAME=__token__ TWINE_PASSWORD=<token> twine upload dist/*`.
- **Package metadata is already live-URL-stamped** — no follow-up metadata-only bump needed; the URLs ship with the first publish above.
- **Custom domain** (owner's jurisdiction call): point `ainra.org` at Pages, then `gh api -X PUT repos/JacobJandon/ainra/pages -f cname=ainra.org`; the site already uses `ainra.org` as its declared canonical.
- **Send outreach** (owner): the 3 verifier emails + custodian/witness packets in `outreach/ready/` (untracked), now carrying the live URL.

## The one release rule, now doubly enforced
Board evidence gates the CHANGELOG (`make changelog-board-check`) **and** the tag-triggered release workflow (`.github/workflows/release.yml`). A version cannot be *claimed* or *released* without a committed board at its commit.
