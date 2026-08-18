<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN — M10: publish-ready + stranger-completable DoD events

M10 adds **no protocol**. It (1) makes the repo safe + inviting to open to the world, and (2) turns the three
"machinery ready" DoD kits into events a stranger can complete unattended, aggregated into one honest board — because
the only thing between here and a founded root is real people running the ceremony, verifications, and soak. Prime
directives bind (nothing fake, no third-party names in public materials, zero telemetry, both-or-invalid,
logged-before-valid, no bespoke crypto, never weaken a test, Apache/MIT + CC0; MTS wins conflicts; log D-025…).

## Task 1 — Publish-readiness audit (`docs/PUBLISH-AUDIT.md`) — GATE, do first, stop if history is dirty
- Full-history secret sweep (gitleaks, all 24 commits) — **DONE: 0 real secrets** (672 hits = public-key vector FPs).
- Third-party / private-material sweep — **DONE: found 2 PRIVATE-labeled strategy docs + `_archive/` in history.**
- **STOP for confirmation** on the one-way history-clean decision (rewrite options in PUBLIC-AUDIT.md) before Task 2.
- `.gitleaks.toml` allowlist for the CC0 vector public-key fields; CI runs gitleaks; audit fails on any *new* hit.
- S7 sweep across everything public (commit messages, docs, kit READMEs, templates); extend `tools/s7-denylist.txt`.
- License/provenance completeness: SPDX header on every source file (CI-enforced), LICENSE-{APACHE,MIT,CC0}, `THIRD-PARTY.md`/NOTICE listing every dep + license (verify path = RFC/FIPS + OSI only), vectors marked CC0.
- `make preflight`: from a cold clone, run test+diff+genesis-local + the 3 smokes, print a green/red board; expected output in README.

## Task 2 — Cold-open onboarding per DoD kit (unattended stranger, self-verifying)
- 2a verifier: `QUICKSTART.md` (≤10 min, D-024 execution-bound flow), one-command `make verify-as-external`, exact "what a pass proves / doesn't" (verbatim D-024), `TROUBLESHOOTING.md`; accept = 3 labelled dry-run envs each emit distinct valid attestations, collector rejects a hand-authored one.
- 2b ceremony: role-split `RUNBOOK.md` (coordinator/N custodians/witness), hardware/air-gap checklist, coordinator `ceremony-checklist.json`, post-hoc transcript-hash verifier; keep TEST-ROOT warning; accept = `make ceremony-dry-run` green + independent hash recompute matches.
- 2c soak: `DEPLOY.md` (≥3 vantage points), live page from measured data only, signed tamper-evident report, `make soak-verify` (re-checks a finished report; rejects a tampered copy); accept = `make soak-smoke` green + `soak-verify` accepts/rejects.

## Task 3 — Coordinator view + evidence aggregation (`tools/genesis-board/`)
- Static, local, zero-telemetry page ingesting collected `verifier-attestation.json` (≥3 distinct), ceremony `transcript.json` + hash, `soak-report.json`; renders the DoD table, refusing ✓ without a signature-checked artifact.
- Computes: distinct valid external verifiers, ceremony transcript status, soak p95 vs `<60s`/3-region/14-day with elapsed-time honesty ("day 3 of 14"). `make genesis-status` prints the honest board.

## Task 4 — Recruitment materials (`outreach/`, plain, no third-party names, no hype)
- `WITNESS-CALL.md`, `EXTERNAL-VERIFIER-CALL.md`, `CEREMONY-CUSTODIAN-BRIEF.md`, `outreach/README.md` mapping each to the three ⏳ DoD events; each a 2-minute read.

## Task 5 — Public front door + close-out
- `README.md`: one-breath def, honest ✓-vs-⏳ status mirroring STATUS.md, `make preflight` promise + expected board, arch map, links to CONTRIBUTING(DCO)/CoC/SECURITY/outreach, CI badge; a check greps README + STATUS for the same status line so they can't disagree.
- Update STATUS.md, docs/DOD.md, GENESIS-CHECKLIST.md; deliver the honest board + the ordered real-world action list (who to recruit, in what order) — so the next thing is human, not code.

## Working method
Per task: ≤12 bullets here → implement → run the gate, paste real output. Ambiguity → stricter reading, log D-025….
Do NOT run a real ceremony/soak, invent verifier results, or publish — prepare to the point where the user presses the buttons.
