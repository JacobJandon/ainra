<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Roadmap

Short and truthful. What shipped, what is left, and the exact conditions under which "left" becomes "done".
Counts here are read from the intake registries (`evidence/`, `witnesses/`), not asserted.

## Shipped

| | What | Where |
|---|---|---|
| **v0.2.0** | The downloadable reference CLI goes hybrid Ed25519 + ML-DSA-65; suite-migration drill; distributable ceremony; witness kit v2 | [release](https://github.com/JacobJandon/ainra/releases/tag/v0.2.0) · signed · board-proven |
| **v0.3.0** | A fourth independent verifier (Python); the self-serve conformance programme; SSH-signed releases with provenance + SBOM | [release](https://github.com/JacobJandon/ainra/releases/tag/v0.3.0) · signed · board-proven |
| Public | Repository, CI (nightly board), branch protection, the live site | github.com/JacobJandon/ainra · https://ainra.vercel.app/ |
| Trust scaffolding | Security policy, contribution + conformance-first rules, governance, and self-verifying intake pipelines | `SECURITY.md` · `CONTRIBUTING.md` · `GOVERNANCE.md` · `evidence/README.md` |

Four independent implementations agree on all **745** conformance vectors; every artifact rebuilds byte-for-byte
from tagged source; a stranger's cold clone passes the full 18-row board (`docs/releases/stranger-test-2026-07-31.md`).

## The three real-world rows (the only work that moves the DoD)

These are **events, not code**. The machinery for all three is built and rehearsed; none is done until the real
event happens, and nothing on this repository claims otherwise. Production log entries sealed under a real root: **0**.

| Row | Flip condition | Current | How it flips |
|---|---|---|---|
| **Independent verifiers** | ≥3 distinct valid attestations | **0 / 3** | strangers submit `evidence/verifier/<id>.json` (CI checks the public half); the maintainer confirms execution against the private answer key; `make genesis-status` counts. `evidence/README.md` |
| **Recorded ceremony** | a recorded FROST 5-of-9 ceremony with independent custodians | **not held** | custodians recruited → ceremony day run from `docs/genesis-day/RUNBOOK.md`; the declaration renders only when the transcript is real |
| **14-day / 3-region soak** | ≥14 days, ≥3 regions, signed reports, p95 < 60s | **not started** | operator starts the instruments on the 3-host platform; the clock does not pause (`outreach/ready/SOAK-REALITY-CHECK.md`) |

Witness candidacies (a prerequisite for the ceremony's witness quorum): **0** in `witnesses/candidates.json`.
Candidacies are candidate-not-production and confer no standing until the charter process constitutes them.

Every one of those numbers moves only when a stranger decides to spend an afternoon on this, so the asking is
scheduled like the engineering was: [`campaign/`](campaign/) holds the calendar, the templates, and two public
kill-gates — **K1** (demand evidence) and **K4** (three independent attestations, 05 Sep) — in
[`campaign/GATES.md`](campaign/GATES.md), along with every re-dating on the record. `make campaign-status` reads
the counts above from their registries rather than restating them, and `node tools/campaign.mjs check` fails the
build if this file's numbers ever drift from what the registries hold.

## After genesis

The root becomes what its charter describes: a member-governed federation with custodians holding threshold keys and
independent witnesses cosigning the log — see `GOVERNANCE.md`. From there the plan is Anchor → Endure → **Disappear**,
and *disappear* means **become unnecessary**, not vanish. The goal is not an ecosystem that depends on us; it is one
that no longer needs us — that is how you know the job was done. This is a relay race, not a solo marathon: you take
the baton, run your section, hand it off, and somebody else carries it on. What that looks like from outside is
verification as boring as the clock — everywhere, invisible, with a public record behind it. The standard is built to
outlive whoever is carrying it; a managed-migration clause is written for the day a legitimate successor emerges.

_This file is updated when a count changes or a version ships — not before._
