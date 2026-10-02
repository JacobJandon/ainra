<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Roadmap

Short and truthful. What shipped, what is left, and the exact conditions under which "left" becomes "done".
Counts here are read from the intake registries (`evidence/`, `witnesses/`), not asserted.

## Shipped

| | What | Where |
|---|---|---|
| **v0.2.0** | The downloadable reference CLI goes hybrid Ed25519 + ML-DSA-65; suite-migration drill; distributable ceremony; witness kit v2 | [release](https://github.com/JacobJandon/ainra/releases/tag/v0.2.0) · signed · board-proven |
| **v0.3.0** | A fourth independent verifier (Python); the self-serve conformance programme; SSH-signed releases with provenance + SBOM | [release](https://github.com/JacobJandon/ainra/releases/tag/v0.3.0) · signed · board-proven |
| **v0.3.1–v0.3.3** | A dependency advisory fixed end to end (ML-DSA timing side-channel) and the CI failure that hid it; the standing staging network; the release that could actually be published to npm and PyPI | `CHANGELOG.md` · boards in `docs/releases/` |
| **v0.4.0–v0.4.1** | The instance credential — a short-lived, audience-bound credential for one running copy (ADR-019) — with its proof of possession bound to the credential (D-049); the MCP server made installable | `CHANGELOG.md` · boards in `docs/releases/` |
| **Unreleased (0.5.0)** | The network keeps time (wall-clock registrar); send-once presentations and signed requests with their own corpus; the edge gate; a Python agent; one answer from every gate; a gate corpus. It carries security fixes for two published packages (D-074, D-075), so it is a security release | `CHANGELOG.md` → Unreleased · `SECURITY.md` |
| Public | Repository, CI (nightly board), branch protection, the live site | github.com/JacobJandon/ainra · https://ainra.vercel.app/ |
| Trust scaffolding | Security policy, contribution + conformance-first rules, governance, and self-verifying intake pipelines | `SECURITY.md` · `CONTRIBUTING.md` · `GOVERNANCE.md` · `evidence/README.md` |
| **Settlers pass** | Five of seven documented industry failure modes closed before we could walk into them: graduated distrust keyed on log position (**D-044**), a log that may never come back shorter (**D-045**), compliance measured adversarially from outside (**D-046**), a 72-hour disclosure term with no severity threshold, and rollback thresholds agreed before any root roll | [`docs/SETTLERS.md`](docs/SETTLERS.md) · [`docs/PROBES.md`](docs/PROBES.md) · [`docs/DISCLOSURE.md`](docs/DISCLOSURE.md) · [`docs/genesis-day/ROLLBACK.md`](docs/genesis-day/ROLLBACK.md) |

Four independent implementations of the verify path exist; the three written in Rust, TypeScript and Python
agree on all **1153** conformance vectors, on the verdict *and* the named reason, and the fourth — a Node
reference CLI — agrees byte-for-byte on canonical encoding. The same core compiled to WebAssembly agrees again
in a browser; every artifact rebuilds byte-for-byte from tagged source; a stranger's cold
clone passes the full 18-row board (`docs/releases/stranger-test-2026-07-31.md`).

## The three real-world rows (the only work that moves the DoD)

These are **events, not code**. The machinery for all three is built and rehearsed; none is done until the real
event happens, and nothing on this repository claims otherwise. Production log entries sealed under a real root: **0**.

| Row | Flip condition | Current | How it flips |
|---|---|---|---|
| **Independent verifiers** | ≥3 distinct valid attestations | **0 / 3** | strangers submit `evidence/verifier/<id>.json` (CI checks the public half); the maintainer confirms execution against the private answer key; `make genesis-status` counts. `evidence/README.md` |
| **Recorded ceremony** | a recorded FROST 5-of-9 ceremony with independent custodians | **not held** | custodians recruited → ceremony day run from `docs/genesis-day/RUNBOOK.md`; the declaration renders only when the transcript is real |
| **14-day / 3-region soak** | ≥14 days, ≥3 regions, signed reports, p95 < 60s | **not started** | operator starts the instruments on the 3-host platform; the clock does not pause (`outreach/ready/SOAK-REALITY-CHECK.md`) |

One further item is open from the settlers pass, and it is not code:

- **Witnesses.** Zero operators today, which blocks the split-view guarantee, the witness-anchored half of D-045, and
  any future root roll ([`docs/genesis-day/ROLLBACK.md`](docs/genesis-day/ROLLBACK.md)).

The other item that list once held — the instance-credential rung, without which a 366-day passport was also the
runtime credential — is built: a running copy carries a credential of minutes to an hour, bound to one audience and
to its own key, and signs each request with it (ADR-019, D-047, D-049, D-062).

Witness candidacies (a prerequisite for the ceremony's witness quorum): **0** in `witnesses/candidates.json`.
Candidacies are candidate-not-production and confer no standing until the charter process constitutes them.

Every one of those numbers moves only when a stranger decides to spend an afternoon on this, so the asking got
the same treatment the engineering did: [`campaign/`](campaign/) holds the ordered sequence of asks, the
templates, and two public kill-gates — **K1** (demand evidence) and **K4** (three independent attestations) — in
[`campaign/GATES.md`](campaign/GATES.md), with every gate reading on the record. Gates are bars, not deadlines.
`make campaign-status` reads the counts above from their registries rather than restating them, and
`node tools/campaign.mjs check` fails the build if this file's numbers ever drift from what the registries hold.

## After genesis

The root becomes what its charter describes: a member-governed federation with custodians holding threshold keys and
independent witnesses cosigning the log — see `GOVERNANCE.md`. From there the plan is Anchor → Endure → **Disappear**,
and *disappear* means **become unnecessary**, not vanish. The goal is not an ecosystem that depends on us; it is one
that no longer needs us — that is how you know the job was done. This is a relay race, not a solo marathon: you take
the baton, run your section, hand it off, and somebody else carries it on. What that looks like from outside is
verification as boring as the clock — everywhere, invisible, with a public record behind it. The standard is built to
outlive whoever is carrying it; a managed-migration clause is written for the day a legitimate successor emerges.

_This file is updated when a count changes or a version ships — not before._
