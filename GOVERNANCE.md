<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Governance

This document says who decides what, **today**, and how that changes. It contains no aspirational fiction: where a
body does not exist yet, it says so, and dates appear only where they are real.

## Today: operator-run, pre-institution

AINRA is currently **one operator with a public repository**. There is no board, no assembly, no custodian set, and
no legal foundation. Every merge decision, release, and roadmap call is made by the maintainers listed in
[MAINTAINERS.md](MAINTAINERS.md).

That is a weakness, and the design assumes it. The mitigations are structural, not promises:

- **The specification is public and frozen.** Normative documents are hash-pinned (`make check-freeze`); changing one
  requires an ADR in `docs/DECISIONS.md` and shows up in every diff.
- **Correctness is external to the maintainers.** Four independent implementations must agree on the public CC0
  corpus (`make diff`), and anyone can run the conformance runner against their own implementation. We certify
  nobody — including ourselves.
- **Everything is reproducible.** Artifacts rebuild byte-for-byte from tagged source (`make repro`), releases are
  signed with an offline key, and the full gate board runs from a cold clone (`make preflight`).
- **The root is forkable by construction.** All keys, rules, logs, and decisions are public. If the operator goes
  wrong, the ecosystem leaves with everything and the operator keeps nothing. The right to leave is what keeps this
  worth staying with.

**Production log entries sealed under a real root: 0.** Nothing on this repository claims otherwise.

## Change 1 — at the genesis ceremony: custodians appear

The production root key is created in a recorded public ceremony as a **FROST 5-of-9 threshold key** held by nine
independent custodians. From that moment:

- No single party — including the maintainers — can sign as the root. Five custodians must act together.
- Custodians are **structurally separate** from the maintainers and from each other: different organizations,
  different jurisdictions, different institution types, per the charter.
- Key ceremonies (creation, rotation, succession) are public and reproducible from their transcripts.

The ceremony is rehearsed and reproducible today (`make ceremony-rehearsal-multi`); the recorded one with real
independent custodians is a **pending real-world event** — see [ROADMAP.md](ROADMAP.md) and `docs/DOD.md`.

## Change 2 — after genesis: the four-constituency federation

The charter's target form is an international, member-governed non-profit federation. Membership is by class, and
each class is a constituency in the assembly that elects the board:

| Constituency | Who | What they hold |
|---|---|---|
| **Issuers** | accredited registrars of every class | the right to issue passports under identical published rules |
| **Attestors** | principal-proof providers | the evidence behind authority classes and assurance tiers |
| **Verifiers** | edges, gateways, merchants, control planes | the demand side; each sets its own acceptance floor |
| **Public interest** | civil-society and standards bodies | a seat that is not a commercial seat |

Separate from all four, and never merged with them: **custodians** (root key shares) and **witnesses** (log
cosignatures). Charter prohibitions — issues no passports, computes no scores, processes no payments, holds no
personal data, never gates L0 existence, features no registrar — are amendable only by supermajority in **every**
constituency after twelve months of public comment.

None of these bodies exist yet. They are constituted after genesis, in the order above.

## How decisions are made in the meantime

| Decision | Path |
|---|---|
| Code change | pull request → gates green (`make preflight`, `make audit`) → maintainer review → merge |
| Verify-logic change | the conformance-first rule in [CONTRIBUTING.md](CONTRIBUTING.md) — four-way differential green, corpus delta explained |
| Specification change | spec-question issue → numbered decision in `docs/DECISIONS.md` → freeze re-recorded (`make freeze`) → code + vectors |
| Release | the one release rule in `RELEASING.md`: no full board at the release commit ⇒ no release. Tagging and publishing are the maintainer's manual buttons |
| Security finding | private advisory → fix → pinning vector + public post-mortem, per [SECURITY.md](SECURITY.md) |
| Anything about the root's *authority* | not ours to make yet — it waits for custodians |

## Amending this document

Until the assembly exists, this file changes by pull request like any other, and every change is visible in history.
After genesis it becomes a charter instrument and changes by the process the charter defines — not by a commit.
