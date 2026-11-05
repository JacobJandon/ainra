<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Amendment record

Every change to constitutional or normative text, in order, with its rationale and who approved it. Required by
[GOVERNANCE-AMENDMENT.md](../GOVERNANCE-AMENDMENT.md) §4 and enforced by `make amendment-check`.

**An empty section below means no amendment has been made — not that one went unrecorded.** The gate fails a
commit that touches the protected text without adding an entry here, so silence in this file is evidence.

## Format

Each entry: a heading `## <date> — <what changed>`, then the era, the approver, the rationale, and the files
touched. The public diff is the commit itself; the entry names it once it exists.

---

## 2026-08-26 — This record established (no text amended)

- **Era:** operator-run
- **Approved by:** the operator, with this public record
- **Files touched:** none of the protected texts. `GOVERNANCE-AMENDMENT.md` and this file are new.
- **Rationale:** the charter, the four rules and the constitutional prohibitions changed because one person
  changed them, with no requirement to say why. That is survivable while the project is small and is exactly the
  property an institution cannot have. The amendment path is written now, while nothing is at stake, because a
  rule about amendment written during a dispute is written by the winner of that dispute.

  This entry amends nothing. It exists so the file is not empty at the moment the gate starts running, and so the
  first real amendment has a format to follow.

## 2026-09-23 — The Standard §5: who signs a presentation

- **Era:** operator-run
- **Approved by:** the operator, with this public record
- **Files touched:** `docs/AINRA_I_The_Standard.md` §5 (one sentence). Decision record: `D-062` in
  `docs/DECISIONS.md`. Plan: `docs/PLAN-M34.md`.
- **Rationale:** the sentence said "the request signature names the passport key". ADR-019 (D-047) says the
  passport's control key never enters the container. A running copy cannot sign with a key it is forbidden to
  hold, so the two normative texts could not both be honoured for the case that matters — an agent making a
  request in production. Neither was implemented, which is why the conflict survived unnoticed until the
  presentation layer was actually built (`docs/PLAN-M34.md`, Task 0: a captured presentation replayed three times
  out of three against the shipped middleware).

  The amended sentence says the **instance key** signs and its `keyid` names the instance credential, which names
  the passport. The chain a verifier walks is unchanged; what changes is that the signing key is one a container
  is allowed to hold. The same sentence described instance credentials as "bound to the connection (mTLS)"; what
  shipped in ADR-019 is audience binding plus proof-of-possession, and the text now says so.

  This is a correction of drift between two normative texts, not a new power. Nothing here touches P1–P6.

## 2026-11-04 — The Standard and the MTS say what the code does: privacy, human backing, delegation depth (D-090)

- **Era:** operator-run
- **Approved by:** the operator, with this public record. The operator's instruction, given after D-090 was proposed
  with its full table of changes: "do all your self automatically and fully continue to all".
- **Files touched:** `docs/AINRA_I_The_Standard.md` §1 (P4 gloss), §5 (one sentence), §6 (A1, A3), §7 (L3 row), §10
  (two clauses), closing line; `docs/AINRA_Master_Technical_Specification_v1.md` — a dated amendment note under
  Provenance, the one-paragraph architecture, ADR-004, ADR-011, §11 (data minimisation), §12 ledger row 9, §15
  (passport), §31; the Standard's renderings in `site/docs.html`; `docs/FREEZE.sha256`. Decision record: `D-090` in
  `docs/DECISIONS.md`. Study: `docs/ZK-STUDY.md` §3.2.
- **Rationale:** four statements in the normative texts were not true of any implementation. The passport is canonical
  JSON signed whole with Ed25519 and ML-DSA-65 — not an SD-JWT, with no KB-JWT, no X.509 bridge and no field-level
  disclosure; every claim is shown. Human backing is not proven in zero-knowledge by AINRA: since D-089 the registrar
  issues A1 only on evidence its principal checker accepts, and the passport carries a digest. The trust ledger's
  Groth16 demo plugin does not exist, and BBS, named on its removal path, is not post-quantum. No implementation caps
  delegation depth. A Standard that describes what was not built is a claim without a gate (`docs/CLAIMS.md`), so the
  texts are brought to the code, not the other way round. Enforcing a depth cap, or adding real selective disclosure,
  would each be their own decision with a corpus. P1–P6 are untouched: P4 holds, and only the sentence describing its
  mechanism was wrong.

## 2026-11-05 — The Standard §9: a revocation reaches each verifier within its freshness class (D-092)

- **Era:** operator-run
- **Approved by:** the operator, with this public record. The operator's instruction, given with an outside summary
  of AINRA's trade-offs: "do we solve this make sure we fix if not already".
- **Files touched:** `docs/AINRA_I_The_Standard.md` §9 (one sentence); its rendering and the charter's Death rule in
  `site/docs.html`; `apps/landing/index.html`; `site/llms.txt`; `docs/FREEZE.sha256`. Decision record: `D-092` in
  `docs/DECISIONS.md`. Evidence: `docs/drills/REGISTRAR-DARK.md` (`make outage-drill`).
- **Rationale:** the sentence promised "a global SLO of <60 seconds issue-to-rejection". The SDK's verifier defaults
  to freshness class F2 (300 s), so a default verifier can accept a revoked passport for up to five minutes; under a
  minute holds at F1. Making F1 the default would make every agent refresh every 30 s and every registrar outage a
  30-second stop, so the text is brought to the code: each verifier refuses within its own class — under 60 s at F1,
  5 minutes at F2, a day at F3 — every class failing closed. P1–P6 are untouched.
