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
