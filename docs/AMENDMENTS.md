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
