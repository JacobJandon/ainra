<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# How AINRA's rules change — and what may never change

Today the charter, the four rules and the constitutional prohibitions change because one person changes them.
That is honest for a project this age and unacceptable for an institution. This document is written now,
deliberately, **while nothing is at stake** — a rule about amendment written during a dispute is written by the
winner of that dispute.

It binds the author first. The most likely amender of these texts is whoever writes them most often, and today
that is one person. `make amendment-check` therefore exists primarily as a gate against its own author (D-056).

---

## 1. What may never change

These are **constitutional prohibitions**. They are not policy, and no process in this document can remove them —
a body that repealed them would not be AINRA exercising an amendment power, it would be a different institution
using the same name. If that ever happens, the honest act is a fork under a new name, and this section exists so
that a reader in any year can tell the difference.

| # | Prohibition | Why it is constitutional rather than policy |
|---|---|---|
| P1 | AINRA **issues no passports** | The root cannot be a competitor to the registrars it accredits. |
| P2 | AINRA **computes no scores** | Ranking agents is judgement; a root that judges is no longer neutral infrastructure. |
| P3 | AINRA **processes no payments** | Money flowing through the root creates a customer, and a root with customers has interests. |
| P4 | AINRA **holds no personal data** | What is never collected cannot be leaked, subpoenaed, or sold. |
| P5 | AINRA **never gates L0 existence** | An agent may exist without permission; the root records, it does not license being. |
| P6 | AINRA **features no registrar** | Including its own. The attribution mark is one-way: registrars reference the standard, the root displays no one's mark. |

**The relationship between P1–P6 and everything else is asymmetric.** Everything else in this project — the wire
format, the validity ladder, the corpus, the gates, this document — may change through the process in §2. P1–P6
may not change at all. `GOVERNANCE.md` states them as "amendable only by supermajority in every constituency after
twelve months of public comment"; this document is stricter, and deliberately so: that clause describes the
*hardest available process*, and the position here is that even that process should not reach them. Where the two
disagree, the reader should know the disagreement exists rather than find it smoothed over.

## 2. What may change, and how

| Class | Examples | Process |
|---|---|---|
| **Constitutional** | P1–P6 above | Unamendable. A change here is a fork, under a different name. |
| **Charter** | the four rules, the neutrality obligations, the Meridian conditions | Supermajority in **every** constituency after twelve months of public comment (`GOVERNANCE.md`). |
| **Normative** | the Standard, the Master Technical Specification, DESIGN.md | An ADR + a `D-0xx` decision record + the era's approval (§3), and the frozen-doc hash updated in the same commit. |
| **Operational** | gates, tooling, corpus, site, docs | Ordinary change. The board is the review. |

## 3. Who must agree, by era

The project passes through three eras. The process is not the same in each, and pretending otherwise would be the
kind of aspirational claim this repository exists to avoid.

| Era | Who approves a charter or normative amendment | Where the record lives |
|---|---|---|
| **Today — operator-run** | The operator alone, **with a public record**. There is nobody else; saying so is more honest than inventing a committee. | `docs/AMENDMENTS.md`, in git, before the change lands |
| **At genesis — custodial** | The custodians who hold the root key shares, by threshold. | The amendment record + the ceremony record |
| **Post-institution** | Supermajority across the four constituencies, after the comment period. | The amendment record + published constituency votes |

The era is determined by facts on the ground, not by declaration: the project is in the custodial era once a
recorded ceremony has happened, and in the institutional era once the four constituencies are constituted. Both are
Definition-of-Done rows, and neither is met today.

## 4. The transparency requirement

No amendment, in any era, without all three:

1. **A public diff.** The exact text before and after. Not a summary of it.
2. **A rationale.** What problem the current text causes, and why this change rather than another. An amendment
   whose rationale is "cleanup" is either not needed or not honest about what it does.
3. **A dated record** in `docs/AMENDMENTS.md`, written *before* the change lands, naming the era and who approved.

This is enforced by `make amendment-check`, not by anyone remembering it.

## 5. The gate

`make amendment-check` fails any commit that touches constitutional or normative text without a matching record in
`docs/AMENDMENTS.md`. It is deliberately annoying to route around, and its negative control — changing one
prohibited line and watching it go red — is part of the board.

It cannot stop a determined author with commit rights; nothing in a repository can. What it does is make the
change **visible in the same commit that makes it**, so that the diff a reader later inspects contains both the
amendment and its justification, or does not pass.
