<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Which country the root incorporates in

**Decide at step 4 of the sequence — and "wait" is one of the two valid answers.** This memo was written on the
premise that every funding application, the regulator letter and the custodian paperwork block on an entity
existing. Research since has shown that premise is largely wrong for the next few months: most of what is reachable
today is reachable *because* there is no company. What remains true is that leaving the question open by default
is the one outcome with no argument for it.

## The decision

<!-- `make campaign-status` reads the line below and lists this as BLOCKING while it says _undecided_.
     Replace it with the choice and the date, and record the reasoning underneath. -->

- **Decision:** _undecided_
- **Decided on:** —
- **Filed on:** —
- **Reasoning:** —

Once decided, this becomes a governance fact rather than a strategy note: say plainly in
[`GOVERNANCE.md`](../GOVERNANCE.md) which legal person operates the root today, because "who is the operator" is a
question every custodian and every relying party is entitled to ask.

## The criteria, in the order they matter

1. **Neutrality optics.** A root that claims to be neutral is read partly through where it sits. The question a
   sceptical reader asks is *whose law can compel this thing*, and the answer should be boring and legible.
2. **The regulator door.** Somewhere, a public body already runs the human version of this problem — certifying
   identity providers against published rules and publishing who is certified. Being incorporated where that
   conversation is natural is worth more than any grant.
3. **Grant access.** Most public innovation funding is nationality-gated on the applicant entity, not the founder.
4. **Speed and cost.** Remote incorporation, days not months, filing overhead you can carry alone.
5. **Your operating reality.** You live and work in Bulgaria. That does not have to be where the shell sits, but it
   is where the practical friction lands.

## The two options

**A UK company** (converting later to a form suited to a non-profit root). The UK's digital-identity office runs a
certification framework for human identity services — the closest existing analogue to what this project needs to
become, and a conversation there is strategy rather than compliance. UK innovation grants are generally gated on a
UK-registered applicant. Incorporation is remote and fast; English-law non-profit forms are legible to almost every
counterpart a trust root eventually acquires.

**A Bulgarian or other EU entity.** It is where you are, which removes real friction from banking, accounting, and
signatures. It opens EU innovation funding routes. Against it: those funding rhythms are slower than the gate dates
in [`GATES.md`](GATES.md), and the entity buys nothing with the regulator or grant body in the first option.

## The finding that cuts the other way (2026-08-05)

A sweep of free infrastructure ([`FREE-INFRASTRUCTURE.md`](FREE-INFRASTRUCTURE.md)) turned up a pattern nobody
expected: **incorporating may cost more than it unlocks, at this stage.** Programmes AINRA qualifies for *today*
gate on being non-commercial or on being a natural person: a major edge provider's OSS programme requires you
*"operate solely on a non-profit basis"*, a developer-tools grant requires *"non-commercial open source development"*,
an AI-tooling programme requires *"a natural person, not a corporation"*, and a hosting programme excludes anything
that is *"a commercial project"*. **NLnet — the best funding fit found,
€5k–€50k — states outright that you may apply as an individual and that not having an entity yet is not a problem.**
The Commons Conservancy offers a legal home at *no cost at all*, designed precisely for projects without an entity.

Against that, the only in-scope programme a company would unlock is a startup track AINRA fails on other grounds.

This does not settle the question — the regulator conversation and the custodian paperwork still want a legal person,
and that argument is unchanged. But "incorporate early to unlock things" is now the weaker half of the case, and the
memo should not pretend otherwise. Consider whether a Commons Conservancy conversation comes *before* a filing.

## The decision table

| | **Incorporate now** | **Wait** |
|---|---|---|
| **Funding** | Unlocks nationality-gated public innovation grants. But the best-fitting funder found — €5k–€50k — **explicitly accepts individuals and states that having no entity yet "is not an issue"**, so it unlocks nothing there. | Keeps the programmes that gate on *non-commercial* or *natural person* status: an edge provider's OSS credits (*"operate solely on a non-profit basis"*), a developer-tools grant (*"non-commercial open source development"*), an AI-tooling programme (*"a natural person, not a corporation"*), a hosting programme that excludes *"a commercial project"*. Incorporating **forfeits** these. |
| **Fiscal hosting** | Not needed — an entity can hold funds itself. | Available without an entity through a fiscal host (≈8–10% + processing), and through a no-cost legal-home foundation whose whole purpose is projects without one. Its gate is an **organization repository**, which costs an hour — see [`../docs/ORG-MOVE.md`](../docs/ORG-MOVE.md). |
| **The regulator door** | Stronger. A public body that certifies human identity services talks to entities more naturally than to individuals. | Weaker, but not closed — an introductory conversation does not require one, and the letter is an introduction, not an application. |
| **Custodian paperwork** | Stronger. Nine custodians across five jurisdictions eventually need a legal counterparty for whatever they sign. | Blocking only at the ceremony, which is not scheduled. |
| **Neutrality optics** | An entity reads as an institution. | A personal account reads as one person's project — but that is fixed by the **organization move**, not by incorporating. Do not conflate the two. |
| **Cost** | Filing, annual accounts, and the quiet one: the tax and reporting consequences of a non-resident director. | Zero, and reversible. |

**What changed:** "incorporate early to unlock things" was the strong half of the case, and the free-infrastructure
sweep inverted it — most of what is reachable *today* is reachable **because** there is no company. What survives
untouched is the long game: the regulator conversation, the custodian paperwork, and the eventual institutional
shell a root has to have. None of those is due this quarter.

## The question only you can answer

> **Does anything I need in the next 90 days require an entity to exist?**

Work through it concretely: the funding application takes individuals. The witness network, the standards groups,
the package registries, the CI tooling and the platform credits all take individuals or projects. The ceremony is
unscheduled. The regulator letter is an introduction.

If the answer is *no*, then the decision is **wait** — and record it as a decision, with the date and the reason,
exactly as a filing would be recorded. **A decision to wait is a decision.** What is not acceptable is leaving this
undecided by default, because that is indistinguishable from avoidance and it keeps showing up as BLOCKING in
`make campaign-status` until someone writes a line here.

If the answer is *yes*, name the thing. One concrete blocked item is enough to justify filing this month.

## Before you file — verify these yourself

Every factual premise above came from a strategy briefing, **not** from a primary source, and none of it is
verified in this repository. **[`JURISDICTION-CHECKLIST.md`](JURISDICTION-CHECKLIST.md) is these five turned into
a one-hour kit** — each with the kind of primary source that settles it, the exact question to answer, and a box.
Confirm each on the issuing body's own pages before it drives a filing:

- [ ] the residency/eligibility rule for the innovation grants you intend to apply for
- [ ] whether the digital-identity certification framework has any standing route for a non-human-identity body,
      or whether the letter is purely an introduction
- [ ] the actual incorporation time, cost, and annual filing burden, including the accounting obligation
- [ ] the tax and reporting consequences of a non-resident director — this is the one that bites quietly
- [ ] whether a non-profit-shaped form is available at incorporation or requires converting later

If any of these turns out to be materially different from the description above, re-open the choice rather than
proceeding on a premise you have now personally disproved.

**This is not legal or tax advice.** It is a sequencing argument, written by the person who has to live with the
sequence. One conversation with an accountant in the chosen jurisdiction, before filing, is cheap and is the step
most likely to be skipped.
