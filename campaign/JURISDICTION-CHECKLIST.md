<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Jurisdiction premises — the one-hour verification kit

`campaign/JURISDICTION.md` argues a sequence. That argument rests on **five factual premises**, and the memo says
plainly that every one of them came from a strategy briefing rather than a primary source. This file turns them
into a checklist you can close in about an hour, with your chat assistant if you like.

**Nothing here was fetched, and nothing here is asserted.** Each row is a claim to test, the kind of primary
source that would settle it, and an empty box. A premise that is not personally verified is not verified — and
this is the blocker `make campaign-status` reports, so closing it is what unblocks step 4.

**How to use it:** open each source yourself, answer the question, tick the box, and write the date and the
answer in the notes column. If any premise comes back materially different from the memo, re-open the decision
rather than proceeding on something you have now personally disproved. This is not legal or tax advice; one
conversation with an accountant in the chosen jurisdiction, before filing, is the step most likely to be skipped.

---

## P1 · Grant eligibility

**The claim.** The innovation grants you intend to apply for have a residency or establishment rule that an entity
in the chosen jurisdiction would satisfy.

**Verify at.** The funder's own eligibility page for the specific programme — not a summary, not an aggregator,
not a news article. If the programme has a call document, the call document wins.

**The question to answer.** *For the specific programme I intend to apply to: what exactly must be established
where, and by when relative to the application?*

- [ ] Verified · date: ____________ · answer: ______________________________________________

---

## P2 · The digital-identity certification route

**The claim.** The digital-identity certification framework either has a standing route that a non-human-identity
body could use, or it does not and the regulator letter is purely an introduction.

**Verify at.** The scheme's own published scope/eligibility document from the office that runs it.

**The question to answer.** *Does the published scope admit anything other than identity services about humans —
yes or no?* A "no" is a perfectly good answer; it just means the letter is an introduction, not an application.

- [ ] Verified · date: ____________ · answer: ______________________________________________

---

## P3 · Incorporation cost, time and ongoing burden

**The claim.** Incorporation is fast and cheap, with a manageable annual filing and accounting obligation.

**Verify at.** The companies registry's own fees and timescales page, plus the tax authority's page on annual
accounts for the entity type you would actually use.

**The question to answer.** *What is the real first-year total — filing plus accounting plus any mandatory
service address — and what recurring obligation does it create?* The recurring half is the one that matters,
because it is the half that keeps costing after enthusiasm fades.

- [ ] Verified · date: ____________ · answer: ______________________________________________

---

## P4 · Non-resident director consequences

**The claim.** A director resident elsewhere does not create a tax or reporting problem.

**Verify at.** The tax authorities of **both** jurisdictions — the company's and your own residence — on
management-and-control and on directors' reporting duties.

**The question to answer.** *Does directing this company from where I live create a filing, a withholding, or a
corporate-residence question in either country?* The memo flags this as the premise that "bites quietly": it is
the one least likely to announce itself and most likely to be expensive later.

- [ ] Verified · date: ____________ · answer: ______________________________________________

---

## P5 · Non-profit form availability

**The claim.** A non-profit-shaped form is available at incorporation, or the entity can convert to one later
without penalty.

**Verify at.** The registry's own guidance on the non-profit form, and — if conversion is the plan — its
published conversion procedure.

**The question to answer.** *Can I start in the right shape, or am I committing to a conversion whose cost and
conditions I should know now?* This matters more than it looks: the root's whole proposition is that it cannot be
squeezed, and the legal form is where that either becomes true or stays a promise.

- [ ] Verified · date: ____________ · answer: ______________________________________________

---

## When all five are ticked

Re-read [`JURISDICTION.md`](JURISDICTION.md) § *The decision table* with your own answers substituted for its
premises. If the table still points the same way, record the decision in that file with the date and the five
answers. If it does not, the memo asked you to re-open the choice — that is the memo working, not failing.

`make campaign-status` reports the undecided entity as a blocker. That line clears when the decision is written
down, not when the boxes are ticked — the boxes are how you earn the right to write it.
