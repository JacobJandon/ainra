<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Rollback thresholds — agreed BEFORE the roll, or the roll does not happen

**Read at T−1d alongside [`GO-NO-GO.md`](GO-NO-GO.md). Nothing here is executed at genesis; it is what must already
be written down before a root key is rolled.**

## Why this file exists at all

The root DNSSEC key roll was **postponed eleven days before it was due**, and the reason is the most useful sentence
in the whole trust-root record:

> *"Historically, there has been no way to determine which trust anchors DNS Security Extensions (DNSSEC)
> validators have been configured, making it difficult to assess the potential impact of the root KSK rollover. But
> that recently changed and we received some new data that we simply could not ignore."*
> — ICANN, 4 October 2017

A signalling protocol finalised **five months earlier** revealed that ~5% of validators held only the old anchor and
would have broken. The automated rollover mechanism was assumed to work. It did not, and until that protocol existed
there had been **no way to know**. A potential 750 million users sat behind that assumption.

When the roll did complete a year later, it worked because two things were true in advance: the old key stayed
valid, and a rollback threshold had been **"defined by the ICANN community"** before the roll rather than argued
about during it.

## The measurement we will never have

**AINRA cannot build the equivalent telemetry, and this is not an oversight.** The charter says verification reports
to no one — no phone-home, no responder, nothing that could count deployed trust anchors. Every mechanism that
would tell us what fraction of verifiers hold the new root is a mechanism the charter forbids.

That is a deliberate trade, and it has a price: **we roll blind.** The honest response is not to pretend otherwise
but to over-engineer reversibility, because reversibility is the only lever left.

## What must be written down before any root roll

Each row must carry a **number** and a **name** before the ceremony is scheduled. A threshold argued about during an
incident is not a threshold.

| | Must be agreed in advance | Why |
|---|---|---|
| **Old anchor stays valid until** | an explicit date, at least one full quarter after the new root is first used | ICANN kept KSK-2010 valid and did not revoke it until a full quarter after the roll succeeded. Revoking the old key is a *separate, later* ceremony, never part of the roll. |
| **Rollback trigger** | a quantitative signal, decided in advance, that means *undo* | Without a number, the decision becomes a judgement made by tired people at 03:00. |
| **Who may call it** | one named role, plus one named deputy | Not a committee. ICANN's postponement was called by a named executive on published data. |
| **How rollback is executed** | the exact command sequence, rehearsed | A rollback path first attempted under pressure is not a rollback path. |
| **What is published, and when** | the statement, before it is needed | *"The integrity of the SSL system cannot be maintained in secrecy"* — the doctrine sentence from the 2011 CA removal. |

## What we can measure, and what we cannot

**Cannot:** how many verifiers hold the new anchor. Ever. By charter.

**Can, and therefore must:**

- **Witness cosignatures on checkpoints under the new root.** Witnesses are the one party that observes our log
  by design, and their cosignature is evidence the new root is being honoured by something other than us. With
  zero witnesses this evidence does not exist — which makes witness recruitment a **prerequisite of a root roll**,
  not a nice-to-have beside it.
- **Mirror fetches of the new `roots.json`.** Aggregate, anonymous, no per-verifier identity. This is the closest
  legitimate analogue to trust-anchor signalling available to us, and it counts *fetches*, never *verifiers*.
- **Our own multi-implementation verification** against the new root, from a clean clone, before the roll.

The gap between those and what ICANN had is real, and it should be stated in the ceremony transcript rather than
glossed: **we will know that the new root works, and not how many people have it.**

## The ceremony will fail for a boring reason

The 40th root key ceremony was stopped by **a malfunctioning safe lock**. Zero service impact, because signatures
were pre-generated and *"We maintain a complete replica facility in Culpeper, Virginia."*

The controls that saved it were redundancy and signature depth — not lock quality. So two numbers belong here too:

- **Signature pre-generation depth:** how many periods of artifacts are signed ahead, so a missed ceremony causes
  no interruption. Today: **not established.**
- **Second facility:** a complete replica. Today: **does not exist.** With nine custodians across five-plus
  jurisdictions this is less acute than for a single-site facility, but the standby-quorum runbook is still an open
  item on the genesis checklist, and it is the same gap.

## Status

**Nothing in this file is agreed yet.** It is the list of decisions that must be made and written down before a root
roll is scheduled, with the numbers left blank on purpose — filling them in is a governance act, not a drafting one.

The one conclusion that *is* settled: **a root roll cannot be scheduled before witnesses exist**, because without
them we have neither the split-view guarantee nor the only evidence available to us that a new root is being
honoured.
