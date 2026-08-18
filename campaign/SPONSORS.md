<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Sponsors — the money path that needs no entity

**Signup is the maintainer's, not the agent's.** Everything a form asks for is drafted below.

## Why this one, and why now

Verified 2026-08-05: the **individual** sponsorship path states that *"anyone who contributes to an open source
project and lives in a supported region is eligible to become a sponsored developer"* — 142 regions, **Bulgaria
included**. The *organization* path is the one that says *"any organization… that legally operates in a supported
region"*. So the personal route needs **no legal entity**, which makes it the cleanest funding channel available in
AINRA's current shape — and it stays open regardless of what
[`JURISDICTION.md`](JURISDICTION.md) eventually decides.

Requirements: two-factor authentication, tax forms (a W-8BEN for a non-US individual), a profile, and **either** a
bank account **or** payouts through a fiscal host — then a review.

## The framing: fund the ceremony, not me

The obvious sponsor pitch — *support my open-source work* — is wrong for this project. AINRA's whole argument is
that it is **not** one person's project, and a sponsor page that reads "buy me a coffee" contradicts the thing being
funded. It also asks for the wrong thing: the repository does not need more engineering hours. It needs three
real-world events that no amount of code produces.

So the page funds **the events, not the author**, and says what is genuinely uncertain.

### Profile text — draft

> **AINRA — the neutral root of AI-agent identity.**
>
> Agents are already acting: buying, building, paying other agents, even renting humans. There is no universal way
> to know who an agent is, who controls it, or what it may do. AINRA is an open standard and a reference
> implementation that answers those three questions with signed facts anyone can verify offline, in about five
> lines, with the root switched off.
>
> The engineering is done and public: four independent implementations agree on 1009 CC0 conformance vectors, every
> artifact rebuilds byte-for-byte from tagged source, and a stranger's cold clone passes an eighteen-row board.
> **Verification is free forever and always will be — that is in the charter, enforced in code.**
>
> What is *not* done is the part money helps with. A neutral root is born in a recorded ceremony across independent
> custodians, proven by independent verifiers, and measured in a multi-region soak. None of that has happened yet,
> and this page says so plainly: **production log entries sealed under a real root: 0.**
>
> Sponsorship funds those events — not salary. The honest status is always at ainra.vercel.app, and the counts
> there are read from registries, never asserted.

### Tiers — deliberately none

No tiers, no perks, no names-in-the-README ladder. Reasons, in order:

1. **A neutral root cannot sell standing.** The moment a sponsorship tier buys visibility, someone can argue money
   bought position in a system whose only product is impartiality. The charter bars the root from selling anything;
   the sponsor page must not quietly reintroduce it.
2. **Perks create obligations** to people the project may later have to refuse.
3. **One-off amounts of any size, no ladder** keeps it a donation to a public good rather than a transaction.

If the platform requires at least one tier, use a single custom-amount tier described as: *"Funds the genesis
events — ceremony, independent verification, the soak. No perks, no listing, no standing. Verification is free
forever."*

### What the page must never claim

- No sponsor logos, no "backed by", no implied endorsement in either direction.
- No count that is not read from a registry — the three rows stay at their real values (**0 / 3** verifiers,
  ceremony **not held**, soak **not started**) on every surface, including this one.
- No implication that sponsorship influences the standard, accreditation, or any verdict.

## Fiscal hosting — the same decision, one step later

The payouts question has two answers: a personal bank account, or a fiscal host. A host takes a percentage (roughly
8–10% plus processing on the two open-source hosts checked) and, in exchange, lets the project hold funds **without
a legal entity** — which is exactly the constraint AINRA is under. One of them requires the repository to sit under
an **organization** rather than a personal account, so [`docs/ORG-MOVE.md`](../docs/ORG-MOVE.md) is a prerequisite,
not a parallel task.

Do not open a host account before the organization exists; the application would fail on a criterion that takes an
hour to satisfy.
