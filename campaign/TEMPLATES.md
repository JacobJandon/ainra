<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# The asks

Six messages, each short enough to send from a phone. The prepared, per-party verifier packets already exist in
`outreach/ready/` (untracked — each party's challenge material travels privately); everything else is here.

## The rules that make them work

1. **Two sentences of personalization, or don't send it.** One line on why *them* specifically, one line
   acknowledging what they do. Everything else is boilerplate and everyone can tell.
2. **The one-nudge rule.** One follow-up per person, one sentence — then stop. `make campaign-status` keeps the
   queue of who has been asked and not answered. A second nudge costs you the third ask you haven't thought of yet.
3. **Ask small.** Every template below asks for one bounded thing: ten minutes, twenty-five minutes, one afternoon,
   one day. Nobody is being asked to believe in anything.
4. **No names in this repository.** Track people in `campaign/tracker.local.json` (gitignored). What is publishable
   is a count — see [D-036](../docs/DECISIONS.md).

---

## 1 · Verifier ask

**Subject:** Be one of the first three to verify a new public trust root

> *<Two sentences: why them. Their conformance work, their log, their tooling, the paper.>*
>
> I'm building AINRA — a neutral, non-profit root for AI-agent identity: passports an agent can prove, revocation
> that fails closed, all of it verifiable offline. The engineering is finished and public. What it can't give itself
> is the one thing that matters: independent verification.
>
> Everything is public and scripted — clone, one command, the board goes green or it doesn't:
> https://github.com/JacobJandon/ainra · https://ainra.vercel.app/skills.md
>
> The attached challenge folder is minted for you alone, so the result proves the run was yours and not a replay.
> It's an afternoon at most, and with your consent you'd be named as one of the first three external verifiers of
> the root. If it fails, I want that publicly too.
>
> *<sign-off>*

**Attach:** the whole `outreach/ready/verifier-NN/` folder (challenge + one-pager). **Never** the answer key.
The per-party draft in that folder is already written; this is the shape it follows.

If they'd rather go deeper than ten minutes, point at the conformance programme: the full CC0 vector corpus and a
language-agnostic runner, so they can build their own verifier and never trust ours at all.

## 2 · Interview ask

**Subject:** 25 minutes on how you decide to trust an agent

> *<Two sentences: what their agents do, named specifically.>*
>
> You run agents that *<do X>*. I'm building the neutral identity layer for exactly that, and I'm doing 25
> structured interviews before genesis — no pitch, no demo, I mostly listen. Twenty-five minutes, and I'll send you
> what I learn from the whole set.
>
> Any time *<two concrete windows>*, or send a link and I'll take whatever's free.
>
> *<sign-off>*

This is the highest-volume ask (30 of them) and the one most likely to be skipped under pressure. It is also the
only one that can tell you the product is wrong while there is still time to change it.

## 3 · Custodian ask

**Subject:** Nine custodians, five jurisdictions, one recorded day

> *<Two sentences: why their judgement specifically. Standards work, institutional standing, public record.>*
>
> I'm assembling nine custodians across at least five jurisdictions for a recorded key ceremony — the constitutional
> moment of a neutral root for AI-agent identity. The commitment is one day, on camera, plus annual availability: it
> is stewardship, not work, and you'd hold one share of a 5-of-9 threshold key that no single party can use alone.
>
> May I have twenty minutes to show you exactly what you'd be attesting to? The runbook and the rehearsal evidence
> are public, so you can read the whole thing before we speak.
>
> *<sign-off>*

**Attach:** `outreach/ready/custodian-packet/INVITATION.md`. Background: `outreach/CEREMONY-CUSTODIAN-BRIEF.md`,
`docs/genesis-day/RUNBOOK.md`, `GOVERNANCE.md`.

## 4 · Witness ask — the easier second yes

Send this to anyone technically warm who declined verifying. It asks for infrastructure rather than attention.

**Subject:** Ten minutes, on your infrastructure

> You said no to the verification ask, which is fair — here's the smaller one. A witness cosigns log checkpoints so
> that nobody, including us, can serve a forked history unnoticed. It's one process, one endpoint, ten minutes to
> stand up, and it runs on your infrastructure under your key: `deploy/witness-quickstart.md`.
>
> Candidacies are candidacies — it confers no obligation and no standing until the charter process constitutes it.

**Attach / link:** `outreach/ready/witness/WITNESS-NOTE.md`, `deploy/witness-quickstart.md`.

## 5 · The regulator letter

One page, sent after the jurisdiction decision, to the office that runs the **human** digital-identity trust
framework in the jurisdiction you chose. This is strategy, not compliance: they have already solved, in law, the
governance problem this project has in code.

> **What it is.** A neutral, non-profit root for AI-agent identity: an agent carries a passport it can prove, a
> relying party verifies it offline in milliseconds, and revocation fails closed. No account with us, no telemetry,
> no per-verification fee — the verification path is public specification plus open-source code.
>
> **The analogy.** Your framework certifies identity-service providers against published rules and publishes who is
> certified, so a relying party can trust a credential without trusting its issuer personally. AINRA needs exactly
> that shape for non-human actors, and it is being built the same way round: the rules and the conformance suite
> first, the institution second.
>
> **Where it stands.** Four independent implementations agree on 1009 conformance vectors; every artifact rebuilds
> byte-for-byte from tagged source; a stranger's cold clone passes the full board. What has *not* happened is
> stated just as plainly on the roadmap — no ceremony yet, no independent verifiers yet.
>
> **The ask.** A conversation. I would like to understand what you learned constituting a trust framework, and
> whether an agent-identity root should sit inside one or beside it.

Keep it to one page. Attach nothing; link the site and the roadmap.

## 6 · The nudge

> Following up once on the below — if it's not for you, no reply needed and I won't chase it.

That is the entire message. Send it once, after a decent interval, and then delete the thread from your mind.

---

## Where the people are

Categories, not names — you pick the faces. Twenty verifier asks to land three attestations; thirty interview asks
to land eight interviews; five custodian conversations to start.

**The positioning rule: go where money flows.** Identity gets adopted where an impostor costs money, and the
parties who verify hardest are the ones moving funds. When two candidates are otherwise equal, take the one closer
to a payment — the agent that transacts over the agent that chats, the marketplace over the demo, the risk owner
over the enthusiast. (Named commercial brands still never appear in our materials — the rule picks *categories*.)

**Verifier targets.** Verifiable-credentials implementers in the standards community · people who run or contribute
to transparency logs and witnesses · university applied-crypto and systems-security groups (say plainly that a
graduate student can do the whole challenge in an afternoon) · maintainers of open-source authentication and PKI
tooling · independent security consultancies that publish research · standards-adjacent engineers who post
conformance and interoperability work. The ask is small and genuinely flattering.

**Interview targets — money-adjacent first.** Teams shipping agents that transact — payments, procurement,
checkout, treasury, operations · fraud and risk people at marketplaces and payment platforms · platform and API
owners deciding whether to admit paying agents at all · maintainers of agent frameworks and their tool layers.
You are asking about their problem, not about your solution.

**Custodian targets.** Respected neutral technologists: standards elders, university faculty, foundation people,
security researchers with public reputations. Five jurisdictions minimum, which is a constraint on *who you ask*,
not a thing to fix at the end.

## The interview script

Twenty-five minutes. Listen eighty percent of it. Ask the question, then be quiet.

1. What do your agents actually do today, end to end?
2. Walk me through the last time an agent's identity or permissions mattered.
3. When another party's agent contacts your system, what do you check now?
4. What's the worst thing an impostor agent could do to you?
5. Have you ever needed to kill an agent's access everywhere at once — what happened?
6. Who in your organization would own "agent identity" if it existed?
7. What would a passport need to assert for you to act on it?
8. What would make you refuse to rely on a third-party root — what breaks trust?
9. Would you rather run verification yourself or call an API — why?
10. Who else should I talk to?

**Close with:** may I follow up once, at genesis?

**Log it the same day.** `node tools/campaign.mjs interview <id>` writes `campaign/notes/<id>.md` pre-filled with
these ten questions. Record **verbatim quotes**, not your summary of them — the sentence you would never have
written yourself is the entire value of the exercise, and it does not survive a day of memory. Those notes are
gitignored and stay that way.
