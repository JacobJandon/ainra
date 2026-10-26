<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# The path to a recognised neutral root

How an open-source project run by one person becomes a non-profit that institutions trust to anchor AI-agent
identity. Researched on 2026-10-26. Costs and timings come from the sources linked, and are marked where they are
estimates. **The owner decides every step that creates an entity, spends money or speaks for the project.**

## The precedent that matches: the Legal Entity Identifier

The LEI system is the closest working example of what AINRA's charter describes. The root accredits issuers and
issues nothing itself.

- **Origin.** In 2011 the G20 "called upon the FSB to take the lead in developing recommendations for a global LEI".
  In 2012 it endorsed them. A Regulatory Oversight Committee was set up in 2013, and the foundation's board first met
  in 2014. <https://www.gleif.org/en/about/history>
- **Design.** The FSB's report recommended "a three-tier structure": oversight by authorities, a central operating unit
  that is "a not for profit foundation", and local issuers. The identifier is "by nature a public good". Funding is
  "non-profit cost recovery ... no monopoly rents accruing to service providers".
  <https://www.fsb.org/uploads/r_120608.pdf>
- **Form.** A Swiss foundation in Basel, with statutes endorsed by the federal supervisory authority. Its board has "a
  minimum number of three members from each of the four regional groupings".
  <https://www.gleif.org/en/about/governance/statutes>
- **Today.** About 2.9 million active identifiers, issued by about 39 accredited organisations. Its verifiable
  credential programme calls GLEIF "the Root of Trust for the vLEI Ecosystem".
- **How it became required.** Regulators wrote it into rules: from January 2018, entities trading on EU venues needed
  an LEI.

Three more precedents, each with one lesson:

- **Let's Encrypt** reached global trust fast because another authority cross-signed it before its own root was
  trusted: on 19 October 2015 it became "trusted by all major browsers"
  (<https://letsencrypt.org/2015/10/19/lets-encrypt-is-trusted/>). Lesson: borrow trust, and automate from day one.
- **The DNS root key** is used at recorded, audited ceremonies held "usually ... four times a year", attended by
  community representatives (<https://www.iana.org/dnssec/ceremonies>). Lesson: a ceremony is legitimacy you can
  watch.
- **ICANN** began as a California non-profit, and needed eighteen years and the end of a government contract, in
  2016, before its stewardship was accepted worldwide (<https://www.iana.org/help/pti-transition>). Lesson: the legal
  home signals who owns you.

## The path

### Now: an individual, building in public

- **Funding that accepts an individual.**
  - NLnet's Restack Fund, €5,000–€50,000, closes 3 November 2026.
  - The Sovereign Tech Agency's standards programme, the next round.
  - AI-safety funders when calls reopen. One recent call asked for "AI agent identity verification systems".
- **Standards.** Contribute drafts to the IETF (agentproto, WIMSE, OAuth, Web Bot Auth) and the W3C Agent Identity
  community group, and answer NIST when comment windows open.
- **Cost:** close to nothing.

### Months 2–6: an interim legal home (owner's decision)

- **Option A: a Bulgarian public-benefit foundation.** One founder and a founding donation. Public-benefit status
  "becomes irrevocable once entered". Fast and cheap; a weak signal of global neutrality, so it is a stepping stone.
- **Option B: a fiscal host.**
  - The Commons Conservancy (Netherlands) takes projects on a written fit with its mission.
  - The Software Freedom Conservancy reviews applications on a rolling basis.
  - A Linux Foundation directed fund starts at "$50k" a year plus membership, so it fits later.
- **Why now:** either option unlocks funders that require an entity.

### Months 3–12: borrowed legitimacy

- **A recorded root ceremony** with keyholders from at least three regions. The runbook already exists
  (`kits/ceremony/RUNBOOK.md`), and the public-transparency-log community's livestreamed, five-keyholder ceremony is the
  cheapest template.
- **Two or three independent registrars,** ideally organisations that already issue credentials. This is the
  cross-sign lesson.
- **One external security audit,** published in full.
- **An interim oversight committee** of outside experts and public-interest bodies: the LEI's oversight committee,
  scaled down.

### Months 12–24: the permanent neutral entity (owner's decision)

- **Option A: a Swiss foundation**, the LEI's choice. A foundation has no members, so no one can capture it.
  Law-firm guides estimate about CHF 50,000 expected endowment, CHF 5,000–25,000 to set up and CHF 3,000–25,000 a year.
- **Option B: a Belgian international non-profit (AISBL).** It has members, which suits a federation of registrars.
  Notary costs are about €2,000, and legal personality comes by royal decree in up to about three months.
- **The board** has regional quotas, as the LEI's does.
- **Funding:** many sponsors, with a cap on any one; grants; and the fee model the charter allows (see D-077).

### Years 2–5: recognition

1. The specification becomes an RFC or a W3C Recommendation.
2. NIST and the EU cite it.
3. An international body names agent revocation a public good, as the FSB did for the LEI in 2012.
4. Regulators reference it.

AINRA cannot cause step 3. It can be the ready answer when someone asks.

## What not to do

- Declare itself "the root" before others recognise it.
- Choose a legal home that signals one country owns it, for the long term.
- Let one sponsor dominate.
- Take per-unit money at the root before an oversight structure exists.
- Found a rival standards forum instead of joining the existing ones.

## Open questions for the owner

- Interim home: a Bulgarian foundation or a fiscal host?
- Permanent home: a Swiss foundation or a Belgian AISBL?
- The fee model: D-077 is still PROPOSED. The LEI's per-unit cost recovery is the main precedent *for* a capped
  per-unit fee, provided an oversight structure exists first.
