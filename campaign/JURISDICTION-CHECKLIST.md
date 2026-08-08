<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Jurisdiction premises — verified against primary sources

`campaign/JURISDICTION.md` argues a sequence, and that argument rested on **five factual premises** that the memo
itself flagged as coming from a strategy briefing rather than a primary source. **All five have now been checked
against the issuing bodies' own pages** — Companies House, gov.uk, HMRC's international manual, legislation.gov.uk,
the Registry Agency, the National Revenue Agency, UKRI, and the funders' own eligibility pages. Verified 2026-08-08.

**This file decides nothing.** The decision is recorded in `JURISDICTION.md`, by the person who has to live with it.
What changed here is only that the premises are no longer assertions.

## How this was checked, and why that matters

Each premise was verified by one pass and then **adversarially refuted by a second**, whose only job was to break
the first. That second pass earned its place: it caught the first pass **fabricating quotes** — presenting
paraphrase as verbatim text on three separate premises (P2's citation of the Act, P3's Companies House and central
bank quotes, P4's identity-verification quote), citing press releases as primary sources, and marking a citation
`fetched_ok` that returns 404 when fetched exactly as recorded.

So: **every quote below was re-fetched and confirmed to exist on the page it is attributed to.** Anything the
refuting pass could not confirm is marked UNVERIFIED and left that way rather than smoothed over. Two premises
changed verdict under refutation, and one had its direction reversed.

**This is not legal or tax advice.** One conversation with an accountant in the chosen jurisdiction, before filing,
is the step most likely to be skipped.

---

## P1 · Grant eligibility — residency/establishment rule

**Claim:** UK innovation grants are gated on a UK-registered applicant; the best-fitting funder accepts individuals
with no entity.

**Verdict: TRUE as a rule-claim — but the practical case it was built to support has weakened.**

- [x] Verified · 2026-08-08 · **both halves hold, and both now cut the same way**

| What | Source | What it says |
|---|---|---|
| Individuals may apply, no entity needed | `nlnet.nl/core/faq/` | *"Do I need to have a legal entity like a company to apply? No, you don't. You can apply as an individual, or as a formal or informal organisation of any type."* |
| Grant size | `nlnet.nl/funding.html` | *"We provide grants between 5.000 and 50.000 euro"* |
| A hard gate the memo never mentioned | `nlnet.nl/core/faq/` | *"It is a knock-out criterion for each project to have a 'European dimension'."* |
| UK schemes are gated on UK registration | `ukri.org/…/funding-rules/` | *"To be eligible as a UK registered business you must have a Companies House registration number."* |
| **A UK branch of a foreign company does not qualify** | `ukri.org/…/funding-rules/` | *"A registration number that does not relate to a fully registered UK business will not be eligible to apply for funding, for example FC or BR prefixes."* |
| **And registration alone is not enough** | `ukri.org/…/smart-innovation-funding-guidance/` | *"all applicants must be UK-registered companies **and carry out their project activities in the UK**"* |

**What replaced the memo's version.** Three things it does not account for:

1. **The activities test.** The UK gate is not "be registered in the UK" — it is registered **and carrying out the
   project in the UK**. A UK shell run from Bulgaria does not satisfy it, which is precisely the configuration the
   memo proposed.
2. **The European-dimension knock-out** at the funder that accepts individuals: a Bulgaria-based founder satisfies
   it automatically; a UK entity would have to argue it.
3. **Timing.** That funder is **closed today** — the next window opens 3 September 2026 with a 3 November deadline —
   and the specific fund is winding down (*"until the budget of the programme has been fully allocated (expected
   June 2026)"*), with successor programmes announced but undocumented. Grant ceilings are also higher than the
   memo says for follow-on work: 50k first proposal, 150k per proposal, 500k lifetime.

**Also verified, and materially different from the memo's framing:** the no-cost legal-home foundation
*"There is no cost attached. We don't interact with money at all"* — but it **cannot hold funds**: *"Handling of
donations … happens through organisations far better equipped to do so."* It is a legal home, not a fiscal host.

**UNVERIFIED:** the memo's specific phrasing that the funder says a not-yet-formed entity "is not a problem" — that
sentence was not found on any of its pages. The stronger, verified statement is that no entity is required at all.

---

## P2 · The digital-identity certification route

**Claim:** the UK digital-identity office runs a certification framework; open question is whether a non-human
identity body has any route into it.

**Verdict: the route does not exist. The framework's own definitions exclude it.** This is the answer the memo
asked for, and it is a clean "no".

- [x] Verified · 2026-08-08 · **published scope is natural persons only**

| What | Source | What it says |
|---|---|---|
| The scope is human beings | gov.uk, DVS trust framework 1.0 §3.1 | *"Unless otherwise stated, 'person' refers a natural person, in the sense of an individual human, rather than a legal person, like a company."* |
| And that is deliberate, to match the Act | same | *"To align the trust framework with the scope it is given in the Act, we have also focused the trust framework's rules on the identities and attributes of natural persons"* |
| **The framework was renamed** | gov.uk collection page | 1.0 is the *"UK digital verification services trust framework"*; *"Prior versions were titled the UK digital identity and attributes trust framework."* |
| Certification against 1.0 is not open yet | OfDIA blog, 3 Mar 2026 | *"DVS providers cannot certify against the 1.0 trust framework or supplementary codes just yet."* |

**What this means for the memo.** The "regulator door" was the strongest argument for a UK entity. As published, that
door is for services that verify facts **about individual humans**. An AI-agent identity body is not in scope, and no
amount of incorporation changes that. The memo's fallback reading — that the letter is *an introduction, not an
application* — is the correct one, and an introduction does not require an entity.

**UNVERIFIED, and left open honestly:** whether any **informal or non-statutory** engagement route exists. The
supplementary codes and the OfDIA annual report published 14 July 2026 were not read. The refuting pass also rejected
the first pass's stronger claim that the humans-only limit is a *statutory ceiling requiring new primary
legislation* — the Act cited does not say that, and the same office ran earlier versions of this framework
non-statutorily. So: **no published route today**, not **no route is possible**.

---

## P3 · Incorporation cost, time and ongoing burden

**Claim:** UK incorporation is remote and fast, with filing overhead one person can carry.

**Verdict: fast and cheap is still TRUE — but "remote" acquired a new prerequisite, and Bulgaria is cheaper and
faster on every figure checked.**

- [x] Verified · 2026-08-08 · **both registries' own fee and timescale pages**

| | **UK** | **Bulgaria** |
|---|---|---|
| To incorporate | **£100** digital, £124 paper (*Companies House fees*, updated 2 Jul 2026) | **28.12 EUR** electronic; 56.24 EUR otherwise (*Tariff, art. 16a*) |
| Time | *"Your company is usually registered within 24 hours"*; postal *"8 to 10 days"* | end of the **next working day** (*ZTRRYuLNTs art. 19(3)*) |
| Annual | Confirmation statement **£50** digital, £110 paper + accounts | **No state fee** for publishing annual financial statements (*art. 12(3), in force 01.01.2022*) |
| Address | *"a physical address in the UK … You can no longer use a Royal Mail PO Box"* | — |

**What replaced the memo's version — the new prerequisite.** Identity verification became a legal requirement on
18 November 2025. A **Companies House personal code** *"is given to a person once they've verified their identity"*,
and registration asks for one **for each director**. The free route's fallbacks are UK-bound; a Bulgaria-resident
director's reliable path is an authorised corporate service provider, which charges. "Remote and fast" now means
*remote and fast once every director has verified*, and that step is neither instant nor necessarily free.

**Caught by the refuting pass:** the first pass fabricated two quotes here — one attributed to the Companies House
identity guidance about verifying "from any country", one to the central bank about the euro changeover. Neither
appears on the cited page. Both were removed. It also cited a **news story** as a primary source for a 2028 accounts
rule and deleted that story's own qualifier, and it priced every hidden UK cost while pricing none of the Bulgarian
ones. The table above is what survived.

**Cuts the other way, and belongs on the record:** the Bulgarian annual statement is filed by *"счетоводителят,
изготвил и подписал годишният отчет"* — the accountant who prepared and signed it. That is a real recurring
obligation on the Bulgarian side, and it is the one the first pass shelved as "could not verify" while it sat on a
page it had already cited.

---

## P4 · Non-resident director consequences

**Claim:** a director resident elsewhere does not create a tax or reporting problem.

**Verdict: FALSE.** This is the premise the memo said "bites quietly", and it bites.

- [x] Verified · 2026-08-08 · **both tax authorities, in their own words**

| What | Source | What it says |
|---|---|---|
| A UK company stays UK tax-resident regardless of where it is run | HMRC INTM120040 | *"The incorporation rule at CTA09/S14 states that, with certain exceptions, a UK incorporated company is resident in the UK for tax purposes."* |
| …and residence can *also* attach where it is actually managed | HMRC INTM120060 | *"A company resides … where its real business is carried on … and the real business is carried on where the central management and control actually abides."* |
| Bulgaria registers a foreign legal entity whose **effective management** is there | BULSTAT Act art. 3(1)(5)(b) | *"чуждестранни юридически лица: … б) чието ефективно управление е на територията на страната"* |
| A **place of management** is a listed permanent-establishment example | DOPK §1(5)(a) | *"'Място на стопанска дейност' е: а) определено място … място на управление; клон; …"* |
| The treaty's tie-breaker can leave a company resident **nowhere** | UK–Bulgaria DTC, synthesised text | *"In the absence of a mutual agreement … the person shall not be considered a resident of either Contracting State"* |

**What this means concretely.** A UK company directed from Bulgaria carries **UK filing that never goes away**
(incorporation rule) **plus** a Bulgarian registration trigger on effective management — and the corporate-tax
exposure, while conditional rather than automatic, turns on a place through which business is carried on, which is
exactly what a working founder is.

**The direction the first pass got wrong, per its own source:** it called this "favours BG", but central management
and control cuts **both** ways — a Bulgarian company managed from the UK would be exposed in the mirror direction.
What is asymmetric is narrower and more useful: **the one configuration with no cross-border management question at
all is an entity in the country where the person actually is.**

**Also:** identity verification now binds every director irrespective of residence, so "non-resident" no longer buys
any reduction in personal obligations at Companies House.

---

## P5 · Non-profit form availability

**Claim:** a non-profit-shaped form is available at incorporation, or the entity can convert later without penalty.

**Verdict: TRUE in both jurisdictions — you can start in the right shape.** But one specific conversion the memo
implies is **not possible**, and knowing which is the point of the premise.

- [x] Verified · 2026-08-08

| | **UK** | **Bulgaria** |
|---|---|---|
| Available directly? | Yes — company limited by guarantee: *"Usually companies limited by guarantee are 'non-profit' or registered as a charity."* | Yes — сдружение or фондация under ЗЮЛНЦ, in **public** or **private** benefit designation |
| Founders | — | *"учредители … могат да бъдат български или чуждестранни юридически и/или дееспособни физически лица **без значение тяхното гражданство**"* (art. 52) — nationality is irrelevant |
| Minimum founders | 1 guarantor | 3 (private benefit); 7 individuals or 3 legal persons (public benefit) |
| Conversion later | CIC conversion **£45**; a charitable company may convert to a CIO | — |

**The trap, stated plainly.** Under the Companies Act you **cannot** re-register a company limited by **shares** as
one limited by **guarantee**, or the reverse:

> *"The Companies Act does not legislate for companies limited by shares to re-register as companies limited by
> guarantee (or vice versa)."* — Companies House conversion checklist

So "incorporate now, convert to the non-profit form later" is only true along the routes that exist (shares →
CIC keeps the type; charitable company → CIO). **The share/guarantee choice is made once, at incorporation.** The
root's whole proposition is that it cannot be squeezed, and the form that expresses that has to be picked on day
one, not deferred.

---

## What the five premises support

The two arguments the memo built its UK case on are the two that did not survive contact with the sources. The
regulator door is **defined for human beings** and no entity opens it. The grant gate is not incorporation but
**carrying out the work in the UK**, which a shell run from Bulgaria does not do — while the funder that fits best
wants a European dimension and asks for no entity at all. On cost, time and recurring burden Bulgaria is cheaper and
faster on every figure checked. And P4 — the premise the memo predicted would bite quietly — says the only
configuration with no cross-border management question is an entity where the person actually is.

**The premises support BG over UK, and support neither cleanly enough to compel filing now.**

That sentence is a reading of five verified facts, not a decision. The decision — including "wait", which the memo
correctly insists is a decision and must be written down — stays yours, in
[`JURISDICTION.md`](JURISDICTION.md) § *The decision*, where `make campaign-status` reads it.
