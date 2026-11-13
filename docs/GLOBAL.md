<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Global: the method AINRA follows to work everywhere

A handful of systems became infrastructure for the whole planet, adopted in every country without anyone being
forced to use them. AINRA studies them for one reason: to copy the habits that made them trusted, and to avoid the
ones that made them owned. This document names each habit, says what AINRA already does about it, and names the
next step. The steps are tracked in [PLAN-M54](PLAN-M54.md).

**What AINRA is, in that company.** The identity layer of the internet for AI agents, built as a global network in
the way the card networks are global payment networks. There, banks issue and shops accept, and the network is the
rulebook that lets a card from any bank work at any shop; the network itself issues no cards. Here, registrars issue
passports and any service verifies them, and the root issues none: it accredits, anchors, revokes and logs. Where the
comparison stops is the form, which is why the form is named last: no fee on a check, no shareholders, a non-profit
home, so that no issuer has to join a competitor's network. Today it is a test network with no outside witness yet;
the habits below are how it becomes the other kind.

## Five systems, five lessons

**1. The most widely deployed open-source kernel: never break what already runs.**
- One public tree, with maintainers per subsystem.
- A release on a fixed rhythm, plus long-term-support lines that are kept alive for years.
- One rule above the others: a change that breaks working programs is a bug, whoever wrote it.

That rule is why a country, a bank or a car maker can build on it for decades.

*AINRA today:*
- The wire formats are frozen, and the conformance corpus is the contract: every
  implementation must answer every vector in it identically.
- Releases are signed and reproducible.

*Missing:* long-term-support lines, a written no-break rule with deprecation windows, and maintainers per subsystem.

**2. The card networks: one rulebook, many issuers, acceptance everywhere.**
- *The four-party model.* The network sets the rules and runs the switch, but does not issue cards. Banks issue to
  holders, other banks sign up merchants, and a card from anywhere works at a terminal anywhere.
- *Certification.* Every card and every terminal is certified against one test suite before it is trusted, and an
  acceptance mark means the same thing in every country.
- *Liability rules,* which make honesty cheaper than fraud.

*AINRA today:* the same shape.
- Registrars issue, and the root never does (P1).
- Gates and verifiers accept.
- One rulebook binds every registrar class.
- The conformance programme re-checks any implementation against the corpus.

*Missing:* an acceptance mark tied to passing the corpus, a certification record anyone can check, and a published
liability and dispute rule for registrars.

**3. The internet's naming system: a registry, many registrars, and portability.**
- A neutral non-profit coordinates one registry.
- Competing registrars serve customers.
- A name moves between registrars at its holder's request.
- Policy is made by more than one kind of stakeholder.

*AINRA today:*
- The registry–registrar split (Standard 0.5).
- Holder-driven moves (D-102) and changes of owner (D-103).
- The custodian model (D-094), and an NGO in formation.

*Missing:* the legal home in a chosen country, and registrars on every continent.

**4. The internet's protocol standards: rough consensus and running code.**
A specification is published openly, anyone may implement it without permission or fee, and it becomes a standard
only once independent implementations interoperate.

*AINRA today:*
- An Internet-Draft.
- Three independent verifier implementations (Rust, TypeScript, Python) and a reference CLI, held to one answer.

*Missing:* standard-track adoption, registration of the `did:ainra` method in the public DID registry, and liaison
with the international and regional standards bodies that regulators cite.

**5. The web: free to implement, works without permission, degrades gracefully.**
Nobody needs anyone's approval to publish or to read, and a page still loads on a slow link.

*AINRA today:*
- Verification is free, offline and needs no account.
- A passport verifies with the root switched off, and the whole network can be mirrored.

*Missing:* low-bandwidth and offline distribution of the directory and status lists, for places with intermittent
connectivity.

## What "everywhere" means, concretely

**Language.** The site, the quickstarts and the Standard in the world's most-spoken languages, translated and then
reviewed by native speakers. The English text stays normative. Machine translation is never published unreviewed.

**Jurisdiction.** At least one accredited registrar per continent. A regulation map per region, each line backed by
a source (`docs/REGULATION.md`). Custodians in five jurisdictions, as D-094 decided.

**Implementations.** Verifiers in the languages the world's back-ends are written in, beyond Rust, TypeScript and
Python. Each one is held to the same corpus by the same differential, before it is called an implementation.

**Standards.** The Internet-Draft on the standards track, `did:ainra` registered, and liaison with the
international standards bodies for identity and security techniques and with the regional bodies that regulators
cite.

**Certification and the mark.** An implementation that passes the full corpus may say so, with a signed,
re-checkable attestation (the conformance programme already produces one). The mark is earned by evidence anyone
can re-run, and it is never sold.

**Stability.** A written no-break rule. Long-term-support releases. Deprecations announced a full release line
ahead.

**Governance.** A non-profit home. Custodians, witnesses and registrars from many countries. The doctrine that ends
the plan: a community that no longer needs its founders to keep running.

## What AINRA will not copy

- A network that owns the switch and charges per transaction: verification stays free, and the root holds no money
  (P2).
- A single company or country able to turn the system off: the root is shared, offline, and forkable.
- Certification sold as a product: the corpus is public, and anyone can check anyone.
