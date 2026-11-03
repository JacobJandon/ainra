<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# How ICANN works, and what AINRA takes from it

Written on 3 November 2026. The owner asked for a full study of how ICANN works before AINRA designs its own control
system ("like ICANN has"). This is the study. `docs/PLAN-M52.md` is the plan it shapes.

Every fact below comes from a primary source listed at the end. Organisations that are companies are named by their
role, not their name, as everywhere else in this repository (S7). Where the research could not confirm something, it
says so (see *Not confirmed*).

## 1. Who does what

ICANN does not sell names, route traffic or assign addresses to networks. It writes contracts and rules, and a small
number of separate parties carry out the work, each checking the one before.

| Party | What it does | What it cannot do |
| --- | --- | --- |
| **ICANN** (a California nonprofit) | Holds the IANA functions. Writes and enforces the registrar and registry contracts. Runs the policy process. Operates one root server identity (L-root). | Edit the root zone file itself, or sign it with the zone key. |
| **PTI** (Public Technical Identifiers, an ICANN affiliate since 2016) | Performs the naming function under contract: receives, checks and authorises root zone changes. Operates the root **Key Signing Key** (KSK). | Make or change policy (Naming Function Contract §4.5). Do the Root Zone Maintainer's work unless ICANN authorises it. |
| **Root Zone Maintainer** (a separate contractor) | Edits, builds and signs the zone with the **Zone Signing Key** (ZSK), changed every quarter, and distributes it. Can re-validate a change and flag a discrepancy. | Decide a change: when it flags one, ICANN consults the TLD manager and decides. |
| **12 root server operators** (13 identities, A–M) | Serve the zone as published, through about 2,048 anycast instances. Self-funded. | Change it: they commit to serving IANA's zone unmodified. They are not ICANN contractors, and no one can remove them. |
| **TLD managers** (registries) | Ask for changes to their own entry, through approvers and counts they set themselves in the change system (RZMS). | Change another TLD's entry. |
| **Registrars** (about 3,000) | Sell names to the public under one standard contract (the RAA). | Register a name outside an accredited path. |

Oversight is layered and has no single approver. The **CSC** (a committee of TLD customers) checks PTI's performance
every month and can escalate. **RZERC** advises the ICANN Board on architectural changes to the root zone. **IANA
Naming Function Reviews** run at least every five years and can lead to a special review and, in the end, a
**separation process** that moves the naming function away from PTI. The **Empowered Community** (five of ICANN's
community bodies) can remove directors, recall the Board, reject budgets and must approve every change to the
fundamental bylaws.

Until 1 October 2016 a US government agency (NTIA) approved root zone changes. Since then no government signs off on
routine changes.

## 2. How a root zone change is made

1. **Filing.** A TLD manager files the change in RZMS from an individual account. MFA is optional, but turning it on,
   or using the API, requires a government-ID check first.
2. **Pre-review** by IANA staff.
3. **Automated technical checks** against published, machine-checkable nameserver and DS requirements. A failure goes
   back to the requester, and there is a path to appeal.
4. **Approval** by the TLD's own designated approvers, in the number the TLD chose for that type of change. Since
   2022 approval is by login, not by an emailed link.
5. **Manual review** by staff. If control of the TLD changes hands, a separate delegation or transfer evaluation runs.
6. **Supplemental re-test** just before submission, so a change that went bad while it waited is caught.
7. **Submission to the Root Zone Maintainer**, which re-validates, builds, ZSK-signs and publishes.

The published target is that 99% of routine technical changes are published within 72 hours. PTI reports against
its targets every month; the September 2026 report shows 64 of 64 met and an average of 22.7 hours. Emergencies are
handled in hours. Anyone can download the root zone. Since December 2023 it carries a ZONEMD digest, so a copy from
anywhere can be checked against the signed zone itself.

## 3. The root key and its ceremonies

- **Two keys, two organisations.** PTI's KSK signs only the root key set, and its public half is the trust anchor
  every validating resolver holds. The Root Zone Maintainer's ZSK signs everything else. No person may hold a
  ceremony role for both.
- **Two facilities.** The KSK lives in tamper-evident hardware security modules in two key management facilities on
  opposite US coasts, with no network connection.
- **People outside the organisation.** A module activates only with 3 of 7 smart cards held by **Crypto Officers**.
  Backups are encrypted under a key split 5 of 7 among **Recovery Key Share Holders**. Both groups are Trusted
  Community Representatives: unpaid volunteers chosen from public statements of interest, not affiliated with ICANN,
  PTI or the Root Zone Maintainer, and listed publicly. Crypto Officers become eligible for retirement after five
  years; Recovery Key Share Holders have no term limit. Restoring the key is deliberately harder than using it.
- **Public, scripted, recorded.** About four ceremonies a year sign the next quarter's keys (the maintainer sends a
  Key Signing Request; the ceremony returns a Signed Key Response). Scripts are published in advance; afterwards come
  the annotated scripts with exception reports, multi-camera video, the hardware and signer logs and the hash of the
  operating system used. Seats are open to witnesses. All of it runs under a public DNSSEC Practice Statement, with an
  independent SOC 3 audit every year since 2011.
- **The honest limit.** The smart-card PIN is a public constant, and the disaster-recovery procedure allows the safe
  deposit box to be drilled. Beyond the cryptographic threshold, the real control is chain of custody, tamper bags,
  witnesses and film, and the documents say so.
- **Signatures made ahead.** Root signatures are produced at least 33 days ahead, so the maintainer runs for weeks
  without the ceremony. Signatures are short-lived (at most 21 days), which bounds how long a stale copy can be passed
  off as current. During COVID, ceremony 41 signed nine months at once with remote participants.
- **Rollover.** The first KSK rollover was planned for 11 October 2017. It was postponed when newly available
  telemetry (RFC 8145) suggested 4–5% of reporting resolvers still trusted only the old key. It happened on 11 October
  2018. ICANN's own review found that resolver behaviour cannot be predicted, that a long rollover loses urgency, and
  proposed a rollback criterion (0.5% of users harmed 72 hours after the change). One planned successor key was
  abandoned because its hardware vendor was leaving the business within the key's lifetime. The next rollover took
  effect on 11 October 2026.
- **Emergency plan.** If the KSK is lost or compromised, PTI publishes an interim trust anchor within 48 hours, gives
  at least 30 days' notice before signing with it, and holds a full ceremony within 90 days. If the old private key is
  gone, automatic updates (RFC 5011) cannot help, and every resolver operator must add the new anchor by hand.

## 4. Governing registrars without issuing names

- **One contract for everyone.** Every registrar signs the same Registrar Accreditation Agreement; every gTLD registry
  signs the same base Registry Agreement. Both bind the parties to future consensus policy by reference, so rules
  change without renegotiating thousands of contracts. Registries must treat all registrars equally and may not
  register names for themselves.
- **Fees.** Registrars pay US$4,000 a year per accreditation plus US$0.20 per domain-year plus a shared variable fee;
  registries pay US$6,250 a quarter plus US$0.25 per transaction past 50,000. About 98% of ICANN's operating money
  comes from these parties, which is a structural dependence on the people it polices.
- **Enforcement ladder.** An informal, confidential stage (up to three notices: email, then email and phone, then
  email, phone and fax), then a public formal stage: breach notice with a cure period, suspension (up to 12 months
  with no new registrations or inbound transfers, while existing names keep working), termination. In 2025 ten breach
  notices and eight terminations were published, all against registrars. The four breach notices of January 2025 were
  for unpaid fees and failing lookup (RDAP) services. Most complaints ICANN receives are outside its scope (831 of 988
  closed in one reported period).
- **Continuity.** Registrars and registries escrow their data with independent agents on a fixed schedule. If a
  registrar is terminated, ICANN approves or refuses the losing registrar's own proposal for a gaining registrar;
  otherwise it runs a request for information, a request for proposals or an auction, and may in the end operate the
  accounts itself. A failing registry's five critical functions pass to one of three pre-contracted standby operators
  (EBERO), used for a real failure at least once (.wed, December 2017).
- **Portability.** The holder controls the transfer secret, the reasons a registrar may refuse a transfer are listed,
  and a 60-day lock follows a transfer. Portability is what makes removing a bad registrar survivable for its
  customers.
- **ccTLDs are outside.** Country-code registries have no ICANN contract; ccNSO policy binds only members, only within
  scope, and never above local law.

## 5. Governance and accountability

Policy is made bottom-up by three Supporting Organisations (generic names, country-code names, addresses) with
Advisory Committees for governments, users, security and root servers. A GNSO supermajority recommendation binds the
Board unless more than two thirds of the Board finds it against the public interest. Fundamental bylaws change only
with three quarters of the Board and the affirmative approval of the Empowered Community, and silence counts as
rejection. Community decisions use thresholds of the form "supported by N participants and objected to by no more
than one", so no single body can act alone or block alone. When a decision rests on one body's own advice, that body
loses its vote on challenging it (the GAC carve-out). Other tools: Reconsideration, a binding Independent Review
Process (its standing panel was seated only in 2024, eight years after it was created), an Ombudsman, and a public
disclosure policy with deadlines.

The recurring criticisms are capture by the contracted parties, very long timelines (the next gTLD round took about
ten years from policy start to open applications), volunteer overload, and the root server operators being
independent but accountable to no one: RSSAC037 (2018) proposed a governance model that is still not in force, and in
October 2026 the IAB criticised the latest proposal as guaranteeing operators longevity without accountability.

## 6. When ICANN is attacked: the record, and a fact-check

ICANN's breaches have hit its corporate and community systems, never the root: the 2014 spear-phishing (administrative
access to the zone-file access service, with users' names, addresses, emails and salted password hashes), the 2015
theft of icann.org profile hashes through an outside provider, a 2020 access bug, denial-of-service attacks on its web
and name servers, the February 2025 takeover of its X account through phishing despite MFA, and a 2025 exposure that
kept its registry testing service offline until 19 November 2025. Each time ICANN stated whether IANA systems were in
scope; they were not. The large 2018–2019 hijacking campaigns (DNSpionage, Sea Turtle) went after registrar,
DNS-provider and some registry accounts, not the root. The real high-value targets are the root change path (a forged
change to a TLD's NS or DS record could redirect a whole TLD) and the KSK.

The owner pasted a summary of "what happens if ICANN is hacked". Claim by claim:

| Claim | Verdict |
| --- | --- |
| The impact depends on which systems are hit; ICANN manages identifiers rather than running core infrastructure. | **Partly.** Every breach on record stayed in its own system. But ICANN does run core infrastructure: it operates L-root, and PTI runs the root change system and the KSK. |
| Website and profile leaks can expose credentials, emails and hashed passwords. | **True** (2014 and 2015). |
| Compromising zone files or TLD authorisation systems could redirect traffic. | **Partly.** The authorisation path (approver accounts plus IANA processing) could redirect a TLD, and is defended by approver thresholds, staff review, checks run twice and the maintainer's own checks. The "zone files" in the access service are read-only copies; changing them redirects nothing. |
| An incident can take operational and testing environments offline for days or weeks. | **True** for ICANN-hosted services (testing until 19 November 2025; the application system for five weeks in 2012). None affected resolution. |
| Social media accounts can be hijacked. | **True** (one incident, February 2025). |
| The Internet does not vanish: ICANN does not route traffic, and cached resolvers keep resolving. | **True, but the reason is incomplete.** Caching alone bridges about two days. The root keeps working because 12 independent operators serve it, the maintainer (not ICANN) builds and signs the zone, signatures are made weeks ahead, and resolvers can serve stale data (RFC 8767) or hold a local copy of the root (RFC 8806). |
| IANA has distinct security controls; a corporate breach does not automatically compromise the root. | **True, with a caveat** the summary leaves out: PTI gets its IT services from ICANN, so the separation lives in system-level controls and audits, not in separate companies. |

## 7. What AINRA takes, adapts and refuses

AINRA's root has exactly one act: it publishes a new **directory epoch** — who is accredited, which delegate
certificates are revoked, where graduated distrust starts — signed by both offline roots (FROST 5-of-9 Ed25519 and
SLH-DSA). It issues nothing, scores nothing, takes no payment, holds no personal data, never gates L0 and favours no
registrar (P1–P6), and it has no console and no self-serve surface (D-034).

**Taken as they are**
- Published, machine-checkable acceptance criteria, run at filing and again just before signing, with appeal by
  reproduction.
- Separate tracks for routine changes and architectural ones (AINRA already has ADRs, decisions, check-freeze and
  amendment-check).
- Every epoch kept and downloadable, so anyone can diff the history.
- Public, scripted, recorded ceremonies with a calendar, annotated scripts and exception reports.
- An emergency plan with clocks on it, written before it is needed, with the rollback criterion stated in advance.
- A public incident log that says which trust components were in scope.
- A monthly report whose every figure resolves to a published artifact.
- Thresholds of the form "N in favour and at most one against", and recusal written down in advance.

**Adapted**
- *Change authorisation.* ICANN uses accounts and approvers; AINRA uses signatures. A change to a registrar's keys or
  endpoints must be signed by an approver set the registrar declared earlier and keeps offline, the analogue of a
  registry lock. Online keys may only ask for changes that close things (revoke their own delegate, distrust
  themselves from a leaf). The root identifies no one.
- *The second key tier.* ICANN's ZSK is held by a contractor and signs every quarter. AINRA's second tier is each
  registrar's own delegate certificates, chained to the registrar's own log root, so the root never signs on a
  schedule. That tier is only as offline as the registrar keeps its log root.
- *The halt right.* ICANN's maintainer can flag a discrepancy and pause; ICANN then decides. In AINRA every custodian
  can refuse and publish a reason, but signing stops only if fewer than five custodians are willing.
- *Custody.* AINRA keeps 5-of-9 FROST across jurisdictions and institution types, and should split the SLH-DSA root's
  recovery across a separate group so that recovery is harder than signing.
- *Compliance.* Everything public from the first notice (ICANN keeps the first stage confidential). Notices state
  facts and never scores. The suspension rung already exists and is stronger than ICANN's: distrust from a log leaf
  (D-044), which cannot be backdated.
- *Escrow.* AINRA's logs are public and hold no personal data, so the log and its mirrored exports are the escrow.
- *Portability.* Driven by the holder, with the operator's key (not only the agent's) as the transfer proof, a
  public pending record, a contest window and a lock after transfer.

**Refused**
- An online root signing key (D-034).
- Accounts, ID checks and access-request surfaces (P4, D-034, D-079).
- A standby operator that takes over a failed registrar (it would issue, P1). A failed registrar's credentials fail
  closed and holders move.
- The root choosing a gaining registrar (P6).
- Telemetry from verifiers. Readiness for a root roll is measured only by signed acknowledgements that verifier
  operators and witnesses choose to send.
- Short signature lifetimes on the directory, for now. They would bound the freeze attack (§8 of PLAN-M52) but need
  either regular signing or an online key; that trade is the owner's to make.

## 8. What this changes in what AINRA says

- Never say ICANN "doesn't run infrastructure"; it operates L-root, and its affiliate runs the root change system
  and the KSK.
- Never say AINRA's directory epochs need floor+1: D-083 accepts any epoch at or above the floor. Two different
  authentic directories at the same epoch are not caught today; PLAN-M52 adds the alarm.
- Never say a compromised delegate key is bounded to its certificate window when the same daemon holds the log root
  that issues new certificates.

## Not confirmed

- The original text, date and signatories of the 2019 joint statement by root server operators; it is known only
  through one operator's restatement.
- An ICANN primary account of a 2019 attack on one root-adjacent operator.
- The exact wording of the Root Zone Maintainer Agreement's verification clauses.

## Sources

Root zone management and PTI
- IANA Naming Function Contract (2016): https://www.icann.org/iana_pti_docs/151-iana-naming-function-contract-v-30sep16
- Root Zone Maintainer Agreement: https://www.icann.org/iana_imp_docs/63-root-zone-maintainer-agreement-v-1-0
- ICANN Bylaws: https://www.icann.org/resources/pages/governance/bylaws-en
- Root zone change process: https://www.iana.org/help/root-zone-process
- RZMS user guide: https://www.iana.org/domains/root/root-zone-management-user-guide.pdf
- RZMS approver model (2022): https://www.icann.org/en/blogs/details/ushering-in-the-next-generation-of-root-zone-management-19-05-2022-en
- ID verification for MFA and API: https://www.iana.org/help/id-verification
- End of the NTIA contract: https://www.icann.org/en/announcements/details/stewardship-of-iana-functions-transitions-to-global-internet-community-as-contract-with-us-government-ends-1-10-2016-en

The KSK and ceremonies
- DNSSEC Practice Statement: https://www.iana.org/dnssec/procedures/ksk-operator/ksk-dps-20261007.html
- KSK Key Management Policy: https://www.iana.org/dnssec/procedures/ksk-operator/20260921/KSK_Key_Management_Policy_v3.9.pdf
- KSK Emergency Rollover Plan: https://www.iana.org/dnssec/procedures/ksk-operator/20260921/KSK_Emergency_Rollover_Plan_v3.8.pdf
- Trusted Community Representatives: https://www.iana.org/dnssec/tcrs and https://www.iana.org/help/tcr-criteria
- Ceremonies and their records: https://www.iana.org/dnssec/ceremonies
- Review of the 2018 rollover: https://icann.org/review-2018-dnssec-ksk-rollover.pdf

Registrars and registries
- Registrar Accreditation Agreement (2024): https://itp.cdn.icann.org/en/files/accredited-registrars/registrar-accreditation-agreement-21jan24-en.htm
- Base Registry Agreement (2024): https://itp.cdn.icann.org/en/files/registry-agreements/base-registry-agreement-21-01-2024-en.html
- FY2027 budget: https://www.icann.org/en/system/files/files/adopted-icann-budget-fy2027-published-2026-en.pdf
- Compliance, informal and formal stages: https://Icann.Org/en/system/files/files/informal-resolution-07mar17-en.pdf and https://Icann.Org/en/system/files/files/formal-resolution-07mar17-en.pdf
- EBERO: https://www.icann.org/en/contracted-parties/registry-operators/resources/emergency-back-end-registry-operator

Governance
- RSSAC037: https://www.icann.org/en/system/files/files/rssac-037-15jun18-en.pdf
- IRP standing panel: https://www.icann.org/en/announcements/details/icann-announces-standing-panel-for-independent-review-process-23-09-2024-en
- Root server operators: https://root-servers.org/

Security
- ICANN cybersecurity incident log: https://www.icann.org/cybersecurityincidentlog
- 2014 spear-phishing: https://www.icann.org/news/announcement-2-2014-12-16-en
- 2015 profile breach: https://www.icann.org/news/announcement-2015-08-05-en
- The root zone file: https://www.internic.net/domain/root.zone
