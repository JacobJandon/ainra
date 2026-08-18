<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# The arrows, and where we are standing

> *The pioneers get the arrows, and the settlers get the land.*

AINRA is not first. Trust roots, transparency logs, credential formats and revocation systems have all been built
before, at scale, by people who wrote down what went wrong. That documentation is the most valuable unowned asset
in this field, and reading it is cheaper than earning it.

This file is the audit. For each **documented** failure: does AINRA carry the same exposure? Every *immune* claim
names the file and line that makes it true, so it can be checked rather than believed. Where a lesson does **not**
apply, that is stated with the reason — a lesson dodged by irrelevance is not a lesson learned, and counting it as
a win would be the self-flattery this project exists to avoid.

**On naming.** Standards bodies and open-source projects are named, because citing published standards work is not
what S7 prohibits. Commercial parties are described generically even where the record names them — a neutral root
does not use a company as a foil. Every claim carries its URL, so the source is identifiable regardless.

---

## Part I — the revocation graveyard

The web PKI spent twenty years failing at revocation. It is the single most relevant body of experience to AINRA,
because revocation is one of our four rules.

### The arrow: soft-fail

A checker cannot distinguish "responder is down" from "attacker is blocking the responder", so every browser
ignored failures. The canonical statement, from a browser security engineer in 2012
([imperialviolet.org](https://www.imperialviolet.org/2012/02/05/crlsets.html)):

> *"So soft-fail revocation checks are like a seat-belt that snaps when you crash. Even though it works 99% of the
> time, it's worthless because it only works when you don't need it."*

A browser vendor measured it
([mozilla](https://blog.mozilla.org/security/2020/01/09/crlite-part-1-all-web-pki-revocations-compressed/)):
*"over 7% of OCSP checks time out today"*, and therefore *"an adversarial monster-in-the-middle (MITM) can simply
block OCSP to achieve their ends."* At shutdown, one CA was serving **340 billion OCSP requests a month** for a
property an attacker could switch off ([letsencrypt](https://letsencrypt.org/2025/08/06/ocsp-service-has-reached-end-of-life/)).

**AINRA: immune, in code.** [`crates/ainra-core/src/status.rs`](../crates/ainra-core/src/status.rs) fails closed on
all four axes — stale → `StaleStatus`; **future-dated → `StaleStatus`** (*"a clock/forgery anomaly is treated as
stale, never trusted"*); index at/beyond list length → `Revoked`; zlib bomb or short list → rejected before
allocation. There is no flag that relaxes any of it.

The two current status specifications define error codes for retrieval and length failures and **never say whether
to accept or reject**. The regulator profile that had to fill the hole chose *"a Relying Party performs a risk
analysis"* — fail-open with paperwork.

### The arrow: the verifier's query leaks what it is verifying

> *"the Certificate Authority operating the OCSP responder immediately becomes aware of which website is being
> visited from that visitor's particular IP address. Even when a CA intentionally does not retain this
> information… CAs could be legally compelled to collect it."*
> — [letsencrypt](https://letsencrypt.org/2024/07/23/replacing-ocsp-with-crls/)

The decisive clause is *legally compelled*: the architecture creates a subpoena target that no privacy policy can
remove.

**AINRA: structurally absent.** The verifier never fetches status — the list travels inside the presentation and is
decoded locally ([`verify.rs:160-161`](../crates/ainra-core/src/verify.rs)). There is no responder, so there is
nothing to compel.

### The arrow: an opt-in hard-fail flag

Must-Staple was the *correct* fix for soft-fail. It died: one browser ever enforced it, *"a very small percentage
of our subscribers"* requested it, and server implementations made it an outage risk
([letsencrypt](https://letsencrypt.org/2024/12/05/ending-ocsp/)).

**Lesson: if hard-fail is right, it must be the default for everyone, not a flag.** AINRA has no flag — `verify()`
takes no policy argument. Immune, and the reason it is immune is that the option was never offered.

### The arrow: curating which revocations you distribute

> *"Roughly half of all revocations are made without a specified reason code… In this environment, the only secure
> approach is to check all revocations."*
> — [mozilla](https://hacks.mozilla.org/2025/08/crlite-fast-private-and-comprehensive-certificate-revocation-checking-in-firefox/)

One vendor ships **100%** of revocations in ~300 kB/day; another ships a curated list covering **~1%**.

**AINRA: immune.** The status list is a complete per-registrar bitmap. Nothing selects which revocations are
distributed, so nothing can select wrongly.

### ⚠ CORRECTED — validity length, and the rung that is missing underneath it

**My first pass had this wrong, and the correction is worth more than the recommendation was.**

After twenty years the standards body wrote down that revocation cannot be made reliable, and re-architected around
expiry ([cabforum, 11 Apr 2025](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/)):

> *"Certificate status services are unreliable also due to **the need for action to be taken by multiple parties**
> in order for those statuses to be effective… **Certificate validity periods, and their enforcement by relying
> parties, are incredibly reliable.**"*

Maximum validity is dropping **398 → 47 days** by 2029. AINRA's default is **366 days**
([`consts.rs:16`](../crates/ainra-core/src/consts.rs)). I flagged that as the pre-conclusion web number.

**It is not.** It is ADR-017, a deliberate inversion made in full knowledge of the web-PKI trade, and its stated
reason is correct:

> *"Why long validity is affordable here: revocation **fails closed in <60 s**… the opposite of Web PKI, whose
> shrinking certificates compensate for revocation that fails open. Short certs are what you need when revocation
> doesn't work; ours does."*

The forum's argument turns on *"action to be taken by multiple parties"*. In the web PKI, suppressing status
yielded **valid** — so an attacker who blocked the check won. In AINRA, suppressing status yields **invalid**,
because freshness is bounded and fails closed. The adversary cannot benefit from silence. **The inversion is
sound, and it is earned by code, not asserted.**

**But it is only half the ladder.** ADR-017's ladder is: identity eternal → passport 366 d → delegate ≤92 d →
**instance credentials minutes–hours** → freshness seconds. Revocation answers **detected** compromise, and AINRA's
answer there is excellent. The instance-credential rung was the answer to **undetected** compromise — a stolen key
nobody has noticed, where there is nothing to revoke because nobody knows.

`INSTANCE_CRED_DEFAULT_SECS = 1 hour` is declared in `consts.rs` and **used nowhere in the codebase**. Its own
comment says so: *"RESERVED: the instance-credential layer… is future work."*

So today the passport is **both** the identity document and the runtime credential — the one role ADR-017 argues a
long-lived credential should not play. The undetected-compromise window is therefore **366 days, not one hour**,
and the top rung is load-bearing in a way the decision record did not intend.

**The fix is not to shorten the passport.** That would trade away a sound design to patch a missing layer. The fix
is R1 below: build the bottom rung, or say plainly that the passport is currently the runtime credential and size
it for that job. What must not happen is the ladder continuing to be cited as a defence while one rung of it does
not exist.

---

## Part II — what kills a root

### The arrow: cannot enumerate what you issued

A CA compromised in 2011 kept its issuance logs **on the machines that were compromised**, and they were tampered
with. The forensic report's conclusion
([Fox-IT, *Black Tulip*](https://roselabs.nl/files/audit_reports/Fox-IT_-_DigiNotar.pdf)):

> *"The log files were generally stored on the same servers that had been compromised and evidence was found that
> they had been tampered with. Consequently… the absence of suspicious entries could not be used to conclude that
> no unauthorized actions took place."*

Because it could not produce a complete list, partial remedy was impossible — the EU agency's post-mortem
([ENISA](https://www.enisa.europa.eu/sites/default/files/all_files/Operation_Black_Tulip_v2.pdf)):
*"did not have a record of all the rogue certificates that were created by the attacker, so the only remedy was to
remove the root certificate."* The company went bankrupt.

**AINRA: immune by construction.** Issuance is logged-before-valid to an append-only transparency log, externally
witnessed, and the credential is not valid until the log entry exists. The issuer's own database is not the record.

### The arrow: concealment beats severity

Both landmark removals were driven by conduct, not by the technical fault. On the 2011 case
([mozilla](https://blog.mozilla.org/security/2011/09/02/diginotar-removal-follow-up/)):
*"Failure to notify. DigiNotar detected and revoked some of the fraudulent certificates 6 weeks ago without
notifying Mozilla."* On the 2016 case
([mozilla](https://blog.mozilla.org/security/2016/10/24/distrusting-new-wosign-and-startcom-certificates/)):
*"The levels of deception demonstrated by representatives of the combined company have led to Mozilla's decision
to distrust."*

The doctrine sentence, worth stealing verbatim:

> *"The integrity of the SSL system cannot be maintained in secrecy."*

It became mechanical: a **72-hour** public incident report, *"regardless of perceived impact"*, with no severity
threshold — so there is never a judgment call about whether to disclose.

**AINRA: partially covered.** Transparency is charter-level and the log makes issuance undeniable. What does not
yet exist is a **mechanical disclosure deadline binding on accredited registrars**. See **R3**.

### The arrow: trust as a state rather than a running claim

Two 2024–25 removals were justified not by a single incident but by
*"a pattern of compliance failures, unmet improvement commitments, and the absence of tangible, measurable
progress"* ([google](https://blog.google/security/sustaining-digital-certificate-security-chrome-root-store-changes/)),
under the standing rule that inclusion *"must provide value to Chrome end users that exceeds the risk of their
continued inclusion."*

**The doctrine: trust is not a state a participant holds; it is a claim that must keep being re-earned — and the
metric is response to incidents, not absence of incidents.**

### ⚠ The arrow still pointed at us: too large to remove

ENISA named it in 2011: a compromise at a CA holding a quarter of the market would have been unremovable —
*"CAs of this size are too large to fail."* Unwinding one large CA took **19 months** of graduated, `notBefore`-keyed
distrust, staged across browser releases, because instant removal would have broken the web.

**AINRA has no graduated distrust.** An accreditation carries keys, a log root and a status URI; a registrar is
either in the signed directory or removed. There is no suspended, no conformance-failing, no
distrust-certificates-issued-after-date-X. Removal is binary and total.

At two registrars this is theoretical. It is also the cheapest moment in the project's life to fix it. See **R2**.

---

## Part III — ceremonies and logs

### The arrow: assuming automated key rollover works

The root DNSSEC key roll was **postponed eleven days out**. The reason is the most quotable sentence in the corpus
([ICANN](https://www.icann.org/en/blogs/details/the-story-behind-icanns-decision-to-delay-the-ksk-rollover-4-10-2017-en)):

> *"Historically, there has been no way to determine which trust anchors DNS Security Extensions (DNSSEC)
> validators have been configured, making it difficult to assess the potential impact of the root KSK rollover.
> But that recently changed and we received some new data that we simply could not ignore."*

A signalling protocol finalised **five months earlier** revealed that ~5% of validators had only the old anchor and
would have broken — affecting a potential *750 million* users. The automated-rollover mechanism was assumed to
work. It did not, and there had been no way to know.

**AINRA: exposed, and it collides with the charter.** We will have to roll the root. We have no trust-anchor-state
telemetry — and by charter we never will: *verification never reports to anyone.* Measurement is not available to
us. That leaves exactly one honest answer: **over-engineer reversibility instead.** See **R4**.

### The arrow: the ceremony fails for a boring physical reason

The 40th root key ceremony was stopped by **a malfunctioning safe lock**
([ICANN](https://www.icann.org/en/blogs/details/root-key-signing-key-ceremony-postponed-12-2-2020-en)). Zero service
impact, because signatures were pre-generated and *"We maintain a complete replica facility in Culpeper,
Virginia."*

**The controls were redundancy and signature depth, not lock quality.** AINRA has `ABORTS.md` and a rehearsed
ceremony; the standby quorum is an open runbook item, and there is no second facility. Prospective, but it is what
made the difference for someone else.

### The arrow: a production key reused in test

A CT log was disqualified for presenting *"two conflicting views of the Merkle Tree"* — caused by
*"reusing the key between a production instance and a testing instance."* Benign cause, fatal outcome.

**AINRA: immune, and visibly so.** Staging runs under a labelled `TEST-ROOT` that is a distinct type in the code
([`checkpoint.rs`](../crates/ainra-core/src/checkpoint.rs)), surfaced in the `X-AINRA-Root` header and printed on
every staging page. The separation is not a convention; it is a type.

### The arrow: disaster recovery that restores a log backwards

A log broke append-only consistency by auto-restoring from a stale backup during a cloud outage, publishing an
inconsistent tree head. **Your restore path must be forward-only or refuse to serve.** AINRA has no documented
forward-only restore constraint. See **R5**.

### The arrow: one operator structurally required

Chrome's CT policy originally required an SCT from a **Google-operated** log. It was removed deliberately to end
*"the explicit dependency on Google CT logs"*, while keeping *"SCTs from at least 2 distinct CT log operators"* for
*"resilience against log operator-wide incidents."*

**AINRA: designed right, unstaffed.** The k-witness quorum exists and the fork drill runs on every board
(`witness quorum · fork refused over HTTP`, [`tools/preflight.sh:69`](../tools/preflight.sh)). But
`witnesses/candidates.json` is an **empty array**. The control has no operators. See **R6**.

### The arrow: asking participants whether they are compliant

Chrome does not ask. It **mandates that every log accept its Merge Delay Monitor Root** so it can inject its own
probes, and measures availability from its own infrastructure over a 90-day rolling window, taking the *minimum*
across endpoints.

~~**AINRA has no probe-injection hook.**~~ **Built — D-046, [`PROBES.md`](PROBES.md), `make probe-drill`.** Nine
checks measured from outside by a probe holding nothing the registrar issued it, minting under an unmarked name,
proven against four dishonest registrars. Chrome's version of this is availability plus merge delay; ours goes further
because our evidence goes further — inclusion is recomputed at a claimed position, a flipped claims byte is refused, a
revocation is timed as an outsider sees it, and a pre-revocation snapshot is refused after the fact. The check that
matters most is the one Chrome does not need: **the probe proves the write door is shut to it before it measures
anything**, and voids its own run if it isn't.

---

## Part IV — credentials and registries

### The arrow: log evidence not bound to the artifact — *taken twice*

A signing tool accepted a log entry that did not reference the artifact (2022, `GHSA-8gw7-4j42-w388`:
*"allowing 'any old rekorBundle' to pass validation"*). It was fixed. **A January 2026 refactor reintroduced it**
(`GHSA-whqx-f9j3-ch6m`).

**AINRA: immune, and guarded against the regression specifically.**
[`verify.rs:188-197`](../crates/ainra-core/src/verify.rs) recomputes the leaf from the credential's own bytes and
refuses a mismatch — *"the echoed leaf is not this credential's body"* — before checking inclusion, and does the
same for **every delegation hop**. The unit test names the failure it guards; conformance vector
`not-logged-binding-0001` runs in the **793-vector corpus across four implementations** on every board. Their
regression tests were added after the second incident; ours exist before the first.

### The arrow: a core nobody can resolve, and a registry that means nothing

The identifier core that drew formal objections standardised syntax but nothing resolvable — the standards body's
own analysis conceded *"it is not possible to use the DID 1.0 specification without an actual method"*. The
registry went **50+ → 112 → 267 methods**, because registering cost less than interoperating, and no entry ever
advanced past `PROVISIONAL`. The objectors' concrete proposal — a `Recommended: Y/N` column, per RFC 8447 — was
never adopted.

**AINRA: immune on resolution** (root-signed directory + thin resolver ship *with* the core, ADR-014; four
implementations agree on every vector). **Exposed on registry semantics** — see R2; and note we cannot copy
`Recommended` as written, because the charter says the root *records facts, never judgment*. The charter-compatible
form is the objectors' *other* idea: mechanically testable predicates whose **result** is a fact.

### The arrow: format fragmentation

Four base specifications required a **fifth** document to remove optionality before anything interoperated. A
government profile demoted one data model to *optional*, and stated why: *"Supporting multiple formats increases
attack surfaces"* and *"Relying Parties would need to support multiple verification pathways."*

**AINRA: immune.** One format (ADR-004), with the linked-data alternative rejected explicitly for
*"canonicalization attack/fragility surface"*. One rulebook, 793 vectors under it.

### Not applicable — and why, rather than claiming a win

About a third of the documented revocation lessons concern **herd privacy**: a status list must be large enough,
and its index random enough, that `(uri, index)` does not identify the holder. One spec sets a 131,072-entry floor
and still concedes small populations are correlatable; the other admits *"the tuple of uri and index… are unique
and therefore is traceable data"*; one reaches the self-defeating conclusion that *"the most privacy-preserving
status list is one that never changes."*

**AINRA has no minimum list size and does not need one.** Those lessons protect an *unlinkability* claim AINRA
never makes: a passport carries an explicit canonical name. The index reveals nothing the name has not already
said. Randomised indices, decoy values and one-time-use batches are answers to a question this design does not ask.

Five lessons dodged because they aim at someone else's design are five lessons **not** learned. Recording them as
passes would inflate the score.

---

## Recommendations, in priority order

Written as an unimplemented list; **five of the seven are now done** and struck through where they are, each
with the decision or file that closed it. The two that remain are the two that were never code: **R1** is a
design question with a real answer either way, and **R6** is people. Each row still names what it protects
against and what it cost.

| | Recommendation | Protects against | Cost |
|---|---|---|---|
| **R1** | **Build the instance-credential rung, or stop citing it.** ADR-017 makes a 366-day passport safe *because* a running copy holds a minutes-to-hours credential. That rung is declared and unimplemented, so the passport is currently the runtime credential too. Either implement it, or amend ADR-017 to say the passport plays both roles and re-derive its lifetime for that. | Undetected key compromise — the case revocation cannot help, because nobody knows to revoke | New credential layer, or an ADR amendment. **Do not "fix" this by shortening the passport** — that trades away a sound design to patch a missing layer. |
| ~~**R2**~~ | **DONE — D-044.** Graduated distrust keyed on the transparency-log **leaf index**, not on a date. Absent = trusted; present = refuse what the registrar logged at index ≥ n, everything earlier still verifies. Enforced in all three implementations after inclusion is proven, for the credential and every hop. 48 new vectors; four-way differential 793/793. The web PKI keyed this on `notBefore` and a CA backdated to evade it — a log index cannot be backdated. | A registrar too large to remove; a registry with no state between listed and gone | **Shipped** |
| ~~**R3**~~ | **DONE — [`DISCLOSURE.md`](DISCLOSURE.md).** 72 hours, public, no severity threshold, no waiting to establish scope; inability to enumerate own issuance is the gravest class; ownership/control change disclosed BEFORE it takes effect; pattern judged, not only events. Binds the root first. Draft term — nothing to bind a registrar to yet. | The failure mode that actually killed two CAs: concealment | **Written** |
| ~~**R4**~~ | **DONE — [`genesis-day/ROLLBACK.md`](genesis-day/ROLLBACK.md).** The decisions that must be numbered and named before a roll is scheduled, with the numbers left blank on purpose because filling them is a governance act. States plainly that we roll blind by charter, lists what we *can* measure instead, and concludes a root roll cannot be scheduled before witnesses exist. | Rolling blind into a 5%-breakage cliff | **Written** |
| ~~**R5**~~ | **DONE — D-045.** `log.highwater` records the largest tree size ever reached; a rebuilt tree below it is refused and the daemon declines to start. Proven: truncating the log to 4 leaves against a mark of 7 refused startup. Honest limit recorded — a whole-directory restore rolls the mark back too; the witness-anchored version is gated on R6. | An outage becoming a consistency violation | **Shipped** |
| **R6** | **Recruit witnesses, or stop describing detection as a control.** Currently honest (site says RECRUITING) — keep it that way until N≥3 operate. | Claiming a control with zero operators | Already row one of the campaign |
| ~~**R7**~~ | **DONE — D-046 + [`PROBES.md`](PROBES.md) + `kits/probe/`.** Nine adversarial checks, no credential held (P0 voids the run if the write door answers), unmarked lineage, root-dark verifier at F1 + currency, wall-clock revocation latency. Negative-controlled against four dishonest registrars, each required to fail the *named* check. Term is proposed, not binding — there is no entity to bind anyone to. | Asking participants whether they are compliant | **Shipped** |

---

## What this settled

AINRA is a genuine settler on the arrows that matter most. The log-binding bug that regressed in someone else's
codebase in January 2026 is structurally impossible here and guarded across four implementations. The twenty-year
soft-fail is a `MUST` in code with no flag to relax it. The format fragmentation that forced a government to write
a fifth specification was avoided by holding one. Test and production keys are separated by type, not by
convention.

The open items were mostly **governance, not engineering** — witnesses, registrar standing, disclosure deadlines,
a rollback threshold. That is the right shape for a project whose engineering is finished and whose remaining risk
is entirely in the world.

## What settling them actually cost

Four of the five closed rows took a day, which is the real argument for doing this early: the arrows are documented,
the fixes are small when nothing is deployed on top of them, and every one of them would be a migration later.
D-044 was 48 vectors across four implementations. D-045 was one file and one refusal. D-046 was a kit and four
dishonest registrars. The two documents were an afternoon each and they are worth as much as the code, because the
failures they address are conduct failures.

The pattern worth carrying forward is not any single arrow. It is that **each of these was found by asking what the
people who went first were forced to admit afterwards**, and every one of those admissions is public. Reading them
was cheaper than earning them.

One more, from this pass rather than from the record: **when you write a check, name the witness and ask whether it
could observe the failure.** The probe's own controls caught two of my checks asserting things that could not have
been false — a constant offset called a rewind, and a deleted inclusion proof in a tree with one leaf. Both would
have shipped as green. A check that has never been shown failing is decoration, and the only way to know which kind
you have is to build the dishonest version and point the check at it.

The exception is **R1**, and it is the one this audit got wrong on the first pass. The industry that invented this
problem did conclude the opposite of what our default encodes — but we inverted it deliberately, and the inversion
is sound because our revocation fails closed where theirs failed open. What is not sound is citing a five-rung
ladder while one rung is declared and unbuilt. Finding that was worth more than the recommendation I started with.
