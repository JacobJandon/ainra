<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M52 — The control system: a control room that reads, a workbench that proposes, a ceremony that signs

First written on 3 November 2026 at the owner's request: "our own AINRA control field in the terminal or a control
panel, like ICANN has, and host AINRA somewhere". Revised the same day after a full study of how ICANN works
(`docs/ICANN-STUDY.md`) and an adversarial review of the first design. Steps 1–3 and 5–8 are built (2026-11-04); D-088 is ACCEPTED;
the owner rules.

## What ICANN's "control" is, and what ours must be

ICANN does not run a panel that hands out names. Its operational core is root zone *change management*: a change is
filed by the party it concerns, checked by machine, approved by that party's own approvers, reviewed, checked again,
and handed to a separate party that signs and publishes it. Independent operators serve the result, and anyone can
download and check it. No step is a single point of control (ICANN-STUDY §1–§2).

AINRA already has the split that matters. Registrars issue, renew and revoke, each through its own open console
(D-034). The root's one act is a new **directory epoch** — who is accredited, which delegate certificates are revoked,
where graduated distrust starts — signed by both offline roots (FROST 5-of-9 Ed25519 and SLH-DSA), never by one key
and never online. That threshold is rehearsed (`make ceremony-rehearsal-multi`) and has not yet been held for real:
today's root is a TEST-ROOT.

D-034 forbids the root a console or any self-serve surface. So the control system is three things, and none can act
alone:

1. **A control room that only reads** — `ainra ctl` in the terminal and a static page. Anyone, not only us, sees
   what the operator sees.
2. **A directory workbench that only proposes** — it drafts the next epoch and its diff, and holds no key.
3. **A ceremony that only signs** — custodians sign a proposal they fetched and checked themselves.

## The parts

| Part | Who uses it | Can | Cannot |
| --- | --- | --- | --- |
| **Public read contract** | everyone | serve bytes: the directory, roots, registry, each registrar's export and status, checkpoints, `/witness-feed`; new: every epoch ever signed, proposals, ceremony packets, compliance notices, incidents, monthly reports | make anything true — every trust-bearing file is signed or hash-pinned and checked by the reader |
| **`ainra ctl`** (from the signed release) | operator, custodians, registrars, witnesses, strangers, cron, CI | verify everything root-dark and offline; remember what it last saw; exit non-zero on any alarm | sign, publish, write to any registrar; send telemetry |
| **`/control.html`** | anyone with a browser | the same view through the WASM verifier | anything `ctl` cannot; it is a convenience, and `ctl` is the authority |
| **Directory workbench** | the directory steward (today the owner), and anyone re-checking | check requests, batch them into an unsigned epoch N+1 with a diff and citations, emit the exact bytes to sign and their SHA-256 | sign; change the frozen schema |
| **Ceremony kit** | 9 custodians (5 needed), the SLH signer, a coordinator who never touches a share, witnesses | sign a proposal each custodian fetched and checked on their own media | sign a digest a custodian did not derive themselves |
| **Registrars** | their operators and customers | issue, renew, revoke; file requests about their own entry | touch another registrar's entry |
| **Witnesses** | independent operators | cosign registrar checkpoints, and (if adopted) the epoch log; refuse replays (D-087) | be counted when the project runs them |
| **Compliance monitor** | an independent party, not the root (see below) | probe and soak on an unannounced schedule; publish every report and fact notice; file adverse requests | sign or publish an epoch; score anyone |
| **Mirrors and the online verifier** | at least two outside parties; callers of `services/verify` | serve bytes readers byte-verify; return decision records that embed their inputs (D-079) | add authority |

**Why the compliance monitor is not the root.** A mystery-shopper probe that buys from registrars on retail terms
makes the root a paying customer (P3), and an unmarked identity needs either a real person's data (P4) or false
business details. So probes run either from an independent monitor (Standard §3 already requires registrars to fund
one watching a competitor) or under an accreditation term that registrars accept probe identities at L0/L1 with no
charge and no business verification. The owner chooses.

## How a directory change flows

**R0 — Filing.** Anyone may file a change request as a public file. Every request gets a public state and a time
limit. The request types are ACCREDIT, WITHDRAW, DISTRUST-FROM-LEAF, REVOKE-DELEGATE, REGISTRAR-KEY-ROLL and
ROOT-KEY-ROLL.
- A change that **closes** something about the filer's own entry (revoke its own delegate, distrust itself from a
  leaf) may be signed by the registrar's current online keys.
- A change that **moves trust** (new keys, a new endpoint or status URI) must be signed by an offline M-of-N approver
  set the registrar declared earlier, disjoint from its online keys — the analogue of a registry lock. A thief who
  owns the registrar's host must not be able to roll its keys and lock the operator out (the DNSpionage path). It must
  also carry proof of possession of every new key, and it goes to the registrar's previously declared out-of-band
  contact with a contest window before freeze. The directory entry has no field for approvers today
  (`deny_unknown_fields`), so this needs a new published object or a schema change, through an ADR and a D-0xx, not
  the routine track.
- **Adverse** requests (DISTRUST-FROM-LEAF and WITHDRAW against someone else) must cite the notice chain, the expired
  cure window, and a reproduction from at least two vantage points on different networks.
- ACCREDIT for a **new** registrar must also carry the Standard §3 prerequisites: the signed identical agreement, an
  independence attestation, a funded competitor monitor, an audit date. Until a legal entity exists, real third
  parties are accredited only under TEST-ROOT.
- ROOT-KEY-ROLL runs on its own track (step 9).

**R1 — Pre-review.** The workbench checks shape and citations.

**R2 — Automated checks**, published as `docs/ACCREDITATION-CHECKS.md` and generated from the code that runs them:
endpoints reachable, keys equal what `/accreditation` serves, `/witness-feed` serves a consistency proof,
`status_uri` verifies, the probe reports COMPLIANT. A failure goes back with its reason; appeal means reproducing the
check from the published inputs.

**R3 — Notice period.** The proposal and its diff are public for a fixed period. Emergency changes that only close
things skip the wait, not the publication.

**R4 — Freeze.** The proposal for epoch N+1 is frozen and its digest published. At least one party other than the
steward runs `check-proposal` and publishes a matching digest. Any custodian may put a request that passed R2 on the
agenda, so the steward cannot sit on it.

**R5 — Re-check.** R2 runs again just before the ceremony.

**R6 — Ceremony.** The packet is published at least 14 days ahead. Each custodian fetches the frozen proposal
themselves from two or more mirrors onto their own write-once media, compares its digest with the R4 digest and the
independent attestation, and reads their own value aloud before signing — never a value computed from media the
coordinator supplied. Five FROST shares are aggregated, the SLH signature is added, and the transcript and its hash
are written for witnesses to recompute. Any custodian may refuse and publish a reason; signing stops only if fewer
than five are willing. A published refusal with a reason forces a new notice period before the ceremony resumes.

**R7 — Publish.** `ainra directory publish` checks both signatures, the approved digest and a transcript that names
it, and pushes to at least two hosts and the mirrors. Any custodian or third party may publish the same signed epoch
from the transcript bundle, so the steward holds no withholding veto. These checks are hygiene inside a tool; the
enforcement that counts is in what readers run (`ctl` alarms on an authentic epoch with no proposal and transcript,
and on an approved proposal left unpublished).

**R8 — Record.** `epochs.json` gains the entry, the proposal gets its outcome, and the monthly report counts how long
each stage took and lists every request past its time limit with the steward's reason.

**Emergencies.** Epochs have no expiry, so a missed ceremony breaks nothing; it only delays a change. The fastest
lever that closes things today is the registrar's own status and revocation, not a root epoch. For root emergencies,
remote FROST rounds keep the air gap: commitments and signature shares travel by QR code or removable media between
each custodian's offline machine and an untrusted relay, and no share-bearing machine ever touches a network (the
COVID-era ceremony 41 is the precedent). The emergency time target is stated honestly once it can be measured.

## Who holds which role

| Role | Before production (TEST-ROOT era) | At production |
| --- | --- | --- |
| Directory steward (drafts and checks) | the owner | one person, no key |
| Policy author (decisions, amendments) | the owner | a body separate from the steward |
| Release-key holder | the owner | not the steward, not a custodian |
| Custodians (5-of-9 FROST) | rehearsal only | independent of the steward and of every registrar (Article S2) |
| SLH-DSA signer | rehearsal only | not the steward |
| Compliance monitor | none yet | independent of the root |
| Reference registrar operator | the owner (labelled affiliated) | never the subject or filer of an adverse request it handles |

Until production, one person holds every role, and this table says so. No person holds two roles at production.

## If AINRA is hacked

| What is compromised | What the attacker gets | What still works | Defence |
| --- | --- | --- | --- |
| The site or static host | defacement; a forged directory, roots file or older epoch; a `/control.html` that shows green; changed contact addresses; phishing | every verifier with pinned roots refuses a directory without both signatures; holders with a floor refuse older epochs (D-083); mirrors byte-verify; `ctl` from the signed release alarms; registrars, logs and witnesses untouched | root fingerprints on at least three independent channels; two or more hosts plus outside mirrors; hardware-key MFA; a 72-hour incident entry. A replaced page can show anything — SRI and on-page fingerprints protect only against swapped data files, not a replaced page; the defence there is `ctl` or a human comparing fingerprints out of band |
| The host or a mirror **withholding** newer epochs (the freeze attack) | hides an emergency REVOKE-DELEGATE or DISTRUST-FROM-LEAF indefinitely, because epochs never expire | anyone who fetches from another mirror | `ctl` alarms when the directory's `issued_at` is older than the published cadence, and cross-checks `epochs.json` across mirrors and witnesses. Closing it for passive verifiers needs an expiry (normative, and needs regular signing) or a timestamp role (an online key, refused by D-034) — the owner's trade, recorded in a D-0xx |
| The code-host account or commit rights | pushed code or docs; edited anchors or project keys; changed CI | the offline release key (D-042); outside rebuilds; check-freeze and amendment-check; published epochs | hardware MFA, branch protection, signed commits, a second reviewer once one exists; any change to anchors reviewed as a change to the roots |
| **The release key** | a `ctl`, SDK or WASM verifier that pins different roots — every user of the release follows it | anyone pinning roots from another channel; outside rebuilds | changing embedded roots is a ROOT-KEY-ROLL, never an operational release; `ctl` prints the fingerprints it pins for comparison against three channels; a release that touches anchors counts only after an outside reproducible rebuild |
| The steward's workstation | a malicious proposal (accredit an attacker, drop or distrust an honest registrar) | nothing changes without five shares and SLH; custodians fetch and check the proposal themselves; the proposal is public before the ceremony; key changes need the registrar's offline approvers and contest window | independent `check-proposal`; comment window; digest read aloud; proof of possession; a compliance chronology for any adverse change |
| 1–4 FROST shares | nothing usable (four shares are refused) | everything | a HIGH report within 72 hours; share refresh if the library supports it, else a planned root roll; standby custodians |
| 5+ custodians colluding, plus the SLH secret | any epoch, including different epochs shown to different audiences | every epoch is public and diffable; the equivocation alarm and (if adopted) the witnessed epoch log expose a fork; floors stop rollback; registrar logs keep history | custodian diversity, transparent ceremonies, the epoch log, the lost-or-compromised-root plan |
| The SLH-DSA secret alone | nothing — a directory needs both signatures | everything | a recovery split, a HIGH report, a planned SLH roll |
| Loss (not theft) of SLH or 5+ shares | nothing; no new epoch can be signed | every existing epoch; registrars keep issuing and revoking | the recovery split, standby custodians, a yearly proof-of-possession inventory, the succession drill |
| A registrar's delegate key only | fresh heads, checkpoints and delta countersignatures for up to 92 days | other registrars; the witness quorum | an emergency REVOKE-DELEGATE epoch (D-019), then a new delegate |
| A registrar's daemon (delegate key **and** log root) | unlimited new delegate certificates — revoking one at a time does not end it | other registrars; the logs are witnessed and public | DISTRUST-FROM-LEAF at the suspect-since leaf plus a key roll through the offline approvers; an accreditation check that recommends keeping the log root offline with delegates renewed by a separate signer |
| A registrar's issuer key and log | passports minted under that registrar, which still have to be logged | other registrars; earlier credentials; probes and witnesses see anomalies | disclosure in 72 hours, DISTRUST-FROM-LEAF, holders port, then WITHDRAW |
| A registrar's write token or console | issue and revoke through it | every issuance is logged and public | rotate the token, audit, revoke, disclose |
| A witness key | one cosignature of the k needed | the k-of-N quorum (D-021) and every other witness's memory (D-087) | distinct keys and networks; project keys never counted |
| The hosted verifier | wrong verdicts for callers who trust it blindly | decision records embed their inputs and re-check offline (D-079) | a pinned build hash; callers re-verify; revoke its key |
| The probe runners | fabricated failure reports to frame a registrar | an adverse epoch needs two vantage points on different networks, a cure window and custodian review; appeal by reproduction | vantage points under different control, published inputs |
| Ceremony equipment or venue | possibly the shares on a breached machine | any network contact outside the remote protocol voids the ceremony; witnesses recompute | a published OS image hash, sealed hardware, write-once media, ABORT rather than improvise |
| Mailbox or social accounts | false "new root" announcements; phishing of custodians | roots change only through signed artifacts and ceremonies | a published rule that a root is never announced by message; phishing-resistant authentication |
| The owner's laptop | TEST-ROOT material and drafts | no trust migrates from TEST-ROOT (D-032) | release key and steward role off the daily machine; hardware MFA; disclose |

## The steps

Each step names a WITNESS: a check that must turn red on the defect it was written for.

**1. Keep every epoch.** *Built 2026-11-04: `ainra directory digest` and `ainra directory archive` (refuses an unsigned directory, an epoch not newer than the last, and a second directory at an archived epoch); `make site-net` archives each published directory into `site/net/epochs/`, and the staging epoch is backfilled.* Publish `/net/epochs/<N>.json` for every epoch and an `epochs.json` index (N, the digest of
the signing bytes, proposal id, ceremony id). Add `ainra directory diff <N> <M>`. Backfill the staging epochs, labelled
TEST-ROOT. WITNESS: an index that skips an epoch, lists a digest that does not match the bytes, or is out of order
makes `ctl` exit non-zero; removing the digest comparison turns the drill red.

**2. `ainra ctl status | diff | watch`, with memory.** *Built 2026-11-04 in the signed release's CLI; `make ctl-drill` raises each alarm below by name from contracts built out of the signed epoch vectors, and shows that deleting the memory makes the rollback alarm disappear. Witness cosignatures and fresh-head signatures are not yet checked here (the published copy carries neither in checkable form); the rest is. 2026-11-06: the published quarterly cadence (D-094 items 3 and 7) is the default staleness bound in `ctl` (pinned in the release, `--max-age` overrides) and in `/control.html` (a fixed `?now=` clock is shown as such; a non-production copy, held still on purpose, gets a labelled warning there while `ctl` still alarms); WITNESS in both drills — 93 days after an epoch is red, 91 is not.* The directory against the pinned roots, the epoch chain, each
registrar's log head, status sequence, fresh-head age and `/witness-feed`; cosignatures from distinct witness keys per
checkpoint; byte agreement across mirrors; the genesis board; soak p95. It keeps `~/.ainra-ctl/seen.json`, prints the
root fingerprints it pins, and alarms on: a shorter log, a lower status sequence, an older directory, **two
authentic directories at the same epoch with different digests** (equivocation — D-083 accepts epoch ≥ floor, so this
is a new refusal with its own D-0xx and a vector in `vectors/v1-directory-epoch`), a directory `issued_at` older than
the cadence (freeze), an authentic epoch with no proposal or transcript, an approved proposal left unpublished, a
witness cosigning two roots at one size, mirrors disagreeing, and a fresh head older than F1. No telemetry. WITNESS:
`make ctl-drill` raises each alarm; deleting the memory file makes the log-shrink alarm disappear, proving the memory
is load-bearing.

**3. The control-room page.** *Built 2026-11-04 (`site/control.html`, not yet linked from the menu or exported); `make control-page-drill` loads it in a real browser against planted copies of the record.* `/control.html` reads the public contract in the visitor's browser with the WASM
verifier, shows the pinned fingerprints, keeps only a last-seen memory, and shows a TEST-ROOT banner while it reads
staging. WITNESS (headless): a flipped directory byte, a swapped roots file, an older epoch and a shrunken log each
render red. The claim is limited to swapped data under an honest page.

**4. Host the network (the owner decides where).** The read contract on at least two hosts; at least one wall-clock
TEST-ROOT reference registrar with `/witness-feed` and its demo door, labelled affiliated and reviewed for sunset;
`services/verify`; `ctl` runners in at least three regions; outside mirrors and witnesses invited. The deployment
exists as code (`deploy/compose.*.yml`, `deploy/runbooks/`, systemd units). Nothing is provisioned on anyone's
account by us. WITNESS: `make claims-live` turns red on each planted divergence — a wrong directory epoch, a missing
`/witness-feed`, a mismatched manifest — and a stranger's witness key polling the public feed is counted by the
board while a project key is not. Distinctness is checked as different keys and different networks; whether two keys
belong to one person cannot be checked, and the board says so.

**5. Change requests and published accreditation checks.** *Built 2026-11-04 (D-088 accepted the same day): the v1 request format and `ainra directory request | check-request` in the adapter's one decode path (`crates/ainra-adapter/src/workbench.rs`); a registrar signs its own requests with its own keys; every refusal names its check, and `docs/ACCREDITATION-CHECKS.md` is `check-request --list-checks`, held to the code by `make accreditation-checks`. A change that moves trust is refused outright, because the declared offline approver set (ADR + D-0xx) is not built; so is REGISTRAR-KEY-ROLL and ROOT-KEY-ROLL. Keys are compared with a copy of `/accreditation` the caller supplies (`--accreditation`); the live R2 checks are listed as not built. An adverse filer is not authenticated (item 14).* The request schema and authorisation rules of R0, the
declared offline approver set (ADR + D-0xx), `ainra directory check-request`, and `docs/ACCREDITATION-CHECKS.md`
generated from it. WITNESS: each is refused with a named reason — a new key without proof of possession; keys that
differ from the live `/accreditation`; a key change signed only by online keys; an adverse request with no
compliance record or from one vantage point; an ACCREDIT without the §3 prerequisites; REGISTRAR-KEY-ROLL while its
model is undecided.

**6. The workbench.** *Built 2026-11-04: `ainra directory propose | check-proposal | sign-request`, each refusal by name in the adapter tests and on a draft epoch in `make sign-epoch-rehearsal`. A cutoff lifted or moved later is refused until the owner rules (item 12). Not built: appending outcomes to `/net/proposals/` (publish keeps each epoch's proposal beside it), and the drill with a fake approver set, which waits for the approver set itself.* `propose` batches requests into an unsigned epoch N+1 with a diff and citations;
`check-proposal` re-derives the diff and digest from the proposal and epoch N alone; `sign-request` emits the signing
bytes and their SHA-256; outcomes are appended to `/net/proposals/`. WITNESS: refused — a skipped epoch, an entry
dropped without a WITHDRAW, a field outside the frozen schema, a cutoff lifted or moved later (pending the owner's
ruling), a diff that does not match. A separate drill plants a **self-consistent** malicious proposal (an attacker's
ACCREDIT with valid proof of possession, a key change from a fake approver set); `check-proposal` alone passes it, so
it must be caught by approver authentication against epoch N and the missing contest-window acknowledgement.

**7. `sign-epoch`: sign an existing proposal.** *Built 2026-11-04 as a rehearsal: `slh-root` (TEST-ROOT SLH-DSA signer, 0600 key file), `ainra directory assemble`, and `make sign-epoch-rehearsal`, in which each signing custodian fetches the proposal from two mirrors, re-derives it and signs only its own digest; a transcript and its SHA-256; `docs/genesis-day/EPOCH-ABORTS.md`. Not built: the ceremony packet template, the annotated script and exception formats, and the air-gapped remote protocol.* FROST commit, sign and aggregate over the sign-request digest, plus an
offline SLH signer; the ceremony packet template (script 14 days ahead, OS image hash, quorum, seats); annotated
script and exception formats; a transcript per epoch; the air-gapped remote protocol; `docs/genesis-day/ABORTS.md`
extended to epoch ceremonies. `accredit.rs`'s fresh DKG on every run is limited to TEST-ROOT. Recordings stay with
the people who made them and the root publishes only their hashes; witness confirmations are key-signed statements,
not names (P4). WITNESS: the coordinator supplies a different, internally consistent proposal and the custodian's own
fetched digest does not match, so the custodian refuses; four shares are refused; a directory with one root's
signature is refused at publish; one changed byte fails `verify-transcript.mjs`.

**8. Publish and mirrors.** *Built 2026-11-04: `ainra directory publish` (no network) archives the epoch with its proposal and transcript and writes `directory.json`; each refusal below is shown in `make sign-epoch-rehearsal`, then `ainra ctl status` reads the two-epoch history with no alarm and `ainra ctl diff 1 2` shows the change. Not built: pushing to hosts and mirrors, and the `ctl` alarm on an epoch that reached mirrors without going through publish.* `ainra directory publish` as in R7, publishing from the transcript bundle open to anyone.
WITNESS: refused — one root's signature, an older epoch, an authentic N+1 that is not the approved digest, an
authentic N+1 that no transcript names — and `ctl` alarms on the same epoch reaching mirrors without going through
publish.

**9. Root custody and the root-key roll.** *Answered 2026-11-06, one question of it: the FROST library (frost-ed25519 3.0.0) refreshes shares and keeps the group key, by a DKG among the custodians who take part. Built: `ThresholdRoot::refresh` (`crates/ainra-ceremony/src/frost.rs`). WITNESS `share_refresh_keeps_the_root_key_and_retires_old_shares`: after a refresh the root key is unchanged and every share differs; five refreshed shares sign and plain Ed25519 accepts it; four cannot; old and new shares never combine; a custodian left out of the refresh is removed and its old share no longer counts; a refresh below the threshold is refused. So a suspected share compromise, or a custodian leaving, is answered by a refresh, not a root roll. The rest of this step waits on items 8–9 and 13.* A recovery split for the SLH root held by a group separate from the FROST
signers; a yearly proof-of-possession inventory; whether the FROST library supports share refresh that keeps the
group key (drill it, or document a root roll as the remedy); custodian eligibility, terms and absence rules. The
ROOT-KEY-ROLL track: a successor announcement signed by both current roots with a published hold-down, a REVOKE
artifact for the old roots, the rollback criterion stated in advance in `ROLLBACK.md`, a fixed maximum overlap,
readiness measured only by signed acknowledgements, and an end-of-life plan for the FROST and SLH-DSA libraries and
the share formats (ICANN lost a year when a hardware vendor left the business). WITNESS: recovery one part below the
threshold fails and at the threshold reproduces the same public key; a holder missing from the inventory is listed as
unproven, never present; a successor signed by one root is refused.

**10. A witnessed epoch log (optional; owner decision plus a D-0xx).** Each leaf is the digest of a dual-signed
directory, appended to an RFC 6962 log (origin `ainra-directory`) and cosigned by witnesses under the D-087 memory
rules. WITNESS: two different epoch-N digests shown to one witness are refused and `ctl` alarms; a leaf whose
directory does not verify under both roots is refused.

**11. Compliance: scheduled probes, notices, the ladder.** Probes and soaks on an unannounced schedule from at least
two vantage points on different networks, every report published, the probe subject published as a salted
commitment (SHA-256 of salt‖name, salt revealed when the identity retires) so a registrar cannot find the probe in its
own log. `kits/probe/notice.mjs` writes fact notices and tracks the ladder: notice 1 (starts the cure window), notice
2, a public breach record, DISTRUST-FROM-LEAF (D-044), a grace window for holders to move, WITHDRAW. An abrupt
registrar loss gets no grace: after the freshness window its credentials fail closed. WITNESS: a deliberately
degraded registrar is caught within one cycle; a failure from one vantage point produces no notice; a distrust request
before the cure window ends is refused; the published report cannot be matched to a lineage in the registrar's log.

**12. Holder-driven portability.** A transfer door at the reference registrar: the proof comes from the operator's
key (Standard 0.5: names belong to the operator relationship), a public pending-transfer record gives the losing
registrar and the operator a contest window, and a lock follows the transfer. The root lists only accredited
registrars, in sorted order, and never chooses a gaining one. WITNESS: a transfer signed only by a stolen agent key,
contested by the operator, is refused; a credential issued after the cutoff at a distrusted registrar is refused
while the transferred credential verifies.

**13. The operator loop.** *Built 2026-11-06 in part: `tools/monthly-report.mjs` writes `reports/monthly/<YYYY-MM>.md` from the published record — each figure names its file, field and hash; `make monthly-report-check` re-derives it byte for byte and drills that a hand-typed figure and a missing source are refused and that an old report labels itself stale (D-058); `make site-net` regenerates it. Open requests are listed with their dates, and nothing is called overdue until the owner sets the target (item 3). Not built: the incident runbook's named role and deputy (item 16), the public incident log, the tabletop drills.* `tools/monthly-report.mjs` builds every figure from artifacts and lists overdue requests;
`deploy/runbooks/root-incident.md` with HIGH / MEDIUM / LOW classes, deadlines, a named role and deputy, and the rule
that no one overrides a witness refusal; a public incident log; tabletop drills for steward compromise and a custodian
no-show. WITNESS: a figure that does not come from an artifact is refused; the staleness drill (D-058) labels a stale
report.

**14. Close the drift the review found.** Done: `docs/genesis-day/RUNBOOK.md` said `make genesis-status` reads 11/11
while the board has 12 rows; it now says 12/12, and `tools/status-consistency.mjs` reads the total from the board.
Open: Standard §4 says online delegates are "quarterly-certified by the root" and §3 speaks of "supervised transfer",
but in the code delegates chain to each registrar's own log root and the root never chooses a gaining registrar.
Done: D-093 accepted 2026-11-06 and applied — both sentences now say what the code does.

## Order

Steps 1–3 (read-only) come first and need no ruling. Step 4 waits for the owner's hosting choice. Steps 5–8 follow
D-088 being accepted. Steps 9–13 follow the decisions below. Step 14's second half can go at any time.

## Left to the owner

*Answered 2026-11-06 by D-094 (accepted with D-077). Still open: the facts it names — the second host, the SLH recovery holders, the custodians, the incident deputy, the jurisdiction.*

1. D-088: accepted or rejected, with the reason.
2. Hosting: the provider or providers, regions and public names; whether `/control.html` ships before the network is
   hosted, reading the labelled staging copy.
3. Cadence and targets: scheduled ceremonies, the longest time from request to publication, the emergency target,
   how far ahead the packet is published.
4. Whether ceremonies may use the air-gapped remote protocol routinely, or only in emergencies.
5. Whether to adopt the witnessed epoch log.
6. Whether pre-signed contingency epochs exist at all (recommended: no, or only to revoke a delegate under a public
   incident record).
7. Closing the freeze attack: accept it as a stated limit, or give directories an expiry and sign on a schedule.
8. SLH-DSA custody: the recovery threshold, who holds the parts, and whether they are a different group.
9. Custodian rules: independence, terms, absence, the backup pool, and whether names are published or only key,
   jurisdiction and institution type.
10. The compliance monitor: an independent party, or a no-charge L0/L1 probe term in the accreditation agreement.
11. Compliance numbers: the cure window, notice spacing, the grace window, the vantage points needed.
12. Whether a distrust cutoff can ever be lifted or moved later.
13. The registrar key-roll model (a two-key overlap in the entry, which is normative, or a renewal cutover) and the
    declared offline approver set.
14. Who may file adverse requests, and the interim appeal path and deadline before any panel exists.
15. D-077 fees, with the rule that non-payment never affects a verification verdict.
16. The named incident role and deputy, the numbers in `ROLLBACK.md`, and the rule that a root is never announced by
    message.
17. Which roles the owner personally keeps before the institution exists, and the jurisdiction of the legal entity,
    on which every proposed term depends.

## Done means

`ainra ctl status` green against the hosted network from a stranger's machine; the control-room page live; one
directory change taken through request → check → proposal → ceremony sign (rehearsal) → publish, with every
negative control in steps 1–8 shown red; the "if hacked" table above re-read against what was built.
