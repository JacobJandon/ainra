<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M53 — The protocol, finished: emergency stops, portability, key rolls, production parts

Written 2026-11-06, after PLAN-M52 steps 9–14 were built (D-094 to D-097). The owner asked for the whole AINRA
control and "a scram" (an emergency stop), and for the protocol and technology to be carried to completion. This plan
lists every open item that an inventory of the plans, decision records, the Standard, the MTS and the code turned up
(40 items), in the order they should be built. People, accounts and hosts are named where an item waits on them.

## What "control" and "SCRAM" mean here

AINRA has no admin panel that can change the network, and it must not have one (D-034: the root gains no console and
no self-serve surface). A button that can change or stop the root is the first thing an attacker or a coercer would
go for, and it would make AINRA a company that runs the root, which the Standard forbids. Control is split three ways
(PLAN-M52): a control room that only reads, a workbench that only proposes, a ceremony that only signs.

An emergency stop therefore exists at three levels, each the fastest lever its holder may have:

| Level | Who pulls it | What it does | State |
|---|---|---|---|
| A gate or verifier | anyone running one | refuses a registrar, a lineage or a name locally, at once, for its own traffic | policy exists in the SDKs; a one-line deny entry is step 6 |
| A registrar | that registrar | revokes a passport, a lineage or its own delegate; distrusts itself from a leaf | built (self-requests, D-088) |
| The root | five custodians and the SLH holder | an emergency epoch: REVOKE-DELEGATE or DISTRUST-FROM-LEAF, published without the notice wait (R3) | built for self-requests; **adverse distrust on cryptographic proof is not** (step 1) |

What is missing is not a button. It is (1) a root-level stop against a registrar caught red-handed, which today
waits 30 days because every adverse request goes through the compliance ladder (D-096), and (2) one place where the
steward sees everything and has each emergency drafted in minutes — without holding any key.

## The steps, in order

Each step gets its own decision record when built and a WITNESS: a drill that fails when the property is removed.

### Phase A — operate it (the emergency stop and the steward's desk)

**1. Distrust on proof (the root's SCRAM).** *Built 2026-11-06 (D-098): `adverse-proof` in the workbench; a fork proof skips the ladder for DISTRUST_FROM_LEAF only, never WITHDRAW.* An adverse DISTRUST-FROM-LEAF may skip the ladder when it carries
self-verifying cryptographic evidence of misbehaviour: two checkpoints of one registrar log, both signed under keys
the directory lists for it, at one size with different roots (a fork), or a smaller size whose root is not a prefix
(a rewrite). The checker verifies the evidence itself; nothing is taken on trust. The cutoff is the smallest size at
which the fork begins. R3 already allows emergency changes that only close things to skip the wait, never the
publication. WITNESS: an honest pair of checkpoints is refused as evidence; a forged signature is refused; a real
fork is accepted with no notice, cure or grace; the same request without the proof is refused by the ladder.

**2. The steward's desk.** *Built 2026-11-06 (D-099): `kits/steward/desk.mjs`, `make desk`, `make desk-drill`.* A local page (`ainra desk`, loopback only) that reads everything the steward needs, one screen:
- `ctl` status;
- the epoch log and its witnesses;
- open requests and proposals with their ages against D-094's targets;
- the incident log and its deadlines;
- compliance ladders;
- the monthly report.

Emergency playbooks draft, in one action, the exact request and the incident entry for:
- a registrar delegate compromised;
- a registrar forking its log (step 1);
- a root share lost;
- the site defaced.

It holds no key and cannot publish. Each playbook ends in the command a custodian or registrar runs. WITNESS: every
playbook's draft passes `check-request` on a rehearsal directory, and the desk has no route that writes outside its
drafts folder.

**3. The control room shows the epoch log** *Built 2026-11-06: an "Epoch log" panel on `/control.html` recomputes the head in the browser, holds the served head to it and verifies each witness cosignature with the browser's own Ed25519 (a browser without it says so and counts none); `make control-page-drill` shows a lying head and a forged cosignature red, an honest cosignature green.* (D-097's open item): head, size, and witnesses on the head, on
`/control.html`, held to the same drill as the rest of the page.

**4. The remote emergency ceremony.** *Built 2026-11-06 (D-101): `kits/ceremony/remote.mjs` (base45 frames, QR- or USB-ready, relay untrusted) and `make remote-ceremony-drill` (five network-less custodians, a real 5-of-9 signature, timed: ~1–2 s of machine time). The human time is the next rehearsal, with the custodians.* FROST rounds carried by QR code or removable media between each custodian's
offline machine and an untrusted relay (PLAN-M52 "Emergencies"), rehearsed and timed. The emergency time target in
D-094 item 3 is then stated from the measurement. WITNESS: a timed rehearsal with five custodian processes that
never share a network.

**5. The freeze attack.** *Built 2026-11-06 (D-100), without a wire change: a gate may set `max_directory_age_s` against the directory's signed `issued_at`; off unless set, so offline gates keep working (the owner's condition).* Directories never expire, so a host that withholds a newer epoch hides an emergency stop
from passive verifiers (D-094 item 7 accepted this as a stated limit). Proposed: an optional `valid_until` that
verifiers with a policy honour, at the published quarterly cadence. This is a wire change. It needs its own record
and the owner's ruling before it is built.

**6. A local deny entry in every gate.** *Built 2026-11-06 (D-100): `deny` and the 21st frozen reason `denied_by_policy` in every implementation, held to gate vectors g31–g37.* One line of configuration refuses a registrar, a lineage or a name, with a
named reason, in all four implementations and the edge gate. This is the fastest stop that needs nobody's permission.

### Phase B — keep the Standard's promises

**7. Portability: the transfer door** *Built 2026-11-07 (D-102): `registrar_transfer.rs` and the `/transfer-*` doors; the operator signs, a five-day public window, a sixty-day lock, the history in the signed passport, distrust honoured both ways. Witnessed by `transfer_door.rs` and `transfer_http.rs`. The Standard §3 was amended 2026-11-07 to cite D-102.* (PLAN-M52 step 12; Standard 0.5(iii); MTS F6 and `POST /transfer-out|in`).
- The transfer is signed by the operator's key. An agent key alone is refused.
- A public pending-transfer record opens a contest window for the losing registrar and the operator.
- A lock follows the transfer.
- `transfer_history` records the move with log continuity, so the old log position is still checkable.
- The root never chooses the gaining registrar.

WITNESS: a transfer signed only by a stolen agent key, contested by the operator, is refused. A credential issued
after the cutoff at a distrusted registrar is refused while the transferred one verifies.

**8. Ownership transfer as a logged event.** *Built 2026-11-07 (D-103): the old operator key gives a lineage away, a five-day public window, assurance set fresh by the registrar for the new owner, the history in the signed passport, the old lineage revoked. Witnessed by `ownership_door.rs` and `a_change_of_owner_over_http`.* A genuine change of operator resets assurance and keeps the history
(Standard §1). It is separate from step 7, which moves the registrar, not the owner.

**R1. Pin the distrust cutoff to a log head** (D-104). A distrusted registrar still holds its log root and can fork its
log to place new passports below its own cutoff. The signed directory entry gains the log head at the cutoff
(`distrust_root`, beside `distrust_from_leaf`, omitted when absent so earlier directories keep their bytes). Every
verifier proves a distrusted registrar's passport against that head. Ceremony tools must require the head on a new
DISTRUST_FROM_LEAF. WITNESS: a forked-log passport below the cutoff is refused in all three implementations, and an
honest pre-cutoff one verifies.

**R2. Bind delegation party keys to the parties named** (D-104). A hop's dual signature is checked under keys the
presentation supplies, so it proves no more than the issuer's word. Each party must be bound to its own passport.
This is a presentation format change. WITNESS: a chain signed by keys that are not the named parties' is refused.

**R3. Re-key the TEST staging registrars** (D-104, the operator's decision). Their keys derive from their public ids.
Fresh keys from the OS CSPRNG, re-accredited in the TEST directory. This wipes the TEST network's state.
**Done 13 November 2026 (D-107).** The directory naming the new keys is epoch 2 and epoch 1 stays in the history;
the wall-clock registrar has its own directory; `make record-agrees` holds the published record to the registrars,
passport by passport. Not covered: the TEST root is still a fixed seed.

**9. Registrar key roll.** D-094 item 13 decided it: a two-key overlap in the entry, and a declared 2-of-3 offline
approver set, disjoint from the online keys. The approver set becomes a published object. REGISTRAR_KEY_ROLL and
key-changing ACCREDITs stop being refused. WITNESS: a roll signed by the approvers passes; one signed by a fake
approver set, or by the online key alone, is refused.

**10. Separate the log root from the delegate in the reference registrar.** Today the registrar certifies its own
delegates in-process. D-093's 92-day bound holds only when the two keys are apart.

**11. A log monitor.** It watches registrar logs for issuance a registrar did not expect, as the Standard says anyone
may. It is the tool behind the "funded competitor monitor" term.

**12. Publish what compliance and the workbench produce:** probe reports, fact notices and proposal outcomes, under
the read contract (`/net/compliance/`, `/net/proposals/`).

**13. Status-list cohort rotation** (D-028). The directory lists a registrar's current and previous status URIs, and
a dead cohort is retired. This is an additive directory change.

**14. The fee schedule object** (D-077, MTS F8). It is root-signed, and its rate may only stay flat or fall. The
check exists now; the first signed one is a genesis-day artefact.

**15. `did:ainra` resolution.** A thin resolver returns a DID document for a name and the signed passport behind it
(MTS ADR-014).

**16. Root key roll and the SLH-DSA recovery split** (PLAN-M52 step 9). This covers:
- the successor announcement, the hold-down and the revoke artefact, rehearsed;
- the 3-of-5 SLH recovery split (D-094 item 8), whose mechanism is built now and whose holders are the owner's to
  name;
- an end-of-life plan for the FROST and SLH-DSA libraries.

**17. Rulings the code waits on.** Each is a decision record:
- the delegation depth cap (D-090), with vectors in four implementations;
- the number-syntax divergence (D-054);
- a structured `principal_proof` (ADR-011);
- the delegate denial of service in currency mode (D-086).

### Phase C — production parts

**18. Hardening `registrar-box`:**
- TLS;
- an origin allow-list;
- the write token through a file and never the environment;
- the key behind an interface a hardware module can implement (the module itself waits on hardware).

**19. The production log and datastore** (ADR-005, ADR-013). Static tiles, a database for the index, and the
index-rebuild tool, replacing in-memory state with file persistence.

**20. Standby status signer per registrar** (TRADEOFFS §4), so an outage is a failover, not a wait.

**21. Verifier persistence and push.**
- The directory rollback floor persists across restarts (D-083).
- The SDKs gain an optional status fetcher and push subscriber (ADR-018, D-091).

**22. Crypto agility, the other half.** Drill the retirement of Ed25519 or ML-DSA-65, not only the addition of a
primitive (CRYPTO-AGILITY §5).

### Phase D — reach

**23. More implementations:**
- a Rust agent SDK;
- a C interface to `ainra-core` (ADR-010);
- ML-DSA in the WIMSE profile, and that profile in Python.

**24. The corpus toward the 10,000-case target** (STATUS, known limitations). This is the full cross-product, not
more of the same.

**25. The mandate lifecycle** (D-013; Standard §2): grant, attenuate, exercise, review and revoke, with ceilings.
It is large and needs a mandate object model of its own.

**26. Lanes the MTS names, none urgent:**
- the permissionless on-chain lane (L0–L1 mapping, ADR-006);
- timestamp-anchored checkpoints as a witness class;
- a cascading-filter status for more than 10^8 entries (ADR-007).

## Waiting on people, accounts or hosts (not code)

- A second static host and a second probe network: PLAN-M52 step 4, D-096.
- Outside witnesses, verifiers and custodians, and the five SLH recovery holders.
- The legal entity's country. The accreditation agreement, the competitor-monitor term and the appeal path stay
  drafts until it exists.
- Hardware for registrar key modules (step 18).

## Order

Phase A first, because it answers the question "what do we do when something goes wrong", and every later step is
safer once it is answered. Then step 7, then step 9. The rest of Phase B and C follow, each pushed with its drill.
