<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Runbook: root incidents

PLAN-M52 step 13, with the answers D-094 item 16 accepted. [`incident.md`](incident.md) covers a single registrar's
service; this file covers anything that touches what verifiers trust: the root, a registrar's keys, the signed
public record, a witness, or a published verifier that gives a wrong answer. Every incident gets an entry in the
public log, [`site/incidents.json`](../../site/incidents.json), and `make incident-check` holds the log to the
deadlines below.

## Roles

| Role | Who | Notes |
|---|---|---|
| Incident lead | the owner | Decides the class, opens the log entry, owns every deadline below. |
| Deputy | **not named yet** | Taken over by the deputy when the lead cannot be reached for 24 hours during a HIGH. Until a deputy is named, no one can act in the lead's place. Verifiers still fail closed, and nothing in this runbook assumes otherwise. |

A deputy is named in this table, and in nothing else, so the role can be checked. Naming one changes this file
and nothing in the wire format or the corpus.

## Classes and deadlines

The clock starts when the lead first learns of the incident. That is the `opened` date in the log.

| Class | What it is | Public log entry | Fix or mitigation published | Post-mortem |
|---|---|---|---|---|
| **HIGH** | A **published** verifier or gate accepts something it should refuse. A root, delegate or registrar key is compromised or suspected. A forged or replaced signed file is accepted anywhere. A witness reports a fork. | within **3 days** (72 hours) | within **14 days** | within **30 days** |
| **MEDIUM** | A wrong verdict on main that is in no release. A secret-side leak (for example a timing leak while signing) where no production key exists. The read contract is unavailable for more than 24 hours. | within **7 days** | within **30 days** | within **30 days** |
| **LOW** | A defect a gate caught before any release, or a process failure that put nothing wrong in front of a verifier. | within **14 days** | within **30 days** | an entry in `SECURITY-ADVISORIES.md` or `SECURITY.md` is enough |

When the lead is unsure between two classes, the higher one applies. A class may be lowered only by a log entry
that says why.

**A HIGH entry within 72 hours does not arm an attacker.** It states the class, the affected surface and what users
should do now. Exploit detail waits for the fix, as `SECURITY.md` promises. A reporter's coordinated window can delay
that detail. It never delays the entry itself.

## Rules that do not bend

1. **No one overrides a witness refusal.** A refusal means a fork, a writer bug or a compromise. Publishing stops
   until the cause is found and logged. There is no flag, key or person that clears it.
2. **A root is never announced by message.** No email, chat, social post or web page introduces, replaces or
   revokes a root. A root change arrives only as a signed directory epoch that verifies against the roots a
   verifier already pins, shipped in a signed release. Any message saying "the root has changed" is treated as
   phishing, whoever appears to send it.
3. **A TEST-ROOT incident is labelled as one.** No trust moves from TEST-ROOT (D-032), so its incidents are logged
   with `"surface": "TEST-ROOT"` and never mixed with production ones.
4. **Nothing is fixed quietly.** Every HIGH and MEDIUM gets a pinning vector or test and a post-mortem in
   `SECURITY.md`, as that file promises. The log entry links to it.

## First hour (HIGH)

1. Write down when you learned of it. That is the `opened` date.
2. Contain it.
   - **Key suspected:** take the key offline and rotate it ([`key-rotation.md`](key-rotation.md)).
   - **Registrar key:** distrust from a log position onward (D-044). The position can only ever move earlier
     (D-094 item 12).
   - **Witness fork:** stop publishing.
   - **Published verifier wrong:** say which versions are affected and what to upgrade to or avoid.
3. Check what the network says on its own: `ainra ctl` from a signed release, and the control page. Both read
   only the published record. If they disagree with what you believe, they win until you know why.
4. Open the log entry. Add a HIGH line to the next monthly report (`make monthly-report` reads the log).

## The log

[`site/incidents.json`](../../site/incidents.json) is served at `/incidents.json`. Each entry records:

- its class and surface;
- the dates it was `opened`, first `disclosed` in public, `fixed` on main, and `released` (or `never in a
  release`);
- the heading of its post-mortem.

`make incident-check` checks four things:

- the dates are in order;
- every advisory and post-mortem in `SECURITY.md` and `SECURITY-ADVISORIES.md` is either logged or listed as not
  an incident, with a reason;
- every release named exists in `CHANGELOG.md`;
- every entry opened on or after this runbook's date met its class's deadlines. A late entry fails unless it
  says why it was late, and that reason is published with it.

Entries opened before this runbook existed are measured and printed, never judged. They had no deadline then, and
we do not invent one after the fact.

## Tabletops

The scenarios in [`tabletop/`](tabletop/) are walked through on paper by the lead (and, once named, the deputy and
the custodians). Each step names the drill or test that proves what the machinery does at that point.
`make incident-check` refuses a tabletop step that names a `make` target or test that does not exist.
