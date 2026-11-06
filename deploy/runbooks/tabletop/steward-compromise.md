<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Tabletop: the steward's workstation is compromised

**Class:** HIGH (a suspected compromise touching what verifiers trust). **Runbook:** [`root-incident.md`](../root-incident.md).
**Players:** the incident lead (today the owner, who is also the steward), the deputy once named, the custodians once
named. Walk it on paper; every step says what the machinery does and which drill proves it.

## The scenario

Two days before a scheduled ceremony, the lead finds an unknown process on the machine that drafts directory
proposals. The proposal already circulated for epoch N+1 looks right. Nobody knows whether it was changed.

## Steps

1. **Day 0, hour 0.** The lead writes down the time; that is `opened`. Class HIGH, because the higher class applies
   when in doubt. *Decision:* stop drafting on that machine; nothing new leaves it.
2. **Hour 1.** What could the attacker have done? Draft a different proposal that is consistent in itself (accredit
   an attacker, drop an honest registrar). They cannot sign one: signing needs five custodian shares and the SLH
   root, none of which live on the steward's machine.
   Witness: `make sign-epoch-rehearsal` (four shares cannot aggregate; one root signature is refused by assemble and
   by publish).
3. **Hour 2.** Every custodian fetches the proposal from two mirrors, re-derives its digest from its own copy with
   `ainra directory check-proposal`, and refuses unless that digest equals the frozen one the custodians read aloud.
   A different proposal handed out by the steward is refused by every custodian, by name.
   Witness: `make sign-epoch-rehearsal` (the coordinator's other epoch is refused; mirrors that disagree are refused).
4. **Hour 3.** Anyone can check the published record without trusting the steward. `ainra ctl` from a signed release
   and the control page read only signed files and alarm on each way the record can lie.
   Witness: `make ctl-drill` and `make control-page-drill`.
5. **Within 72 hours.** Open the public log entry in `site/incidents.json`: class, surface ("the directory steward's
   workstation"), and what users should do (nothing: no signed epoch changed). `make incident-check` holds the date.
6. **Within 14 days.** Re-draft the proposal on a clean machine; a second party re-derives it with
   `check-proposal`; the ceremony goes ahead only if both digests match the one read aloud. If the ceremony date
   cannot hold, it moves; it is never rushed.
7. **Within 30 days.** Post-mortem in `SECURITY.md`; the steward role moves off the daily machine (PLAN-M52 threat
   table) if it had not already.

## What this tabletop shows we cannot do yet

- There is no deputy. If the lead is also the compromised party, nobody else can open the entry. The custodians'
  refusal still holds, because it does not depend on the lead.
- There are no custodians yet (D-094 item 9), so steps 2 and 3 are proven only in the TEST-ROOT rehearsal.
