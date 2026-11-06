<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Tabletop: custodians do not show up

**Class:** MEDIUM when a scheduled ceremony slips; HIGH if a missing custodian's share may be lost or stolen.
**Runbook:** [`root-incident.md`](../root-incident.md). **Rules:** D-094 item 9 (a custodian who misses two
scheduled ceremonies is replaced from a standby pool of three by a share refresh).

## The scenario

A quarterly ceremony is due. Of nine custodians, five confirm, then one cancels on the day. A second custodian has now
missed two ceremonies in a row and does not answer.

## Steps

1. **Ceremony day.** Four custodians are present. Four shares cannot make a root signature, and nobody can make
   them, so no epoch is signed today. Verifiers keep the last epoch.
   Witness: test `four_of_nine_cannot_sign`, and `make sign-epoch-rehearsal` (four shares cannot aggregate).
2. **Same day.** The slip is public: the ceremony packet's date passes with no epoch, and `ainra ctl` starts its
   clock. Once the last epoch is older than the published quarterly cadence (92 days), `ctl` alarms and the control
   page says so. Nobody has to admit it.
   Witness: `make ctl-drill` (93 days alarms, 91 does not) and `make control-page-drill`.
3. **Within 7 days.** Log entry, class MEDIUM: a scheduled ceremony slipped, the epoch in force, the new date.
4. **The custodian who missed twice.** Five or more custodians run a share refresh that leaves out the missing
   custodian's share and takes in one from the standby pool. The root public key does not change, so no verifier
   notices anything; the old shares, including the missing one, stop working.
   Witness: test `share_refresh_keeps_the_root_key_and_retires_old_shares` (a refresh below five is refused).
5. **If the missing share may be stolen, not just absent.** Class HIGH. One share is below the threshold and signs
   nothing alone; the refresh in step 4 retires it. The deadlines are the HIGH ones: entry within 72 hours, refresh
   within 14 days.
6. **The rescheduled ceremony.** Five present custodians sign; the epoch is published; `ctl` stops alarming.
   Witness: `make sign-epoch-rehearsal`.

## What this tabletop shows we cannot do yet

- There are no custodians and no standby pool yet (D-094 item 9); every step above is proven only with TEST-ROOT
  rehearsal keys.
- The emergency remote protocol (D-094 item 4) has no measured target yet, so an emergency signing day cannot be
  promised from this tabletop.
