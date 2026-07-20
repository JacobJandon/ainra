<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Abort & incident playbooks

> **An aborted genesis costs a date. A fudged genesis costs the project.** When a trigger below fires, you ABORT —
> you do not improvise, retry-in-place, or "fix and continue." The Coordinator is the sole abort authority. Honesty
> even in failure: what happened is **published**, never papered over.

Each playbook: **trigger → immediate action → what gets published → how to reschedule.**

## Custodian no-show (before root assembly)
- **Trigger:** fewer than 9 confirmed custodians present, or one withdraws before the DKG completes.
- **Action:** invoke the **standby-quorum substitution** — a standby custodian takes the open seat; the substitution
  is **disclosed on camera** (who stepped out, who stepped in, why). If no standby is available → ABORT.
- **Publish:** the substitution (or the abort) in the ceremony record; the final custodian list reflects reality.
- **Reschedule:** if aborted, re-confirm 9 + standby (T−7d checklist) and pick a new date.

## Hardware failure mid-ceremony
- **Trigger:** the ceremony machine faults during DKG/assembly.
- **Action:** **ABORT** the run. Do NOT move shares to an unverified machine mid-flow. Power down; secure any media.
- **Publish:** "genesis aborted at T0+Nm, hardware fault, no root assembled." Nothing partial is trusted.
- **Reschedule:** boot the **standby ceremony machine** (verified at T−1d); restart the full sequence from step 1 on
  a new date (a genesis is atomic — no resuming a half-run).

## Transcript hash mismatch on independent recomputation (cutover)
- **Trigger:** the independent recompute (`make verify-transcript`) does NOT match the published hash.
- **Action:** **HALT the cutover immediately.** Do not boot production against an unverified directory.
- **Publish:** the **mismatch itself** — both hashes, which mirror, the transcript bytes. This is the most important
  honesty rule: a transparency root that hid a transcript discrepancy is disqualified. Never re-publish to "fix" it.
- **Reschedule:** investigate the discrepancy (a real bug or tamper); genesis does not proceed until an independently
  recomputed transcript matches on ≥2 mirrors.

## A kit assertion fires mid-sequence
- **Trigger:** any `kits/ceremony/` step exits nonzero or an assertion prints.
- **Action:** **ABORT** — the kit's expected state is the contract; a firing assertion means reality diverged.
- **Publish:** the assertion output + the step it fired at.
- **Reschedule:** diagnose (the kit is the source of truth); only an ABORT-class fix may touch the frozen ref, which
  then re-runs the full GO/NO-GO and re-tags.

## Venue / recording failure
- **Trigger:** recording drops, or the venue is compromised (someone unaccounted, network appears).
- **Action:** **ABORT.** A genesis with a gap in the recording is not a recorded genesis.
- **Publish:** "aborted — recording/venue integrity lost at T0+Nm."
- **Reschedule:** restore continuous recording + a sealed room; new date, full sequence.

## Post-cutover production incident (inside the 14-day soak)
- **Trigger:** an incident on the production deployment during the soak.
- **Aborts the soak clock (restart the 14 days):** a **root/delegate key compromise**, a **log fork** a witness
  refuses, or a **directory/checkpoint integrity failure** — anything that breaks the chain the soak measures.
- **Does NOT abort the clock (fix forward, note it):** a single-region **availability** blip (the read path is
  static/CDN and survives; the soak measures propagation, tolerant of transient outages within SLO), a registrar
  restart, a CDN edge failover. Record it against the soak report; the clock continues.
- **Publish:** every incident in the soak log; a clock-aborting one is disclosed and the 14 days restart from a clean
  checkpoint. The founding declaration reads the **actual** soak days, so a restart simply moves the declaration date.
- **Reschedule:** for a clock abort, remediate the root cause, re-establish witness cosigns on a clean checkpoint,
  restart `kits/soak/`.

---

**Define now, not during.** These are the only sanctioned responses. If a situation isn't covered here, the default
is **ABORT + publish + reschedule** — never improvise a genesis.
