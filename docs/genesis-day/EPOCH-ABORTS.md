<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Abort playbooks for epoch ceremonies

> Genesis makes the roots once (`ABORTS.md`). Every later directory epoch is a smaller ceremony: five of nine
> custodians and the SLH-DSA signer sign a proposal for epoch N+1 (PLAN-M52 R4–R7). The same rule holds: **an aborted
> epoch costs a delay; a fudged epoch costs the root.** Directories do not expire, so a missed ceremony breaks
> nothing; it only delays a change. There is never a reason to improvise.

Each playbook: **trigger → immediate action → what gets published → how to resume.** Today every one of these is
rehearsed, not lived: `make sign-epoch-rehearsal` runs the ceremony across nine custodian processes under a TEST-ROOT,
and the refusals named below are the ones it shows by name. Until production, one person holds every role
(PLAN-M52, "Who holds which role"), and this page says so.

## A custodian's own copy does not match
- **Trigger:** a custodian's digest, derived with `ainra directory sign-request` from the proposal it fetched itself
  onto its own media, differs from the frozen R4 digest, from the independent re-derivation, or from what the
  coordinator's packet says — or `ainra directory check-proposal` refuses its own copy against its own copy of epoch N.
- **Action:** that custodian **does not sign** and says why, aloud and in writing. Nobody hands it another copy to
  "try again": a value computed from media the coordinator supplied is never signed (R6). The ceremony continues
  only if five custodians each derived the frozen digest from their own copies.
- **Publish:** the refusal with its reason, the digest the custodian derived, and where it fetched from. A published
  refusal with a reason forces a new notice period before the ceremony resumes (R6).
- **Resume:** find out which copy is wrong. If the coordinator's packet differs from the mirrors, the coordinator is
  replaced for this epoch and the incident is recorded. If the mirrors differ from each other, the mirror is the
  incident. A new freeze (R4) follows any change to the proposal.

## Two mirrors serve different copies
- **Trigger:** the custodian's two fetches of the proposal (or of epoch N) are not byte-identical.
- **Action:** the custodian refuses, as above. Nobody chooses between the copies on the day.
- **Publish:** both digests and which mirror served which.
- **Resume:** re-run the independent `check-proposal` against the copy that matches the frozen digest; republish the
  frozen proposal to every mirror; start the notice period again.

## Fewer than five custodians willing or present
- **Trigger:** fewer than five custodians are present, or fewer than five are willing after refusals.
- **Action:** **stop.** Four shares cannot make a signature (the aggregation refuses), so nothing partial exists.
  Do not gather a fifth share remotely outside the air-gapped protocol of PLAN-M52 ("Emergencies").
- **Publish:** "epoch N+1 not signed: K of 5 needed"; the refusals and their reasons.
- **Resume:** re-schedule with the standby custodians (PLAN-M52 step 9 sets the rules). The proposal stays frozen
  unless a refusal changed it.

## Aggregation or assembly refuses
- **Trigger:** `dkg-participant aggregate` refuses the shares, or `ainra directory assemble` refuses
  (`assemble-both-roots`): the FROST aggregate or the SLH-DSA signature does not verify over the proposal's signing
  bytes under the pinned roots.
- **Action:** **ABORT the epoch.** Do not re-sign with a different message, and do not publish one signature
  without the other: a directory needs both.
- **Publish:** which signature failed, over which digest.
- **Resume:** fresh signing round on a new date (fresh nonces: a FROST commitment is never reused across messages).

## Publication refuses
- **Trigger:** `ainra directory publish` refuses: `publish-both-roots` (one root's signature), `publish-next-epoch`
  (not the archive's last + 1, or drafted on another epoch N), `publish-approved` (an authentic directory that is not
  the approved proposal's digest) or `publish-transcript` (a transcript that does not name it, or does not hash to
  its published SHA-256).
- **Action:** **do not publish by hand.** An authentic directory that is not the approved proposal is the
  root-compromise case of the "If AINRA is hacked" table: five custodians and the SLH secret signed something nobody
  approved.
- **Publish:** the refusal, both digests, and — for `publish-approved` — a HIGH incident within 72 hours.
- **Resume:** for a transcript or archive mistake, correct the transcript bundle and publish again (anyone may: the
  steward holds no withholding veto, R7). For an unapproved authentic directory, follow the root-compromise plan.

## Transcript hash mismatch
- **Trigger:** an outsider's recomputation (`kits/ceremony/verify-transcript.mjs`) does not match the published
  transcript SHA-256.
- **Action:** halt publication; never re-publish the transcript to "fix" the hash.
- **Publish:** both hashes and the bytes, as for genesis (`ABORTS.md`).
- **Resume:** only when an independently recomputed transcript matches on two or more mirrors.

---

**Define now, not during.** If a situation is not covered here, the default is **do not sign, publish the reason,
reschedule.** No epoch is urgent enough to sign a digest a custodian did not derive themselves.
