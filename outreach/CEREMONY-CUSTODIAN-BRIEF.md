<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Be a genesis-ceremony custodian

**The ask:** hold one of nine shares of AINRA's root key, generated on an air-gapped machine during a recorded
ceremony, so that the root that anchors AI-agent identity for decades is controlled by **no single person and no single
institution**.

## What you'd commit to
- **One share of a 5-of-9 root.** The root is a FROST threshold key: any 5 of the 9 custodians can act together; no
  one can act alone; 4 compromised shares are useless. A verifier can't even tell the root is thresholded.
- **A recorded, in-person ceremony** (one session). On camera you show sealed hardware, boot an air-gapped ephemeral
  OS, generate your share (it **never leaves that machine**), publish a commitment, cross-read everyone else's on
  camera, and reveal. The full choreography is in `kits/ceremony/RUNBOOK.md`; you'll rehearse it with
  `make ceremony-dry-run` (which touches nothing real) until it's routine.
- **Custody afterward.** Keep your share per the sealing policy; be reachable if a signing round is ever needed.

## Why the roster is chosen for diversity
Nine seats across **≥5 jurisdictions** and different kinds of institutions — so that no government, company, or single
legal regime can compel a quorum. That diversity *is* the security property; it's why we care who holds a seat, not
just that seats are filled. A **standby quorum** exists so the root survives custodians becoming unreachable.

## What makes it trustworthy (and checkable by outsiders)
Everything but your secret share is public: the ceremony is recorded, the transcript is published, and anyone can
recompute its hash from the published bytes (`make verify-transcript`) and confirm it matches the recording. You are
trusting the *process*, not us — and so is everyone else.

## Cost to you
One recorded session + rehearsals, fresh hardware we help arrange, and being reachable long-term. In return you are one
of nine people the entire agent-identity ecosystem relies on to keep the root neutral. The recorded ceremony is a
remaining DoD item (`GENESIS-CHECKLIST.md` §2). If you'd consider a seat, reply and we'll share the roster plan and
hardware checklist.
