<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# AINRA Genesis Ceremony — Operator Runbook

This is the runbook for the **real, recorded** AINRA genesis ceremony: minting the dual root — a **FROST 5-of-9
threshold Ed25519** group key (ADR-001) plus an **SLH-DSA-SHA2-128s** ceremony root — that anchors everything for
decades. It is designed so **no single person, and no single machine, ever holds the whole secret**, and so that an
outsider watching the recording + holding the public artifacts can confirm the ceremony was honest.

> **Rehearse first.** `make ceremony-dry-run` walks N custodians through the *choreography* (commit → cross-read →
> reveal), runs the real dual-root ceremony with **TEST-ROOT** material, and has an independent witness recompute the
> transcript hash. Run it until every custodian is fluent. **The dry-run touches nothing real.**

---

## ⚠️ The one irreversible, real-secret step
There is exactly **one** step below that generates and uses **real** key material (§ 5, "Generate shares"). It runs
**only** on air-gapped, ephemeral-OS machines that are physically destroyed/wiped afterward. Everything else —
including the entire dry-run — uses clearly-labeled TEST-ROOT material. **If a machine that generated a real share
has ever touched a network, the ceremony is void; start over with fresh hardware.**

---

## 1. Roster & quorum
- **9 custodians**, geographically and organizationally separated; **5-of-9** threshold (FROST RFC 9591). No custodian
  can sign alone; any 5 can. A verifier cannot tell the root is thresholded — FROST emits standard RFC 8032 signatures.
- **≥1 independent witness** (not a custodian) who only observes + recomputes hashes.
- A **coordinator/scribe** who assembles public artifacts and publishes the transcript. The coordinator never touches
  a share.

## 2. Hardware checklist (per custodian)
- A **fresh, sealed** laptop or single-board machine, purchased/handled to a documented chain of custody.
- Boots a **read-only, ephemeral OS** from external media (e.g. a live image); no persistent disk mounted.
- **Air-gapped**: Wi-Fi/Bluetooth/cellular physically removed or disabled in firmware; RJ45 unplugged. Verify with a
  radio survey on camera.
- A **hardware RNG** or well-seeded entropy source; a QR/camera or one-time write-only medium (write-once optical, or
  a fresh USB used once then destroyed) for moving **public** commitments only — never a share.
- A recording setup with a synchronized clock in frame.

## 3. On-camera opening
- Each custodian, on camera, states their identity, shows the sealed hardware, and boots the ephemeral OS.
- The coordinator reads the **software provenance**: the exact `ainra-ceremony` commit hash (from this repo, itself
  reproducible — `make repro`) and the pinned toolchain (`rust-toolchain.toml`). Custodians confirm they run the same.

## 4. Commit (choreography — the dry-run rehearses this exactly)
- Each custodian generates a per-ceremony contribution and publishes a **commitment** `commit = SHA-256(contribution)`
  and their signing public key, signed by their key. (`kits/ceremony/operator.mjs` is the dry-run stand-in.)
- **On-camera cross-read:** every custodian reads every other custodian's commitment aloud and confirms it matches
  what the coordinator recorded. This binds the reveal order and prevents last-mover bias.

## 5. Generate shares — **THE REAL-SECRET STEP (air-gapped only)**
- On the air-gapped machines, run the FROST **DKG** (no dealer): each custodian produces their share; the group public
  key is derived. The SLH-DSA-SHA2-128s ceremony root is generated on a separate air-gapped machine.
- **Shares NEVER leave their machine.** Only **public** values (the group pubkey, the SLH root pubkey, per-custodian
  commitments/reveals) move — via the write-once medium, on camera.
- Each custodian's share is split/backed-up per your custody policy (e.g. Shamir backup to sealed envelopes in
  separate vaults). Document it; it is out of scope for this repo's code.

## 6. Sign the genesis directory
- The coordinator assembles the **genesis directory** (the accredited registrars) and both roots co-sign it (FROST
  5-of-9 threshold Ed25519 + SLH-DSA). Both signatures are required; a verifier rejects the directory unless both
  verify (D-019).
- The coordinator certifies the **online delegate** (ADR-002, scope-limited, ≤ 92-day cert) for fresh-heads and delta
  countersigns — so the real root goes back offline immediately after the ceremony.

## 7. Reveal, transcript, publish
- After the directory is signed, custodians **reveal** their contributions on camera; the witness confirms each
  `SHA-256(reveal) == commit` and each signature (`kits/ceremony/witness.mjs` does this in the dry-run).
- The coordinator writes the **transcript** (roots' fingerprints, accredited registrars, the drills, `verified_at`)
  and its **SHA-256** (`transcript.json` + `transcript.sha256`, exactly as the `ceremony` bin emits).
- **Independent hash:** the witness (and anyone with the published transcript) recomputes `SHA-256(transcript.json)`
  and confirms it equals the published hash and the recording. This is the check the dry-run automates and asserts.
- Publish `directory.json`, `roots.json`, `transcript.json` + hash to the mirrors (M7); confirm ≥2 mirrors
  byte-verify (`make verify-mirror`). Publish the recording.

## 8. Wipe & seal
- Physically destroy or verifiably wipe the air-gapped machines and any one-time media used for share generation.
- Seal share backups per policy. Record the chain of custody.

---

## What "done" looks like (and what the dry-run proves)
| Property | Real ceremony | Dry-run proof |
|---|---|---|
| No single-holder root | FROST 5-of-9 shares, air-gapped | `make ceremony` mints a real 5-of-9 dual root (TEST-ROOT) |
| Every custodian committed + revealed, cross-read | on camera | `operator.mjs` × N + `witness.mjs` verify commit-reveal + sig |
| Transcript is witness-reproducible | independent recompute + recording | `witness.mjs` recomputes `SHA-256(transcript.json)` == published |
| A skipped step is caught | ceremony halts on camera | `make ceremony-dry-run` negative test: skip a custodian → witness FAILS |
| Public artifacts, root dark | published dir/roots/transcript + mirrors | `make verify-mirror` byte-verifies; `make genesis-local` verifies root-dark |

The **only** thing the dry-run cannot rehearse is the physical air-gap + real entropy of § 5 — by design. Everything
that can be checked in software is checked, and fails loudly if skipped.
