<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# The AINRA Genesis Day Runbook

**The production root is born here.** This is the one master document for genesis day — imperative, minute-level
where it matters. A competent coordinator who has never met the authors can execute genesis from this document plus
the repo. Read it end-to-end once, then run it as a countdown.

> **The rule, above everything:** any deviation from a kit's expected state is an **ABORT**, never an improvisation
> (docs/genesis-day/ABORTS.md). An aborted genesis costs a date. A fudged genesis costs the project.

**What genesis produces:** a recorded 5-of-9 threshold ceremony that mints the real root key pair (FROST-Ed25519 +
SLH-DSA, ADR-001), a signed production directory, delegate keys, a booted production deployment (separate keys /
domains / volumes from staging — staging keeps running, TEST-labeled, untouched), the first registrar accreditations
through the identical public door, witness cosigns on the first production checkpoints, and the start of the 14-day
soak clock. When the soak completes and `make genesis-status` reads 11/11, the founding declaration publishes
(docs/genesis-day/declaration/, Task 4). **Genesis does NOT require the external-verifier row** — attestations can
accrue before or after; if fewer than 3 exist on the day, that row simply stays ⏳ and the declaration waits.

Roles (assign names at T−30d): **Coordinator** (reads this runbook aloud, calls GO/NO-GO, sole ABORT authority),
**9 Custodians** (hold the FROST shares; ≥5 jurisdictions), **Witness-of-record** (independently recomputes on
camera), **Camera** (unbroken recording). Standby custodians: ≥2, reachable.

---

## T−30d → T−7d — Confirmations & procurement

- [ ] **Custodian seats (9).** Confirm 9 named custodians across **≥5 jurisdictions**. Record each confirmation in
      `genesis-evidence/custodians.md` (name-placeholder OK; the *confirmation* must be real: a signed reply + a
      backup contact). Fewer than 9 confirmed by T−7d → slip the date.
- [ ] **Standby quorum.** ≥2 standby custodians confirmed, briefed on the substitution procedure (ABORTS §custodian
      no-show) and its on-camera disclosure requirement.
- [ ] **Venue + recording.** Book a venue that permits continuous multi-angle recording. Requirements: one unbroken
      camera on the ceremony machine + custodian actions; a second angle on the coordinator's screen; audio.
- [ ] **Air-gapped hardware.** Procure per `kits/ceremony/RUNBOOK.md`: the ceremony machine (ephemeral OS, network
      hardware physically removed/disabled), 9 custodian devices, offline media for share transport, a standby
      ceremony machine. Verify each boots the ephemeral image.
- [ ] **Witness commitments.** ≥3 independent witness operators scheduled to onboard **on the day** (deploy/
      witness-quickstart.md). Each confirms host + public key in `genesis-evidence/witnesses.md`.
- [ ] **External-verifier status (informational).** Record how many valid attestations exist now:
      `make genesis-status` → the "external verifiers" count. Attestations may be collected before genesis
      (kits/verifier/OPERATOR.md); note the count at each checkpoint below. This does **not** gate genesis.
- [ ] **Domains + DNS (the operator registers domains).** Follow the DNS checklist in
      docs/genesis-day/CUTOVER.md; confirm each record resolves from ≥2 networks before T−1d.
- [ ] **Mirrors.** Line up **≥2 independent** static hosts for transcript publication; test an upload to each.

## T−1d — Full check & GO/NO-GO #1

- [ ] **Equipment check.** Every device from procurement boots the ephemeral image; cameras record; media reads/writes.
- [ ] **Dry-run on the real hardware.** `make ceremony-dry-run` **on the actual ceremony machine** → green; the
      witness-of-record recomputes the dry-run transcript hash independently and matches.
- [ ] **Staging healthy.** `make stage-status` UP on all regions; `make soak-smoke` green (the instrument works).
- [ ] **Frozen tag ready.** The commit that will ship is chosen; `make preflight` green at it; `make config-diff`
      green (staging≡production except the four allowed axes); freeze window begins (docs/genesis-day/CUTOVER.md).
- [ ] **Read GO/NO-GO #1 aloud** (docs/genesis-day/GO-NO-GO.md). Any NO-GO → slip or remediate; a waiver requires a
      written D-0xx. Do not proceed on a silent waiver.

---

## T0 — Ceremony execution (on camera, no network)

The exact kit sequence is `kits/ceremony/RUNBOOK.md`; this is the choreography around it. **Camera rolling before
step 1; it does not stop until cutover is confirmed.**

| Time | Step | Action | ABORT if |
|---|---|---|---|
| T0+00m | Room seal | Coordinator states date, purpose, participants on camera; confirms the ceremony machine is air-gapped (network hardware absent). | network present, anyone unaccounted |
| T0+05m | Custodian DKG | Each of the 9 runs `kits/ceremony/operator.mjs` to generate + commit their FROST share; SLH-DSA root component generated. | any device off-image, any kit assertion fires |
| T0+20m | **Commitment cross-read** | Each custodian reads their share **commitment hash** aloud; the witness-of-record records all 9; the coordinator confirms they match the kit's expected set. | any commitment mismatches |
| T0+30m | Root assembly | 5-of-9 threshold assembles the root public key; the SLH-DSA ceremony root is sealed; a standby share set is written to escrow media. | threshold fails to assemble |
| T0+45m | Directory sign | The production **directory** (day-one registrars, honest notes — see CUTOVER) is signed by both root components; `kits/ceremony/verify-transcript.mjs` run in-room. | signature does not verify in-room |
| T0+55m | Transcript | Generate the ceremony **transcript.json** + its **sha256**; both written to offline media. | transcript incomplete |
| T0+60m | Seal | Camera pans the sealed escrow media + the transcript media; coordinator states the transcript hash on camera. | — |

**Hard rule restated:** if any kit assertion fires, or any hash/commitment mismatches, the coordinator calls
**ABORT** (docs/genesis-day/ABORTS.md). Do not retry in place, do not "fix and continue" — abort, publish the
reason, reschedule.

---

## T+0h → T+4h — The cutover

- [ ] **Publish the transcript** + its hash to **≥2 mirrors** (the ones tested at T−30d).
- [ ] **Independent recomputation.** At least one party OTHER than the transcript author fetches from a mirror and
      recomputes the hash: `make verify-transcript TRANSCRIPT=<url> SHA256=<published>`. It must match. **Mismatch →
      halt, publish the mismatch itself (ABORTS §hash-mismatch), never paper over.**
- [ ] **Boot production.** `docker compose --env-file deploy/.env.production -f deploy/compose.production.yml up -d`
      — the production profile (real root chain, production domains/volumes, **no TEST banner**). Staging keeps
      running untouched, still TEST-labeled.
- [ ] **Root keys → production directory.** The ceremony's root public keys are the directory's trust anchor;
      confirm the running services read a directory signed by the **production** root (the banner flips to
      PRODUCTION by key-detection — one codebase, D-033).
- [ ] **Delegate keys.** Issue the online delegate certs (checkpoint / status / fresh-head) under the production
      root (≤92d, ADR-002).
- [ ] **First registrar(s) accredited** through the identical public door as any future registrar; the day-one
      registrar list + their operators are stated honestly in the published directory's `notes`.
- [ ] **Witness onboarding.** Execute the ≥3 witness onboarding calls; confirm their cosigs appear on the first
      production checkpoints (`make stage-status`-equivalent against production).
- [ ] **Soak clock starts.** Start `kits/soak/` against the **production 3-region** deployment
      (docs/runbooks/soak.md). **The 14-day timer begins now, by design.**
- [ ] **AINRAscan on production.** Point AINRAscan at the production artifact server; it shows honest near-zeros
      becoming real entries (its empty-state design), banner reading PRODUCTION by key-detection.

## T+1d → T+14d — Soak & declaration

- [ ] **Daily** (each day): soak checkpoint review (`make soak-verify` per region), witness health, board watch
      (`make genesis-status`). Record any incident against docs/genesis-day/ABORTS.md (what aborts the clock vs not).
- [ ] **T+14d:** the signed 14-day / 3-region soak report is complete → `make genesis-status` reads **11/11** →
      run the declaration pipeline (`make declaration`). It renders + publishes **only** if every claim resolves to
      a real artifact (Task 4). If the external-verifier row is still ⏳, the declaration waits for it — genesis is
      real regardless; the declaration is the honest summary of what is proven.

---

**After genesis, this repo's next commit should be the `v1.0.0-genesis` tag.** Everything past this runbook is a
human decision.
