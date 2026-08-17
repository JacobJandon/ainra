<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# GO / NO-GO — read aloud at T−1d and again at T−0h

The Coordinator reads every line aloud. Each is **binary** and has the command/evidence that satisfies it. **A NO on
any line is NO-GO.** No gate is waived silently — a waiver requires a written **D-0xx** with reasoning, read aloud
and recorded on camera. When in doubt: slip the date. An aborted genesis costs a date; a fudged genesis costs the
project.

## People & place

- [ ] **9 custodians physically present** (or on the confirmed remote protocol), IDs matched to `genesis-evidence/custodians.md`. — *count heads = 9*
- [ ] **Standby quorum reachable** — ≥2 standby custodians on call. — *ring them; both answer*
- [ ] **Jurisdiction spread** — the 9 span **≥5 jurisdictions**. — *check the confirmed list*
- [ ] **Recording live** — primary camera on the ceremony machine + a second angle, audio confirmed. — *play back 30 s*

## Hardware & software

- [ ] **Ceremony machine air-gapped** — network hardware absent/disabled. — *`ip link` shows no up interface; visual*
- [ ] **Dry-run green on THIS hardware** — `make ceremony-dry-run` → PASS, witness-of-record recomputed the hash and it matched. — *paste the PASS line + the two hashes*
- [ ] **Frozen tag preflight green** — `make preflight` at the shipping commit → ALL GREEN. — *paste the board*
- [ ] **Parity holds** — `make config-diff` → parity. — *`✓ config-diff … parity holds`*
- [ ] **Freeze window active** — no commits to the shipping ref since T−1d except ABORT-class. — *`git log` since the tag is empty*

## Network & witnesses

- [ ] **Staging healthy** — `make stage-status` UP on all regions; `make soak-smoke` green. — *paste the board*
- [ ] **Production DNS resolves** — every record in CUTOVER.md resolves + TLS validates from an external network. — *`dig`/`curl -Iv` outputs*
- [ ] **≥3 witness operators reachable** — each confirms host + key, ready to onboard on the day. — *`genesis-evidence/witnesses.md`, live ping each*
- [ ] **Mirrors ready** — ≥2 independent transcript-publication hosts tested. — *a test upload to each succeeded*

## Evidence (informational — does NOT gate genesis)

- [ ] **External-verifier attestation count stated** — `make genesis-status` → the "external verifiers" number, read aloud honestly. **Target ≥3, but genesis does NOT require it:** if fewer, that row stays ⏳ past genesis and the founding declaration simply waits for it. Say this explicitly; do not let a low count trigger any shortcut.

## Read aloud, but not a box

Genesis mints the first root; it does not roll one. **[`ROLLBACK.md`](ROLLBACK.md)** is read aloud at T−1d anyway,
because it states the one thing genesis determines forever: we will never be able to measure how many verifiers hold
a given root, so every future roll depends on reversibility that has to be designed before it is needed — and on
witnesses, which is why the witness rows above outlive this ceremony.

---

**Decision.** All non-informational boxes GO → the Coordinator declares **GO** on camera and proceeds to T0. Any NO
→ **NO-GO**: slip or remediate; if remediated, re-read this list in full before proceeding.
