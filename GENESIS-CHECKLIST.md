<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# GENESIS CHECKLIST — how we declare the AINRA prototype DONE

The engineering ladder (M1–M8) is complete and CI-gated. The prototype is **not** done until the three real-world
§29 events happen — and they must happen so that **outsiders can confirm them without trusting us**. This is the
ordered runbook that ties the kits together into that declaration. Every row names the **artifact that proves it**.

Nothing here is faked. A step is ✅ only when its artifact exists and independently verifies; until then it is ⏳.

## Ordered runbook

### 0. Pre-flight (done — CI-gated)
- [x] Repo public, CI green on every push (`.github/workflows/ci.yml`): test · diff · wedge · drill · testbed ·
  genesis-local · repro · verify-mirror · check-freeze · fuzz · S7 · license · N7.
- [x] Every published artifact byte-reproducible (`make repro`) and mirror-verifiable root-dark (`make verify-mirror`).
- **Proof:** the green CI run + `MANIFEST.sha256`.

### 1. Rehearse (done — smoke-proven)
- [x] Ceremony choreography rehearsed, transcript witness-reproducible, skipped step fails loud
  (`make ceremony-dry-run`, `kits/ceremony/RUNBOOK.md`).
- [x] Witness quorum runs over the network, fork refused (`make drill-networked`, `kits/witness/`).
- [x] Verifier kit produces a valid, collectible attestation (`make verifier-kit-smoke`, `kits/verifier/`).
- [x] Soak instrument measures propagation into a signed, tamper-evident report (`make soak-smoke`, `kits/soak/`).
- **Proof:** each `make *-smoke`/`*-dry-run` green; the kit READMEs.

### 2. Run the recorded ceremony (⏳ real-world event)
- [ ] 9 custodians on air-gapped, ephemeral-OS machines; 5-of-9 FROST + SLH-DSA; on-camera commit → cross-read →
  reveal; publish `directory.json`, `roots.json`, `transcript.json` + hash to ≥2 mirrors; publish the recording.
- **Runbook:** `kits/ceremony/RUNBOOK.md` (the one real-secret step is marked).
- **Proof:** a published transcript whose SHA-256 an independent witness recomputes (`kits/ceremony/witness.mjs`),
  plus the recording; ≥2 mirrors byte-verify (`make verify-mirror`).

### 3. Enroll ≥3 independent external verifiers (⏳ real-world)
- [ ] Three unaffiliated operators, on three different machines, each run `kits/verifier/` against the published
  artifacts and send us a signed `verifier-attestation.json`.
- **Proof:** three attestations that each pass `kits/verifier/check-attestation.mjs` (signature + canonical artifact
  hashes + conformant verdicts) under **distinct** verifier keys. (Kill-gate K4.)

### 4. Stand up witnesses on independent infra (⏳ real-world)
- [ ] ≥3 `witnessd` run by separate operators (TLS-fronted); a relying party assembles a quorum certificate over the
  network; an injected fork is refused by their quorum, not by us.
- **Proof:** a signed quorum certificate for the honest head + a refused fork, verifiable against the published
  witness roster (`kits/witness/`).

### 5. Run the 14-day / 3-region soak (⏳ real-world)
- [ ] `kits/soak/` running from ≥3 regions against the live registrar/mirrors for 14 days; revocation **p95 < 60 s**.
- **Proof:** signed `soak-report.json` per region + the append-only hash-chained logs, all passing
  `kits/soak/verify-log.mjs`, with the SLO **computed from the data** (never asserted). A `BREACH` is recorded
  honestly and blocks the declaration.

### 6. Declare (⏳ — gated on 2–5)
- [ ] The DoD table below is all ✅ with an independently-verifiable artifact per row. The founding table convenes
  with the live artifacts. Publish the declaration + links to every proof.

## The §29 Definition-of-Done table (which artifact proves each row)

| Criterion | Status | Artifact that proves it |
|---|---|---|
| Dual-root ceremony (FROST 5-of-9 + SLH-DSA), self-verified | ✅ (rehearsal) / ⏳ (recorded) | `make ceremony`; step 2 transcript + recording |
| Two registrar classes live | ✅ | `make genesis-local` → `directory.json` with two distinct issuer keys |
| Logged-before-valid | ✅ | inclusion proofs in the vectors; `make demo` |
| Offline / external verify (root dark) | ✅ | `make genesis-local` stage 3; `kits/verifier/` |
| Revocation fails closed (< 60 s class) | ✅ (local) / ⏳ (p95×3-region×14d) | `make genesis-local` stage 4; step 5 `soak-report.json` |
| Injected fork caught by witnesses, not us | ✅ (in-proc + networked) / ⏳ (independent operators) | `make drill` / `make drill-networked`; step 4 |
| Outsider forks the root from public artifacts | ✅ (machinery) / ⏳ (3rd-party infra) | `make repro` / `make verify-mirror`; a 3rd-party rebuild |
| ≥3 external verifiers | ⏳ | step 3 — three passing `verifier-attestation.json`, distinct keys |
| Recorded ceremony + 14-day soak | ⏳ | steps 2 + 5 — recording + transcript; regional soak-reports |

## The one-line honest summary
**Engineering: done. Machinery for the external events: done and smoke-proven. The events themselves: pending, and
each will be provable by an artifact an outsider can check without trusting us.**
