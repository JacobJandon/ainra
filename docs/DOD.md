<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# DoD — the Genesis Definition of Done (MTS §29)

The MTS §29 prototype exit: *"a recorded ceremony, two registrar classes live, ≥3 external verifiers, revocation
p95 < 60 s across three regions for 14 days, an injected log fork caught by witnesses (not by us), and an outsider
forking the root from public artifacts alone."* Each item below is marked **honestly**: **✓ laptop-provable now**
(with the command that proves it) or **external / pending** (a real-world soak / multi-region / third-party item that
code cannot fake — M8 delivers the machinery + the local proof and leaves the external column unfaked).

## §29 prototype-exit criteria

| Criterion | Status | Evidence / what's left |
|---|---|---|
| Dual-root ceremony (FROST 5-of-9 + SLH-DSA), self-verified | ✓ | `make ceremony` · `make genesis-local` stage 1 (both roots required; a stranger's `accredit()` trust-anchors it) |
| **Two registrar classes live** | ✓ | `make genesis-local` stands up `registrar-07` + `registrar-02` — **cryptographically distinct** (id-derived keys; directory.json lists two different issuer keys), both accredited into one directory, both issuing |
| Logged-before-valid (unlogged credential rejected) | ✓ | every passport carries a real RFC 6962 inclusion proof to a delegate-signed checkpoint; `not_logged` on tamper (vectors + `make demo`) |
| Offline / external verify (root dark) | ✓ | `make genesis-local` stage 3 — the 5-line SDK verifies holding only the directory + roots; `ainra-verify` is air-gappable (F9) |
| Revocation fails closed (< 60 s freshness class) | ✓ (local) / external (p95×3-region×14d) | `make genesis-local` stage 4 revoke → INVALID + forged all-clear → INVALID; the *p95 < 60 s across three regions for 14 days* soak is the external column |
| **Injected log fork caught by witnesses, not us** | ✓ (in-proc + networked) / external (independent operators) | `make drill` (in-proc) + **`make drill-networked`** (N `witnessd` over HTTP, distinct keys) refuse the fork; k stays the relying party's (D-021). Witnesses run by *separate operators* on separate infra is the external column — machinery: `kits/witness/` |
| **Outsider forks the root from public artifacts alone** | ✓ (machinery) / external (3rd-party infra) | `make repro` rebuilds every artifact byte-for-byte; `make verify-mirror` byte-verifies any mirror root-dark. An *independent* party rebuilding on *their* infra is the external column (GENESIS-CHECKLIST §0) |
| **≥3 external verifiers** | ⏳ external (machinery ready) | **`kits/verifier/`** lets any stranger verify root-dark + reject revoked/forged with only `@ainra/sdk` and emit a **challenge-bound signed attestation** we collect without trusting them (`check-attestation.mjs` requires the nonce we issued + the **complete** byte-matching corpus — empty/partial fails closed). Bar = 3 attestations under distinct keys, one issued challenge each, 3 machines. Honest scope: crypto proves execution+freshness; distinctness is the one-nonce-per-vetted-party issuance (kill-gate K4; GENESIS-CHECKLIST §3) |
| Recorded in-person ceremony + 14-day soak | ⏳ external (machinery ready) | ceremony: **`kits/ceremony/RUNBOOK.md`** + `make ceremony-dry-run` (witness-reproducible transcript; witness binds each part to its slot + requires distinct custodian keys, so a copied part can't fake a no-show). Soak: **`kits/soak/`** + `make soak-smoke` (measured p95, signed report, verifier **pins the SLO + challenge out of band** so a re-signed PASS over a breaching log is rejected, SLO fail-closed). The recorded ceremony + the 14-day/3-region run are the scheduled events (GENESIS-CHECKLIST §2, §5) |

## Non-functional (N1–N12, MTS §4) — laptop-checkable subset

| ID | Requirement | Status | Evidence |
|---|---|---|---|
| N1 | Independence — kill any vendor, verify path unaffected | ✓ | verify path = `ainra-core` + RFCs only; `make drill` fork-kill; no vendor in the path |
| N2 | Decentralization — threshold root, witnessed logs, byte-mirrorable artifacts | ✓ | FROST 5-of-9 · witness quorum · `make repro`/`make verify-mirror` (M7) |
| N3 | Vendor neutrality — verify path = RFCs + OSI-licensed deps | ✓ | §24 audit; `license-check.mjs` green |
| N6 | Mechanical neutrality — S7 linter, mechanical ordering | ✓ | `s7-lint.mjs` green; directory entries sorted+unique |
| N7 | Privacy — no PII, herd-private status, local verify (no phone-home) | ✓ | forbidden-key parser gate; TSL herd status; verify is offline |
| N8 | PQ posture — hybrid mandatory where root/registrar sign | ✓ | Ed25519+ML-DSA-65 both-or-invalid; SLH-DSA root (crypto agility, `QUANTUM`) |
| **N9** | **Laptop-runnable — `make genesis-local` boots the full stack** | ✓ | **this milestone** |
| N11 | ≤1 kLoC bespoke security code; reproducible builds | ✓ | core is thin over RFCs/FIPS; `make repro` (M7) |

## How to reproduce the local proof

```
make genesis-local        # boots the whole world; writes genesis-out/transcript.json + artifact hashes
make repro                # proves the published artifacts rebuild byte-for-byte from source
make verify-mirror MIRROR=<dir>   # any third party byte-verifies a mirror, root dark
# M9 machinery for the external events (each proven at smoke scale; see GENESIS-CHECKLIST.md for the real runbook):
make verifier-kit-smoke   # kits/verifier — external verifier attestation
make ceremony-dry-run     # kits/ceremony — witness-reproducible ceremony rehearsal
make soak-smoke           # kits/soak — measured revocation p95, signed report
make drill-networked      # kits/witness — quorum over HTTP, fork refused
```

The ordered runbook that turns these into "prototype DONE" — the recorded ceremony, ≥3 external verifiers, the
14-day/3-region soak — is **[GENESIS-CHECKLIST.md](../GENESIS-CHECKLIST.md)**, with the artifact that proves each row.

The transcript (`genesis-out/transcript.json`) records the ceremony roots, the two registrars, every passport's
verdict before/after revocation, the forged-status rejection, the witness-quorum fork-catch, and a SHA-256 of every
emitted artifact — everything a third party needs to reproduce and independently verify the run.
