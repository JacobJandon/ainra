<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Changelog

All notable changes to the AINRA reference implementation. Format follows [Keep a Changelog](https://keepachangelog.com/);
this project versions the **reference implementation + conformance vectors** (the normative spec is versioned in
`docs/AINRA_Master_Technical_Specification_v1.md`). The engineering milestone ladder is MTS §27 (M1–M11); design
decisions are `docs/DECISIONS.md` (D-001…). Cut a release with `make release`; verify one per `RELEASING.md`.

We **publicly own fixed security bugs** — hiding them would be the opposite of a trust root.

## [Unreleased]

Nothing yet. `v0.1.0` is the first tag (the human cuts it as step 3 of the pre-push checklist in `docs/PUBLISH-AUDIT.md`).

## [v0.1.0] — the first public release (pending tag)

The first tag of the reference implementation: the full MTS §27 engineering ladder (M1–M8) plus the public-readiness
and stranger-runnable-DoD work (M9–M11). Everything below is provable from a clean clone with `make preflight`.

### Protocol & core (M1–M8)
- **M1** — `ainra-core` pure verify/issue library (N7: no I/O, no clock), canonical encoder, 15 frozen reasons, hybrid
  **Ed25519 + ML-DSA-65 (both-signatures-or-invalid)**; **684 CC0 conformance vectors** + a 3-way differential harness.
- **M2** — transparency pipeline (`logd`), RFC 6962 Merkle inclusion, **logged-before-valid**, dual-signed hops.
- **M3** — Token Status List deltas + fresh head, registrar-in-a-box, `ainra-cli-rs`, explorer.
- **M4** — **FROST 5-of-9 threshold Ed25519 + SLH-DSA-128s dual root** (D-001), delegate cert/rotation (D-002).
- **M5** — the verifier **wedge**: `@ainra/sdk` GA `Verifier` (~5-line, offline, fail-closed) + `@ainra/middleware`.
- **M6** — **witness quorum (k-of-N)** fork drill; fresh-head currency mode; k is the relying party's, never a cert's (D-021).
- **M7** — **reproducible builds** (`make repro`, byte-identical clean rebuild ×2) + mirror byte-verify (D-022).
- **M8** — **`make genesis-local`**: the whole stack on one laptop; two cryptographically distinct registrar classes;
  the §29 DoD table marked honestly (D-023).

### Public-ready & stranger-runnable (M9–M11)
- **M9** — own git repo, dual-license Apache-2.0 OR MIT + CC0 vectors, CI on every push, four **kits** (verifier /
  ceremony / soak / witness) so outsiders run the pending DoD events; the verifier attestation is **execution-bound**
  (D-024).
- **M10** — publish audit + history hygiene (D-025), cold-open onboarding per kit, the **genesis board**
  (`make genesis-status`, honest 7/11), `outreach/` recruitment, front door with a CI-enforced status line.
- **M11** — CI runs the full gate set on the host (+ a `make audit` PR gate + nightly), community-health files, this
  changelog + `make release`, the external-verifier **operator loop**, and a durability pass (D-026).

### Security (fixed before first release — owned publicly)
Each was found by adversarial review, reproduced against the real code, fixed, and regression-tested (see D-024):
- **CRITICAL — verifier collector fail-open.** An attestation with an empty artifact set passed vacuously. Fixed: a
  required, complete, byte-matching corpus; empty/partial fails closed.
- **HIGH — ceremony quorum forgeable by base64 aliasing.** The distinct-custodian check compared raw base64 strings, so
  padding-stripped aliases of one key posed as N "distinct" signers (3 keys forged a 5-of-5). Fixed: dedup on the
  canonical decoded key.
- **HIGH — attestation proved *agreement*, not *execution*** (and the docs over-claimed "execution"). Fixed: a fresh,
  secret coin-flip challenge corpus the party can only answer by actually verifying (forge prob 2⁻ᴷ); docs corrected to
  the exact honest scope.
- **HIGH — soak report trusted its own SLO threshold.** A re-signed PASS over a breaching log could pass. Fixed: the
  verifier pins the SLO + challenge itself and recomputes from the log.
- **MEDIUM** — canonical-JSON array-replacer dropped nested keys from signatures; soak trailing-drop; ceremony
  file-count without identity binding — all fixed with regression tests.

### Not done (by design — real-world events, not code)
A recorded 5-of-9 ceremony · ≥3 independent external verifiers · a 14-day/3-region revocation soak · independent
witnesses on separate infra. The machinery for all four is built and smoke-proven; `make genesis-status` shows the
honest count (**7/11** today). See `GENESIS-CHECKLIST.md` and `outreach/`.

[Unreleased]: https://github.com/<owner>/ainra/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/<owner>/ainra/releases/tag/v0.1.0
