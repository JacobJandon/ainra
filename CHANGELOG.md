<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Changelog

All notable changes to the AINRA reference implementation. Format follows [Keep a Changelog](https://keepachangelog.com/);
this project versions the **reference implementation + conformance vectors** (the normative spec is versioned in
`docs/AINRA_Master_Technical_Specification_v1.md`). The engineering milestone ladder is MTS §27 (M1–M11); design
decisions are `docs/DECISIONS.md` (D-001…). Cut a release with `make release`; verify one per `RELEASING.md`.

We **publicly own fixed security bugs** — hiding them would be the opposite of a trust root.

## [Unreleased]

### M19 — the network runs under a real genesis root; next-version roadmap

- `make stage-up` now runs the genesis ceremony over the live registrars: `accredit` DKGs a FROST 5-of-9 +
  SLH-DSA dual-root, dual-signs the directory, and publishes the signed directory + `roots.json`. The public
  contract serves `X-AINRA-Root: genesis:<fp>` (was `test-root`); **`make genesis-verify`** proves a live passport
  verifies ROOT-DARK against the published root, and a tampered root is rejected. This is an OPERATOR-RUN genesis
  (single-host DKG) — the distributed public ceremony (independent custodians), ≥3 external verifiers, and the
  14-day 3-region soak remain the real-world DoD events (not fabricated).
- The registrar public door accepts an optional `{operator, lineage}` so a visitor can NAME their agent
  (sanitized to the grammar, still a low-tier specimen stamped `demo:specimen`); the public revoke is gated on
  that marker (`is_demo_specimen`).
- CLI README: spec reference corrected v4.0 → **v5.1**; the Ed25519-only limit is stated with hybrid as v0.2.

### Next (v0.2.0) — planned

- **Downloadable reference CLI goes hybrid** (Ed25519 + ML-DSA-65), matching the standard's mandate — the Rust
  core and browser SDK are already hybrid; the JS CLI (this download) is Ed25519-only. Flagship item: needs a
  careful crypto rework across every sign/verify site, with the audited `@noble/post-quantum` ML-DSA bundled so
  the single-file CLI still runs with just `node`.
- Threshold root ceremony in the CLI (single-key today), independent-witness wiring, push-based status fabric.
- The three real-world genesis DoD events: a recorded public ceremony with independent custodians, ≥3 external
  verifiers, and a 14-day 3-region soak.

### M12.1 — canonical-encoding sweep (D-029)

- The base64 fail-open class (M9 dedup, M12 prev_leaf) is closed at every base64url ingestion point: core was already
  strict (base64ct); the SDK now routes EVERY external decode through one strict gateway (`strictB64u` + canonical
  round-trip, `dec(s, reason)` fails closed) — claims-internal fields keep core's reason (hop sigs → `alg_downgrade`,
  `log.leaf`/hop `log_leaf` → `not_logged`), boundary decodes → `schema_violation`.
- New differential vector class `noncanon-*` + extended `renewal-invalid-prevleaf-*` cover trailing-bits, padding,
  whitespace, and standard-alphabet swaps; both implementations reject identically. Corpus 737 → **745** (745/745).
- Locked by unit tests: core `b64::decoder_is_canonical_only`, SDK `test/canonical.test.mjs` (exhaustive last-char
  sweep = the 16 canonical values). The two M12 prev_leaf differentials were independently re-verified closed
  (202 + 151 adversarial inputs, zero divergences). D-029.

### M12 — validity & renewal (ADR-017): identity eternal, credentials bounded, renewal invisible

- **One duration ladder** in `ainra_core::consts` — `PASSPORT_VALIDITY_DEFAULT_SECS` (366 d), `RENEWAL_LEAD_SECS`
  (30 d), `DELEGATE_CERT_MAX_SECS` (92 d, moved; re-exported from `checkpoint`), `INSTANCE_CRED_DEFAULT_SECS`
  (reserved) — cited by every issuer path, demo seed, the P0 CLI, and mirrored in `@ainra/sdk` (+ `renewalDue`).
- **Exact window boundaries pinned** by new `boundary-*` conformance vectors: `nbf` inclusive, `exp` exclusive; the
  ADR-016 ±30 s skew is freshness-layer only — **no skew on the passport window, no grace period: expiry is expiry**.
- **REISSUE (renewal) as a first-class operation**, distinct from ROTATE: fresh `[now, now+366 d]` window, a new
  status index, and a signed+logged **`prev_leaf`** continuity claim (schema-gated to a strict 32-byte leaf hash in
  all implementations) so renewals walk back through the transparency log as one unbroken chain. ACME-style
  issuance-side validation against the lineage continuity head — wrong/missing/forked links are refused before
  anything is logged. Overlap semantics: both generations verify until the old `exp`, then the old fails closed.
  `ainra renew <dir> <sub> [--version V] [--dry-run]` performs it. Chained (delegated) passports are explicitly NOT
  auto-renewable (renewal of a delegation is a re-delegation).
- **Revocation is lineage-wide across generations** — revoking a renewed lineage flips every unexpired generation's
  bit, so renewal can never be a revocation bypass (test-proven).
- **L3+ audit cap**: issuance/renewal refuses a passport whose `exp` exceeds the registrar-side tier audit's own
  expiry (`AuditRequired`/`AuditStale`, with the reason spelled out) — "audited" means audited recently. The wire
  format is unchanged (evidence stays at the registrar per Standard §4).
- **Status-list GC deferred honestly** (D-028): measured math + the 2^24 index-burn threshold recorded; the status
  URI is already the cohort discriminator, so sharding needs a directory-side extension only, no credential change.
- Corpus 684 → **737** passport vectors (all three implementations agree 737/737; existing vectors byte-identical);
  release tests 104 → **117**. Decisions: D-027, D-028; spec: MTS ADR-017.

`v0.1.0` is the first tag (the human cuts it as step 3 of the pre-push checklist in `docs/PUBLISH-AUDIT.md`).

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
