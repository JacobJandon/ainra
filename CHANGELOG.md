<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Changelog

All notable changes to the AINRA reference implementation. Format follows [Keep a Changelog](https://keepachangelog.com/);
this project versions the **reference implementation + conformance vectors** (the normative spec is versioned in
`docs/AINRA_Master_Technical_Specification_v1.md`). The engineering milestone ladder is MTS §27 (M1–M11); design
decisions are `docs/DECISIONS.md` (D-001…). Cut a release with `make release`; verify one per `RELEASING.md`.

We **publicly own fixed security bugs** — hiding them would be the opposite of a trust root.

## [Unreleased]

The three real-world genesis DoD rows remain the only open work: a recorded public ceremony with independent
custodians, ≥3 external verifiers, and a 14-day 3-region soak. The machinery for all three is built and rehearsed.

### L3 — the human half gets a schedule, and published counts get a gate

- **`campaign/`** — the fourteen days that move those three rows: one primary action per day, the six asks and the
  interview script, the jurisdiction decision with a date on it, and two public kill-gates (**K1** demand evidence,
  **K4** three independent attestations by 05 Sep). `make campaign-status` prints the day, the action, and every
  count with the registry it came from.
- **Gates are re-dated in the open or not at all.** `node tools/campaign.mjs redate` refuses without a written
  reason, appends to `campaign/gates.json`'s history, and regenerates the public table (D-043).
- **Published counts are now enforced, not promised.** `node tools/campaign.mjs check` runs inside the board's
  status-honesty row and in CI: if `ROADMAP.md`'s verifier or witness numbers drift from the genesis board and
  `witnesses/candidates.json`, or a generated campaign table drifts from `gates.json`, the build goes red. Proven
  with a negative control (a false `2 / 3` turns the board red).
- **People never enter this repository (D-043, applying D-036 to ourselves).** The tracker and interview notes are
  gitignored; no command writes a person into a tracked file; `drop <id>` clears one on request. Counts are
  publishable, people are not. No campaign command can move a Definition-of-Done row.
- **`make publish-preflight`** — everything checkable before the maintainer pastes an npm/PyPI token, publishing
  nothing and holding no credentials: versions agree across all four packages, the version is tagged, each package
  packs with a README, a license, and no local `file:` dependency, and the packed npm tarball *and* the built wheel
  each install into a throwaway environment and reproduce all **745** recorded conformance verdicts. It found four
  real blockers on first run (three missing package READMEs — now written — and the middleware path dependency).

## [v0.3.0] — a fourth independent verifier · self-serve conformance · signed releases (pending tag)

Cut with `make release`; the human tags it (see `RELEASING.md`). Everything below is provable from a clean clone.

### M24 — independence, self-serve conformance, and supply-chain trust

- **A fourth, independent implementation.** `packages/sdk-py` is a Python verifier written from the Standard, the
  MTS, `docs/reasons.json` / `docs/PRESENTATION.md`, and the CC0 vectors — **not** transliterated from `ainra-core` or
  the TypeScript SDK. It joins the conformance differential as a fourth column: `make diff` is now
  **core ↔ sdk ↔ cli ↔ py**, and all four agree byte-for-byte on **745/745 passport + 17/17 delta + 9/9 directory**
  vectors, on verdict *and* reason. A fourth brain reaching the same verdict on every vector is independent
  confirmation the Standard is unambiguous; a disagreement would have been a finding.
- **The independence caveat, stated precisely (D-041).** The verification *logic* is independent; the cryptographic
  *primitives* are shared, audited libraries — reimplementing a signature scheme would be less safe, not more
  independent. Ed25519 + ML-DSA-65 come from pyca `cryptography` (OpenSSL 3.5+), SLH-DSA-SHA2-128s from the same
  OpenSSL `libcrypto` via `ctypes`, SHA-256 from the stdlib. The differential exercises the logic, not the primitives;
  every crypto wrapper fails **closed**. The package is `ainra` (checked unregistered on PyPI 2026-07-30, **not** published).
- **The self-serve conformance programme.** `tools/conformance/` + `docs/conformance/PROGRAMME.md`: a
  **language-agnostic runner** any third party points at their **own** implementation over a documented stdin/stdout
  contract (`tools/conformance/CONTRACT.md`) — the corpus streams in as JSON Lines, one `<name>\t<result-json>` line
  streams back, no files and no network. `make conformance` proves it **both ways**: the three in-repo verdict impls
  (Rust core, TS SDK, Python) each pass **clean** over the full corpus with the same corpus hash, and a deliberately
  **sabotaged** impl is caught with named divergences (a conformance tool that cannot fail is theatre). An implementer
  **self-attests** by signing their own result with their **own** SSH key; anyone re-runs the corpus and checks. The
  root certifies no one — the only truthful claim is "self-attested conformant, re-runnable", never "AINRA-certified".
- **Supply-chain trust for our own releases (D-042).** `make release` writes `dist/` — the reference CLI, the CC0
  corpus, a reproducibility `MANIFEST.sha256`, a **SLSA-style `provenance.json`** (source commit, toolchain, artifact
  digests) and a **CycloneDX `sbom.json`** (every locked crate + Node dep with its `purl`) — and signs `SHA256SUMS`
  with an **offline SSH Ed25519 key** (`ssh-keygen -Y`): tiny keys, detached signatures, verified against one pinned
  public key, no keyserver and no web-of-trust. The private key never enters the repo or CI. **`RELEASE-VERIFY.md`** is
  the stranger's four-step verify guide — check the signature, check every artifact against the signed manifest, read
  the provenance + SBOM, and (the strong check) rebuild the corpus **byte-for-byte** from the tagged source, which
  needs no key at all. Signatures prove *who*; reproducibility proves *what*.
- **Versions bumped to 0.3.0** everywhere from one source each — the workspace `Cargo.toml` (every crate inherits),
  `@ainra/sdk` / `@ainra/middleware` / `@ainra/mcp`, the Python `ainra`, the downloadable reference CLI, and the site
  labels — with the `make site` drift-guard that fails the build if any page's CLI version ≠ `apps/cli-node/package.json`.
- The **DoD table is untouched.** The three real-world genesis rows — a recorded public ceremony with independent
  custodians, ≥3 external verifiers, and a 14-day 3-region soak — remain **honestly pending**; the machinery for all
  three is built and rehearsed. Decisions this milestone: **D-041** (the fourth Python column), **D-042** (SSH-signed releases).

## [v0.2.0] — hybrid CLI + suite-migration / ceremony / witness / push (pending tag)

Cut with `make release`; the human tags it (see `RELEASING.md`). Everything below is provable from a clean clone.
The rebuilt hybrid CLI's own demo:

```
— AINRA reference lifecycle demo (hybrid Ed25519 + ML-DSA-65) —
  keys: hybrid Ed25519 + ML-DSA-65 (both mandatory) · single-key root, 3 local witness keys — labeled
→ suite      Ed25519 + ML-DSA-65 ✓
✓ VALID · verified in 16.9 ms
✓ revoked · ainra:registrar-07:acme-corp:invoicing@4.2.1 · reason: key-compromise · log #000003
→ suite      Ed25519 + ML-DSA-65 ✓
✗ INVALID · revoked · verified in 16.0 ms
done. every signature above is real hybrid Ed25519 + ML-DSA-65; strip the ML-DSA half and it fails closed.
```

### M23 — the downloadable CLI goes hybrid; the v0.2.0 milestone

- The **downloadable reference CLI is now hybrid Ed25519 + ML-DSA-65**, both-signatures-or-invalid, at parity with
  the Rust core and browser SDK — keygen, every issuance signature (issuer/root/cert/checkpoint/status), and
  verification. It stays **one self-contained file**: `make site` esbuild-bundles the canonical source with the
  audited `@noble/post-quantum` ML-DSA inlined, so the download runs with just `node` — no install, zero runtime
  deps (64 KB bundle, 18 KB zipped). Every external decode goes through the one strict canonical gateway (D-029).
- **Migration semantics, fail-closed:** a legacy Ed25519-only credential is recognized and named — `alg_downgrade`
  by default, verifying **only** under an opt-in `--accept-legacy` overlap; a credential whose ML-DSA half is
  present but broken or non-canonical is `sig_invalid`, rejected under **every** policy. Proven by `make cli-check`
  (4 downgrade vectors × 2 policies), wired into `ci` + `preflight`. The core↔SDK corpus already proved this at the
  protocol level (24 `alg-downgrade-*` + `noncanon-*` inside the 745; unchanged, still `make diff` green).
- Measured on the reference machine: hybrid sign ≈ 7 ms, verify ≈ 3 ms; CLI implementation **v0.1.0 → v0.2.0**.
- **Suite Migration Drill 01 (Task 2)** — a real Ed25519→hybrid migration over a running network: `ainra migrate`
  REISSUEs with `prev_leaf` continuity (nothing wiped), the overlap is an auto-expiring fail-closed policy epoch
  (`--accept-legacy-until`, D-037), and the staging audit confirms the live network is already hybrid (0 stragglers).
  `make suite-migration-drill`; transcript in `docs/drills/SUITE-MIGRATION-01.md`; AINRAscan shows the live suite mix.
- **Distributable genesis ceremony (Task 3)** — `make ceremony-rehearsal-multi` runs FROST 5-of-9 across NINE
  isolated OS processes (file-based rounds, air-gap shape): one group key emerges, 5 shares sign / 4 cannot,
  transcript reproducible. Changes no DoD row; runbook gains the multi-party appendix.
- **Witness kit v2 (Task 4)** — single-binary `witnessd` from a one-file config, self-declared `/info` (verified by
  no one), `/root` alias, bare-address back-compat; verifier quorum-k worked examples; `make witness-check` times the
  <10-min onboarding; AINRAscan shows witness diversity from live data.
- **Push status = ADR-018 (Task 5)** — push is advisory transport over a sovereign pull: an unsigned SSE/webhook may
  announce a new head/delta, but the verifier always pulls + validates. Suppression fails closed on freshness;
  forgery is ignored. `make push-advisory-check`, `tools/push-announce.mjs`; MTS ADR-018, D-038 (the Standard stays v5.1).
- **Release (Task 6)** — versions bumped to **0.2.0** everywhere from one source each (workspace `Cargo.toml` →
  every crate; `@ainra/sdk`, `@ainra/middleware`, `@ainra/mcp`; the site labels, with a `make site` drift-guard that
  fails the build if any page's CLI version ≠ `apps/cli-node/package.json`). Reproducibility re-proven byte-for-byte
  (`make repro`); the M23 checks are linked from the verification map (`docs/STATUS.md`), the drill transcript from
  there and the manual. Decisions this milestone: **D-037** (legacy-policy epoch), **D-038** (push advisory),
  **D-039** (ceremony file-transport). The **DoD table is untouched** — the three real-world genesis rows (recorded
  public ceremony with independent custodians, ≥3 external verifiers, 14-day 3-region soak) remain honestly pending.

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

- ~~Downloadable reference CLI goes hybrid~~ — **done in M23** (above).
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

[Unreleased]: https://github.com/JacobJandon/ainra/compare/v0.3.0...HEAD
[v0.3.0]: https://github.com/JacobJandon/ainra/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/JacobJandon/ainra/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/JacobJandon/ainra/releases/tag/v0.1.0
