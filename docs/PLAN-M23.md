<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M23 — Suite Migration Drill 01

M23 executes the v0.2.0 roadmap as **one deliberate event**, not a feature bump. We are in testing, with real
test passports live under the operator-run genesis root — which makes bringing the downloadable CLI to hybrid the
perfect rehearsal of the exact thing ADR-017 trap (ii) says the protocol must survive: **a cryptographic-suite
migration over a running network**, existing credentials carried across by **REISSUE + prev_leaf continuity**,
never wiped. The transcript becomes a permanent artifact for every future verifier who asks "what happens when
Ed25519 falls?" Prime directives bind: nothing fake, fail closed, one strict decode gateway (D-029), no
third-party names, zero telemetry, TEST-ROOT labels intact, **DoD table untouched and unfaked**, `make preflight`
+ `make diff` green from a clean clone before and after. Spec stays **v5.1** (Task 5 may add **ADR-018** only).
Implementation **v0.1.0 → v0.2.0**, semver everywhere.

## Task 0 — the gap, mapped (blast radius, honestly, before anything changes)

| Surface | Current suite | Migration action |
|---|---|---|
| Staging registrar door (`registrar-box`, Rust core) | **HYBRID** Ed25519 + ML-DSA-65 — *measured*: 64 B + 3309 B sigs on a live `/present` | none; **confirm** in the drill, REISSUE any straggler (expected **0**) |
| Rust core (`ainra-core`) · Browser SDK (`@ainra/sdk`) | HYBRID (sign + verify) | none |
| **Downloadable JS CLI** (`apps/cli-node`) — keygen | Ed25519-only (`generateKeyPairSync('ed25519')`) | → hybrid keypair (T1) |
| JS CLI — issuance (issuer/root/cert/checkpoint/status sigs) | Ed25519 sign | → dual-sign, both-or-invalid (T1) |
| JS CLI — verification | Ed25519 verify | → require both + `alg_downgrade` (T1) |
| JS CLI key/bundle file formats | v1, `alg:'Ed25519'` | → versioned; legacy **recognized + named**, never silently reinterpreted (T1) |
| JS CLI local testbeds (`~/.ainra` credentials, `demo`) | Ed25519-only | → REISSUE to hybrid via `ainra migrate`, prev_leaf continuity (T2) |
| Conformance corpus | **745** vectors (classes incl. alg 24, noncanon 5, renewal 32) | → add `hybrid-*` + extended `noncanon-*`; state new count (T1) |

**Honest headline:** the network is already hybrid; the legacy suite lives only in the CLI download. The drill
migrates the CLI's own testbed credentials (REISSUE + prev_leaf), then audits staging to *prove* it is already
hybrid — the migration is real where legacy exists, and honest where it does not.

## Tasks (in order)

- **T1 — Hybrid CLI (flagship).** keygen/sign/verify → Ed25519 + ML-DSA-65, both-or-invalid parity with core/SDK;
  `@noble/post-quantum` bundled so the single-file CLI still runs with just `node`; every external decode via the
  one strict canonical gateway (D-029); versioned key/bundle formats (legacy named, never silently reinterpreted).
- **T1b — downgrade vectors.** strip ML-DSA → `alg_downgrade` fail-closed; mismatched ML-DSA key → fail; legacy
  Ed25519-only → fails closed by default, accepted **only** under the T2 legacy flag. Extend the differential
  corpus (state the new count); all three implementations agree on every vector incl. `hybrid-*` / `noncanon-*`.
- **T1c — measure, state numbers.** hybrid sig sizes, sign/verify timings on the reference machine, bundle-size
  delta; replace the docs' "Ed25519-only" line with the measured hybrid reality.
- **T2 — `ainra migrate <dir>`.** REISSUE every live credential to hybrid: fresh window, prev_leaf continuity to
  the legacy leaf, overlap honored; **dry-run prints the plan**; nothing deleted, history only grows.
- **T2b — policy epoch.** `--accept-legacy-until <epoch>`; default after migration **OFF** (Ed25519-only →
  `alg_downgrade`); existence + default + rationale logged **D-0xx**.
- **T2c — run the drill.** (a) local testbeds migrated; (b) staging audited — hybrid confirmed *measured*, any
  straggler REISSUEd (expected 0); (c) flip staging policy hybrid-required; (d) prove a legacy credential that
  verified in (a) now fails closed with the named reason while its hybrid successor verifies, and prev_leaf walks
  the boundary in the log **and** the on-site explorer. Transcript → `docs/drills/SUITE-MIGRATION-01.md`; suite mix
  shown honestly on status/scan during the overlap.
- **T3 — distributable ceremony.** participant CLI (file-based rounds, air-gap-friendly) + coordinator, transcript
  byte-compatible; `make ceremony-rehearsal-multi` — 5 shares across ≥2 isolated processes, timed, transcript
  verified. Changes **no DoD row**; M15 runbook gains the multi-party appendix.
- **T4 — witness kit v2.** single-binary `witnessd`, one-file config, self-declared metadata (shown as
  self-declared), verifier-side quorum-`k` docs with worked examples; re-time the <10-min outsider onboarding;
  witness diversity on status/scan from live data.
- **T5 — push status = ADR-018 (advisory transport, pull sovereign).** optional SSE/webhook announces deltas;
  the verifier still fetches + validates the signed delta + enforces freshness; **suppression** → pull fails closed
  on schedule; **forgery** → ignored. SDK optional subscriber triggers only the normal refresh path. Append ADR-018
  to the MTS with those two threat cases as its rationale.
- **T6 — release v0.2.0.** version bumps everywhere (CLI/SDK/core/site via live adapters, nothing hand-editable
  that can drift); outsider CHANGELOG; rebuilt CLI artifact, hybrid demo re-run + output pasted; reproducibility
  re-proven byte-for-byte; manual delta chapters (issue/verify/renew show hybrid); `docs/drills/` linked from the
  manual + status page; D-0xx ≥ {legacy-policy default, push-advisory, ceremony-transport}.
- **Acceptance.** clean clone → `preflight` + `diff` green with the extended corpus (state N); the drill transcript
  exists with real before/after counts + the legacy-fails/hybrid-passes proof against staging;
  `ceremony-rehearsal-multi` green + timed across isolated processes; witness onboarding re-timed; both push
  threat-tests green; the rebuilt CLI's hybrid demo output pasted; versions consistent everywhere; **DoD table
  untouched** — the three real-world rows (distributed public ceremony, ≥3 external verifiers, 14-day soak) remain
  honestly pending and are named in the CHANGELOG as exactly that.
