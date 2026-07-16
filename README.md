<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# AINRA — reference implementation (M1 + M2 + M3 + M4 + M5 done)

**AINRA** is the neutral root of AI-agent identity: it *accredits* registrars, *anchors* names, *revokes*, and
*logs* — and it never issues credentials or scores anyone. This repository is the production-track reference
implementation. See **[docs/STATUS.md](docs/STATUS.md)** for the exact, honest state, and
**[docs/PLAN.md](docs/PLAN.md)** for the one merged execution plan.

> Read **[docs/AINRA_Master_Technical_Specification_v1.md](docs/AINRA_Master_Technical_Specification_v1.md)** (the
> normative engineering spec — wins conflicts) and **[docs/AINRA_I_The_Standard.md](docs/AINRA_I_The_Standard.md)**
> (the public standard) first. Every deliberate deviation is logged in **[docs/DECISIONS.md](docs/DECISIONS.md)**.

## Quick start (the acceptance bar)

```sh
make test      # cargo test --release --workspace — 99 tests (core + directory + frost + ceremony + registrar + service)
make vectors   # regenerate 660 passport + 24 delegate-revocation + 17 delta + 9 directory CC0 vectors + self-check
make diff      # differential: core vs sdk-ts vs P0 — verdicts 684/684, canon 10/10, delta 17/17, directory 9/9
```

All go green in well under 10 minutes on a laptop (the release build is shared between `test` and `vectors`, so the
heavy compile is paid once). `make ci` runs the full local gate (adds fmt, clippy, S7, license, no-network, fuzz
smoke). See it move:

```sh
make drill     # the M2 transparency pipeline end-to-end — the witness catches an injected fork
make console   # local passport-book viewer + LIVE verify API (tamper switches → exact reasons)
cargo run --release -p ainra-cli-rs -- demo   # M3: issue → verify → revoke → re-verify, one process, real crypto
cargo run --release -p ainra-cli-rs -- seed apps/registrar-explorer/data   # build the fictional registry
make explorer  # the registrar explorer over that registry (search / filter / sort / verify trace / revoke)
make scale     # the billion-device proof: builds a REAL 1-billion-lineage status list, 16M-leaf trees,
               # sharded issuance — measures everything → docs/SCALE.md (measured vs structural, labeled)
make ceremony  # M4: FROST 5-of-9 DKG + SLH-DSA dual root → signed directory → mint/verify a real passport →
               # revoke the delegate (passport → checkpoint_invalid) → rotate (VALID again) → replayable transcript
make testbed   # M5 the WEDGE: live registrar → accredit into a signed directory → 5-line ainra-verify → VALID;
               # revoke → INVALID; verify-latency. Local, offline, ~5-line integration (see examples/verify-5-lines.mjs)
```

## Layout

| Path | What |
|---|---|
| `crates/ainra-core/` | **The product.** Pure library (no I/O, no network, no clock): canonical encoding, hybrid Ed25519+ML-DSA-65 sign/verify, SLH-DSA checkpoints, RFC 6962 Merkle, passport schema, TSL, delegation, mandates, and the 9-step `verify` → `Verdict`. |
| `crates/ainra-core/examples/sample_passport.rs` | Generates one real, fully-signed illustrative credential (used by `samples/`). |
| `crates/ainra-cli-rs/` | **The `ainra` CLI (M3)** — offline + persistent, over core+services: `init/issue/verify/log-verify/revoke/present/status/fresh-head/deltas/seed/demo`. |
| `crates/ainra-ceremony/` | **The M4 root ceremony (signing side, never in verify)** — FROST 5-of-9 DKG + SLH-DSA dual root → dual-root-signed directory + delegate certs + replayable transcript (`make ceremony`). |
| `packages/sdk-ts/` | **`@ainra/sdk`** — verify-only mirror (impl #2, byte-matches canon) + the GA **`Verifier`** (M5, 5-line verify from a signed directory). |
| `packages/middleware/` | **`@ainra/middleware` (M5)** — the fail-closed verifier gate (`ainraGate` for Connect/Express + `checkRequest` for edge). |
| `apps/cli-node/` | The P0 Node CLI, imported **as-is** — implementation #3 for the canonical differential. |
| `apps/landing/index.html` | The v12 marketing site — **the canonical source of the AINRA brand** (sigil, palette, type). Every other surface, including `samples/`, derives its design from this file; see `docs/DESIGN.md`. |
| `apps/console/` | Local test console — passport-book viewer + LIVE verify API over `sdk-ts` (`make console`). |
| `apps/registrar-explorer/` | **The registrar explorer (M3)** — a functional client-side app over a signed registry export: search / filter / sort / URL-state / 9-step verification trace / revoke workflow. |
| `services/ainra-services/` | **M2 transparency pipeline + M3 registrar-box** — `logd` + `witnessd` + `statusd` (now delta+fresh-head) + the `registrar-box` issuer engine & daemon, thin over `ainra-core` (`make drill`). |
| `tools/vector-gen/` | Deterministic CC0 conformance-vector generator + replay checker + `--canon`/`--bench`. |
| `tools/render-samples.mjs` | Renders `samples/data/*.json` into v12-design passport-card SVGs. |
| `tools/diff-harness/` | The 3-way differential harness (`make diff`). |
| `tools/s7-lint.mjs`, `tools/license-check.mjs` | Neutrality (no real company names) + license-header gates. |
| `vectors/v1/` | 684 CC0 passport vectors; `vectors/v1-delta/` 17 delta/fresh-head; `vectors/v1-directory/` 9 directory vectors (CC0). |
| `samples/` | Three illustrative passport cards (valid / delegated / revoked) — real crypto and a real computed verdict, illustrative field values. See `samples/README.md`. |
| `fuzz/` | cargo-fuzz targets (parser / TSL / canon); `tools/fuzz-smoke.sh` runs an in-process no-panic smoke without nightly. |
| `docs/` | Spec, Standard, STATUS, DECISIONS, PLAN + PLAN-M1/M2/M3/M4, DESIGN, BENCHMARKS, **SCALE**. |
| `_archive/` | Historical / superseded — the pre-M1 Node/TS prototype, kept for reference only. See `_archive/LEGACY.md`. Not part of the shipped product. |

## Prime directives (brief §0)

Nothing fake ever · no real company names (registrars are `registrar-NN`, operators `acme`/`globex`/`operator-NN`) ·
zero telemetry, `ainra-core` makes no network calls · only audited crypto libraries · **both signatures or invalid**
· **logged-before-valid** · fail closed everywhere.

## Licensing

Code is dual-licensed **Apache-2.0 OR MIT** (`LICENSE-APACHE`, `LICENSE-MIT`). The conformance vectors are **CC0**
(`vectors/LICENSE`).
