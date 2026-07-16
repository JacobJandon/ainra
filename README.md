<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# AINRA — the neutral root of AI-agent identity

<!-- CI badge: replace <owner> with your GitHub org/user after pushing -->
[![CI](https://github.com/<owner>/ainra/actions/workflows/ci.yml/badge.svg)](https://github.com/<owner>/ainra/actions/workflows/ci.yml)

**AINRA** does exactly four jobs — **accredit · anchor · revoke · log** — and nothing else. It answers the three
questions every counterparty asks about an AI agent — *who is behind it, what may it do, is it still trusted right
now* — with **facts, never scores, never a price, never the decision itself.** Doctrine: **login is ours; the
decision is the verifier's.** Everything is built so a stranger can verify **offline, in ~5 lines, with the root
dark**, trusting the **source** — not us.

This repository is the production-track reference implementation. The **normative spec** is
[docs/AINRA_Master_Technical_Specification_v1.md](docs/AINRA_Master_Technical_Specification_v1.md) (it wins
conflicts); the **public standard** is [docs/AINRA_I_The_Standard.md](docs/AINRA_I_The_Standard.md); every deliberate
deviation is in [docs/DECISIONS.md](docs/DECISIONS.md).

## Honest status

The **MTS §27 engineering ladder M1–M8 is complete** and **M9** makes it committed, CI-gated, and executable by
strangers. What remains to *ship the prototype* is **not code** — it is three real-world events (a recorded ceremony,
≥3 independent external verifiers, a 14-day/3-region revocation soak). M9 builds the machinery that lets others run
those events **without us in the room**, and proves each at smoke scale. See the honest, per-row picture in
[docs/DOD.md](docs/DOD.md) and [GENESIS-CHECKLIST.md](GENESIS-CHECKLIST.md).

> Nothing here is asserted; if it says green, a `make` target proves it. Logs sealed by the real root: **0** — the
> Genesis ceremony has not happened yet, and we say so.

## Quick start (3 commands)

```sh
make test          # cargo test --release --workspace — the full test suite (RELEASE required; see the note below)
make genesis-local # the whole stack on one laptop: dual root → 2 registrars → verify root-dark → revoke/forge fail
                   # closed → an injected fork caught by a witness quorum → a signed transcript
make verifier-kit-smoke   # become an external verifier: verify root-dark + reject revoked/forged with only @ainra/sdk
```

All go green in minutes on a laptop. `make diff` runs the 3-way differential (684/684). `make ci` runs the full
local gate; CI runs it on every push (see `.github/workflows/ci.yml`).

> **Release-test trap:** `make test` uses `--release` on purpose. A *debug* build stack-overflows one crypto-heavy
> test (large unoptimized ML-DSA/SLH-DSA stack frames) — not a bug; use `make test`.

## See it work

```sh
make drill            # witness QUORUM catches an injected fork (5 witnesses, k=3, refused 5/5)
make drill-networked  # the same quorum over HTTP — independently-operated witnesses (kits/witness)
make ceremony-dry-run # rehearse the 5-of-9 ceremony choreography; a witness recomputes the transcript hash
make soak-smoke       # measure revocation propagation (p50/95/99) into a signed, tamper-evident report
make repro            # rebuild every published artifact byte-for-byte from source (729 files)
make verify-mirror MIRROR=<dir>   # any third party byte-verifies a mirror, root dark
```

## Kits — run the external events yourself (`kits/`)

| Kit | What a stranger does | Proof |
|---|---|---|
| [`kits/verifier/`](kits/verifier/) | verify root-dark + reject revoked/forged with only `@ainra/sdk`; emit a signed attestation | `make verifier-kit-smoke` |
| [`kits/ceremony/`](kits/ceremony/) | rehearse the recorded 5-of-9 ceremony (RUNBOOK); a witness recomputes the transcript hash | `make ceremony-dry-run` |
| [`kits/soak/`](kits/soak/) | measure revocation p95 from ≥3 regions into a signed report; SLO computed, never asserted | `make soak-smoke` |
| [`kits/witness/`](kits/witness/) | run independently-operated witnesses over HTTP; a fork can't reach quorum | `make drill-networked` |

## Architecture

```
                      the STANDARD + CC0 conformance vectors (vectors/)  ── anyone builds against these
                                          │
  crates/ainra-core  ── the pure verify/issue library (N7: no I/O, no clock) ── the 9-step verify, 15 reasons
        │  hybrid Ed25519 + ML-DSA-65 (both-or-invalid) · RFC 6962 Merkle · Token Status List
        ▼
  crates/ainra-ceremony (FROST 5-of-9 + SLH-DSA dual root, signing side, NEVER in verify)
  services/ainra-services (logd · statusd · witnessd + k-of-N quorum · registrar-box)
        │
        ▼
  packages/sdk-ts (@ainra/sdk — independent verify mirror #2 + the 5-line Verifier) · packages/middleware (the gate)
  apps/cli-node (P0 — differential impl #3)
        │
        ▼
  make genesis-local — the whole world on one laptop  ·  make repro / make verify-mirror — reproducible + mirrorable
```

The verify path is **RFCs + FIPS + OSI-licensed deps only** — no vendor, no bespoke crypto. Three independent
implementations (core, sdk-ts, P0) agree on every one of the 684 vectors (`make diff`).

## Prime directives (brief §0)

Nothing fake ever · no real company names (registrars `registrar-NN`, operators `acme`/`globex`/`operator-NN`; the
S7 linter enforces it) · **zero telemetry** in shipped components (`ainra-core` makes no network calls; any traction
metric is opt-in, count-only, in the kit layer only) · only audited crypto libraries · **both signatures or invalid**
· **logged-before-valid** · fail closed everywhere.

## Contributing & security

- [CONTRIBUTING.md](CONTRIBUTING.md) — how to build, the gates your PR must pass, and the **DCO** sign-off (not a CLA).
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Contributor Covenant.
- [SECURITY.md](SECURITY.md) — how to report; our **fail-closed** posture; we adversarially review every milestone.

## Licensing

Source **code** is dual-licensed **Apache-2.0 OR MIT** ([LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT)).
The **conformance vectors** and other CC0-marked data artifacts are public domain **CC0** ([LICENSE-CC0](LICENSE-CC0))
— the shared test corpus is ownable by no one.
