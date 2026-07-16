<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Contributing to AINRA

AINRA is a **neutral root**: the bar is high and the rules are mechanical, on purpose. Thank you for helping.

## Ground rules (non-negotiable — the MTS wins conflicts)
- **Nothing fake, ever.** No stubbed verdicts, no asserted-not-measured numbers, no "TODO: real crypto".
- **Fail closed.** Any ambiguity resolves to reject. A gate that 500s or allows-on-error is a bug.
- **Both signatures or invalid · logged-before-valid.** Don't weaken these.
- **No bespoke crypto.** Use the audited libraries already vendored; algorithm changes go through an ADR + DECISIONS.
- **No third-party names anywhere** (code, fixtures, docs) — registrars are `registrar-NN`, operators `acme` /
  `globex` / `operator-NN`. The S7 linter enforces it.
- **Zero telemetry in shipped components** (`ainra-core`, the SDKs). Any traction metric is opt-in, count-only, and
  lives only in the kit/tutorial layer (see the kit READMEs).
- **Never weaken a test to make it pass.** Fix the code, or open an issue explaining why the test is wrong.
- Every deliberate deviation from the spec is logged in `docs/DECISIONS.md` (continue the `D-0xx` sequence).

## Build & gates (what your PR must pass)
Requires Rust `1.96` (pinned in `rust-toolchain.toml`) and Node 18+.

```sh
make ci             # fmt · clippy -D warnings · test (release) · vectors · diff · sdk-test · S7 · license · N7 · fuzz
make diff           # the 3-way differential must stay 684/684 (core · sdk-ts · P0)
make genesis-local  # the whole-stack end-to-end must stay green
```
CI (`.github/workflows/ci.yml`) runs all gates on every push/PR, including `make repro`, `make verify-mirror`,
`make check-freeze`, and the end-to-end integration. **`make test` uses `--release` deliberately** — a debug build
stack-overflows one crypto-heavy test.

- Touching `ainra-core`? It stays **pure** (no `std::net`/`std::fs`/clock/env — the N7 gate checks this).
- Changing the verify path or a reason string? That is a **frozen contract** (D-004) — it needs an ADR + regenerated
  vectors + the differential still passing, and almost certainly a DECISIONS entry.
- Editing a normative doc (`AINRA_I_The_Standard`, the MTS, `DESIGN.md`)? They are **frozen** (`make check-freeze`);
  update `docs/FREEZE.sha256` with `make freeze` in the same PR and explain why in the description.

## Developer Certificate of Origin (DCO — not a CLA)
We use the **DCO**, not a contributor licence agreement. You keep your copyright; you certify you have the right to
submit the contribution under the project's licences (Apache-2.0 OR MIT for code; CC0 for vectors). Sign off every
commit:

```sh
git commit -s -m "your message"     # adds a "Signed-off-by: Your Name <you@example.com>" trailer
```

By signing off you agree to the DCO (https://developercertificate.org/). PRs whose commits are not signed off will be
asked to amend.

## Style
- Rust: `cargo fmt` + `clippy -D warnings`; match the surrounding code's comment density and naming.
- Every source file carries the SPDX header `SPDX-License-Identifier: Apache-2.0 OR MIT` (data artifacts that are CC0
  use `CC0-1.0`); `make ci` checks headers.
- Keep security-critical bespoke code minimal (the two-maintainer rule / ≤1 kLoC budget, N11) — prefer composing the
  audited primitives.

## Reporting security issues
Do **not** open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).
