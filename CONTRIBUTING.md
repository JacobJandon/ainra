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
make preflight      # the one-command board a reviewer expects green: build+test · diff · genesis-local · kit smokes · S7 · license · repro
make audit          # the publish gate: S7 (incl. commit messages) · license headers · gitleaks over full history
make ci             # fmt · clippy -D warnings · test (release) · vectors · diff · sdk-test · S7 · license · N7 · fuzz
```
CI (`.github/workflows/ci.yml`) runs all gates on every push/PR, including `make repro`, `make verify-mirror`,
`make check-freeze`, and the end-to-end integration. **`make test` uses `--release` deliberately** — a debug build
stack-overflows one crypto-heavy test.

- Touching `ainra-core`? It stays **pure** (no `std::net`/`std::fs`/clock/env — the N7 gate checks this).
- Changing the verify path or a reason string? That is a **frozen contract** (D-004) — it needs an ADR + regenerated
  vectors + the differential still passing, and almost certainly a DECISIONS entry.
- Editing a normative doc (`AINRA_I_The_Standard`, the MTS, `DESIGN.md`)? They are **frozen** (`make check-freeze`);
  update `docs/FREEZE.sha256` with `make freeze` in the same PR and explain why in the description.

## The conformance-first rule (verify-logic PRs)

Four independent implementations — the Rust core, the TypeScript SDK, the reference CLI, and the Python verifier —
must agree **byte-for-byte on every vector, on verdict *and* reason**. That agreement is the product; a PR that
touches verify logic is judged against it first:

1. **`make diff` stays green.** All four columns, the full corpus (`1009` passport + `17` delta + `9` directory).
   A disagreement is not a "flaky test" — it is either a bug in your change or a real ambiguity in the Standard, and
   both outcomes need writing down before the PR moves.
2. **A gate that checks one place a claim is made does not check the claim.** Every public fact — a version, a
   count, a capability — has ONE source of truth, is asserted in N places, and is verified by a gate that scans all
   N, including **generated output and the sources it is generated from**. `make claims-check` enforces this; the
   registry is [`docs/CLAIMS.md`](docs/CLAIMS.md).

   This rule is written down because the same defect landed three times: `reasons-check` compared three of four
   implementations and missed a reason that had been absent from the Python SDK's closed set for a milestone; a
   witness-gap gate read the built page while the edit that mattered went to the include it is generated from, so
   it passed while the deployed footer said the opposite; and an RFC-adapter line was corrected in one file and
   survived in a second. Asserting an existing claim somewhere new **fails the build until you register it** — and
   registering it is what makes you confirm it is true in the new place.

3. **Any corpus delta is explained in the PR body.** If your change adds, removes, or alters vectors, say which and
   why in plain words: what behaviour is now pinned that was not pinned before. Silent corpus edits are the one
   thing a reviewer will always reject — the corpus is the contract.
4. **New behaviour arrives with a vector, not just a unit test.** A unit test protects one implementation; a vector
   protects all four, forever.
5. **`make conformance` stays green both ways** — the three in-repo verdict implementations pass clean over the same
   corpus hash, *and* the deliberately sabotaged adapter is still caught with named divergences. A conformance tool
   that cannot fail is theatre; if your change makes the broken adapter pass, the runner is what broke.

Adding vectors deliberately? Generate, never hand-write: `cargo run -p ainra-vector-gen -- --out vectors/v1 …`,
then `make diff`. Proposing a spec change? The MTS is the constitution — open a spec-question issue first, land the
ADR in `docs/DECISIONS.md`, then the code.

## A check that has never passed does not exist

**Every check you add must be shown to fail, and shown to pass, before it counts.** Not "the code looks right" —
run it both ways and paste both outputs.

This is not a style preference. In one milestone (M26) we found three checks in this repository that had never
once done their job, and each looked healthy from a distance:

| Check | What it appeared to be | What it actually was |
|---|---|---|
| `scorecard` | a published OpenSSF score | referenced `ossf/scorecard-action@v2`, a tag that does not exist — it had never resolved, so the score was never published |
| `clusterfuzzlite` | continuous fuzzing on the parsers | failed at *build* (`rustc 1.91 is not supported`) on every run — it had never fuzzed a single input |
| `cargo-audit` | advisories gated | short-circuited on an "unmaintained" notice, hiding a real timing side-channel in a **direct dependency of the verify path** |

A red job reads as "the check found something". Two of those three meant "the check never ran". That failure mode
is worse than having no check, because it buys false confidence and trains people to route around the red.

### Worked example: a check that passed while checking nothing

`tools/interop-verify.mjs` verifies that freshly-signed material is accepted by our two independent ML-DSA
implementations, and that each refuses a flipped bit. The first version did this:

```js
if (sdk.verifyHybrid(pk, msg, sig) !== "ok") bad("rejected a genuine signature");   // WRONG
if (sdk.verifyHybrid(pk, msg, tampered) === "ok") bad("accepted a flipped bit");    // WRONG, and silent
```

`verifyHybrid` returns **`null`** on success — `HybridResult = null | "alg_downgrade" | "sig_invalid"`. There is
no `"ok"`. So the first line reported every genuine signature as rejected (loud, and caught), and the second line
compared against a value that can never occur, so it reported **"3/3 flipped-bit refused" while testing nothing**
(silent, and nearly missed).

The loud half is not the lesson. The silent half is: a negative control that cannot fire is indistinguishable
from one that passes.

### What this means for your PR

- Add a **negative control** the same day you add the check — usually an env-gated corruption, as in
  `NEGATIVE_CONTROL=1 node tools/interop-verify.mjs` or `make wasm-diff-negative`. Prove it exits non-zero.
- **Paste both runs** in the PR: the failing one and the passing one.
- If a check cannot be made to fail on demand, say so explicitly rather than leaving it looking green.
- A gate that skips when its tooling is missing must **say so in the board output** (`[SKIP]` with the reason).
  Silence is indistinguishable from success.

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
