<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Security advisories affecting AINRA

Every advisory that reaches a dependency on a path we ship gets an entry here: what it is, where it actually
touches us, what we did, and how we proved the fix. `SECURITY.md` promises a public post-mortem for every finding;
this file is where the technical scoping lives, and the post-mortem links to it.

Scoping an advisory is **not** the same as softening it. The scope decides how loudly we have to talk about
exposure; it never decides whether we fix it. Every advisory below is fixed regardless of blast radius.

---

## RUSTSEC-2025-0144 — timing side-channel in ML-DSA decomposition

| | |
|---|---|
| **Advisory** | [RUSTSEC-2025-0144](https://rustsec.org/advisories/RUSTSEC-2025-0144) · [GHSA-hcp2-x6j4-29j7](https://github.com/RustCrypto/signatures/security/advisories/GHSA-hcp2-x6j4-29j7) |
| **Crate** | `ml-dsa` — the ML-DSA-65 half of our hybrid signature |
| **Affected** | `< 0.1.0-rc.2` — we shipped **0.0.4** |
| **Fixed in** | `>= 0.1.0-rc.3` — we moved to **0.1.1** |
| **Severity** | 6.4 medium · adjacent network · low privileges · high attack complexity |
| **Published** | 2025-12-12 · **found by us 2026-08-06** (see "Why our CI missed it") |

### What the defect is

`decompose` computed `r1.0 / TwoGamma2::U32` with a **hardware division instruction**, whose latency is
operand-dependent on common CPUs. It is reached through `high_bits()` and `low_bits()`.

Per the advisory, those are called during **signing**, over values derived from two secret key components:

* `s2`, via `(&w - &cs2).low_bits()`
* `t0`, via `Hint::new()`

An attacker who can trigger many signatures and measure their timing precisely can, in principle, recover
information about those secret components.

### Where this touches AINRA — traced, not assumed

**The verify path: no secret to leak.**
`ainra_core::crypto::verify_hybrid` ([crates/ainra-core/src/crypto.rs](crates/ainra-core/src/crypto.rs)) takes a
`HybridPublic`, a message, and signature bytes. Every input is public by construction — a verifier holds no ML-DSA
secret at any point, and the passport it checks was signed by someone else. ML-DSA *verification* does reach
`Decompose` (through `UseHint`/`HighBits` when recomputing `w'`), so the vulnerable code executes; but it executes
over public values, and a timing channel that leaks public data leaks nothing.

That covers, with no exposure:

* the browser verifier (`crates/ainra-wasm`) and everything the live site runs
* `ainra verify` in the CLI, `@ainra/sdk`, `@ainra/middleware`, `packages/sdk-py`
* `crates/ainra-adapter` — it has no signing entry point at all

**The signing path: this is the real concern.**
`HybridKeypair::sign` holds `ml_dsa::KeyPair<MlDsa65>` and calls `sign_deterministic`. Ranked by how reachable an
attacker's timing measurements are:

| Signer | Long-lived secret? | Network-reachable? | Assessment |
|---|---|---|---|
| **`registrar-box`** ([services/.../bin/registrar_box.rs](services/ainra-services/src/bin/registrar_box.rs)) — "a live AINRA registrar over HTTP" wrapping `RegistrarBox`, which signs issued claims and delegation hops on request | **yes** — the issuer key | **yes** — HTTP daemon | **The genuine exposure.** An adjacent attacker who can request issuance repeatedly and time the responses matches the advisory's model directly. |
| `crates/ainra-ceremony` | yes — ceremony material | no — run air-gapped, one-shot, by design | Low. Not exposed to an online timing oracle, but ceremony material is the most valuable key we have, so it is fixed on the same schedule. |
| `tools/vector-gen`, tests, examples | no — seeded, published TEST keys | no | None. The "secret" is a public seed printed in the corpus. |

**Was it exploited?** No evidence either way, and we will not claim otherwise. No production root exists, no
registrar has ever issued to a real counterparty, and logs sealed by the real root remain **0** — so the population
of secrets that could have leaked is the staging TEST-ROOT and locally-run boxes. That is a statement about how
early we are, not a mitigating control, and it stops being true the day a real registrar runs.

### Why our CI missed it for eight months

`security.yml` ran `cargo audit --deny warnings` on every push. `--deny warnings` **short-circuits on the first
denied finding**, and the first finding was an unrelated *unmaintained* notice (RUSTSEC-2023-0089,
`atomic-polyfill`, reached only through the signing-side FROST dependency). The job went red on the notice and
never reached the real vulnerability underneath it. The red was being read as "that known unmaintained crate
again".

Three separate failures made that possible, and all three are fixed:

1. **One finding could hide another.** `cargo-audit` now reports *every* finding before failing, so a notice can
   never mask a vulnerability again.
2. **A permanently-red job teaches people to ignore it.** The two long-red security jobs
   (`clusterfuzzlite` had never built; `scorecard` referenced a tag that does not exist) are green, and every
   security job now carries a negative control proving it *can* pass — see [docs/_archive/plans/PLAN-M26.md](docs/_archive/plans/PLAN-M26.md).
3. **We had no ground truth outside our own corpus.** The 745 conformance vectors were generated *by* the
   vulnerable crate, so they could never have adjudicated a change to it. FIPS 204 known-answer tests are now
   wired in as an external oracle.

### The fix

`ml-dsa` `0.0.4` → **`0.1.1`** across the workspace, proven against evidence that does not originate with the
crate being replaced. The full proof — KATs, corpus, four-way differential, cross-implementation signing, byte
reproducibility, clean-clone board — is in [docs/_archive/plans/PLAN-M26.md](docs/_archive/plans/PLAN-M26.md) and the post-mortem in
[SECURITY.md](SECURITY.md).

**The wire format is fixed by FIPS 204.** A signature produced under 0.0.4 must still verify under 0.1.1; if any
existing vector had flipped, that would have been a conformance finding to investigate — never a reason to
regenerate the corpus.

---

## RUSTSEC-2023-0089 — `atomic-polyfill` unmaintained

Not a vulnerability: an unmaintained notice. Reached only as
`ainra-ceremony → frost-ed25519 3.0 → frost-core → postcard → heapless 0.7 → atomic-polyfill`, i.e. the signing
side. `cargo tree -p ainra-core` is clean, as are `ainra-adapter`, `ainra-wasm`, `ainra-cli-rs`,
`ainra-services` and the vector generator — nothing a relying party executes touches it. `frost-ed25519 3.0.0` is
the current release and pins the dependency internally, so no upgrade removes it today.

Recorded as a single narrowly-scoped ignore in [.cargo/audit.toml](.cargo/audit.toml) with its revisit condition.
It is one advisory ID, not a category: any other finding — including a future real vulnerability in that same
crate — still fails the gate. Silencing this notice is what let RUSTSEC-2025-0144 become visible.
