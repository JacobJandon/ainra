<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M5 — the verification wedge: SDK GA + middleware + live testbed

M5 per MTS §27 + the **Execution Playbook** (wk8): ship the wedge — **verify in ~5 lines**, local, offline,
fail-closed — so a verifier estate can gate agent traffic in a 10-minute integration. The playbook is explicit:
verification is the wedge; issuance follows demand. The verify path is static artifacts + client-side proof
checking — it never changes; M5 only *packages* it for adopters.

## What M5 delivered (all green under `make`)

1. **`@ainra/sdk` GA `Verifier`** (`packages/sdk-ts`). Build once from a **dual-root-signed directory**
   (`Verifier.fromDirectory` / `fromDirectoryB64` → the trust anchors + revoked-delegate set, or `null` if the
   directory is not authentic), then `.verify(bundle, now)` any number of presentations. Two hardenings over the
   raw `verify`: the verifier uses **its own clock** and **the directory's revoked-delegate set** — a presenter can
   neither dictate `now` nor omit its own revocation. **Never throws**: a structurally-broken bundle returns an
   `invalid` Verdict, never a crash, never a wrong `valid`. The `PresentationBundle` type is exactly the
   conformance corpus's `presentation` block, so the SDK and the vectors share one decode path (diff stays 684/684).

2. **`@ainra/middleware`** (`packages/middleware`) — the gate. `ainraGate(verifier, opts)` is Connect/Express
   `(req, res, next)`: reads the passport from a header (or `req.body`), verifies, and either `next()`s (attaching
   `req.ainra`) or answers **403 fail-closed** with a machine-readable `x-ainra-reason`. `checkRequest(verifier,
   bundle)` is the framework-agnostic edge form → `{ allow, reason?, verdict }`. **4 fail-closed tests** prove: a
   valid directory builds a verifier, a tampered one yields `null`; every malformed bundle (undefined / non-JSON /
   partial / wrong-type / huge / base64url-garbage) is denied and **nothing throws**; the gate 403s with no header
   and on a garbage header, never calling `next()`.

3. **The presentation bundle** — `registrar-box` gained `GET /present?sub=&now=` → a self-contained bundle
   (`RegistrarBox::present`) whose fields map 1:1 to what the SDK verifies: base64url claims + issuer signature,
   chain keys + per-hop proofs, the current signed status list, and the log anchor (checkpoint + inclusion proof).

4. **Directory over live registrars** — `ainra-ceremony::accredit_external` + the `accredit` bin read a running
   registrar's published `/accreditation` (public keys only), DKG a FROST + SLH dual root, and write a
   dual-root-signed `directory.json` + `roots.json` — self-verified before writing. This composes the *real*
   registrar daemon with the *real* ceremony.

5. **`make testbed`** (`tools/testbed.sh`) — the wedge, end to end with real components: start the registrar-box
   daemon → `accredit` its keys into a signed directory → issue a passport → `GET /present` → the **5-line
   `ainra-verify`** step → **VALID**; then **revoke** → re-present → **INVALID (revoked)**; then a verify-latency
   line. Nothing asserted by narration — the run fails if the gate ever allows a revoked passport.

6. **`ainra-verify` CI/edge step** (`tools/ainra-verify.mjs`) — verify a bundle against a directory, exit `0`
   VALID / `1` INVALID / `2` untrusted-directory. Drop it into a pipeline as an `ainra-verify` step. `--bench N`
   reports verify latency (the "cost is local CPU, once per relationship" number). The **5-line quickstart** lives
   at `examples/verify-5-lines.mjs` — the same five lines an integrator writes against `@ainra/sdk`.

## Playbook alignment

- **Wedge = verification** (free, local, offline, ~5-line): the `Verifier` + middleware + `make testbed` are that,
  literally. **TTFV**: the 5 lines + the testbed prove a running-registrar → verified-passport in one command;
  per-verify cost is sub-millisecond local CPU (root does zero work).
- **`ainra-verify` step** (Playbook §6 CI action): shipped.
- **Verify path never changes** (Playbook §4): M5 added packaging only — the SDK reuses the exact `verify` + the
  conformance decode; the diff is unchanged at 684/684 + directory 9/9.
- **One-way doors respected**: no scores, no fees to verify, no telemetry; the gate is pure over the SDK.

## Deferred to M6–M8 (recorded, not faked)

| Item | Milestone |
|---|---|
| Live status **signature** verification in the bundle path (currently the status list is a freshness-gated verifier input, as in the core contract; verifying its publisher signature needs the registrar's status key in the directory) | M6 |
| Framework adapters (agent SDKs) + a published npm release + the conformance leaderboard site | M5 tail / M6 |
| Real external-verifier onboarding (≥3 in production paths) | external (K4, 05 Sep) |
| Multi-witness fork drill · reproducible builds ×2 + mirrors · `make genesis-local` + Genesis + DoD | M6 · M7 · M8 |

## Gates

`make wedge-build` + `make wedge-test` (4 middleware fail-closed tests) · `make testbed` (VALID→revoke→INVALID +
latency) · `make diff` (684/684 + directory 9/9 — unchanged) · `make test` / `ceremony` / `scale` · fmt/clippy/S7/
license clean. See STATUS.md.
