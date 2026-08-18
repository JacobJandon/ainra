<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M4 — FROST threshold root + dual-root registrar directory + delegate revocation/rotation

M4 per MTS §27 (§13/ADR-001/ADR-002): the **real threshold root**, the **signed registrar directory** (the concrete
"accredit registrars" function), and **delegate-cert revocation + rotation** — all verification-identical to the
M1–M3 stand-ins, so the corpus + verifier are unchanged and the whole thing is cross-checked by `sdk-ts`. Prime
directive unchanged: **nothing fake** (a below-threshold or forged signature is never accepted, anywhere).

## What M4 delivered (all green under `make`)

1. **FROST 5-of-9 threshold Ed25519 root** (`crates/ainra-ceremony/src/frost.rs`, audited ZF `frost-ed25519` 3.0,
   RFC 9591). A real 3-round **DKG** among 9 custodians (the group secret is never assembled) + 2-round threshold
   signing with a 5-signer quorum. The group verifying key is a standard 32-byte Ed25519 key and an aggregated
   signature is a standard 64-byte RFC 8032 signature — so **`ainra-core` verifies it with plain Ed25519 and never
   links against FROST** (N7 preserved). Proven: a 5-of-9 signature verifies through `ainra_core::crypto::
   ed25519_verify`; **4-of-9 cannot sign** (D-018).

2. **Dual-root registrar directory** (`crates/ainra-core/src/directory.rs`). `Directory` maps registrar id → its
   hybrid issuer key + log-checkpoint SLH root, carries `epoch`/`issued_at` + the revoked-delegate list, and is
   signed by BOTH roots (FROST-Ed25519 group key + SLH-DSA-128s) over one canonical body. `accredit(root_ed,
   root_slh)` requires **both** signatures + **strictly sorted/unique** entries; any failure → `unknown_registrar`
   (fail closed). It returns the `TrustAnchors` a verifier feeds to `verify::verify` **plus** the revoked-delegate
   set — trust anchors are now *derived from a signed artifact*, not hand-built (D-019). Pure (N7).

3. **Delegate-cert revocation + rotation** (`checkpoint::DelegateCert::fingerprint` + `verify::verify`). A cert's
   identity is `SHA-256(canonical signing bytes)` — it names exactly one cert, so rotating the same delegate key
   mints a *different* fingerprint. `verify::verify` gained a `revoked_delegates` input (from the accredited
   directory): after a checkpoint's delegate signature verifies, a revoked fingerprint makes it `checkpoint_invalid`
   — fail closed, even though the cert itself still verifies (the online key is dead network-wide). This is the real
   mechanism D-017 deferred.

4. **The genesis ceremony rehearsal** (`crates/ainra-ceremony/src/bin/ceremony.rs`, `make ceremony`). End to end,
   real crypto: DKG the dual root → sign the directory → **verify its own output** the way a stranger would
   (`accredit`) → mint a **real passport**, verify it VALID → **revoke** that registrar's checkpoint delegate in a
   new directory epoch → the SAME passport now verifies to `checkpoint_invalid` → **rotate** to a fresh delegate →
   VALID again → write `directory.json` / `directory-epoch2.json` / `roots.json` / `transcript.json` + its SHA-256,
   then re-verify the written directory from disk. The run fails if any invariant breaks — nothing asserted by
   narration. (This one artifact covers both the ceremony and the rotation/revocation drills.)

5. **Cross-implementation ripple.** `sdk-ts` gained `verifyDirectory` (dual-root accredit mirror) + `certFingerprintB64`
   + the delegate-revocation check in the passport verifier. `vector-gen` emits **24 delegate-revocation passport
   vectors** (a valid delegate checkpoint whose cert fingerprint is revoked → `checkpoint_invalid`) and a **9-vector
   directory corpus** (`vectors/v1-directory/`: valid / empty / with-revocation / wrong-ed-root / wrong-slh-root /
   tampered-entry / unsorted / duplicate / malformed-fingerprint). The differential (`make diff`) now runs **five phases**: A verdicts
   **684/684** (incl. delegate revocation), B canon 10/10, C reject 4/4, D delta 17/17, **E directory 9/9**. Both new
   corpora are replay-gated (`--check-directory`) locally and in CI.

## Deliberately deferred to M5–M8 (recorded, not faked)

| Item | Why later |
|---|---|
| Real recorded ceremony (live custodian entropy, ≥5 jurisdictions, transcript hash published) | external-world M8; the rehearsal is deterministic (labeled TEST seed), single-host |
| FROST **witness** thresholding + real witness-network onboarding | M6/external; M2's single-witness fork drill stands |
| Directory **distribution** (mirrors, rollback-monotonicity enforcement across fetches) | the type carries `epoch`; the fetch/rollback policy is client-side deployment work (M5/M7) |
| Verifier middleware + TS SDK GA + live testbed | M5 |
| Reproducible-build proof of the published artifacts | M7 |
| One-command `make genesis-local` (ceremony → registrars → fork drill → transcript) | M8 |

## Gates (the acceptance bar, MTS §28)

`make test` (core unit incl. 3 directory + 10 property + 2 frost + 2 ceremony + registrar + service) · `make vectors`
(660 passport + 24 delegate-revocation + 17 delta + 9 directory, all self-checked, replay-gated) · `make diff`
(A 684/684, B 10/10, C 4/4, D 17/17, **E 9/9**) · `make ceremony` (dual-root genesis + revoke→invalid + rotate→valid)
· `make drill` / `make demo` / `make scale` · S7 / license clean · `cargo fmt`/`clippy -D warnings` clean. See STATUS.md.
