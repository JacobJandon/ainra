<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M2 — execution plan (≤15 bullets, per the working method)

Scope = MTS §27 M2 ("checkpoint pipeline + witness prereqs") **plus** the two D-009 deferrals the M1 review
surfaced, so the credential model reaches its full MTS §15 shape before services are built on it. Order matters:
core schema first (everything downstream consumes it), then services, then the ripple.

1. **Dual-signed hops (D-009a).** `ActLink` gains `sig_child_ed25519` + `sig_child_mldsa65`; a hop verifies only if
   BOTH the delegator's AND the delegatee's hybrid signatures verify over the same canonical hop bytes (child key =
   next hop's `from`-holder key, supplied hop-aligned by the caller like delegator keys). Missing → `alg_downgrade`;
   wrong → `sig_invalid`. Closes the "delegation laundering" gap (Standard §6 A3).
2. **Per-hop `log_leaf` (D-009a).** Each hop carries `log_leaf` = RFC 6962 leaf hash of its canonical signing bytes;
   the presentation carries one inclusion proof per hop against the same checkpoint. Absent/broken → `not_logged`.
3. **Dynamic mandates (D-009b).** `mandates_root` becomes operative: a presented mandate path binds via RFC 6962
   inclusion (each node's leaf under `mandates_root`), replacing the M1 in-passport-only path. In-passport `mandates`
   remains valid for static grants; when `mandates_root` is present the presented path MUST prove inclusion.
4. **did:web mapping (ADR-014).** `name.rs` gains the bidirectional `did:ainra:` ↔ `did:web:` mapping (pure
   string transform — resolution stays caller-side; the core still does no I/O).
5. **Consistency proofs.** `merkle.rs` gains RFC 6962 §2.1.2 consistency-proof generation (test log) + verification
   — the witness's core primitive (proves append-only between two checkpoints).
6. **Delegate signer (ADR-002).** `checkpoint.rs` gains a delegate model: TEST-ROOT (SLH-DSA) certifies a delegate
   Ed25519 key (canonical cert, expiry); checkpoints are signed by the delegate; verifiers accept root-sig OR
   (valid cert chain + delegate sig). Bad/expired cert → `checkpoint_invalid`.
7. **`services/logd`** (Rust): persistent append-only log daemon — submit leaf, get inclusion/consistency proof,
   signed checkpoint per batch (delegate signer). Storage = append-only JSONL + fsync; RFC 6962 semantics from
   ainra-core. Local HTTP (127.0.0.1), zero telemetry. *(Tessera swap-in remains the production target — D-011.)*
8. **`services/statusd`** (Rust): Token Status List publisher — signed list + `issued_at`, delta endpoint,
   fail-closed semantics documented; consumes the registrar key model from vectors.
9. **`services/witnessd`** (Rust): fetches checkpoints from logd, verifies consistency vs its last-seen checkpoint,
   cosigns (Ed25519 witness key), refuses + alarms on fork. An integration test injects a fork and asserts the
   witness catches it.
10. **Vectors:** new corpus revision (v1 stays; add dual-sig/hop-log/mandate-proof cases + regenerate) — every new
    failure mode gets ≥24 vectors; count stays ≥500.
11. **sdk-ts:** mirror all schema/verify changes byte-for-byte; diff harness must return to 100% agreement.
12. **Samples/console:** regenerate the book (stamps page's "DUAL-KEY SIGNED" becomes true); console gains tamper
    switches for the new failure modes (strip child sig, drop hop proof, fake mandate proof).
13. **Docs:** DECISIONS D-011..D-01x for every judgment call; STATUS.md rewritten honestly; BENCHMARKS regenerated.
14. **Gates:** `make ci` green end-to-end; adversarial review workflow over the M2 diff; findings fixed before done.
15. **Out of scope for M2** (recorded, not faked): FROST (M4), Tessera itself (infra), registrar-box (M3),
    TSL *delta compression* refinements (M3), real witness-network onboarding (external).
