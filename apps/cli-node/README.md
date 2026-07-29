# ainra — reference implementation v0.2.0
Agent passports: issue, verify, revoke, with a hash-chained, checkpoint-signed transparency log.
**Hybrid Ed25519 + ML-DSA-65** throughout — both signatures mandatory, both-or-invalid — at parity with the Rust
core and the browser SDK. The download is **one self-contained file**: the audited `@noble/post-quantum` ML-DSA is
bundled in, so it runs with just `node` — no install, no `node_modules`, zero runtime dependencies. Node >= 18.

## The suite (measured on the reference machine)
Ed25519 (32 B key, 64 B sig) + ML-DSA-65 (1952 B key, 3309 B sig), so a hybrid signature is ~3.3 KB. One hybrid
sign ≈ 7 ms, one hybrid verify ≈ 3 ms (both halves). The single-file bundle is ~64 KB (~18 KB zipped).

## Honest limits (v0.2.0)
Single-key root — the threshold ceremony (FROST 5-of-9 + SLH-DSA) runs in the network's genesis; the participant
CLI is v0.2 work · 3 witness keys generated locally and labeled `(local)` (independent witnesses pending) · status
list is poll-based (push fabric pending). Everything else is real: tamper with any byte of a passport, cert, or log
line and verification fails.

## Suite migration (Drill 01)
A legacy Ed25519-only credential is **recognized and named**, never silently reinterpreted: by default it fails
closed as `alg_downgrade`; it verifies **only** during a migration overlap you opt into with `--accept-legacy`. A
credential whose ML-DSA half is present but broken or non-canonical is `sig_invalid` — rejected under **every**
policy, the flag included. `ainra migrate <dir>` REISSUEs every local credential to hybrid, carrying `prev_leaf`
continuity to the legacy leaf (nothing is deleted; `--dry-run` prints the plan first).

## Try it
    node bin/ainra.js demo          # full lifecycle in a clean directory (prints the hybrid suite line)
    node bin/ainra.js init
    node bin/ainra.js accredit registrar-07
    node bin/ainra.js issue ainra:registrar-07:acme-corp:invoicing@4.2.1 --operator "Acme Corp" --tier L3
    node bin/ainra.js verify ainra:registrar-07:acme-corp:invoicing@4.2.1
    node bin/ainra.js revoke ainra:registrar-07:acme-corp:invoicing@4.2.1 --reason key-compromise
    node bin/ainra.js verify ainra:registrar-07:acme-corp:invoicing@4.2.1   # → INVALID, exit 1
    node bin/ainra.js log verify

`--json` on verify gives machine output (`suite`, `reason`, `legacy_credential`, …); exit codes are 0 valid /
1 invalid for CI use. Apache-2.0. Specification: AINRA Standard v5.1.
