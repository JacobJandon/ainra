# ainra — reference implementation v0.1.0
Agent passports: issue, verify, revoke, with a hash-chained, checkpoint-signed transparency log.
Real Ed25519 throughout. Zero dependencies. Node >= 16.

## Honest limits (v0.1.0)
Single-key root (threshold ceremony = v0.2) · 3 witness keys generated locally and labeled `(local)`
(independent witnesses pending) · status list is poll-based (push fabric pending). Everything else is real:
tamper with any byte of a passport, cert, or log line and verification fails.

## Try it
    node bin/ainra.js demo          # full lifecycle in a clean directory
    node bin/ainra.js init
    node bin/ainra.js accredit registrar-07
    node bin/ainra.js issue ainra:registrar-07:acme-corp:invoicing@4.2.1 --operator "Acme Corp" --tier L3
    node bin/ainra.js verify ainra:registrar-07:acme-corp:invoicing@4.2.1
    node bin/ainra.js revoke ainra:registrar-07:acme-corp:invoicing@4.2.1 --reason key-compromise
    node bin/ainra.js verify ainra:registrar-07:acme-corp:invoicing@4.2.1   # → INVALID, exit 1
    node bin/ainra.js log verify

`--json` on verify gives machine output; exit codes are 0 valid / 1 invalid for CI use.
Apache-2.0. Specification: AINRA Master Specification v4.0.
