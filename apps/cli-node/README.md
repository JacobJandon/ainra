# ainra — reference implementation v0.3.5
Agent passports: issue, verify, revoke, with a hash-chained, checkpoint-signed transparency log.
**Hybrid Ed25519 + ML-DSA-65** throughout — both signatures mandatory, both-or-invalid — at parity with the Rust
core and the browser SDK. The download is **one self-contained file**: the audited `@noble/post-quantum` ML-DSA is
bundled in, so it runs with just `node` — no install, no `node_modules`, zero runtime dependencies. Node >= 18.

## The suite (measured on the reference machine)
Ed25519 (32 B key, 64 B sig) + ML-DSA-65 (1952 B key, 3309 B sig), so a hybrid signature is ~3.3 KB. One hybrid
sign ≈ 7 ms, one hybrid verify ≈ 3 ms (both halves). The single-file bundle is ~75 KB (~22 KB zipped); `make site`
builds it as `site/ainra-cli-v<version>.zip`.

## Honest limits
Single-key root — the threshold ceremony (FROST 5-of-9 + SLH-DSA) runs in the network's genesis; the participant
CLI is v0.2 work · 3 witness keys generated locally and labeled `(local)` (independent witnesses pending) · status
list is poll-based (push fabric pending). Everything else is real: tamper with any byte of a passport, cert, or log
line and verification fails. `verify` checks the signatures, that the passport has not expired, revocation and the
log. It does not check that the validity window has opened (the Rust core and the SDKs refuse that as
`not_yet_valid`). It prints the KYB flag and whether an authority proof is present, and checks neither: `issue`
writes random bytes as the A1 proof. When the chain fails, it marks those fields and the tier as not authenticated.

## What 0.3.3 and earlier printed
Up to 0.3.3, `verify` printed claims it had not checked: "KYB verified" whenever the KYB flag was set; a green check
and "PII: none" on every authority line, with "(zk-commitment)" for class A1; "version ✓"; the suite as hybrid from
the cert's declared algorithm; a forged tier in green; and a green "ACTIVE ✓" when the status list's signature had
failed. `instance verify` said the passport underneath had verified when it had read only the local revocation list,
without its signature, and the expiry date. Verdicts and exit codes are the same in 0.3.4.

## What 0.3.4 and earlier printed from a stranger's file
`verify some.json` reads a passport file anyone may have written. Up to 0.3.4 its name, operator, jurisdiction, tier
and dates were printed as written, so a name carrying a newline could put a line of its own on the screen ("✓ VALID")
and a terminal escape could recolour or clear it. From 0.3.5 every character outside printable ASCII is printed as its
`\uXXXX` escape. Verdicts and exit codes are the same in 0.3.5; `make cli-check` holds it.

## Suite migration (Drill 01)
A legacy Ed25519-only credential is **recognized and named**, never silently reinterpreted: by default it fails
closed as `alg_downgrade`; it verifies **only** during a migration overlap you opt into with `--accept-legacy`. A
credential whose ML-DSA half is present but broken or non-canonical is `sig_invalid` — rejected under **every**
policy, the flag included. `ainra migrate` REISSUEs every legacy (Ed25519-only) credential in its home (`./.ainra`,
or `AINRA_HOME`) to hybrid, carrying `prev_leaf` continuity to the legacy leaf (nothing is deleted; `--dry-run`
prints the plan first).

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
1 invalid for CI use. Two fields say less than their names: `suite` is the algorithm the registrar's cert declares,
not the one that verified (`legacy_credential` is true when the passport's or the cert's signature is Ed25519-only),
and `checks.dates` is true when the passport has not expired, whatever its start date. Apache-2.0. Specification:
AINRA Standard v5.1.
