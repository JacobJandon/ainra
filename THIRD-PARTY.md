<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Third-party dependencies & licenses

AINRA's own code is dual-licensed **Apache-2.0 OR MIT** (`LICENSE-APACHE`, `LICENSE-MIT`); the conformance **vectors
are CC0-1.0** (`LICENSE-CC0`, public-domain dedication) so any implementer may reuse them freely. This file inventories
every third-party dependency and confirms the design rule from MTS §24 / N3:

> **The verify path depends only on RFC/FIPS standards and OSI-approved, permissively-licensed software — no copyleft
> is forced on anyone, and no proprietary component sits on the path a relying party must trust.**

Standards themselves (IETF RFCs, NIST FIPS, C2SP, W3C) are specifications, not code — they impose no license on an
implementation. What follows is the actual *code* we depend on.

## Rust workspace — 115 transitive crates, all OSI-permissive

Generated from `cargo metadata` (authoritative — each crate's own `license` field). License histogram:

| Count | License expression |
|------:|--------------------|
| 65 | MIT OR Apache-2.0 |
| 18 | Apache-2.0 OR MIT |
| 6 | MIT |
| 5 | MIT/Apache-2.0 |
| 4 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| 4 | BSD-2-Clause OR Apache-2.0 OR MIT |
| 3 | BSD-3-Clause |
| 2 | Unlicense OR MIT |
| 2 | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| 1 | 0BSD OR MIT OR Apache-2.0 |
| 1 | MIT OR Apache-2.0 OR BSD-1-Clause |
| 1 | Apache-2.0 / MIT |
| 1 | MIT OR Zlib OR Apache-2.0 |
| 1 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| 1 | Zlib OR MIT OR Apache-2.0 |

**No forced copyleft.** Every crate is usable under a permissive license:
- The two `… OR LGPL-2.1-or-later` crates are both `r-efi` (a UEFI-runtime shim pulled in transitively on some `std`/`getrandom` targets — **not** in `ainra-core`'s dependency tree). They **also** offer MIT/Apache-2.0 — we take the permissive option; LGPL is never selected and is not on the verify path.
- `unicode-ident`'s `AND Unicode-3.0` is the **Unicode License v3** on its Unicode data tables — a permissive, redistribution-allowing license (proc-macro tooling, not the verify path).
- `BSD-3-Clause` (`ed25519-dalek`, `curve25519-dalek`) and `BSD-2/1-Clause`, `0BSD`, `Unlicense`, `Zlib`, `Apache-2.0 WITH LLVM-exception` are all OSI-approved permissive.

### Verify-path direct dependencies (`crates/ainra-core`)
The pure verify/issue library — the only code a relying party's verifier links — depends on:

| Crate | Purpose | License |
|-------|---------|---------|
| `ed25519-dalek` | Ed25519 signatures (RFC 8032) | BSD-3-Clause |
| `ml-dsa` | ML-DSA-65 (FIPS 204) | Apache-2.0 OR MIT |
| `slh-dsa` | SLH-DSA (FIPS 205) root suite | Apache-2.0 OR MIT |
| `sha2` | SHA-256 (FIPS 180-4) | MIT OR Apache-2.0 |
| `base64ct` | constant-time Base64 | Apache-2.0 OR MIT |
| `flate2` | DEFLATE (status-list codec) | MIT OR Apache-2.0 |
| `signature` | signature traits | MIT OR Apache-2.0 |
| `rand_core` | RNG traits (issuance only) | MIT OR Apache-2.0 |
| `serde`, `serde_json` | (de)serialization | MIT OR Apache-2.0 |
| `thiserror` | error enums | MIT OR Apache-2.0 |

`frost-ed25519` (ZF; MIT OR Apache-2.0) is used only by `crates/ainra-ceremony` (root ceremony), not by the verifier.

## Node / TypeScript

**`packages/sdk-ts` (`@ainra/sdk`) — the verify-only mirror.** Runtime dependencies (on the verify path):

| Package | Purpose | License |
|---------|---------|---------|
| `@noble/curves` | Ed25519 verify | MIT |
| `@noble/hashes` | SHA-256 | MIT |
| `@noble/post-quantum` | ML-DSA / SLH-DSA verify | MIT |

Dev-only (not shipped, not on the verify path): `typescript` (Apache-2.0), `@types/node` (MIT).

The verifier kit (`kits/verifier`) and middleware (`packages/middleware`) add **no** runtime dependency beyond
`@ainra/sdk` — they import only it and Node built-ins.

## How this is kept honest
- `tools/license-check.mjs` (CI-gated) fails the build if any authored source file lacks the `SPDX-License-Identifier:
  Apache-2.0 OR MIT` header.
- The histogram above is regenerable from `cargo metadata`; a copyleft dependency entering the *verify path* would be
  a licensing regression and is treated as a bug.
- No network or proprietary SDK is on the verify path (N1/N3); `make genesis-local` proves an outsider verifies with
  only the public directory + roots.
