<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Toolchain — exactly what you need

Run **`make doctor`** first; it checks everything below and prints what's missing (and how to get it) before you waste
an hour on a cryptic error. This is the supported set — CI runs on the pinned versions, so if `make doctor` is green,
`make preflight` should be too.

## Required

| Tool | Version | Why / notes |
|---|---|---|
| **Rust** | **1.96** (pinned) | `rust-toolchain.toml` pins `channel = "1.96"`; CI uses `dtolnay/rust-toolchain@1.96`. With `rustup` installed, the pin is automatic. Newer stable (1.97+) also builds, but 1.96 is what's tested. |
| **Cargo** | ships with Rust 1.96 | workspace build/test. |
| **Node.js** | **22** (CI); **18+** works | the kits, `@ainra/sdk`, and the JS tools use only Node built-ins + a few audited libs. |
| **npm** | ships with Node | installs `@ainra/sdk` / middleware deps. |
| **GNU Make** | 4.x | every gate is a `make` target. |
| **git** | 2.x | version control; the S7 lint scans commit messages; gitleaks scans history. |
| **bash** | 4+ | the `tools/*.sh` gates. |
| **curl** | any | the kit smokes talk to a local `registrar-box`. |
| **tar**, **sha256sum** (coreutils) | any | `make release` packaging + checksums. |
| **python3** | 3.8+ | a couple of tools/CI steps use it for small JSON/YAML tasks. |

## Optional

| Tool | For |
|---|---|
| **rustup** | makes the Rust 1.96 pin automatic (recommended). |
| **gitleaks** | `make audit` / `make gitleaks` (the secret scan). CI installs it; locally, install from your package manager or the GitHub releases. |
| **gpg** / cosign / minisign | signing a release manifest (`make release` → `RELEASING.md`). Unsigned releases still verify by rebuild-from-source. |

## The one trap worth knowing

`make test` uses `--release` **on purpose**. A *debug* build stack-overflows one crypto-heavy test
(`registrar::tests::issue_then_verify_valid`) because unoptimized ML-DSA/SLH-DSA stack frames are huge — it's not a
bug. Always use `make test` / `make preflight` (never a bare `cargo test`).

## Platform
Developed and CI-tested on **Linux (x86-64)**. macOS should work (same toolchain); Windows is untested — use WSL.
