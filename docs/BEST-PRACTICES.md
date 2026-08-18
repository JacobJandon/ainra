<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# OpenSSF Best Practices — the self-certification answers

Free self-certification (*"projects… voluntarily self-certify, at no cost"*). Filling the form is the maintainer's;
the answers are here so it is a paste, and so any claim made there is one this repository can back.

**Badge policy: earned, never claimed.** Add the badge to `README.md` only after the form is submitted and the
level is actually awarded. A trust project displaying an unearned badge would be the exact failure it exists to
prevent.

| Criterion | Answer | Evidence |
|---|---|---|
| Project homepage / repository | yes | the public site and repository |
| Free/libre licence | yes | Apache-2.0 OR MIT; corpus CC0 |
| Licence in standard location | yes | `LICENSE`, and an SPDX header on every source file (`make license`) |
| Documentation: basics + interface | yes | `README.md`, `docs/quickstarts/`, `skills.md`, the site's docs page |
| Public version-controlled source | yes | git, public |
| Unique version numbering + release notes | yes | semver tags, `CHANGELOG.md` gated by `make changelog-board-check` |
| Bug-reporting process | yes | issue templates in `.github/ISSUE_TEMPLATE/` |
| Vulnerability report process | yes | `SECURITY.md` with a private advisory channel, response times stated |
| Working build | yes | `make preflight` — eighteen gates from a cold clone |
| Automated test suite, invoked by one command | yes | `make test`; plus 1009 conformance vectors across four implementations |
| New functionality adds tests (policy) | yes | `CONTRIBUTING.md` — the conformance-first rule: new behaviour arrives with a vector |
| Static analysis | yes | CodeQL (Rust + TS + Python), clippy `-D warnings`, `make s7`, `make license` |
| Dynamic analysis / memory safety | yes | cargo-fuzz targets + ClusterFuzzLite; Miri on the parsing paths; Rust throughout the verify path |
| Crypto: published, standard algorithms | yes | Ed25519, ML-DSA-65, SLH-DSA-SHA2-128s, SHA-256, RFC 6962 — audited libraries only, no bespoke primitives |
| Crypto: no hard-coded credentials | yes | `make gitleaks` over full history; release key offline by policy (D-042) |
| Delivery against MITM | yes | signed releases, byte-reproducible artifacts, `make repro` / `verify-mirror` |
| Fix vulnerabilities promptly / publicly | yes | `CHANGELOG.md` states the policy: fixed security bugs are publicly owned |
| Two-factor for maintainers | maintainer to confirm | required for publishing |
| Signed releases | yes | offline SSH Ed25519 signatures, key never in CI (D-042) |

**Gold requires multiple unaffiliated maintainers.** AINRA has one, and saying otherwise would be a lie on a form
about trustworthiness. Answer honestly; target Passing, and let Silver follow the second maintainer rather than
the other way round.
