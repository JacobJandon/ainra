<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# AINRA — the neutral root of AI-agent identity

<!-- The org name appears ONLY here (both spots on the next line); `tools/org-rename.sh` moves it everywhere else.
     The repository is public and the badge resolves; the historical pre-publication audit is docs/_archive/PUBLISH-AUDIT.md. -->
[![CI](https://github.com/JacobJandon/ainra/actions/workflows/ci.yml/badge.svg)](https://github.com/JacobJandon/ainra/actions/workflows/ci.yml)

**Live site:** https://ainra.vercel.app/ · **Source & releases:** https://github.com/JacobJandon/ainra · **[Roadmap](ROADMAP.md)** · **[Governance](GOVERNANCE.md)**

**Prove your agent. Check theirs.** Both halves run locally — an agent presents signed facts, whoever receives them
verifies on their own machine, and nothing reaches us in either direction.

**AINRA** does exactly four jobs — **accredit · anchor · revoke · log** — and nothing else. It answers the three
questions every counterparty asks about an AI agent — *who is behind it, what may it do, is it still trusted right
now* — with **facts, never scores, never a price, never the decision itself.** Doctrine: **login is ours; the
decision is the verifier's.** Everything is built so a stranger can verify **offline, in ~5 lines, with the root
dark**, trusting the **source** — not us.

**No install at all?** Two routes, differing in which verifier answers.
[`examples/verify-in-browser/`](examples/verify-in-browser/) is four static files running the JavaScript verifier —
open it, change one byte of a signature, watch it refuse. the live site's [**Try it**](https://ainra.vercel.app/verify.html#try) panel (`make site SERVE=1` locally) runs
**`ainra-core` itself**, the Rust verify path compiled to WebAssembly (`make wasm`), so the browser is checking with
the same code the CLI does — and `make wasm-diff` pushes the whole corpus through that exact artifact in a headless
browser, requiring agreement on verdict *and* named reason. Nothing is uploaded and no request leaves the page at
verification time, either way.

## Start here — two commands

```sh
make verify        # verify a valid + a revoked credential with the real verifier, offline. No account, no server, no config.
make issue-first   # boot a local registrar, issue your first passport, verify it — and keep the registrar for reuse.
```

Measured on a warm toolchain: `make verify` ≈ **1.7 s**, `make issue-first` ≈ **2.2 s** (both far under the 60 s / 5 min
targets). From there: the [cookbook](docs/quickstarts/) · the [MCP server](docs/quickstarts/mcp.md) (AINRA as native
agent tools) · the [registrar console](docs/quickstarts/console.md) (`make registrar-console`) · the
[examples](examples/) · and **[`skills.md`](skills.md)** — an agent onboards itself end to end from that one file.
Every command prints honest labels (`LOCAL TESTBED` / `STAGING · TEST-ROOT`) and names the next step on failure.

This repository is the production-track reference implementation.

## What to read

| | |
|---|---|
| **[The Standard](docs/AINRA_I_The_Standard.md)** | what AINRA is, in public terms |
| **[Master Technical Specification](docs/AINRA_Master_Technical_Specification_v1.md)** | normative — **it wins conflicts** |
| **[DECISIONS.md](docs/DECISIONS.md)** | every deliberate deviation, D-001…D-046, each with its reasoning |
| **[STATUS.md](docs/STATUS.md)** | component-by-component state, honestly, including what is unbuilt |
| **[ARTIFACTS.md](docs/ARTIFACTS.md)** | the public artifact contract · mirroring · reproducibility |
| **[SETTLERS.md](docs/SETTLERS.md)** | the arrows other projects took, and which of them we walked into anyway |
| **[PROBES.md](docs/PROBES.md)** · **[DISCLOSURE.md](docs/DISCLOSURE.md)** | proposed accreditation terms: compliance measured from outside, and a 72-hour disclosure deadline with no severity threshold |
| **[HISTORY.md](docs/HISTORY.md)** | how it was built — the milestone ladder in one page, plans archived beneath it |

Everything a machine needs is in **[`skills.md`](skills.md)** — an agent onboards itself end to end from that one
file.

## Honest status

<!-- STATUS-LINE -->Engineering ladder M1–M27 and launch sessions L1–L5 complete; the repository is public with signed releases; the settlers pass closed five of seven arrows (graduated distrust D-044, forward-only log D-045, adversarial compliance probes D-046, a deadlined disclosure term, a rollback threshold); what remains is not code but three real-world events and the people to run them; logs sealed by the real root: 0.

What remains to *ship the prototype* is **not code** — it is three real-world events (a recorded ceremony, ≥3
independent external verifiers, a 14-day/3-region revocation soak). The machinery to run those **without us in the
room** is built and smoke-proven, and the **genesis board** shows exactly how far along we are, unfaked:

```sh
make genesis-status   # the honest §29 DoD board — a row is ✅ ONLY when a signature-checked artifact backs it
```

Today that board reads **7/11** — the 7 laptop-provable rows are green; the 4 external rows are ⏳ pending real people
running the events (see [outreach/](outreach/), [docs/DOD.md](docs/DOD.md), [GENESIS-CHECKLIST.md](GENESIS-CHECKLIST.md)).

> Nothing here is asserted; if it says green, a `make` target proves it. Logs sealed by the real root: **0** — the
> Genesis ceremony has not happened yet, and we say so.

## Clone it and it works

```sh
make preflight        # from a cold clone: build+test, differential, genesis-local, all kit smokes, S7, license, repro
```

Expected — a stranger sees this board go all-green in one command:

```
AINRA preflight — clone-and-it-works board          (26 rows; a representative slice)
  [PASS] build + tests          release test suite
  [PASS] differential           4 impls agree over vectors
  [PASS] genesis-local          whole stack boots on 1 host
  [PASS] verifier kit           execution-bound attestation
  [PASS] ceremony dry-run       witness-reproducible
  [PASS] soak instrument        measured p95, signed report
  [PASS] witness quorum         fork refused over HTTP
  [PASS] compliance probe       honest passes, 4 dishonest caught
  [PASS] reason contract        docs name every reason impls return
  [PASS] browser verifier       the corpus agrees in-browser
  [PASS] status honesty         README == STATUS claim
  [PASS] doc freeze             normative docs unchanged
  [PASS] reproducibility        artifacts rebuild byte-exact
  ALL GREEN — a stranger can clone this repo and every gate passes.
```

`make audit` runs the publish gate (S7 + license headers + gitleaks over full history). `make ci` mirrors CI, which
runs every gate on push (see `.github/workflows/ci.yml`).

> **Release-test trap:** `make test` uses `--release` on purpose. A *debug* build stack-overflows one crypto-heavy
> test (large unoptimized ML-DSA/SLH-DSA stack frames) — not a bug; use `make test` / `make preflight`.

## See it work

```sh
make drill            # witness QUORUM catches an injected fork (5 witnesses, k=3, refused 5/5)
make drill-networked  # the same quorum over HTTP — independently-operated witnesses (kits/witness)
make ceremony-dry-run # rehearse the 5-of-9 ceremony choreography; a witness recomputes the transcript hash
make soak-smoke       # measure revocation propagation (p50/95/99) into a signed, tamper-evident report
make repro            # rebuild every published artifact byte-for-byte from source (838 files)
make verify-mirror MIRROR=<dir>   # any third party byte-verifies a mirror, root dark
make probe-drill      # measure a registrar from OUTSIDE holding nothing it issued — and catch four dishonest ones
make miri             # undefined behaviour in the byte-handling code (needs nightly + miri)
```

## Kits — run the external events yourself (`kits/`)

Each kit is completable by an unattended stranger and self-verifying. Start with the kit's `QUICKSTART`/`DEPLOY`/`RUNBOOK`.

| Kit | What a stranger does | Cold-open | Prove the machinery |
|---|---|---|---|
| [`kits/verifier/`](kits/verifier/) | verify root-dark + reject revoked/forged, then verify a fresh secret-coin-flip challenge → an **execution-bound** attestation certified against a private answer key | [QUICKSTART](kits/verifier/QUICKSTART.md) · `make verify-as-external` | `make verifier-triple-drill` |
| [`kits/ceremony/`](kits/ceremony/) | rehearse the recorded 5-of-9 ceremony by role; an outsider recomputes the transcript hash | [RUNBOOK](kits/ceremony/RUNBOOK.md) | `make ceremony-dry-run` · `make verify-transcript` |
| [`kits/soak/`](kits/soak/) | measure revocation p95 from ≥3 regions into a signed report; SLO computed, never asserted | [DEPLOY](kits/soak/DEPLOY.md) | `make soak-smoke` · `make soak-verify` |
| [`kits/witness/`](kits/witness/) | run independently-operated witnesses over HTTP; a fork can't reach quorum | [WITNESS-CALL](outreach/WITNESS-CALL.md) | `make drill-networked` |

Collected evidence rolls up into one honest picture — `make genesis-status`. The materials for recruiting the people
those three events need are in **[outreach/](outreach/)**; the schedule for actually asking them — with two public
kill-gates and every re-dating on the record — is **[campaign/](campaign/)** (`make campaign-status`).

## Website

The public front door lives in [`site/`](site/) — the landing (with the founding-table call to get involved), the
Standard, verify and claim walkthroughs, foundations, and the honest [status page](site/status.html). Plain HTML/CSS,
**no framework, no analytics** (no CDN, no web fonts, no external scripts or images, zero telemetry — deliberate for a
neutral root). Build + serve locally:

```sh
make site SERVE=1     # refreshes the derived downloads from canonical sources, serves at http://127.0.0.1:8088
```

Deploy is one GitHub Pages workflow the owner enables at publish time (see `site/README.md` + the pre-push checklist).

## Architecture

```
                      the STANDARD + CC0 conformance vectors (vectors/)  ── anyone builds against these
                                          │
  crates/ainra-core  ── the pure verify/issue library (N7: no I/O, no clock) ── the 10-step verify, 20 reasons
        │  hybrid Ed25519 + ML-DSA-65 (both-or-invalid) · RFC 6962 Merkle · Token Status List
        ▼
  crates/ainra-adapter ── the ONE place external bytes become core verify types, and the canonical verdict event.
        │  Pure, fail-closed. Every Rust consumer goes through it; `make one-decode-path` fails the build if a
        │  second parser appears anywhere else (L5).
        ├──▶ crates/ainra-wasm ── that same path compiled to WebAssembly for the browser. A thin binding: no
        │      parsing, no network, no clock. `make wasm-diff` = the full corpus, in a headless browser.
        ▼
  crates/ainra-ceremony (FROST 5-of-9 + SLH-DSA dual root, signing side, NEVER in verify)
  services/ainra-services (logd · statusd · witnessd + k-of-N quorum · registrar-box)
        │
        ▼
  packages/sdk-ts (@ainra/sdk — independent verify mirror #2 + the 5-line Verifier) · packages/middleware (the gate)
  apps/cli-node (P0 — differential impl #3)
        │
        ▼
  make genesis-local — the whole world on one laptop  ·  make repro / make verify-mirror — reproducible + mirrorable
```

The verify path is **RFCs + FIPS + OSI-licensed deps only** — no vendor, no bespoke crypto. **Four independent
implementations** — `ainra-core`, the TypeScript SDK, the Python SDK and the Node CLI (P0) — agree on every one of the
**1009** vectors (`make diff`), and the same core compiled to WebAssembly agrees again in a browser.

**Validity (ADR-017):** the *identity* — the lineage and its AINRA Number — is permanent; the *credential* defaults
to **366 days** and renews invisibly (ACME-style at T−30 d, overlap issuance, a logged REISSUE whose `prev_leaf`
makes renewals walkable through the log as one unbroken chain). Long credentials are safe here **because revocation
fails closed in under 60 seconds** — short certificates are what you need when it doesn't. There is no grace period
anywhere: expiry is expiry.

## Prime directives (brief §0)

Nothing fake ever · no real company names (registrars `registrar-NN`, operators `acme`/`globex`/`operator-NN`; the
S7 linter enforces it) · **zero telemetry** in shipped components (`ainra-core` makes no network calls; any traction
metric is opt-in, count-only, in the kit layer only) · only audited crypto libraries · **both signatures or invalid**
· **logged-before-valid** · fail closed everywhere.

## Contributing & security

- [CONTRIBUTING.md](CONTRIBUTING.md) — how to build, the gates your PR must pass, and the **DCO** sign-off (not a CLA).
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Contributor Covenant.
- [SECURITY.md](SECURITY.md) — how to report; our **fail-closed** posture; we adversarially review every milestone.

## Licensing

Source **code** is dual-licensed **Apache-2.0 OR MIT** ([LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT)).
The **conformance vectors** and other CC0-marked data artifacts are public domain **CC0** ([LICENSE-CC0](LICENSE-CC0))
— the shared test corpus is ownable by no one. Every third-party dependency + its license is inventoried in
[THIRD-PARTY.md](THIRD-PARTY.md): all OSI-permissive, no forced copyleft, verify path = RFC/FIPS + OSI only.
