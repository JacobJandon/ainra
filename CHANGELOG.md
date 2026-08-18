<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Changelog

All notable changes to the AINRA reference implementation. Format follows [Keep a Changelog](https://keepachangelog.com/);
this project versions the **reference implementation + conformance vectors** (the normative spec is versioned in
`docs/AINRA_Master_Technical_Specification_v1.md`). The engineering milestone ladder is MTS §27, summarised in
[`docs/HISTORY.md`](docs/HISTORY.md); design decisions are `docs/DECISIONS.md` (D-001…). Cut a release with `make release`; verify one per `RELEASING.md`.

We **publicly own fixed security bugs** — hiding them would be the opposite of a trust root.

## [Unreleased]

### The settlers pass — five documented industry failure modes, closed before we walked into them

`docs/SETTLERS.md` audited what comparable efforts were forced to admit publicly, and asked which of those arrows
this project was still walking toward.

- **D-044 — graduated distrust, keyed on transparency-log position.** Absent = trusted; present = refuse what a
  registrar logged at index ≥ n, with everything earlier still verifying. The web PKI keyed the equivalent on
  `notBefore` and a CA backdated certificates to evade it; a log index cannot be backdated. Enforced in all four
  implementations *after* inclusion is proven, for the credential and every hop. 48 new vectors in two families —
  `registrar-distrusted-*` and `distrust-below-cutoff-*`, the second being what makes the first mean anything.
- **D-045 — a log may never come back shorter than it has already been.** `log.highwater` records the largest tree
  size ever reached and a rebuilt tree below it refuses to start. A CT log once auto-restored from a stale backup
  during a cloud outage and published a tree head inconsistent with its own earlier ones; that is not recovery, it
  is equivocation with a sympathetic cause.
- **D-046 — compliance measured adversarially** (`kits/probe/`, `make probe-drill`). Nine checks run from outside by
  a probe holding nothing the registrar issued it, minting under an unmarked name, every verdict from a root-dark
  verifier at the strictest policy. Its load-bearing check is that the **write door is shut to the probe** — if an
  unauthenticated write succeeds the run is void rather than failing, because an operator measuring itself with its
  own token has produced a self-report. Negative-controlled against four dishonest registrars, each required to fail
  the *named* check.
- **`docs/DISCLOSURE.md`** — a 72-hour public incident report with no severity threshold and no waiting to establish
  scope. Two landmark CA removals turned on concealment rather than on the technical fault.
- **`docs/genesis-day/ROLLBACK.md`** — the thresholds that must carry a number and a name before any root roll. We
  can never measure how many verifiers hold a given root, because the charter forbids the telemetry that would say;
  so reversibility is over-engineered instead, and a root roll cannot be scheduled before witnesses exist.

### Fixed — checks that reported health they could not observe

- **The `security` workflow had never concluded success**, across 40 consecutive runs. `miri` was pointed at the
  whole `ainra-core` suite, which cannot complete under an interpreter (measured: >900 s for a 15-minute cap), and
  the job had no `timeout-minutes` — so every run was killed at GitHub's 6-hour ceiling and labelled `cancelled`,
  which reads like a person cancelled it rather than like a broken check. Now `tools/miri-parsers.sh` runs the
  byte-handling code and only that: 10 filters, 26 tests, ~100 s. **Every job in every workflow now has a timeout**
  (eleven were missing).
- **`docs/reasons.json` never got D-044's sixteenth reason.** Four implementations and 48 vectors agreed on
  `registrar_distrusted` while the published contract — the file `tools/verify-60s.mjs` loads at runtime and the
  quickstarts point readers at — listed fifteen, as did a dozen prose claims. The differential could not catch it:
  the implementations agreed, and only the prose was wrong. `make reasons-check` now fails the build if the
  documented reasons and `Reason::ALL` ever diverge again.
- **The same defect, ten times larger: the vector count.** D-044 added 48 vectors and updated the number in zero
  places, so forty-odd live surfaces went on claiming **745** — four pages of the deployed site, both SDK READMEs,
  CONTRIBUTING, RELEASING, the quickstarts, STATUS, and the preflight board's own label. The most checkable claim
  this project makes was wrong on the front page. `make corpus-check` now holds every stated count to the corpus on
  disk; where the number is not load-bearing the claim was rewritten so it cannot go stale at all ("the whole
  corpus"). Historical records — CHANGELOG, releases, DECISIONS, the archived plans — keep their numbers, because
  rewriting a record to match today falsifies it rather than fixing it.
- **`MANIFEST.sha256` had been 48 files short since D-044.** It *is* the published artifact set, so a mirror
  assembled from it would have silently omitted every graduated-distrust vector.

### Docs

- **`docs/HISTORY.md`** — the M1–M27 / L1–L5 ladder in one page; the 24 milestone plans moved to
  `docs/_archive/plans/` unedited, because a plan rewritten after the fact records nothing.
- **`docs/ARTIFACTS.md`** — the artifact contract, mirroring and reproducibility merged into the one topic they
  always were.
- README gains a *What to read* table and drops several stale numbers (745 → 793 vectors, 3 → 4 implementations,
  15 → 16 reasons, 790 → 838 artifacts).

## [0.3.3] — the release that could actually be published

`v0.3.2` is a real, signed, board-proven tag, and it **cannot be published**. Finding out why is this release.

With v0.3.2 tagged and `publish-preflight` printing READY locally, the publish workflow was dispatched — and its
own preflight job blocked:

```
[BLOCK] tag matches tree   packages differ from tag v0.3.2 — Drifted: packages/sdk-ts/package-lock.json
[SKIP]  clean tree         working tree is dirty — publish from a clean checkout of the tag, not from here
```

Nothing had drifted. The workflow provisions the SDK before running the release gate, and it did so with
`npm install`, which **writes** `package-lock.json`. That lockfile had said `0.1.0` since v0.1.0 — through
v0.2.0, v0.3.0, v0.3.1 and v0.3.2, because every version bump touched `package.json` and none touched the lock.
So `npm install` dutifully synced it, and the gate then diffed a tree that the step three lines above it had just
dirtied.

**The publish path had therefore never once got past its own preflight, on any version.** It could not have. It
never failed visibly either, because it had never been run to completion — the same family as the three
never-run checks M26 found, and the reason "the board is green" is not the same claim as "this works".

It never reproduced locally, and never would have: the lockfile is only rewritten when `npm install` runs, and a
developer machine already has `node_modules`.

### Fixed

- **The lockfiles state their real version.** `packages/sdk-ts` and `packages/middleware` were at `0.1.0`; both
  are regenerated at 0.3.3.
- **The provisioning step can no longer dirty the tree it is about to gate.** It uses `npm ci`, which reads the
  lockfile and never writes it, so a future drift fails loudly at install time instead of being rewritten
  silently underneath the release gate — and a new step asserts the tree is still pristine afterwards, so this
  specific betrayal cannot come back by another route.
- **The npm publish job no longer self-upgrades npm.** `npm install -g npm@latest` replaces npm's own global
  install while it is running and can die half-way with `MODULE_NOT_FOUND`. The dry-run job already refused to do
  this and said why in a comment; the publish job — the one actually holding the credential — still did it. Both
  now assert the version instead of mutating the toolchain.

### Added

- **`make lockfile-sync`** (board row + `make ci`): every committed lockfile must state the version its
  `package.json` states, in both places npm writes it. Negative-controlled — restoring `0.1.0` produces two named
  failures and a red board.


## [0.3.2] — the operations release

The published library source is **byte-identical to 0.3.1** — `git diff v0.3.1..v0.3.2 -- packages/*/src crates/`
is empty. Everything below is the surface around it: the network that serves the demo, and the deployed site that
describes it. The version moves because the packages needed a tag that *contains* their bump before they could be
published at all; `publish-preflight` compares bytes, not tag existence, and was correctly refusing.

Full workings: [`docs/_archive/plans/PLAN-M27.md`](docs/_archive/plans/PLAN-M27.md) · board at the release commit:
[`docs/releases/v0.3.2-board.md`](docs/releases/v0.3.2-board.md).

### Fixed — eleven things the public site told visitors that were not true

Found by walking production end to end as a stranger, with no context and no login. Not one was a failing test:
every one was a claim nothing checked.

- The **404's own escape links were relative**, so at any nested path they resolved into that directory and were
  themselves 404 — the one page a lost visitor lands on had no working way back.
- **Two pages published two different networks**, each denying the other's passports: `verify.html` read a 13-lineage
  dataset while the record browser read an 8-lineage one, the same registrar carrying a different root key in each.
- **`llms.txt` named the wrong release** — "two signed releases; current: v0.3.0" — the file that calls itself an
  AI agent's map.
- **The install step pointed at a download that does not contain what the sentence promised**: "runs with just node"
  against a release containing only a Linux x86_64 Rust binary.
- **The verifier kit documented an install route that cannot work** — `npm install @ainra/sdk`, unpublished, and the
  remedy its troubleshooting page offered for the failure was the cause of the failure.
- **A registrar that accepts and never answers hung the page forever.** A refused port always failed in
  milliseconds, which is why this was never caught; a host that drops never rejects, so the honest note never
  appeared and the mint button sat enabled with no listener attached.
- **A "110 days old" staleness warning over a current record** — read out of `generated_window.verified_at`, which
  is a pinned staging constant, not a publication time.
- **`foundation.html` declared one canonical URL and a different `og:url`**, so every share of the page resolved
  elsewhere; and it repeated the stale "two signed releases" claim in its description and share card.
- Plus `verify.html` claiming nine checks while rendering seven, and "live record" surviving in titles above a
  panel that had been corrected to say published.

### Added — the surface is now watched, not assumed

- **The staging network stands as a service** (`deploy/systemd/`, `make stage-install`). Two layers of recovery,
  both proven rather than assumed: `Restart=always` catches a process that exited, a watchdog catches one that is
  alive and useless by probing the same contract a consumer reads. The honest claim is unchanged and deliberately
  small: *runs whenever this machine is on; binds 127.0.0.1, not reachable from the internet.*
- **The stranger journeys run daily against the deployed site** (`make stranger`,
  `.github/workflows/stranger.yml`) with three verdicts kept apart — SITE BROKEN / NETWORK DOWN / ALL UP — and its
  own negative control in the same job, because a monitor that cannot fail is not a monitor.
- **`make site-net` stamps the published record when it is copied**, and `make site-net-check` proves the copy
  still matches the running network byte for byte.
- **One network gateway for the site** (`site/js/net.mjs`): no page fetch can be written without a deadline.

### Changed — the gates that let those claims through

Each fix is paired with a gate, and each gate is negative-controlled by restoring the defect and watching the board
go red.

- `tools/status-consistency.mjs` derives the release count and current version from git tags and checks **every**
  such claim across `site/`, not one file — the first version checked only `llms.txt` and walked straight past the
  identical stale sentence in `foundation.html`.
- `tools/link-check.mjs` compares `canonical` against `og:url` on every page.


## [0.3.1] — security

Fixes one advisory, end to end, and closes the class of CI failure that hid it. Full workings:
[`docs/_archive/plans/PLAN-M26.md`](docs/_archive/plans/PLAN-M26.md) · board at the release commit:
[`docs/releases/v0.3.1-board.md`](docs/releases/v0.3.1-board.md).

### Security

- **RUSTSEC-2025-0144 — timing side-channel in `ml-dsa` `decompose()`.** `ml-dsa` 0.0.4 → 0.1.1, where Barrett
  reduction replaces an operand-dependent hardware division on values derived from the secret components `s2` and
  `t0`. **Signing-side leak**: verification consumes only public inputs, so relying parties had no secret exposed
  — but registrar issuance, ceremony delegates and the CLI all sign, so the fix was taken in full. Publicly owned
  in [`SECURITY.md`](SECURITY.md) with the post-mortem, as promised there.
- **`getrandom` removed from the verify path.** A default feature of `ml-dsa` 0.1 that our seed-first key
  derivation never reaches, and which broke the WebAssembly build outright.
- **The pinning vector is NIST's own answers.** Our 745 vectors were generated *by* the vulnerable crate and could
  not adjudicate a change to it, so FIPS 204 ML-DSA-65 known-answer tests were wired in first — keyGen, byte-exact
  sigGen, and 15 sigVer cases of which 12 are negative. 0.0.4 passed them, so there was no second finding.

### Fixed — checks that had never once run

- **`scorecard` had never resolved.** It referenced `ossf/scorecard-action@v2`, which is not a tag on that action,
  so the OpenSSF score this project advertises had never been published.
- **`clusterfuzzlite` had never fuzzed anything.** It failed at *build* on every run (`rustc 1.91 is not
  supported` against `ainra-core`'s declared 1.96 floor). All three targets now build and run — proven with a
  short campaign: 2,819,057 / 2,365,037 / 589,127 executions, no crashes.
- **`cargo-audit` short-circuited.** `--deny warnings` stopped at an unmaintained notice on a transitive crate and
  never reached the real vulnerability in a direct dependency. It now reports every advisory before it gates.
- **56 GitHub Actions references pinned to commit SHAs**, 0 floating, across all 8 workflows.

### Added

- `make interop` — freshly-signed material verified by two independent ML-DSA implementations
  (`@noble/post-quantum` and OpenSSL), each required to refuse a flipped bit. Necessary because the regenerated
  corpus came out byte-identical, which makes "the vectors still pass" an easy test to pass.
- A **negative control for every security gate**, and the rule behind them in [`CONTRIBUTING.md`](CONTRIBUTING.md):
  *a check that has never passed does not exist* — with a worked example of a negative control that reported
  "3/3 refused" while testing nothing.


The three real-world genesis DoD rows remain the only open work: a recorded public ceremony with independent
custodians, ≥3 external verifiers, and a 14-day 3-region soak. The machinery for all three is built and rehearsed.

### L5 — one decode path in Rust, and a browser surface that uses it

- **`crates/ainra-adapter`** — there is now exactly **one** code path that turns external bytes into core verify
  types, and every consumer calls it. Mapping the boundary first (`docs/_archive/plans/PLAN-L5.md`) found that the second
  implementation **already existed**: `anchors_from_export` in the CLI's seed path was a partial trust-anchor
  decoder that **failed open**, substituting an all-zero issuer key for a malformed one, so a corrupt export
  produced a plausible verdict instead of `unknown_registrar`. It is deleted. Blast radius, checked and stated: it
  was reachable only from fixture generation, so no released verify path consumed it — latent, not exploited.
- **The one path now fails closed.** It was `.expect()` throughout, which is safe for a generator reading fixtures
  it just wrote and fatal for a browser taking pasted bytes. A malformed field now yields `schema_violation` for
  every caller instead of aborting. The differential is **byte-identical before and after**: 745/745 core↔sdk,
  10/10 canon 3-way, 4/4 canon-reject, 17/17 delta, 9/9 directory, core↔py 745/745 · 17/17 · 9/9.
- **Enforced mechanically, not by convention** — `make one-decode-path` scans every Rust file and fails if a moved
  signature reappears or if `TrustAnchors`/`Presentation` are built from parsed JSON outside the adapter. It is a
  CI gate and a board row. It earned its place on first run by catching the fail-open decoder.
- **`crates/ainra-wasm`** — the verify path compiled to WebAssembly: three exports, each one line, each handing
  straight to the adapter. No parsing of its own, no network, no telemetry, and no clock (`now` is an argument,
  because freshness is the verifier's policy, never the presenter's). **367 KiB** under a ceiling enforced at build
  time; a dedicated Cargo profile, so every existing artifact's bytes and the reproducibility manifest are
  unchanged.
- **The browser joins the differential as a verified surface** — `make wasm-diff` runs the full corpus through the
  compiled artifact in a headless browser and requires agreement with the core on verdict *and* named reason:
  **745/745**. The harness carries its own negative control (`NEGATIVE_CONTROL=1` flips one signature bit; the run
  must fail — proven at 744/745, exit 1), because a differential that cannot fail proves nothing.
- **The demo runs on our own ground, on the real core.** `/verify.html#try` verifies through the compiled Rust
  verifier, so "the same code that passes all 745 conformance vectors" is literal. Paste-or-pick; a malformed paste
  says *what it could not find*; and if WebAssembly will not load the page falls back to the JavaScript mirror and
  **says so** rather than quietly answering with a different implementation than it claims.

#### Fixed

- **The forge half of the live demo did nothing.** On `/verify.html#try`, the assurance-tier rail selected
  `[data-t]` globally, which also matched the four "try to forge one" buttons: clicking one flipped
  `aria-pressed` and then threw, and the demo's own listener read that as "already on" and switched the forgery
  back off. Every visitor who tried to forge a passport was shown **VALID**. The selector is scoped to its own
  rail; all four controls are verified to produce the reason their label promises, on both engines.

### L3 — the human half gets a sequence, and published counts get a gate

- **`campaign/`** — the fourteen ordered steps that move those three rows: one primary action per step, the six
  asks and the interview script, the jurisdiction decision, and two public kill-gates (**K1** demand evidence,
  **K4** three independent attestations). Gates are bars, not deadlines — no dates anywhere, since a deadline is a
  promise about a calendar that nothing in the repository can verify. `make campaign-status` prints the step, the
  action, and every count with the registry it came from.
- **Gates are read in the open or not at all.** `node tools/campaign.mjs record` refuses without a written
  reason, stamps the count as it stood, appends to `campaign/gates.json`'s history, and regenerates the public
  table (D-043).
- **Published counts are now enforced, not promised.** `node tools/campaign.mjs check` runs inside the board's
  status-honesty row and in CI: if `ROADMAP.md`'s verifier or witness numbers drift from the genesis board and
  `witnesses/candidates.json`, or a generated campaign table drifts from `gates.json`, the build goes red. Proven
  with a negative control (a false `2 / 3` turns the board red).
- **People never enter this repository (D-043, applying D-036 to ourselves).** The tracker and interview notes are
  gitignored; no command writes a person into a tracked file; `drop <id>` clears one on request. Counts are
  publishable, people are not. No campaign command can move a Definition-of-Done row.
- **`make publish-preflight`** — everything checkable before the maintainer pastes an npm/PyPI token, publishing
  nothing and holding no credentials: versions agree across all four packages, the version is tagged, each package
  packs with a README, a license, and no local `file:` dependency, and the packed npm tarball *and* the built wheel
  each install into a throwaway environment and reproduce all **745** recorded conformance verdicts. It found four
  real blockers on first run (three missing package READMEs — now written — and the middleware path dependency).

## [v0.3.0] — a fourth independent verifier · self-serve conformance · signed releases

**Released:** signed tag `v0.3.0` at the pinned commit, signed artifacts + provenance + SBOM on the
[releases page](https://github.com/JacobJandon/ainra/releases/tag/v0.3.0). Everything below is provable from a clean clone.

### M24 — independence, self-serve conformance, and supply-chain trust

- **A fourth, independent implementation.** `packages/sdk-py` is a Python verifier written from the Standard, the
  MTS, `docs/reasons.json` / `docs/PRESENTATION.md`, and the CC0 vectors — **not** transliterated from `ainra-core` or
  the TypeScript SDK. It joins the conformance differential as a fourth column: `make diff` is now
  **core ↔ sdk ↔ cli ↔ py**, and all four agree byte-for-byte on **745/745 passport + 17/17 delta + 9/9 directory**
  vectors, on verdict *and* reason. A fourth brain reaching the same verdict on every vector is independent
  confirmation the Standard is unambiguous; a disagreement would have been a finding.
- **The independence caveat, stated precisely (D-041).** The verification *logic* is independent; the cryptographic
  *primitives* are shared, audited libraries — reimplementing a signature scheme would be less safe, not more
  independent. Ed25519 + ML-DSA-65 come from pyca `cryptography` (OpenSSL 3.5+), SLH-DSA-SHA2-128s from the same
  OpenSSL `libcrypto` via `ctypes`, SHA-256 from the stdlib. The differential exercises the logic, not the primitives;
  every crypto wrapper fails **closed**. The package is `ainra` (checked unregistered on PyPI 2026-07-30, **not** published).
- **The self-serve conformance programme.** `tools/conformance/` + `docs/conformance/PROGRAMME.md`: a
  **language-agnostic runner** any third party points at their **own** implementation over a documented stdin/stdout
  contract (`tools/conformance/CONTRACT.md`) — the corpus streams in as JSON Lines, one `<name>\t<result-json>` line
  streams back, no files and no network. `make conformance` proves it **both ways**: the three in-repo verdict impls
  (Rust core, TS SDK, Python) each pass **clean** over the full corpus with the same corpus hash, and a deliberately
  **sabotaged** impl is caught with named divergences (a conformance tool that cannot fail is theatre). An implementer
  **self-attests** by signing their own result with their **own** SSH key; anyone re-runs the corpus and checks. The
  root certifies no one — the only truthful claim is "self-attested conformant, re-runnable", never "AINRA-certified".
- **Supply-chain trust for our own releases (D-042).** `make release` writes `dist/` — the reference CLI, the CC0
  corpus, a reproducibility `MANIFEST.sha256`, a **SLSA-style `provenance.json`** (source commit, toolchain, artifact
  digests) and a **CycloneDX `sbom.json`** (every locked crate + Node dep with its `purl`) — and signs `SHA256SUMS`
  with an **offline SSH Ed25519 key** (`ssh-keygen -Y`): tiny keys, detached signatures, verified against one pinned
  public key, no keyserver and no web-of-trust. The private key never enters the repo or CI. **`RELEASE-VERIFY.md`** is
  the stranger's four-step verify guide — check the signature, check every artifact against the signed manifest, read
  the provenance + SBOM, and (the strong check) rebuild the corpus **byte-for-byte** from the tagged source, which
  needs no key at all. Signatures prove *who*; reproducibility proves *what*.
- **Versions bumped to 0.3.0** everywhere from one source each — the workspace `Cargo.toml` (every crate inherits),
  `@ainra/sdk` / `@ainra/middleware` / `@ainra/mcp`, the Python `ainra`, the downloadable reference CLI, and the site
  labels — with the `make site` drift-guard that fails the build if any page's CLI version ≠ `apps/cli-node/package.json`.
- The **DoD table is untouched.** The three real-world genesis rows — a recorded public ceremony with independent
  custodians, ≥3 external verifiers, and a 14-day 3-region soak — remain **honestly pending**; the machinery for all
  three is built and rehearsed. Decisions this milestone: **D-041** (the fourth Python column), **D-042** (SSH-signed releases).

## [v0.2.0] — hybrid CLI + suite-migration / ceremony / witness / push

**Released:** signed tag `v0.2.0` at the pinned commit, signed artifacts on the
[releases page](https://github.com/JacobJandon/ainra/releases/tag/v0.2.0). Everything below is provable from a clean clone.
The rebuilt hybrid CLI's own demo:

```
— AINRA reference lifecycle demo (hybrid Ed25519 + ML-DSA-65) —
  keys: hybrid Ed25519 + ML-DSA-65 (both mandatory) · single-key root, 3 local witness keys — labeled
→ suite      Ed25519 + ML-DSA-65 ✓
✓ VALID · verified in 16.9 ms
✓ revoked · ainra:registrar-07:acme-corp:invoicing@4.2.1 · reason: key-compromise · log #000003
→ suite      Ed25519 + ML-DSA-65 ✓
✗ INVALID · revoked · verified in 16.0 ms
done. every signature above is real hybrid Ed25519 + ML-DSA-65; strip the ML-DSA half and it fails closed.
```

### M23 — the downloadable CLI goes hybrid; the v0.2.0 milestone

- The **downloadable reference CLI is now hybrid Ed25519 + ML-DSA-65**, both-signatures-or-invalid, at parity with
  the Rust core and browser SDK — keygen, every issuance signature (issuer/root/cert/checkpoint/status), and
  verification. It stays **one self-contained file**: `make site` esbuild-bundles the canonical source with the
  audited `@noble/post-quantum` ML-DSA inlined, so the download runs with just `node` — no install, zero runtime
  deps (64 KB bundle, 18 KB zipped). Every external decode goes through the one strict canonical gateway (D-029).
- **Migration semantics, fail-closed:** a legacy Ed25519-only credential is recognized and named — `alg_downgrade`
  by default, verifying **only** under an opt-in `--accept-legacy` overlap; a credential whose ML-DSA half is
  present but broken or non-canonical is `sig_invalid`, rejected under **every** policy. Proven by `make cli-check`
  (4 downgrade vectors × 2 policies), wired into `ci` + `preflight`. The core↔SDK corpus already proved this at the
  protocol level (24 `alg-downgrade-*` + `noncanon-*` inside the 745; unchanged, still `make diff` green).
- Measured on the reference machine: hybrid sign ≈ 7 ms, verify ≈ 3 ms; CLI implementation **v0.1.0 → v0.2.0**.
- **Suite Migration Drill 01 (Task 2)** — a real Ed25519→hybrid migration over a running network: `ainra migrate`
  REISSUEs with `prev_leaf` continuity (nothing wiped), the overlap is an auto-expiring fail-closed policy epoch
  (`--accept-legacy-until`, D-037), and the staging audit confirms the live network is already hybrid (0 stragglers).
  `make suite-migration-drill`; transcript in `docs/drills/SUITE-MIGRATION-01.md`; AINRAscan shows the live suite mix.
- **Distributable genesis ceremony (Task 3)** — `make ceremony-rehearsal-multi` runs FROST 5-of-9 across NINE
  isolated OS processes (file-based rounds, air-gap shape): one group key emerges, 5 shares sign / 4 cannot,
  transcript reproducible. Changes no DoD row; runbook gains the multi-party appendix.
- **Witness kit v2 (Task 4)** — single-binary `witnessd` from a one-file config, self-declared `/info` (verified by
  no one), `/root` alias, bare-address back-compat; verifier quorum-k worked examples; `make witness-check` times the
  <10-min onboarding; AINRAscan shows witness diversity from live data.
- **Push status = ADR-018 (Task 5)** — push is advisory transport over a sovereign pull: an unsigned SSE/webhook may
  announce a new head/delta, but the verifier always pulls + validates. Suppression fails closed on freshness;
  forgery is ignored. `make push-advisory-check`, `tools/push-announce.mjs`; MTS ADR-018, D-038 (the Standard stays v5.1).
- **Release (Task 6)** — versions bumped to **0.2.0** everywhere from one source each (workspace `Cargo.toml` →
  every crate; `@ainra/sdk`, `@ainra/middleware`, `@ainra/mcp`; the site labels, with a `make site` drift-guard that
  fails the build if any page's CLI version ≠ `apps/cli-node/package.json`). Reproducibility re-proven byte-for-byte
  (`make repro`); the M23 checks are linked from the verification map (`docs/STATUS.md`), the drill transcript from
  there and the manual. Decisions this milestone: **D-037** (legacy-policy epoch), **D-038** (push advisory),
  **D-039** (ceremony file-transport). The **DoD table is untouched** — the three real-world genesis rows (recorded
  public ceremony with independent custodians, ≥3 external verifiers, 14-day 3-region soak) remain honestly pending.

### M19 — the network runs under a real genesis root; next-version roadmap

- `make stage-up` now runs the genesis ceremony over the live registrars: `accredit` DKGs a FROST 5-of-9 +
  SLH-DSA dual-root, dual-signs the directory, and publishes the signed directory + `roots.json`. The public
  contract serves `X-AINRA-Root: genesis:<fp>` (was `test-root`); **`make genesis-verify`** proves a live passport
  verifies ROOT-DARK against the published root, and a tampered root is rejected. This is an OPERATOR-RUN genesis
  (single-host DKG) — the distributed public ceremony (independent custodians), ≥3 external verifiers, and the
  14-day 3-region soak remain the real-world DoD events (not fabricated).
- The registrar public door accepts an optional `{operator, lineage}` so a visitor can NAME their agent
  (sanitized to the grammar, still a low-tier specimen stamped `demo:specimen`); the public revoke is gated on
  that marker (`is_demo_specimen`).
- CLI README: spec reference corrected v4.0 → **v5.1**; the Ed25519-only limit is stated with hybrid as v0.2.

### Next (v0.2.0) — planned

- ~~Downloadable reference CLI goes hybrid~~ — **done in M23** (above).
- Threshold root ceremony in the CLI (single-key today), independent-witness wiring, push-based status fabric.
- The three real-world genesis DoD events: a recorded public ceremony with independent custodians, ≥3 external
  verifiers, and a 14-day 3-region soak.

### M12.1 — canonical-encoding sweep (D-029)

- The base64 fail-open class (M9 dedup, M12 prev_leaf) is closed at every base64url ingestion point: core was already
  strict (base64ct); the SDK now routes EVERY external decode through one strict gateway (`strictB64u` + canonical
  round-trip, `dec(s, reason)` fails closed) — claims-internal fields keep core's reason (hop sigs → `alg_downgrade`,
  `log.leaf`/hop `log_leaf` → `not_logged`), boundary decodes → `schema_violation`.
- New differential vector class `noncanon-*` + extended `renewal-invalid-prevleaf-*` cover trailing-bits, padding,
  whitespace, and standard-alphabet swaps; both implementations reject identically. Corpus 737 → **745** (745/745).
- Locked by unit tests: core `b64::decoder_is_canonical_only`, SDK `test/canonical.test.mjs` (exhaustive last-char
  sweep = the 16 canonical values). The two M12 prev_leaf differentials were independently re-verified closed
  (202 + 151 adversarial inputs, zero divergences). D-029.

### M12 — validity & renewal (ADR-017): identity eternal, credentials bounded, renewal invisible

- **One duration ladder** in `ainra_core::consts` — `PASSPORT_VALIDITY_DEFAULT_SECS` (366 d), `RENEWAL_LEAD_SECS`
  (30 d), `DELEGATE_CERT_MAX_SECS` (92 d, moved; re-exported from `checkpoint`), `INSTANCE_CRED_DEFAULT_SECS`
  (reserved) — cited by every issuer path, demo seed, the P0 CLI, and mirrored in `@ainra/sdk` (+ `renewalDue`).
- **Exact window boundaries pinned** by new `boundary-*` conformance vectors: `nbf` inclusive, `exp` exclusive; the
  ADR-016 ±30 s skew is freshness-layer only — **no skew on the passport window, no grace period: expiry is expiry**.
- **REISSUE (renewal) as a first-class operation**, distinct from ROTATE: fresh `[now, now+366 d]` window, a new
  status index, and a signed+logged **`prev_leaf`** continuity claim (schema-gated to a strict 32-byte leaf hash in
  all implementations) so renewals walk back through the transparency log as one unbroken chain. ACME-style
  issuance-side validation against the lineage continuity head — wrong/missing/forked links are refused before
  anything is logged. Overlap semantics: both generations verify until the old `exp`, then the old fails closed.
  `ainra renew <dir> <sub> [--version V] [--dry-run]` performs it. Chained (delegated) passports are explicitly NOT
  auto-renewable (renewal of a delegation is a re-delegation).
- **Revocation is lineage-wide across generations** — revoking a renewed lineage flips every unexpired generation's
  bit, so renewal can never be a revocation bypass (test-proven).
- **L3+ audit cap**: issuance/renewal refuses a passport whose `exp` exceeds the registrar-side tier audit's own
  expiry (`AuditRequired`/`AuditStale`, with the reason spelled out) — "audited" means audited recently. The wire
  format is unchanged (evidence stays at the registrar per Standard §4).
- **Status-list GC deferred honestly** (D-028): measured math + the 2^24 index-burn threshold recorded; the status
  URI is already the cohort discriminator, so sharding needs a directory-side extension only, no credential change.
- Corpus 684 → **737** passport vectors (all three implementations agree 737/737; existing vectors byte-identical);
  release tests 104 → **117**. Decisions: D-027, D-028; spec: MTS ADR-017.

`v0.1.0` is the first tag (the human cuts it as step 3 of the pre-push checklist in `docs/_archive/PUBLISH-AUDIT.md`).

## [v0.1.0] — the first public release (pending tag)

The first tag of the reference implementation: the full MTS §27 engineering ladder (M1–M8) plus the public-readiness
and stranger-runnable-DoD work (M9–M11). Everything below is provable from a clean clone with `make preflight`.

### Protocol & core (M1–M8)
- **M1** — `ainra-core` pure verify/issue library (N7: no I/O, no clock), canonical encoder, 15 frozen reasons, hybrid
  **Ed25519 + ML-DSA-65 (both-signatures-or-invalid)**; **684 CC0 conformance vectors** + a 3-way differential harness.
- **M2** — transparency pipeline (`logd`), RFC 6962 Merkle inclusion, **logged-before-valid**, dual-signed hops.
- **M3** — Token Status List deltas + fresh head, registrar-in-a-box, `ainra-cli-rs`, explorer.
- **M4** — **FROST 5-of-9 threshold Ed25519 + SLH-DSA-128s dual root** (D-001), delegate cert/rotation (D-002).
- **M5** — the verifier **wedge**: `@ainra/sdk` GA `Verifier` (~5-line, offline, fail-closed) + `@ainra/middleware`.
- **M6** — **witness quorum (k-of-N)** fork drill; fresh-head currency mode; k is the relying party's, never a cert's (D-021).
- **M7** — **reproducible builds** (`make repro`, byte-identical clean rebuild ×2) + mirror byte-verify (D-022).
- **M8** — **`make genesis-local`**: the whole stack on one laptop; two cryptographically distinct registrar classes;
  the §29 DoD table marked honestly (D-023).

### Public-ready & stranger-runnable (M9–M11)
- **M9** — own git repo, dual-license Apache-2.0 OR MIT + CC0 vectors, CI on every push, four **kits** (verifier /
  ceremony / soak / witness) so outsiders run the pending DoD events; the verifier attestation is **execution-bound**
  (D-024).
- **M10** — publish audit + history hygiene (D-025), cold-open onboarding per kit, the **genesis board**
  (`make genesis-status`, honest 7/11), `outreach/` recruitment, front door with a CI-enforced status line.
- **M11** — CI runs the full gate set on the host (+ a `make audit` PR gate + nightly), community-health files, this
  changelog + `make release`, the external-verifier **operator loop**, and a durability pass (D-026).

### Security (fixed before first release — owned publicly)
Each was found by adversarial review, reproduced against the real code, fixed, and regression-tested (see D-024):
- **CRITICAL — verifier collector fail-open.** An attestation with an empty artifact set passed vacuously. Fixed: a
  required, complete, byte-matching corpus; empty/partial fails closed.
- **HIGH — ceremony quorum forgeable by base64 aliasing.** The distinct-custodian check compared raw base64 strings, so
  padding-stripped aliases of one key posed as N "distinct" signers (3 keys forged a 5-of-5). Fixed: dedup on the
  canonical decoded key.
- **HIGH — attestation proved *agreement*, not *execution*** (and the docs over-claimed "execution"). Fixed: a fresh,
  secret coin-flip challenge corpus the party can only answer by actually verifying (forge prob 2⁻ᴷ); docs corrected to
  the exact honest scope.
- **HIGH — soak report trusted its own SLO threshold.** A re-signed PASS over a breaching log could pass. Fixed: the
  verifier pins the SLO + challenge itself and recomputes from the log.
- **MEDIUM** — canonical-JSON array-replacer dropped nested keys from signatures; soak trailing-drop; ceremony
  file-count without identity binding — all fixed with regression tests.

### Not done (by design — real-world events, not code)
A recorded 5-of-9 ceremony · ≥3 independent external verifiers · a 14-day/3-region revocation soak · independent
witnesses on separate infra. The machinery for all four is built and smoke-proven; `make genesis-status` shows the
honest count (**7/11** today). See `GENESIS-CHECKLIST.md` and `outreach/`.

[Unreleased]: https://github.com/JacobJandon/ainra/compare/v0.3.0...HEAD
[v0.3.0]: https://github.com/JacobJandon/ainra/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/JacobJandon/ainra/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/JacobJandon/ainra/releases/tag/v0.1.0
