<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M9 — commit, public-ready, executable by strangers

M9 turns "engineering-complete on my laptop" into "committed, public, and runnable by third parties with us not in
the room." The remaining DoD items (ceremony, ≥3 external verifiers, 14-day/3-region soak) are real-world *events*;
M9 builds the machinery + runbooks that let strangers execute them and produce self-verifying, unfakeable evidence.
Prime directives still bind: nothing fake · no third-party names (incl. fixtures, S7) · zero telemetry in shipped
components · both-sigs-or-invalid · logged-before-valid · no bespoke crypto · never weaken a test · Apache/MIT + CC0.
Conflicts → the MTS wins, logged in DECISIONS (continuing D-024…).

## Task 0 — Into git, safely (FIRST; stop for confirmation before the first real commit)
- Git root today is `$HOME`; there is no `.git` in `ainra/`. Create a fresh repo rooted at `ainra/` (`git init`),
  confirm `git rev-parse --show-toplevel` = the project.
- Strict `.gitignore` BEFORE `git add`: `target/`, `node_modules/`, `dist/`, `genesis-out/` + `*-out/` + `build/`,
  generated registrar demo state (`apps/registrar-explorer/data/`), **all secrets** (`*.secret`, `.env`, `*.key`,
  `*.pem`), fuzz crash artifacts (keep seeds), kit run-outputs, OS cruft. Keep `Cargo.lock`, `MANIFEST.sha256`,
  `docs/FREEZE.sha256`, the CC0 vectors.
- `git add -n` dry-run + `git status --porcelain`; print the staged list; **stop for confirmation** if anything looks
  like a key/secret/multi-MB blob.
- Add `LICENSE-CC0` (vectors); confirm `LICENSE-APACHE`/`LICENSE-MIT` present.
- Commit in milestone-mapped conventional commits (core+vectors → … → docs), each referencing MTS §/D-0xx.
- Acceptance: a `git clone` into a fresh temp dir runs `make test && make diff && make genesis-local` GREEN.

## Task 1 — CI on every push (`.github/workflows/ci.yml`)
- Extend the existing CI to run every green gate: `cargo test --release`, `make diff`, `make wedge-test`, `make
  drill`, `make testbed`, `make repro`, `make verify-mirror` (+ tamper regression), `make check-freeze`, fuzz-smoke
  (bounded), fmt, clippy `-D warnings`, S7, license, N7. Pin toolchains (Rust 1.96, Node). Encode the release-test
  trap (comment: debug stack-overflows on the crypto-heavy test). Green badge in the README.

## Task 2 — Make the three external DoD events executable by strangers
- **2a Verifier Kit** (`kits/verifier/`): drop-in package using ONLY published `@ainra/sdk`; ≤10-min quickstart;
  scripted run vs the testbed → verifies a live passport root-dark, a revoked one (INVALID+reason), a forged one
  (INVALID+reason); emits a signed `verifier-attestation.json` (their key, vector hashes, verdicts, ts). `SECURITY.md`
  for isolated running. Success = 3 strangers, 3 machines, 3 valid attestations. `make verifier-kit-smoke` proves it.
- **2b Ceremony Kit** (`kits/ceremony/`): operator runbook for the real recorded 5-of-9 (hardware, air-gap/ephemeral
  OS, on-camera cross-read, SLH-DSA seed handling, transcript hashing/publishing) + `make ceremony-dry-run` walking N
  operators on separate machines → a transcript whose hash a witness independently recomputes; fails loudly if a step
  is skipped. TEST-ROOT material only, with a loud marker where the real-secret step is.
- **2c Soak Harness** (`kits/soak/`): continuously issue+revoke, measure propagation from ≥3 configurable vantage
  points, record p50/p95/p99 into an append-only log, render a live status page FROM measured data, fail closed on
  missed SLO. `make soak-smoke` = ~10-min local proof. Output = signed tamper-evident `soak-report.json` + summary;
  NO hardcoded latencies in docs.

## Task 3 — Witness transport (close D-021 to deployable)
- Minimal HTTP(S) `witnessd` transport (C2SP tlog-witness shape): serve cosigned checkpoints, accept submissions;
  the quorum fetches cosignatures over the network; `k` stays the relying party's argument (regression: a fetched
  cert claiming `threshold:0` still can't self-certify). `make drill-networked` = ≥3 witnesses as separate
  processes, fork injected, refused by the networked quorum. Boring: fetch + verify, no gossip. `kits/witness/` docs.

## Task 4 — Public-readiness pass
- `README.md` front door (one-breath def, honest status, 3-command quickstart, arch, license/CoC/security links,
  CI badge); `CONTRIBUTING.md` (DCO not CLA), `CODE_OF_CONDUCT.md`, `SECURITY.md`; refresh `STATUS.md` + `DOD.md`.
- N7-respecting instrumentation: any traction/quickstart metric lives ONLY in the kit/tutorial layer, opt-in,
  count-only, documented, off by default — never in `ainra-core` or a shipped SDK.
- `GENESIS-CHECKLIST.md`: the ordered real-world runbook tying 2a+2b+2c into "how we declare the prototype done,"
  with the DoD table and which artifact proves each row.

## Acceptance bar for M9
A stranger clones, CI is green, `make genesis-local` passes, and they run the verifier kit to produce a valid
attestation — all without talking to us. End with an honest ✓-vs-pending picture + the exact real-world events still
required to call the prototype DONE.
