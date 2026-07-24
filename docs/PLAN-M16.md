<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M16 — The onramp

The protocol is deeper than the current agent-infrastructure wave; the onramp is a README. This milestone builds the
onramp — self-serve paths, an MCP server, an agent-readable onboarding file, one presentation envelope + verdict event
shape, an open registrar console, and a DX polish pass. Two constitutional constraints bind every task: **the ROOT gains
no product surface and sells nothing** (all self-serve lands in the registrar layer + verifier tooling, per the ICANN
model), and **no third-party company/product names anywhere** (describe patterns, never vendors). All prime directives
bind (nothing fake, zero telemetry, fail closed, never weaken a test, D-0xx decisions, DoD untouched, preflight green).

## Task 0 — the onramp we actually have (measured, clean clone, this host)

- **Cold build** (fresh `git clone` → `cargo build --release -p ainra-cli-rs`, whole dep tree): **37.9 s**. Clone: 0.25 s.
- **(a) verify a seeded credential** — no single documented command today; closest is `make demo`: **warm 0.44 s**, **cold 38.6 s**. There is no offline "fetch a directory + a bundle → verdict" path a stranger can run.
- **(b) clone → own registrar → issue → verify** — `ainra init` + `ainra issue` + `ainra verify`, no single documented command: **warm 1.34 s** (verdict VALID), **cold 39.5 s**.
- **Verdict:** warm timings already beat the targets; the gap is that **there is no one documented command and no offline stranger-verify path** — the newcomer must read the tree and assemble it. That is what Tasks 1–6 fix. Targets: (a) ≤ 60 s, (b) ≤ 5 min on a warm toolchain — honest numbers stated, never rounded.
- **After (this milestone):** one documented command each. `make verify` (offline, fetches a directory + a sample bundle → real verdict + named-reason legend, honest label) ≈ **1.7 s** warm; `make issue-first` (persistent registrar) ≈ **2.2 s** warm. Cold (fresh clone, includes the one build) both land well under the targets. The onramp went from *a README* to *two commands + an MCP server + `/skills.md` an agent follows itself*.

## Tasks

- **T1 — Sixty-second paths.** `make verify` (one command: fetch a directory + sample bundle → real verifier verdict + named-reason legend, no account/server/config, honest LOCAL TESTBED / STAGING·TEST-ROOT label) and `make issue-first` (`ainra init` → issue → verify, plain-words narration, leaves a **persistent reusable** registrar). Both point at the cookbook. After-timings pasted.
- **T2 — MCP server** (`packages/mcp`, `@ainra/mcp`): `ainra_verify/lookup/issue/renew/revoke/status` mapped 1:1 onto existing surfaces; safety annotations (read-only vs destructive, destructive needs explicit confirm); one config field selects genesis-local vs staging; zero telemetry; wrapper-fidelity differential (MCP verify ≡ SDK byte-identical over sampled vectors); generic three-step quickstart.
- **T3 — Agent-readable onboarding** `/skills.md` (+ `/agents.md` alias) from repo root and the staging public surface: deterministic, marketing-free, every step executable-as-written, replayed green in CI.
- **T4 — One envelope, one event shape** (`docs/PRESENTATION.md`): the single recommended request envelope (header + encoding + size) and the single verdict event shape (status, named reason, name, Number, tier, freshness age); middleware + MCP + CLI all emit it; one differential asserts the three serialize identically.
- **T5 — Open registrar console** inside registrar-in-a-box (local + staging registrars): issue/renew/revoke/list with live verdicts, ADR-017 fleet expiry horizon, mandate/delegation views; unbranded + neutral, no pricing/accounts (D-0xx); M14 write-path rate limits apply; CLI stays the power surface.
- **T6 — DX polish:** error-message sweep (every newcomer failure names the next command), per-surface quickstarts (`docs/quickstarts/`, ≤1 screen each, real pasted output), `examples/` gallery (gate / verify-then-act / MCP issue→verify→revoke), README rewritten around the two paths with the honest-status block above the fold.

## Acceptance

Both sixty-second paths run from a clean clone with pasted real timings; MCP wrapper-fidelity differential green; skills file
replays green in CI; three-surface verdict-shape differential green; console demonstrates the full lifecycle against
genesis-local **and** staging; `make preflight` + `make diff` green from a clean clone; DoD table untouched; every staging
surface still labeled TEST-ROOT; zero telemetry; no third-party names. Root gains no issuance/self-serve surface; no
accounts/billing/pricing anywhere. End: paste before/after onramp timings + one true sentence on what a stranger's agent can now do by itself.
