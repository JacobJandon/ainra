<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# M29 — the rung reaches the integrator, and claims get a registry

M28 landed ADR-019 in `ainra-core` and the corpus: 1009 vectors, five surfaces agreeing, the stolen-container hole
closed. **A protocol feature that exists only in the core and the vectors is a feature no integrator can use.** This
milestone carries it to every developer-facing surface, and closes a defect class that has now bitten three times.

---

## Task 0 · Where the repo still speaks pre-ADR-019

**Audit only — nothing fixed in this task. This table is the milestone's scope; nothing outside it.**

| Surface | State | Evidence |
|---|---|---|
| **TS SDK — code** | **UPDATED** (M28) | `packages/sdk-ts/src/index.ts` — `InstanceCredential`, `InstancePop`, `verifyInstance`, `mintInstanceCredential`, `proveInstancePossession`, `Verifier.audience` all exported |
| **TS SDK — README** | **PRE-019** | `packages/sdk-ts/README.md:15` — "Verify a presentation" documents only the passport bundle; zero mentions of the instance rung |
| **@ainra/middleware — code** | **UPDATED** (M28) | reaches the rung through the SDK; proven by `make instance-gate` |
| **@ainra/middleware — README** | **PRE-019** | `packages/middleware/README.md:24` — "every /agent request must carry a valid passport"; no audience, no instance path |
| **@ainra/mcp — tools** | **PRE-019** | `packages/mcp/README.md:36` — `ainra_verify` described over "a bundle"; the tool reports no instance-layer distinction and there is no audience input |
| **Python SDK — verify path** | **UPDATED** (M28) | `packages/sdk-py/ainra/verify.py` — `_verify_instance`, four reasons in the closed set |
| **Python SDK — public API** | **PRE-019** | `packages/sdk-py/ainra/__init__.py` exports no instance name; `_verify_instance` is private, and there is no mint helper |
| **Python SDK — `Verifier`** | **PRE-019 · SECURITY** | `packages/sdk-py/ainra/verifier.py:57` — `verify()` overrides only `revoked_delegates`, so **`audience` comes straight off the bundle**. This is the exact fail-open closed in TS during M28 and never carried across: a presenter can name its own audience and defeat audience binding. |
| **Python SDK — README** | **PRE-019** | `packages/sdk-py/README.md:45` — "Verify a bundle"; no instance path |
| **Rust core — public docs** | **PRE-019** | `crates/ainra-core/src/lib.rs:5` — the crate doc still enumerates "the four verify steps" and does not name the tenth or the rung; `instance` appears only in the module list at `:31` |
| **CLI (`apps/cli-node`) — help** | **UPDATED** (M28) | `ainra --help` lines 10–11 carry `instance issue` / `instance verify` |
| **CLI (`ainra-cli-rs`) — help** | **N/A** | the Rust CLI is the P0 differential implementation and issues nothing; it has no presentation-side surface to update |
| **`docs/quickstarts/sdk.md`** | **PRE-019** | `:14` — the five-line wedge, passport only |
| **`docs/quickstarts/middleware.md`** | **PRE-019** | `:2` — gate described as passport-only |
| **`docs/quickstarts/python.md`** | **PRE-019** | `:2` — verify described as passport-only |
| **`docs/quickstarts/mcp.md`** | **PRE-019** | `:5` — `ainra_verify` over a bundle |
| **`docs/quickstarts/cli.md`** | **PRE-019** | `:4` — no instance lifecycle |
| **`docs/quickstarts/console.md`** | **N/A** | registrar console: issuance/administration, not presentation |
| **`docs/quickstarts/conformance.md`** | **N/A** | the runner contract; corpus counts already updated in M28 |
| **`docs/PRESENTATION.md`** | **UPDATED** (M28) | carries the instance envelope and both new event fields |
| **`examples/verify-5-lines.mjs`** | **PRE-019** | `:9` — the wedge, passport only. *Correct as-is:* the five-line case must stay five lines. Needs no change. |
| **`examples/gate-http-service.mjs`** | **PRE-019** | `:9` — a real service gate with no audience and no instance path |
| **`examples/verify-then-act.mjs`** | **PRE-019** | passport-only decision flow |
| **`examples/mcp-lifecycle.mjs`** | **PRE-019** | lifecycle without the instance rung |
| **`examples/` — deployment shape** | **MISSING** | no example shows the real shape: control key outside the container, instance credential inside, service verifying with audience binding |
| **`skills.md`** | **UPDATED** (M28) | §3b, executed by `make skills-replay` |
| **`site/llms.txt`** | **PRE-019** | 74 lines, zero instance mentions — the agent-facing index does not know the rung exists |
| **site — integrate section** | **PRE-019** | `site/index.html:606` — "One line for your agent. A few for your code."; passport only |
| **site — verify page** | **PRE-019** | `site/verify.html` — zero instance mentions |
| **site — get flow** | **PRE-019** | `site/get.html` — zero instance mentions |
| **`docs/manual/*`** | **N/A — does not exist** | no `docs/manual/` in this repository; the equivalent material lives in `docs/quickstarts/` and is audited above |
| **OpenAPI specs** | **N/A — do not exist** | no OpenAPI document in the repository (`find` for `openapi*` / `*.openapi.*` returns nothing). The machine-readable contracts are `docs/ARTIFACTS.md` § the contract and `tools/conformance/CONTRACT.md`, both non-OpenAPI |

**Scope: 19 PRE-019 surfaces, 1 MISSING, 6 UPDATED (skip), 5 N/A (two of which do not exist and are not being
invented to fill a row).** One PRE-019 entry — `examples/verify-5-lines.mjs` — is deliberately left alone: the
five-line wedge staying five lines is a requirement, not an oversight.

**The one that is not documentation:** the Python `Verifier` audience fail-open. It is a live security defect of
the same shape this milestone's Task 2 exists to prevent — a fix applied in one of the places a rule lives.
