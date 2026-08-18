<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M17 — the public face becomes real

M16 built the onramp; M17 wires `site/` to the live staging backend and adopts the agent-first onboarding
conventions (skills, MCP, plain HTTP) with **zero vendor branding** — copy line: *"works with any agent that
speaks the open conventions: skills, MCP, plain HTTP."* All prime directives bind: nothing fake, zero telemetry,
fail closed, TEST-ROOT labels on every staging surface, D-0xx decisions, DoD untouched, `make preflight` green.

- **0 — GATE (done).** Clean `stage-down → stage-up` resurrects the network; `make stage-status` is real; the live
  board equals the published contract (2 registrars / 8 records / 2 revoked); the registrar console is live at
  `<reg>/console`; the artifact contract serves live JSON with CORS + `X-AINRA-Network: staging`. **Fixed D-035:**
  `publish()` is now idempotent — it dropped a stale `registrar-22` dir that had inflated `registry.json` past the
  live board (the contract was advertising a dead registrar).
- **1 — one-command serve + deploy profile.** `make site-up` serves `site/` (built downloads refreshed first);
  `make stage-all` brings site + artifacts + console + explorer up together.
- **1 — live-data adapter.** `site/js/live.mjs` reads the public artifact contract client-side for the numbers that
  *can* be live (registrars, issued, revoked, checkpoint height, witness, freshness age); honest constants
  (production logs sealed = 0 until genesis) stay **config-driven from root-key detection**, not copy.
- **1 — no drift, no dead links.** One shared header/footer, generated into every page at build so pages can't
  diverge; `tools/link-check.mjs` in CI fails on any dead internal href/anchor.
- **1 — access form.** Structured `mailto:` that stores **no PII on any server we run** (D-036); no fake success states.
- **2 — the working demo.** `/demo` completes the full lifecycle against staging with real crypto: **issue** (registrar
  public door, rate-limited, TEST-ROOT banner, placeholder operator) → **watch it log** (leaf + checkpoint height +
  witness cosigs, AINRAscan deep-link) → **verify in-browser** (SDK recomputes the inclusion proof locally; the page
  says exactly that) → **revoke** → re-verify the named fail-closed reason. A visible **verdict-event console** streams
  the one M16 envelope at each step. Acceptance = a **headless CI walkthrough** asserting all five transitions.
- **3 — agent-first surface.** `agent-instructions` meta on every page → `/llms.txt`; `/llms.txt` capability map
  (two honest sentences, four functions, links to `/skills.md`, the `.md` mirrors, the OpenAPI specs, the conformance
  vectors, the honest-status block); generated `.md` twins of every content page (in `sitemap.xml`, cannot drift);
  `/.well-known/skills/index.json` + real `skills add <url>` install test; a landing **self-onboard block** whose
  `/skills.md` loop an MCP agent runs with only the human approval click (M16 confirm-required write path); **OpenAPI**
  (JSON+YAML) for the read contract + registrar door + console API, verified against reality — **no invented verify
  REST API** (verification is local; the spec says so, prominently — the absence is the product).
- **4 — prove "any agent," name none.** Run self-onboard → issue → verify → revoke through **3 independent
  MCP/skills-capable clients**; record generic evidence ("3 clients, all green, no client-specific code"), transcripts
  kept as redacted artifacts.
- **5 — landing compression.** Shrink the hero (≈⅓ less vertical padding, one type-step down on H1, one-line subhead,
  the **compact** passport card: NAME · NUMBER · AUTHORITY · TIER · VALIDITY · STATUS + MRZ); remove the statement band
  (its CTA folds into the hero row); merge the facts strip into one line; keep the developer + status-disclosure blocks;
  add the self-onboard block where the band was. Palette / sigil / crest / kicker / footer untouched. State the line delta.
- **Acceptance.** Clean clone → `make stage-up && make site-up` → the scripted headless walkthrough passes; `/llms.txt`,
  `/skills.md`, `/.well-known/skills/index.json`, both OpenAPI specs, and every `.md` mirror serve with live-checked
  links; the demo lifecycle is green headlessly and by hand; an agent self-onboards with only the approval click; the
  landing is measurably shorter; `make preflight && make diff` green; DoD untouched; zero vendor names; zero telemetry.
