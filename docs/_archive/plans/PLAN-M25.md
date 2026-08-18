<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M25 — state audit · M24 close · the front door

Three jobs, in order: (0) establish exactly where the repo stands — evidence, not memory; (1) close whatever of
M24 remains; (2) rebuild the landing's opening so the first screen carries the argument (owner's explicit
authorization: the hero protection is **lifted for this task only**; palette, sigil, crest, the kicker slogan,
and the 3/3/3 nav remain sacred). All prime directives bind: nothing fake, fail closed, no third-party names
(S7 with full output read), zero telemetry, DoD untouched, D-0xx decisions, the one release rule.

## Task 0 — exact state audit (evidence pasted at audit time, HEAD = `f8bd2ed`, 2026-07-30)

| # | Row | Status | Evidence (pasted, not remembered) |
|---|-----|--------|-----------------------------------|
| 1 | v0.2.0 tagged? | **NOT TAGGED — tag-ready, maintainer's button** | `git tag -l` → *(empty)*. RELEASING.md pins the target: `\| **v0.2.0** \| **`5ae1b12`** \| docs/releases/v0.2.0-board.md — full 17-row board ALL GREEN from a clean clone; ran at parent 0691f38 …\| tag-ready; awaiting the maintainer's git tag -s v0.2.0 5ae1b12 \|`. Pin matches the board-evidence commit. Not agent work. |
| 2 | M24·1 Python implementation | **DONE** | `packages/sdk-py/pyproject.toml` exists; joins the differential as column 4 over the FULL corpus — `make diff` (fresh run): `(F) verdict diff core↔py : 745/745 agree · (F) delta diff core↔py : 17/17 agree · (F) directory diff core↔py : 9/9 agree · DIFF OK: all implementations agree (core ↔ sdk ↔ P0 ↔ py)`. Crypto out loud: D-041 (pyca `cryptography`/OpenSSL for Ed25519+ML-DSA-65, ctypes-bound SLH-DSA — shared primitives, independent logic). Quickstart `docs/quickstarts/python.md` with real pasted output; landing `#integrate` has the Python tab. |
| 3 | M24·2 Conformance Programme | **DONE** | `tools/conformance/{run.mjs,CONTRACT.md,adapters/broken.mjs}` + `docs/conformance/PROGRAMME.md` exist; PROGRAMME.md line 4 verbatim: `**We don't certify implementations — we make certification unnecessary.**` Fresh `make conformance`: 3 verdict impls clean (`ainra-core / ainra-sdk-ts / ainra-sdk-py — passport 745/745 delta 17/17 directory 9/9 divergences=0 → PASS`), sabotaged adapter `correctly FAILED — 66 named divergence(s)`, self-attestation `ACCEPTED — ainra-sdk-ts@0.3.0`. Honest caveat: the runner covers the **three** implementations that implement vector-verify; the downloadable CLI (P0) has no vector-verify surface — it participates in the differential's canon lanes (B: 10/10 byte-identical), which is why the differential is 4-way and the conformance table is 3-row. |
| 4 | M24·3 Supply-chain | **DONE** | D-042 (SSH-Ed25519 `ssh-keygen -Y`, offline key); `tools/release-attest.mjs` (SLSA-shaped provenance + CycloneDX SBOM in `dist/`); `release/ainra-release.pub` committed; `RELEASE-VERIFY.md` **executed for real** against the v0.2.0 artifacts with pasted output — line 36: `Good "file" signature for release@ainra.org with ED25519 key SHA256:V1ZbCNdPDEe5plpYq07dGCsoensF4Q+MPPQQkcj5pi4`. Site: `status.html` "Release integrity" block fed by live data. |
| 5 | M24·4 Publish dry-runs | **DONE** | RELEASING.md publish checklists (commit `49af7f1`) are dry-run-verified: `npm pack` contents listed per tarball, wheel + sdist built, wheel installed clean in a fresh venv, quickstarts pass. No registry publish, no tags — maintainer's buttons. Known blockers documented there: middleware `file:`→`^0.3.0` repoint at publish time; `@ainra/mcp` not standalone. |
| 6 | M24·5 v0.3.0 closure | **PARTIAL → the work of M25 Task 1** | Versions bumped 0.2.0→0.3.0 everywhere drift-guarded (commits `27e320d`…`f8bd2ed`); CHANGELOG v0.3.0 entry present; owner's manual gained the Python cookbook + conformance chapter. **Missing: `docs/releases/v0.3.0-board.md`** — `node tools/changelog-board-guard.mjs` → `✗ v0.3.0 — CHANGELOG claims it, but docs/releases/v0.3.0-board.md is ABSENT` (exit 1). Expected red; the board runs from a clean clone at the M25 release commit, LAST. |
| 7 | Site state | **DONE (pre-M25-Task-2)** | Content pages: `index get verify standard foundations status` + `404` + redirect stubs `demo scan` (both `http-equiv="refresh"`). Nav 3/3/3. `#integrate` Python tab present; `get.html` carries the live-network surface (6 refs); `status.html` release-integrity + fingerprints from live data. S7 fresh, all three lines: `S7 OK (fixtures): 32 denied names, none present… · S7 OK (brand): 27 foil brands, none present… · S7 OK: neutral…`. |

Only row 6 is open work. Row 1 is the maintainer's button by design.

## Task 1 — close M24: the v0.3.0 board

Per the one release rule (RELEASING.md, D-040): full preflight board from a **clean clone** at the release
commit → `docs/releases/v0.3.0-board.md` in the same shape as the v0.2.0 evidence file, every row green
including the new `conformance` row, `make changelog-board-check` green with it, and the v0.3.0 tag target
pinned in RELEASING.md's pending-tags table. Runs **last**, after Task 2, so the board proves the commit that
actually ships.

## Task 2 — the front door

Rebuild the landing opening with the owner-approved neutral wording: the reality line under the H1, the seven
questions as the unmissable centerpiece (static no-JS / reduced-motion fallback showing the full list), the
three-line answer. The hero gets **shorter overall**; CTAs stay two; the kicker stays above; `#root` orbit
untouched below. The lower "Soon, your AI will act for you" section — now largely duplicated by this hero —
is cut to a compact three-beat remnant (problem → fix → control); zero repeated sentences on the page. Claims
stay measured ("milliseconds", "under a minute [measured]"). Mirrors/sitemap/llms regenerate.

## Task 3 — QA and closure

Browser QA (real Chromium): every page renders off live data, nav 3/3/3 + mobile burger, the questions device
works with JS off and honors reduced-motion, zero console errors. `make site-check`, link-check, S7 full-output
green and quoted. Launch bundle regenerated (old zip deleted, current CLI inside, standalone serve proven).
Working tree clean; every commit maps to its task.

Prohibitions: no tag, no publish, no certify, DoD untouched, merged pages stay merged, palette/sigil/crest/
kicker/nav unaltered, no claim outruns its evidence.
