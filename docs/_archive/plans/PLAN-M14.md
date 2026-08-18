<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# M14 — the staging network: the full stack on the internet, honestly labeled

M1–M13 made the protocol + reference stack engineering-complete (745/745 differential, preflight green from a clean
clone, board 7/11). The gap was real: everything ran on one laptop. M14 puts the **whole stack up as a staging
network on a TEST-ROOT** — real deployment, real crypto, real public artifacts a browser verifies — refusing every
dishonest shortcut. "Used by billions" is not code; adoption is humans. What is built and measured is the property
that *makes* billions possible: verification is local (N agents → ~zero root load) and the only global surface is
cacheable static files. Labeled STAGING/TEST-ROOT in every artifact, page, and README.

- **Runnable network (one host):** `make stage-up` → 2 registrar classes (distinct keys) + an independent witness +
  the artifact server; genesis-seeded over HTTP with real crypto (issue · delegate · revoke · **ADR-017 renew**),
  every lifecycle state. `make stage-status` = the live board from real endpoints. `make stage-down`.
- **The public artifact contract** (D-031, docs/ARTIFACT-CONTRACT.md): `tools/artifact-server.mjs` serves the
  CDN-shaped read surface — CORS `*` + preflight, `immutable`/`max-age=1y` on content-addressed checkpoints/tiles,
  `max-age=5` + strong ETag on heads/deltas/exports, gzip, and the `X-AINRA-Network: staging` / `X-AINRA-Root:
  test-root` banner on every response. docs/MIRRORING.md: mirror the whole surface with rsync/HTTP; point any
  verifier at any mirror (the root can be dark).
- **`make stage-smoke`** (real output, live deployment): issue → log → verify in the real SDK **over the public
  contract** → revoke → propagate; asserts CORS/ETag/immutable/banner headers; and the write path returns 401
  unauthenticated.
- **Online-exposure hardening** (D-032, docs/SECURITY-STAGING.md): registrar `/issue|/revoke|/renew` require a
  bearer token (`AINRA_STAGE_ISSUE_TOKEN`, never in an image/repo) + a coarse rate limit + a 1 MiB body cap; read
  path open. Zero PII in artifacts/logs (placeholder operators; schema rejects PII); client surfaces telemetry-free;
  server observability self-hosted (ADR-015). An attacker owning staging gains nothing about the production root —
  different root, different keys, labeled — and tampered data fails closed at every verifier.
- **AINRAscan goes real, on staging:** `…/ainrascan/?net=<artifact-server>` fetches the staging registry over CORS
  and verifies every lineage **in the browser** with the real `@ainra/sdk` bundle + an independent RFC 6962
  inclusion recompute — proven live over 8 staging lineages (valid green, revoked red, one renewal chain).
- **Planet-scale proof** (docs/SCALE.md via `make scale`): device verify cost (measured), log proofs at 8.6 B
  (measured trees + extrapolated), revocation for 10⁷/10⁸/10⁹ (measured; decode/lookups on a real ≤2²⁴ segment,
  full-blob compressed size measured), sharded issuance (measured), and a **distribution load test** of the artifact
  server (~8000 req/s immutable / ~5000 mutable, 1 laptop node, 0 failures) with the honest CDN argument. Closing:
  the numbers prove the architecture holds at planetary scale; they do **not** prove usage.
- **Deployment engineering:** `deploy/` — minimal non-root health-checked containers (Dockerfile.services /
  .artifacts), `compose.staging.yml` (validated), a documented 3-host regional layout, and runbooks (deploy,
  upgrade, rollback, backup/restore, incident, key-rotation). Operator supplies hosts/domains; everything else is here.
- **Soak-ready handoff** (T7): the 3-host deployment IS the soak platform; docs/runbooks/soak.md is the exact
  start procedure for the human. `make genesis-status` turns the soak row ✅ only on a signature-checked ≥14-day /
  ≥3-region report.

## Which DoD rows this advanced the machinery for (and which await humans)

- **Advanced machinery for:** *≥3 independent witnesses on separate infra* (deploy/witness-quickstart.md — an
  outsider witnesses staging in <10 min, refusing forks); *14-day/3-region soak* (the deployment is the platform;
  runbook ready).
- **Still await humans (unfaked, untouched):** the recorded genesis ceremony, ≥3 external verifiers, and the actual
  14-day soak clock — I did not start any of them, register a domain, publish a repo, or claim usage.

`make preflight` + `make diff` stay green from a clean clone. Decisions D-031, D-032.
