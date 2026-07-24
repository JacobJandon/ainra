<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Console quickstart — the open registrar console

Registrar-in-a-box serves a minimal web console so a first-time operator sees the whole lifecycle without reading
anything. It's neutral open-core (D-034): unbranded, no pricing, no accounts beyond the registrar's own write-token.
The CLI stays the power surface; this is the friendly face.

```bash
make registrar-console                 # serves at http://127.0.0.1:4899/console
# override: PORT=4899 ID=registrar-07 DIR=stage/console-registrar make registrar-console
```

Open it and you get:

- **Issue** — operator / lineage / version / tier / auth / capabilities → a new passport.
- **Renew / revoke** — ADR-017 renewal (fresh window, `prev_leaf` continuity) and the fail-closed kill-switch.
- **Fleet** — every lineage with its **live verdict** (recomputed by the registrar's core verifier), **standing**,
  delegation **chain**, and the **expiry horizon** (days left; renewal-due flagged at ≤30 days).

The **write path is open locally** and needs the registrar's `AINRA_STAGE_ISSUE_TOKEN` on a network deployment; paste
it into the operator-auth field (kept in memory, never stored). Every **staging registrar** serves the same console at
its own `/console`. Self-contained (no CDN, no web fonts), zero telemetry, talks only to its own registrar.

Honest labels: the header shows `STAGING · TEST-ROOT` (or `PRODUCTION`, data-driven from the signing root). This is a
reference deployment — no trust migrates to a production root.
