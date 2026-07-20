<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Production cutover — config, not a fork (D-033)

Production is the **same reviewed staging deployment** with four axes changed. It is not a new codebase, not a
branch, not a hand-edited compose. Any divergence beyond the four is a place trust silently drifts — so it is
**pinned by a test**: `make config-diff` fails if `deploy/compose.production.yml` differs from
`deploy/compose.staging.yml` anywhere except:

1. **name** — `ainra-production`.
2. **banner env** — `AINRA_NETWORK=production` (no TEST banner). Services + AINRAscan display STAGING vs PRODUCTION
   **by which root key signs the directory they read** — one codebase, honest either way (the artifact server emits
   `X-AINRA-Network`/`X-AINRA-Root`; AINRAscan reads them; the deploy profile sets them from the real signing root).
3. **volumes** — `prod_*` (separate from staging; staging's data is never touched).
4. **key source** — the root chain comes from the **recorded genesis ceremony**, mounted into the production
   registrars on first boot, NOT the dev first-boot key generation staging uses.

**Nothing trusted migrates from staging to production:** different root, different keys, different domains, and the
banner tells anyone which they are looking at. Staging keeps running throughout, TEST-labeled, untouched.

## DNS / domain checklist (the operator registers the domains)

Before T−1d, create and verify each record. Placeholders — substitute your registered domain:

| Record | Value | Verify |
|---|---|---|
| `A`/`AAAA` `cdn.<domain>` | the artifact-server edge(s) / CDN origin | `dig +short cdn.<domain>` resolves from ≥2 networks |
| `A`/`AAAA` `registrar-07.<domain>` | host-A | `curl -fsS https://registrar-07.<domain>/health` → `network:production` |
| `A`/`AAAA` `registrar-11.<domain>` | host-B | `curl -fsS https://registrar-11.<domain>/health` |
| `CAA` `<domain>` | your ACME CA | `dig CAA <domain>` |
| TLS | ACME (certbot/caddy/LB) — standard, not reinvented | `curl -Iv https://cdn.<domain>/index.json` shows a valid cert |

Do not proceed to T0 until every record resolves and TLS validates from an external network (GO/NO-GO gate).

## Release discipline — the `v1.0.0-genesis` tag

- **Which commit ships:** the exact commit `make preflight` + `make config-diff` are green at, tagged
  `v1.0.0-genesis` (signed: `git tag -s`). Its `MANIFEST.sha256` is the byte-for-byte artifact set (`make repro`).
- **Freeze window:** from T−1d GO/NO-GO #1 to cutover confirmation, **no commits** to the shipping ref except an
  **ABORT-class fix** (a change required to safely abort/reschedule — nothing else).
- **Re-tag on abort:** an aborted genesis deletes the tag; the next attempt re-runs the full GO/NO-GO and re-tags at
  the (possibly patched) commit. A tag is never reused across attempts.
- The freeze covers the normative docs already (`make check-freeze`); this extends the discipline to the deploy
  profile + the shipping commit.
