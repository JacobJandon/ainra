<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Deploying the AINRA staging network

**STAGING on a TEST-ROOT — real infrastructure, real crypto, honest labels.** No trust migrates to the future
production root (born only at the recorded genesis ceremony — a pending DoD row). See docs/SECURITY-STAGING.md.

## The fastest path — one host, no containers (runnable now)

```sh
make stage-up        # 2 registrar classes + a witness + the artifact server; genesis-seed a real network
make stage-status    # the live board (services up, records, checkpoint height, write-auth)
make stage-smoke     # issue → log → verify via the public contract → revoke → propagate; assert headers
make stage-down
```

AINRAscan against it: `http://localhost:8090/?net=http://127.0.0.1:8091`.

## One host with containers

```sh
cp deploy/.env.example deploy/.env      # then edit: set AINRA_STAGE_ISSUE_TOKEN to a random secret
docker compose --env-file deploy/.env -f deploy/compose.staging.yml up -d --build
# populate the public volume from the running registrars (publisher step):
bash tools/stage.sh publish             # or run it on a cron; a production deploy publishes on every log growth
```

Services: `registrar-07` (:4907), `registrar-11` (:4911, a distinct key class), `witness` (:4891), `artifacts`
(:8091, the public read surface). Images are minimal, non-root (uid 10001/10002), read-only rootfs, health-checked.
Pin image digests in production (`docker inspect --format '{{index .RepoDigests 0}}'`).

## Three-host regional layout (you supply hosts + domains)

The read surface scales by CDN, not by more registrars; the split is about **failure independence** and putting
witnesses on separate operators/infra.

```
  host-A (region 1)          host-B (region 2)          host-C (region 3)
  ─────────────────          ─────────────────          ─────────────────
  registrar-07               registrar-11               witness (independent operator)
  artifacts (edge)           artifacts (edge)           artifacts (edge / mirror)
  → cdn.staging.example       → behind the same CDN       → a third mirror
```

1. Run `ainra/services:staging` on host-A (`registrar-07`) and host-B (`registrar-11`) — distinct keys already
   (the daemon derives them from the id).
2. Run `ainra/artifacts:staging` on all three, each serving a mirror of the public tree (docs/ARTIFACTS.md § mirroring); front
   them with one CDN hostname (e.g. `cdn.staging.<your-domain>`) with the two cache rules from
   docs/ARTIFACTS.md § the contract. **You supply the hosts + domain; everything else is here.**
3. Publish artifacts from each registrar into its edge's public volume (the `publish` step, on a cron).
4. TLS: standard ACME (`certbot` / `caddy` / a load-balancer's ACME) — documented, never reinvented in-process.
5. Witnesses: recruit more via deploy/witness-quickstart.md — each on a *different* operator's infra.

## Config + secrets discipline

- **One env schema** — `deploy/.env.example`. The only secret is `AINRA_STAGE_ISSUE_TOKEN` (a bearer token for the
  TEST-ROOT write path). It is **never** baked into an image or committed; compose reads it from `deploy/.env`
  (gitignored). Staging delegate/registrar keys are generated on first boot into the mounted data volume (they are
  TEST-ROOT dev material; production keys come from the ceremony tooling, not a container).
- Runbooks: `deploy/runbooks/` (deploy, upgrade, rollback, backup/restore, incident, key-rotation).
