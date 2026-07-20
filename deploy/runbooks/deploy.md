<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Runbook: deploy the staging network
1. `cp deploy/.env.example deploy/.env` and set `AINRA_STAGE_ISSUE_TOKEN` to a random secret (`openssl rand -hex 16`).
2. `docker compose --env-file deploy/.env -f deploy/compose.staging.yml up -d --build`.
3. Wait for health: `docker compose -f deploy/compose.staging.yml ps` — all `healthy`.
4. Seed + publish: `bash tools/stage.sh publish` (or `make stage-up` for the no-container path).
5. Verify: `make stage-smoke` → must print `STAGE-SMOKE OK`. Confirm `curl -sI http://<host>:8091/registry.json`
   shows `access-control-allow-origin: *` and `x-ainra-network: staging`.
6. Point AINRAscan: `…/ainrascan/?net=https://cdn.staging.<domain>` and click Verify — a green you compute.
