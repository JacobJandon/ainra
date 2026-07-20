<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Runbook: upgrade
1. Build + tag the new image; pin its digest.
2. Roll ONE registrar at a time (the other keeps serving): `docker compose up -d --no-deps registrar-07`.
3. Health-gate each before the next (`ps` → healthy).
4. `bash tools/stage.sh publish` to refresh artifacts; `make stage-smoke`.
5. The artifact server is stateless — replace freely; a CDN keeps serving cached immutable objects during the swap.
Rollback if smoke fails → deploy/runbooks/rollback.md.
