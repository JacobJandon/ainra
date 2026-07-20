<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Runbook: rollback
1. `docker compose -f deploy/compose.staging.yml up -d --no-deps <service>` pinned to the PREVIOUS image digest.
2. Data volumes are backward-compatible (the log is append-only; snapshots reload) — no data migration to undo.
3. `make stage-smoke`. If a bad artifact was published, re-run `bash tools/stage.sh publish` from a healthy registrar.
The read path is immutable-cached: a rolled-back checkpoint at height N is byte-identical, so caches need no purge.
