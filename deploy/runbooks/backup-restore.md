<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Runbook: backup / restore (log + status volumes)
The source of truth is the append-only log; the DB/snapshot is a rebuildable index.
Backup:  `docker run --rm -v reg07:/data -v "$PWD":/b alpine tar czf /b/reg07-$(date +%F).tgz -C /data .`  (repeat per volume)
Restore: stop the service, `tar xzf` into the volume, start it. The daemon replays `entries.log` + stored deltas and
**re-verifies every replayed delta** (fail-closed on a tampered snapshot). Then `bash tools/stage.sh publish`.
Verify a restore: `make stage-smoke`. Integrity-check any mirror: `make verify-mirror MIRROR=<dir>`.
