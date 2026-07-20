<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Runbook: the 14-day / 3-region revocation soak (DoD row — the human starts it)

The 3-host staging network (deploy/README.md) IS the soak platform. This measures revocation propagation p50/95/99
from ≥3 regions into a **signed, tamper-evident** report that `make genesis-status` reads. The machinery is
`kits/soak/`. **Do not start the 14-day clock casually — that is the operator's button.**

## Start (on the deployed 3-region network)

1. Stand up staging across ≥3 regions (deploy/README.md, three-host layout); confirm `make stage-status` UP on each.
2. On each region's vantage host, point the soak agent (kits/soak/) at that region's published fresh-head + status
   endpoints (`http://<edge>:8091/registrars/<id>/{fresh-head,status/current}.json`).
3. Start the measurement: the agent revokes a canary lineage on the registrar and times how long each region's
   published fresh-head reflects it — p50/95/99 into a hash-chained, signed report. Target: p95 < 60 s.
4. Let it run **14 days**. The signed report accrues under the soak evidence path.

## How it lands as a DoD row

`make genesis-status` turns the "14-day / 3-region soak (p95 < 60s)" row ✅ **only** when a signature-checked report
with ≥3 regions over ≥14 days backs it — never on assertion. `make soak-verify` independently rechecks the report
(catches tamper; does not trust the report's own SLO claim). Smoke-test the instrument any time without the 14-day
commitment: `make soak-smoke`.

This runbook advances the machinery; the 14-day real-world measurement is the human's to start and the clock's to finish.
