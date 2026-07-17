<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Deploy the 14-day / 3-region revocation soak

The §29 exit bar includes *revocation p95 < 60 s across three regions for 14 days*. This is how you run it for real.
The instrument only ever **measures** — every number is the real wall-clock time from a revocation to when a root-dark
verifier in a region first sees `INVALID(revoked)`. Nothing is hardcoded; a missed SLO is recorded honestly and fails
closed.

## What you need
- A **live registrar** (or its public mirror) reachable from each region — the one whose revocations you're measuring.
- **≥3 vantage points**: any three hosts you control in three regions (VMs, containers, a Pi in a closet — independence
  of *location* is what matters, not the provider). Each needs **Node 18+** and outbound HTTPS to the registrar.
- The published **`directory.json` + `roots.json`** (so each vantage runs a real root-dark verifier), and a run
  **`CHALLENGE`** nonce you pick and keep (it binds this run's log + report; a collector pins it out of band).

## Per region (one process each)
On each host, from `kits/soak/` (with `@ainra/sdk` installed):

```sh
node soak.mjs \
  --registrar https://registrar.example \
  --directory ./directory.json --roots ./roots.json --now $(date +%s) \
  --vantages <this-region>            # e.g. eu-west  (one label per process)
  --duration-sec $((14*24*3600)) --poll-ms 1000 --slo-p95-sec 60 \
  --challenge <RUN_NONCE> --out ./soak-out-<this-region>
```

Each process continuously issues + revokes real lineages and appends every measurement to an **append-only,
hash-chained** log (`soak-out-*/soak-log.jsonl`), renders a live status page (`soak-status.html`) from that log, and
writes a **signed** `soak-report.json`. Run one process per region so each report reflects what that region actually
observed. (A single coordinator polling three regional endpoints also works; what matters is that each latency is
measured *from* the region.)

## Watch it live
`soak-status.html` is rendered from the measured log — open it, or serve the `soak-out-*/` dir. The genesis board
(`make genesis-status`) ingests the finished `soak-report.json`s and shows p95 vs the 60 s target with elapsed-time
honesty ("day 3 of 14").

## Verify a run without trusting the runner
Any third party checks a finished run:

```sh
# structural integrity (signature + tamper-evident chain + numbers recompute from the log):
make soak-verify OUT=./soak-out-eu-west
# to also GATE the SLO, pin the target + challenge YOURSELF (never read them from the report — D-024):
make soak-verify OUT=./soak-out-eu-west SLO=60 CHALLENGE=<the-nonce-you-pinned>
```

A tampered log or a re-signed PASS over a breaching log is rejected. A `BREACH` is recorded honestly and **blocks** the
DoD declaration — that's the point.

## Prove the instrument first (10 min, local)
Before committing to 14 days, confirm the whole mechanism end-to-end on one host:

```sh
make soak-smoke        # real registrar, ~12 issue/revoke cycles, 3 local vantage points, signed report, verify + tamper-reject
```

The smoke's vantages all poll one `localhost` registrar, so its numbers are real **single-host** latency (ms) — it
proves the *mechanism*, not WAN propagation. The real run is the identical instrument with `--duration-sec` and
regional `--registrar` URLs.
