<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# AINRA Soak Harness — revocation propagation, measured

The §29 exit bar includes *revocation p95 < 60 s across three regions for 14 days*. This is the **instrument** that
measures it — and it never asserts a number: every latency is the **real wall-clock time** from a revocation to when
a **root-dark** verifier at a given vantage point first sees the passport as `INVALID(revoked)`. Measurements go into
an **append-only, hash-chained** log; the live page and the **signed** `soak-report.json` are rendered from that log;
the SLO verdict is **computed from the data** and **fails closed** if missed.

## Prove the instrument works (≈ minutes)
```sh
make soak-smoke            # from the repo root: real registrar, ~20 issue/revoke cycles, 3 vantage points
```
You'll see the measured p95, a `PASS`/`BREACH` verdict, and an independent verification of the log + report against a
**pinned** SLO and challenge (see below):
```
measured p95 = 0.0XXs (SLO < 60s) · misses 0 · → PASS
  ✓ report + log soak-start carry the challenge we issued (this run is ours, not fabricated)
  ✓ append-only hash chain intact over N entries
  ✓ soak-report signature covers the whole body
  ✓ SLO verdict recomputed against OUR pinned target → PASS
```
The smoke's vantage points all poll one registrar on `localhost`, so the numbers are real **single-host** latency
(milliseconds) — it proves the *mechanism*, not a WAN latency. `make soak-smoke` recommends a ~10-minute run; pass a
larger cycle count (`make soak-smoke CYCLES=2000`) or use `--duration-sec` directly for longer.

## Run a real 3-region, 14-day soak
The instrument is `kits/soak/soak.mjs`. Run **one process per region**, each pointed at the registrar's public URL
(or that region's mirror), so each vantage point measures what it actually observes from where it is:

```sh
# in region eu-west, us-east, ap-south — same command, different --vantages label + --out.
# NONCE is a single-use challenge the party collecting evidence pins out of band; it binds this run's log + report.
node kits/soak/soak.mjs \
  --registrar https://registrar.example \
  --directory ./directory.json --roots ./roots.json --now $(date +%s) \
  --vantages eu-west,us-east,ap-south \
  --duration-sec $((14*24*3600)) --poll-ms 1000 --slo-p95-sec 60 --challenge <NONCE> \
  --out ./soak-out
```
(For a genuinely independent 3-region measurement, run three copies — one per region — each with a single
`--vantages <region>` — and merge their reports; or run one coordinator that fetches from three regional endpoints.
What matters is that each latency is measured *from* the region, not asserted by us.)

Outputs (all gitignored — evidence is generated, not committed):
- `soak-log.jsonl` — every measurement, hash-chained (append-only, tamper-evident).
- `soak-status.html` — a live status page rendered from the log.
- `soak-report.json` — a signed `{body, reporter_pubkey, sig}` with p50/p95/p99 per vantage + overall, the SLO
  verdict, host/region/time stamps, and the log's tip hash.

## Collecting evidence without trusting the runner
The runner self-signs with an **ephemeral** key, so the signature alone proves only internal consistency. A third
party verifies a run by **pinning the target SLO and the expected challenge themselves** — never reading either from
the report:
```sh
node kits/soak/verify-log.mjs --log soak-log.jsonl --report soak-report.json \
  --slo-p95-sec 60 --challenge <NONCE>          # optionally: --reporter-pubkey <spki-b64 given out of band>
```
It confirms the report + the log's `soak-start` both carry the nonce we pinned (the run is ours, not fabricated for a
challenge we never issued), the hash chain is unbroken (no line edited/inserted/dropped) and its measurement count
matches the report's (catching a trailing drop), the signature covers the whole body, `log_head_hash` equals the chain
tip, and the SLO verdict is **recomputed against OUR pinned target** — a re-signed `PASS` report over a breaching log
is rejected because the threshold is never taken from the report. A `BREACH` is recorded honestly and exits nonzero —
a missed SLO is a finding, never smoothed over.

## Privacy / N7
This is the **kit layer**, not `ainra-core` or the shipped SDK. It makes exactly the requests it needs to the
registrar you point it at, and writes local files. No third-party telemetry, no phone-home.
