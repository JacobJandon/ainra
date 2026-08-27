<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Drill — mirror sufficiency and what a mirror costs

**Question.** Does the full verification path work from a mirror-only environment, and what does running such a
mirror cost per day at present scale?

**That it WORKS is [ROOT-DARK.md](ROOT-DARK.md)** — an issued credential and a conformance vector both verify from
mirror bytes alone, in an isolated cage, with a revoked credential refused as the control. This document is the
cost.

**Run.** 2026-08-27T11:46:46.680Z · all sizes measured from artifacts on disk.

## The split that a single number would hide

| | What it is | How often |
|---|---|---|
| **static** | corpus, samples, trust anchors | fetched once; changes only on release |
| **dynamic** | the revocation surface — fresh head + status list | every freshness window, or verification fails closed |

Only the dynamic half recurs, and it is the only part a mirror operator is really signing up for.

## Measured

| Artifact | Files | Size |
|---|---|---|
| the mirror (static) | 1204 | 33.0 MB |
| fresh head, all 2 registrars | 2 | 0.4 KB |
| status list, all 2 registrars | 2 | 9.1 KB |
| **per refresh window** | | **9.5 KB** |

## Per verifier, per day

Method: `bytes/day = (86400 / freshness_window_seconds) × bytes_per_window`. The freshness constants are read
from `ainra-core/src/status.rs` at run time rather than restated here, so this table cannot drift from the code.
Worst case assumed: a cache-less verifier re-fetching both artifacts every window.

| Class | Window | Fetches/day | Bytes/day |
|---|---|---|---|
| F1 | 30s | 2880 | **26.8 MB** |
| F2 | 300s | 288 | **2.7 MB** |
| F3 | 86400s | 1 | **9.5 KB** |

## What this is and is not

**Measured:** every artifact size, the registrar count, the freshness constants.

**[extrapolated]:** the per-day figures are arithmetic on those measurements — real bytes multiplied by a real
cadence, not observed traffic. This project has never run a mirror for a day at any scale, and the number of
verifiers is **zero**, so a total-fleet figure would be a measurement of nothing. The per-verifier figure is the
honest unit and the one an operator can multiply by their own fleet.

**Not covered:** compression (these are raw sizes; the transfer is smaller), CDN caching between verifiers sharing
a mirror, and any growth in registrar count — 2 registrars is what exists today, not a forecast.
