<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# M14 (partial) — AINRAscan goes real; the browser verifies for itself

The M14 vision is to put the whole stack on the public internet as a **staging network on a TEST-ROOT** and prove
the planet-scale property with measurements. That is a large, multi-host deployment milestone (containers,
multi-region layout, artifact CDN contract, load tests, soak) that needs an operator's hosts and domains. This
increment delivers the piece that is fully buildable on the reference machine and is the heart of the request:
**AINRAscan becomes a real, client-verifying application over real pipeline data — the "verify it yourself"
promise made literal.**

## What shipped (real, proven)

- **The real `@ainra/sdk` runs in the browser.** `packages/sdk-ts/browser/` bundles the exact SDK (the code that
  agrees 745/745 in the conformance differential) into one self-contained ES module — `@noble` inlined, the single
  Node dependency (`node:zlib`) aliased to `fflate.unzlibSync`, `Buffer` shimmed. Proven: the browser bundle
  reproduces core's verdict on **all 745 conformance vectors** and on **all 13** seeded staging records.
- **Real data, every lifecycle state.** `make ainrascan` seeds a real network through the real `RegistrarBox`
  pipeline (real hybrid signing, real RFC 6962 log inclusion, real signed status deltas) — 3 registrars, 13
  lineages, delegation chains, revocations, and a real **ADR-017 renewal** (`scheduler` 2.2.0 → 2.3.0 with a
  `prev_leaf` continuity link). The seed self-checks every verdict with the core verifier; no verdict is asserted.
- **The green is one the viewer produces.** `ainrascan/index.html` reconstructs the SDK-verifiable bundle from the
  public export and, on click, runs the full 9-step verify **plus** an independent RFC 6962 recompute in the page's
  own JavaScript (leaf = SHA-256(0x00 ‖ canonical body) → walk the proof → equals the signed checkpoint root). Both
  computed client-side; nothing trusted from the export.
- **Honest to the letter.** Persistent `STAGING NETWORK · TEST-ROOT` banner (machine-readable `data-network` /
  `data-root` + human string); the independence colophon and oath; **mechanical ordering** (by subject, always);
  **zero telemetry** and **self-contained** (no CDN, no web fonts, no external request except fetching the public
  artifacts it verifies — confirmed: a browser session makes zero cross-origin calls). Placeholder operators only
  (S7-clean).

## What this does NOT do (honest, deferred to the full staging-network milestone)

- No deployment: no containers, no multi-region hosts, no public domain, no CDN. AINRAscan here runs against a
  locally-served real export, not an internet-exposed network. Standing up the 3-host staging network + the public
  artifact contract (cache/CORS headers, mirror guide) is the deployment-engineering half of M14.
- No new real-world DoD rows. The pending rows (recorded ceremony, ≥3 external verifiers, 14-day/3-region soak,
  independent witnesses) are untouched and unfaked. `docs/SCALE.md` already carries the measured billions-math from
  `make scale`; the distribution/CDN load test belongs to the deployment half.
- Nothing published, no domains registered, no ceremony/soak started.

## Run it

```sh
make ainrascan SERVE=1     # bundle the SDK for the browser + seed a real staging network, serve at :8090
```

Open a lineage, press **Verify in your browser**. The verdict and the inclusion proof are recomputed on your
machine by the real verifier — for real this time. Decisions: D-030.
