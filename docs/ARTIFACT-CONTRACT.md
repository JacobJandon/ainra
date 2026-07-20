<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# The AINRA public artifact contract

This is the interface every verifier, mirror, and explorer (AINRAscan) reads. It is **static files served with
correct HTTP caching + CORS** — the only globally-distributed surface AINRA has. Verification is local and offline,
so N agents add ~zero load to the root; scale is a CDN configuration of these files, not a protocol problem
(measurements: `docs/SCALE.md`). The reference implementation is `tools/artifact-server.mjs`; a production
deployment fronts the same paths with a real CDN.

Every artifact and index served by staging carries the banner headers **`X-AINRA-Network: staging`** and
**`X-AINRA-Root: test-root`**, and the `/index.json` manifest repeats them machine-readably. No trust migrates from
a TEST-ROOT staging network to the future production root.

## URL scheme

| Path | What | Mutability |
|---|---|---|
| `/index.json` | network manifest: labels, window, registrar list, artifact map | mutable |
| `/directory.json` | the accredited-registrar directory (staging: real accreditations; production: dual-root-**signed** at genesis) | mutable |
| `/registry.json` | the combined per-registrar export a browser SDK verifies (records + anchors + signed status) | mutable |
| `/registrars/<id>/accreditation.json` | that registrar's public keys (the verify anchor) | mutable |
| `/registrars/<id>/export.json` | that registrar's full export (records + live verdicts + signed status list) | mutable |
| `/registrars/<id>/status/current.json` | the signed Token Status List | mutable (revocation moves it) |
| `/registrars/<id>/status/deltas.json` | signed status deltas since head 0 | mutable |
| `/registrars/<id>/fresh-head.json` | the ≤30 s delegate-signed fresh head | mutable, very short-lived |
| `/registrars/<id>/checkpoints/<height>.json` | a log checkpoint at a tree height | **immutable** (height-addressed) |
| `/registrars/<id>/tiles/…` | RFC 6962 log tiles (future: served like checkpoints) | **immutable** (content-addressed) |

**Immutable artifacts get immutable paths.** A checkpoint at height N never changes, so `checkpoints/<N>.json` is
content-stable; tiles are content-addressed. Everything else (heads, deltas, directory, exports) changes as the log
grows and revocations land, so it is mutable-with-revalidation.

## HTTP behaviour (planet-scale static serving)

- **CORS on every response:** `Access-Control-Allow-Origin: *`, `Access-Control-Expose-Headers: ETag,
  X-AINRA-Network, X-AINRA-Root`, and an `OPTIONS` preflight answered with `Access-Control-Allow-Methods: GET,
  HEAD, OPTIONS`. **Client-side verification in a browser dies without this** — the SDK cannot fetch tiles/heads
  cross-origin otherwise.
- **Immutable artifacts:** `Cache-Control: public, max-age=31536000, immutable` — cache forever, never revalidate.
- **Mutable artifacts:** `Cache-Control: public, max-age=5, must-revalidate` + a strong **`ETag`** (SHA-256 of the
  bytes); a conditional `If-None-Match` GET returns `304`. Short max-age keeps revocation fresh; ETag makes
  revalidation a header, not a download.
- **Content-Type:** `application/json` for `.json` (correct types for other classes).
- **Compression:** `gzip` when the client sends `Accept-Encoding: gzip` (`Vary: Accept-Encoding`). Status lists and
  tiles compress heavily.
- **Read-only:** only `GET`/`HEAD`/`OPTIONS`; anything else is `405`. The server holds no keys and verifies nothing.

A conformance check runs in **`make stage-smoke`**: it fetches each artifact class and asserts CORS `*`, the ETag on
mutable artifacts, the `immutable` cache policy on checkpoints, and the STAGING banner — against the live
deployment, with real output.

## Decisions (D-031)

- The immutable/mutable split is by **path**, decided by the server from the URL (`…/checkpoints/`, `…/tiles/`, or a
  `.immutable.` marker → immutable; else mutable + ETag) — so a CDN needs no per-object configuration, only two
  cache rules keyed on path prefix.
- **CORS is `*` deliberately:** the artifacts are public by definition (a transparency log is world-readable), and
  browser client-verification is the whole point; there is nothing to protect on the read path.
- The **staging directory is unsigned-by-the-root on purpose** — the production directory's dual-root signature is
  minted only at the recorded genesis ceremony. Staging publishes the real registrar accreditations and says so, in
  `/directory.json`'s `note` field. Verifiers on staging anchor to those accreditations; production verifiers anchor
  to the root-signed directory. This is the staging-vs-production key separation, stated in the artifact itself.
