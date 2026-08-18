<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# The public artifact surface — contract, mirrors, reproducibility

Everything AINRA publishes is **static files**. That single fact is what makes the rest of this document possible:
verification is local and offline, so N agents add ~zero load to the root; a mirror is a plain CDN edge; and anyone
can rebuild the whole set from source and check any mirror against it without trusting the mirror or us.

Three things used to be three documents. They are one topic, read in this order:

1. **[The contract](#the-contract)** — what is served, at which paths, with which HTTP behaviour.
2. **[Mirroring](#mirroring)** — how to serve a copy, and how to point any verifier at it.
3. **[Reproducibility](#reproducibility)** — how to rebuild every published byte from source, and what is
   deliberately excluded from byte-identity.

---

## The contract

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

---

## Mirroring

The entire public surface (§ the contract, above) is static files. Anyone can mirror all of it and any verifier
can point at any mirror — the transparency guarantee travels with the **content**, not the channel. The root
operating the log can go offline and every verifier keeps working from mirrors, because a checkpoint is
root/delegate-**signed** and an inclusion proof is checked against it with local hashing.

## Mirror the whole surface

```sh
# HTTP (any static host): recursively pull the public tree
wget -r -np -nH --cut-dirs=0 http://<origin>:8091/ -P ./ainra-mirror
# or rsync if the origin exposes it
rsync -a --delete rsync://<origin>/ainra-public/ ./ainra-mirror/
```

Serve the mirror with the SAME contract headers (§ the contract, above):

```sh
node tools/artifact-server.mjs ./ainra-mirror 8091     # the reference server already sets CORS/cache/ETag/banner
# or any CDN/static host with: CORS *, immutable cache on */checkpoints/* and */tiles/*, short-cache+ETag elsewhere
```

## Point a verifier at any mirror

- **AINRAscan:** open `…/ainrascan/?net=http://<mirror>:8091` — it fetches `/registry.json` from the mirror and
  verifies every proof in the browser. Nothing else changes.
- **The SDK / a custom verifier:** fetch `/directory.json` (anchors) + `/registrars/<id>/{export,status/current}.json`
  from the mirror and run `@ainra/sdk`. The verdict is identical regardless of which mirror served the bytes — a
  mismatch is impossible without breaking a signature, which is the point.
- **Integrity of a mirror:** `make verify-mirror MIRROR=<dir>` byte-verifies a mirror against the signed manifest
  (fail-closed on tamper/missing/extra) — the same machinery that guards the CC0 artifact set.

## Why this is the scale story

Because verification consults only signed static files and never the root, a mirror is a plain CDN edge. Global
scale is adding edges — a configuration, not a protocol change. See `docs/SCALE.md` for the measured numbers.
Nothing here implies usage: mirrors serve the truth; whether anyone reads it is earned by the humans running the
pending DoD rows.

---

## Reproducibility

The trust root of the AINRA conformance corpus is the **source**, not our word: anyone can rebuild every published
artifact from a clean checkout and get byte-identical output, then verify any mirror against the resulting manifest.
This document is the toolchain lock an external builder needs.

## What is reproducible (the published artifact set)

Pure, seeded, path-independent files — exactly what a mirror serves and a second implementation checks itself
against:

| Artifact | Generator | Determinism |
|---|---|---|
| `vectors/v1` (1009) · `vectors/v1-delta` (17) · `vectors/v1-directory` (9) | `ainra-vector-gen` | seeded `ChaCha20Rng` (fixed seeds; no clock, no OS RNG) |
| `samples/data/*.json` | `ainra-core` example `sample_passport` | seeded `ChaCha20Rng` |
| `samples/*.svg` · `samples/manifest.json` | `tools/render-samples.mjs` | dates derive from **fixed claim values**, not wall-clock; no `Date.now()`/`Math.random()` |

`make repro` rebuilds this set **from source into a fresh empty temp tree — twice** — and asserts **committed ==
clean-rebuild-1 == clean-rebuild-2**. Because the rebuild starts from nothing, it compares *sets*, not a pre-captured
file list: it catches byte drift AND a committed **orphan** file that a fresh build never produces (a stale artifact
left by a refactor, or a planted one) AND a **missing** file the build now produces — any of which fails the proof.
It then writes `MANIFEST.sha256`, the canonical content list mirrors are verified against. (An earlier in-place
version could launder an orphan as "reproducible"; the clean-rebuild-into-temp design, found by the M7 adversarial
review, closes that — D-022.)

## The toolchain lock (what an external builder must match)

- **Rust `1.96.1`**, pinned in `rust-toolchain.toml` (`profile = minimal`, `+ rustfmt, clippy`).
- **`Cargo.lock`** committed — every dependency version + hash is pinned (the crypto crates are additionally
  size-conformance-asserted, see D-006).
- **Node** — a current LTS (the sample renderer + SDK use only Node built-ins: `crypto`, `zlib`, `fs`). The renderer
  is deterministic on any Node that implements standard SHA-256 + JSON; no packages are involved.
- No network, no environment inputs, no timestamps enter the artifact set (verified: N7 keeps `ainra-core` free of
  clock/IO; the generators take fixed seeds).

Given the same source tree + this toolchain, `make repro` on a stranger's laptop yields the identical
`MANIFEST.sha256`. That is the byte-for-byte reproducibility external builders confirm.

## What is deliberately EXCLUDED from byte-identity (documented, not faked)

- **The SDK `dist/`** (`packages/sdk-ts/dist`) — a `tsc` build output whose exact bytes depend on the TypeScript
  compiler version. It is verified for **behaviour**, not byte-hash: the four-way differential (`make diff`)
  proves `dist` agrees with `ainra-core` on all 1009 + 17 + 9 vectors. Byte-pinning a compiler output would couple the
  spec corpus to a compiler release; the differential is the stronger, version-independent guarantee.
- **`docs/BENCHMARKS.md`** — timing-derived (`Instant::now()`), intentionally not an artifact.

## Mirrors

A **mirror** is any host serving the artifact set. `make mirror OUT=<dir>` assembles one from `MANIFEST.sha256`;
`make verify-mirror MIRROR=<dir>` recomputes every file's hash in the mirror and diffs against the manifest — exit 0
iff **byte-identical, no missing, no extra** files. A relying party verifies any mirror (ours or a third party's)
using a manifest it trusts, which it can itself reproduce from source via `make repro`. So a mirror's honesty is
checkable **without trusting the mirror or us** — only the source.

The manifest is trust-anchored today by *reproducibility + repo provenance*. A signature by a **persistent** root is
deferred to the M8 Genesis ceremony (which mints that root); the verify path already carries a signature hook for it.

## Docs freeze

`make freeze` records `docs/FREEZE.sha256` over the **normative** docs (The Standard, the Master Technical
Specification, the design system); `make check-freeze` fails if any drifted. Living docs (`DECISIONS`, `STATUS`, and the
archived plans) are intentionally not frozen. Freezing makes an unintended edit to a contract doc detectable.
