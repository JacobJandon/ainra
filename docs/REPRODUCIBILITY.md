<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# REPRODUCIBILITY — rebuild the published artifacts byte-for-byte (M7)

The trust root of the AINRA conformance corpus is the **source**, not our word: anyone can rebuild every published
artifact from a clean checkout and get byte-identical output, then verify any mirror against the resulting manifest.
This document is the toolchain lock an external builder needs.

## What is reproducible (the published artifact set)

Pure, seeded, path-independent files — exactly what a mirror serves and a second implementation checks itself
against:

| Artifact | Generator | Determinism |
|---|---|---|
| `vectors/v1` (684) · `vectors/v1-delta` (17) · `vectors/v1-directory` (9) | `ainra-vector-gen` | seeded `ChaCha20Rng` (fixed seeds; no clock, no OS RNG) |
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

- **Rust `1.96`**, pinned in `rust-toolchain.toml` (`profile = minimal`, `+ rustfmt, clippy`).
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
  compiler version. It is verified for **behaviour**, not byte-hash: the 3-way differential harness (`make diff`)
  proves `dist` agrees with `ainra-core` on all 684 + 17 + 9 vectors. Byte-pinning a compiler output would couple the
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
Specification, the design system); `make check-freeze` fails if any drifted. Living docs (`PLAN*`, `DECISIONS`,
`STATUS`) are intentionally not frozen. Freezing makes an unintended edit to a contract doc detectable.
