<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# The no-install demo — what shipped, and the one piece that did not

## Shipped and proven

**[`examples/verify-in-browser/`](../examples/verify-in-browser/)** — four static files, no install step at all.
It runs a real, independently-written implementation of the verifier in the visitor's browser over a real
conformance vector, and performs **no network request at verification time**.

Proven in a headless browser: the published vector returns **VALID**; flipping **one byte** of the issuer
signature returns **INVALID · sig_invalid**; zero page errors. The recorded corpus verdict is shown beside the
live one, so a visitor sees their own result agree with the answer three other implementations produce.

The same verification already runs on the project's own site (the machine door's self-test), so the canonical
demo needs nobody's platform. The example directory exists so it can also be dropped into a hosted playground for
the README — using the hosted path only; the container API is never self-hosted (licensing).

One correction worth recording: the first attempt imported the package's `dist/` build and failed in the browser
with `node:zlib` blocked by CORS. That build targets Node. The browser bundle is a separate artifact, and it is
the one the site already serves — the example now uses it.

## Shipped in L5: the Rust core compiled to WebAssembly

**This section's blocker is now closed.** The site's **Try it** panel (`/verify.html#try`) runs `ainra-core`
itself — `crates/ainra-wasm`, a thin `wasm-bindgen` binding over the extracted adapter — and `make wasm-diff`
pushes all **1009** vectors through that exact artifact in a headless browser, requiring agreement with the core on
verdict *and* named reason. Result: **1009/1009**. The harness carries its own negative control, so the number means
something: with `NEGATIVE_CONTROL=1` one bit of one issuer signature is flipped and the run must fail (proven —
744/1009, exit 1). Artifact: **367 KiB** wasm + 9 KiB glue, under a ceiling enforced by `tools/build-wasm.sh`.

The prerequisite below was done in **L5 Task 1** — and mapping it found the second implementation had *already*
grown, in the CLI's seed path, where it failed open. See [`_archive/plans/PLAN-L5.md`](_archive/plans/PLAN-L5.md). The extraction landed as
`crates/ainra-adapter` (the name `ainra-vectors` proposed below was dropped: it now carries the verdict-event
vocabulary too, so "vectors" would have undersold it), and `tools/one-decode-path.mjs` enforces the single path
mechanically rather than by convention.

### The original note, kept for the record

The stronger version — *the Rust core itself* executing in the page — is blocked on a real structural fact, not
on effort, and the blocker is worth stating precisely because it is a small, well-defined piece of work:

**`ainra-core` exposes `verify(&Presentation, &TrustAnchors) -> Verdict`, but nothing public turns a conformance
vector's JSON into those types.** `Presentation<'a>` carries a lifetime and neither it nor `TrustAnchors` derives
`Deserialize`. The adapter that does this — the `Vector` wire type and its `run()` — lives inside
`tools/vector-gen/src/main.rs`, a **binary** crate, so it cannot be depended on.

**The prerequisite:** extract the wire types and `run()` from that binary into a small library crate
(`ainra-vectors`), leaving `vector-gen` and a new `ainra-wasm` cdylib both depending on it. That keeps **one**
deserializer — which matters, because the entire value of the four-way differential is that these implementations
agree, and a second hand-written adapter would quietly become a fifth opinion.

The `wasm32-unknown-unknown` target is installed and the core's dependency set (`ed25519-dalek`, `ml-dsa`,
`slh-dsa`, `sha2`, `base64ct`, `flate2`, `serde`) contains nothing that obviously bars a wasm build — no I/O, no
clock, no network, which is exactly the N7 purity the core already guarantees. A scaffold was written and then
**removed rather than left broken**: a crate that cannot compile is worse than an honest note.
