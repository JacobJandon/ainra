<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# L5 — one decode path, and a WASM surface that uses it

Follows L4, which **declined** to hand-roll a WASM adapter because it would have created a second implementation
of "bytes → `Presentation`/`TrustAnchors`" — the exact divergence class the four-way differential exists to catch.
L5 removes the blocker properly.

**The governing constraint, enforced mechanically from here on:** there is exactly **one** code path in Rust that
turns external bytes into core verify types, and every consumer calls it. If the design ever appears to require a
second parse implementation, that is a **stop-and-report** signal, not a thing to write.

## Task 0 — the boundary, mapped before anything moved

The survey found something L4 did not: **the second implementation already exists.** This is not a hypothetical
risk being prevented; it is a live divergence being closed.

| # | Function | Crate · kind | Converts | Callers | Verdict |
|---|---|---|---|---|---|
| 1 | `Wire{Key,Sig,Registrar,Checkpoint,HopProof,CheckpointSig,DelegateCert,Presentation,Expect}` + `Vector` (≈91 lines) | `tools/vector-gen` · **binary** | vector JSON → wire structs | `run`, `check`, `--emit` | **MOVES** |
| 2 | `run(&Vector) -> Verdict` (≈108 lines) | `tools/vector-gen` · **binary** | wire structs → `Presentation` + `TrustAnchors`, then verifies | `check`, `--emit`, the differential | **MOVES** |
| 3 | `WireDelta{Cert,Expect,Vector}` + `delta_verify` | `tools/vector-gen` · **binary** | delta JSON → status/delta types | `check_delta`, `--emit` | **MOVES** |
| 4 | `directory_result(&Value) -> Value` | `tools/vector-gen` · **binary** | directory JSON → `Directory` → accredit | `--emit`, directory check | **MOVES** |
| 5 | `reason_str(Reason) -> String` | `tools/vector-gen` · **binary** | core enum → wire string | delta + emit paths | **MOVES** (wire vocabulary, not a binary concern) |
| 6 | **`anchors_from_export(&Value) -> TrustAnchors`** | `crates/ainra-cli-rs` · **library module** | registrar-export JSON → `TrustAnchors` | `seed` | **DELETES** — see below |
| 7 | `check`, `check_delta`, `--emit` loop, argv parsing, file I/O, stdout | `tools/vector-gen` · binary | — | main | **STAYS** (binary concerns) |
| 8 | `reconstruct_presentation(&IssuedRecord)` | `services/ainra-services` | the registrar's **own** persisted record → `Presentation` | issuer-side present | **STAYS** — issuer reconstructing its own material, not third-party wire bytes |
| 9 | `MintedPassport` → `Presentation` | `crates/ainra-ceremony` · binary | in-process values, never parsed | ceremony rehearsal | **STAYS** |
| 10 | `sample_passport.rs` | `crates/ainra-core/examples` | in-process values | example | **STAYS** |

### The live divergence — finding #6

`anchors_from_export` is a **second, partial decoder for trust anchors**, and it does not merely duplicate #2, it
disagrees with it. It **fails open**:

```rust
let ed = b64::decode(acc["issuer_key"]["ed25519"].as_str().unwrap_or(""))
    .ok().and_then(|v| v.try_into().ok())
    .unwrap_or([0u8; 32]);          // a malformed issuer key silently becomes an all-zero key
```

A corrupt or truncated issuer key does not raise `unknown_registrar`; it installs an all-zero anchor and the
verdict becomes whatever a zero key produces. Every other decode path in this repository is fail-closed by
construction. This is exactly the class of drift the single-path rule exists to prevent, and it is why #6 is
**DELETE**, not "move alongside".

Blast radius, checked: `anchors_from_export` is called only from the `seed` path (fixture generation), so no
released verify path consumed it. It is a latent divergence, not an exploited one — recorded rather than
downplayed.

### The contract

Everything marked **MOVES** lands in one new library crate as pure functions — no I/O, no clock, no argv, matching
`ainra-core`'s N7 purity. `tools/vector-gen` keeps only **STAYS** and depends on the library. #6 is deleted and its
caller re-pointed at the library. Old bodies are **removed, not left behind**, and a CI check fails if they
reappear. Deviations from this table get reported, not improvised.

## Status

- **Task 0 — DONE.** Table above is the contract. One deviation from L4's assumption, recorded: the second parse
  path already existed (#6), so this milestone closes a real divergence rather than only preventing a future one.
- **Task 1 — extraction — DONE.** `crates/ainra-adapter` holds every MOVES row (354 lines); 321 lines deleted
  from the binary, not copied. `anchors_from_export` and its fail-open substitution are **gone** — its one call
  site now calls the library directly, so there is not even a delegating shim to drift. Mechanically enforced by
  `tools/one-decode-path.mjs` (`make one-decode-path`, and a board row), which scans every Rust file and fails if
  a moved signature or a JSON→`TrustAnchors`/`Presentation` conversion appears outside the adapter. Proven both
  ways: it caught the fail-open decoder and three assembly sites on first run, then narrowed to the real parse
  signal (assembling anchors from in-process keys is legitimate; decoding them from a `serde_json::Value` is not).
  **Acceptance met: the differential is byte-identical before and after** — 745/745 core↔sdk, 10/10 canon 3-way,
  4/4 canon-reject, 17/17 delta, 9/9 directory, and core↔py 745/745 · 17/17 · 9/9. `make repro` still byte-exact
  across 790 files.
- **Task 2 — WASM surface — DONE.** `crates/ainra-wasm` exports `verify(bundle, directory, now) -> verdictEvent`,
  `run_vector`, and `version` — three functions, each one line, each handing straight to the adapter. It parses
  nothing of its own, **not even JSON text**, because deciding what counts as readable input is a decision and that
  decision must have one home; a CI gate greps the crate for any decode call. No network, no telemetry, no clock.
  **One thing had to change to do this honestly, and it is worth recording rather than burying:** the single decode
  path was `.expect()` throughout. That is safe for a generator reading fixtures it just wrote and fatal for a
  browser taking pasted bytes, where an abort is a dead page rather than a refusal. The *forbidden* fix was a
  lenient decoder inside the WASM crate — the exact second implementation this milestone exists to prevent. The
  correct fix was making the one path fail closed, so a malformed field now yields `schema_violation` for **every**
  caller. Same reasoning moved the verdict-event vocabulary (`number_from_name`, `event_json`) out of the CLI
  binary: a third Rust copy is the same drift class as a second decoder. The differential is unchanged
  byte-for-byte, re-proven after the rewrite.
  **Acceptance met — the browser is a verified surface, not a demo:** `make wasm-diff` pushes all 745 vectors
  through the compiled artifact in a headless browser and requires agreement on verdict *and* named reason →
  **745/745**. Negative control proven (one flipped signature bit → 744/745, exit 1). Artifact **367 KiB** + 9 KiB
  glue, under a ceiling enforced at build time; a dedicated `[profile.wasm-release]` keeps every existing
  artifact's bytes — and `make repro` — untouched.
- **Task 3 — demo on our own ground — DONE.** `/verify.html#try` now runs `ainra-core` itself, so the page's claim
  is literal rather than a family resemblance. Paste-or-pick (a vector, an `{anchors, presentation}` pair, or a
  bare presentation); a malformed paste says *what it could not find*, because a demo that answers "invalid" to a
  typo teaches the wrong lesson about why things fail; the flip-a-byte controls are verified to produce the reason
  each label promises. Degradation is honest: if WebAssembly will not load, the page falls back to the JavaScript
  mirror and **says so** in the provenance line. Wired through README, `/llms.txt`, `skills.md`, and the landing
  page's integrate door — each naming *which* verifier answers, since that is the whole claim.
  **Driving the real page found a live bug worth more than the feature:** the assurance-tier rail selected
  `[data-t]` globally, which also matched the four forge buttons — clicking one threw and left the forgery *off*,
  so every visitor who tried to forge a passport saw **VALID**. The entire "then try to forge one" half of the
  page had been doing nothing. Fixed and re-verified on both engines.
- **Task 4 — close it like a release — DONE.** This plan, the CHANGELOG entry, the code map in README, and
  `docs/WASM-DEMO.md` (L4's honest "not shipped" note, now recorded as closed with the original text kept).
  Counts restated above. **No version bump:** this changes internal structure and adds a surface; it does not cut a
  release.

_No version bump is planned: this milestone changes internal structure and adds a surface; it does not cut a
release. Versions stay where they are unless a release is actually being closed._
