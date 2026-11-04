<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Fuzzing the newer parsers: one recorded soak

PLAN-M51 step 5, 4 November 2026. Five coverage-guided targets were added to `fuzz/` (cargo-fuzz, libFuzzer) for the
parsers written since the first three: AINRA Link with ES256K keys, decision records and logged heads, RFC 9421 request
presentations, root-signed directories with their gates and currency gates, and status deltas with fresh heads. Each
enters through `crates/ainra-adapter`, the one path from external bytes to core types (L5), and is seeded from the
published corpus in `vectors/`. The property is the same as the first three: **no input makes it panic.**

`make fuzz-smoke` runs all eight for 15 seconds each (`FUZZ_SECS` to change it). This is the record of one longer run.

## The run

cargo-fuzz 0.13.2, nightly cargo 1.100.0 (2026-08-15), one core each at low priority, 600 seconds per target.

| Target | Executions | Per second | Coverage (edges) | Crashes |
|---|---|---|---|---|
| `link` | 3,899,702 | 6,488 | 6,356 | 0 |
| `decision` | 8,460,911 | 14,078 | 6,044 | 0 |
| `presentation` | 8,726,834 | 14,520 | 3,236 | 0 |
| `directory` | 554,268 | 922 | 6,880 | 0 (after the fix below) |
| `delta` | 20,355,408 | 33,869 | 4,071 | 0 (after the fix below) |

## What it found

The first run of `directory` and `delta` crashed within a second, both in the adapter's **vector runners**:

- `directory_result` called `expect` on a vector with no `directory` field (the first input it tried was the corpus
  manifest itself);
- `delta_verify` called `expect` on a delegate-certificate signature that was not base64url.

Both are reached only from the vector generator, which reads the committed corpus; no verifier, gate, WASM export or
service calls them, so no untrusted input could trigger them. They still broke the property that the one decode path
never panics. Both now answer a malformed vector with a refusal (`{"accept": false}`, `schema_violation`), the crash
inputs are kept as tests in `crates/ainra-adapter/tests/fuzz_regressions.rs`, the corpus regenerates byte for byte
(`make vectors-check`), and the second 600-second run of each target found nothing.

## Limits

Ten minutes per target is a soak, not an audit. The targets check for panics, not wrong answers; wrong answers are what
the four-way differential and the corpora are for. The directory target is slow (922 per second) because each input is
up to 114 KB and carries SLH-DSA signatures.
