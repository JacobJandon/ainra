// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The verify path, in a browser — a **thin binding**, and nothing more.
//!
//! Every function here does the same thing: hand its arguments to [`ainra_adapter`] and return the string it gets
//! back. It **parses nothing of its own**, not even JSON text, because deciding what counts as readable input is a
//! decision, and that decision must have exactly one home. That is not stylistic caution: L4 declined to hand-roll
//! this surface precisely because a second decoder is how a verifier stops agreeing with itself, and mapping the
//! boundary for L5 found one had already grown and was failing open. If this file ever appears to need its own
//! conversion, that is a design fault to report — not code to write.
//!
//! What it deliberately cannot do, matching `ainra-core`'s N7 purity:
//!   * **no network** — nothing is fetched, nothing is reported, there is no telemetry of any kind
//!   * **no clock** — `now` is an argument, because freshness is the *verifier's* policy, never the presenter's
//!     and never the machine's
//!   * **no I/O** — the host reads the bytes; this only interprets them
//!
//! A hostile paste is answered with a **verdict**, never an exception: nothing here can panic across the
//! WebAssembly boundary, so a page that verifies one bad bundle still verifies the next one.

use wasm_bindgen::prelude::*;

/// Verify a presented bundle against a directory, at a caller-supplied time.
///
/// Returns the canonical verdict event — `{status, reason, name, number, tier, freshness_age_s}` — the same shape
/// the CLI, the middleware and the MCP server emit, so one log format covers every surface.
#[wasm_bindgen]
pub fn verify(bundle_json: &str, directory_json: &str, now_secs: f64) -> String {
    ainra_adapter::verify_bundle_json(bundle_json, directory_json, clamp_secs(now_secs))
}

/// Run one conformance vector exactly as the Rust core does — the entry the corpus harness drives.
#[wasm_bindgen]
pub fn run_vector(vector_json: &str) -> String {
    ainra_adapter::run_vector_json(vector_json)
}

/// The build this module was compiled from, so a page can state which verifier answered it.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// JavaScript has one number type, so `now` arrives as an `f64`. A negative, NaN, or absurd value becomes `0`
/// rather than wrapping into a plausible-looking timestamp — fail closed, never fail interesting.
fn clamp_secs(n: f64) -> u64 {
    if n.is_finite() && n >= 0.0 && n <= u64::MAX as f64 {
        n as u64
    } else {
        0
    }
}
