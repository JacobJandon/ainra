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
///
/// NOT A GATE (D-072): the directory is taken as given and the bundle's own freshness class and status list are
/// believed — fixture semantics, for the page's demonstration on specimen records. To decide access, use the edge
/// build's `accredit` + `gate`.
#[wasm_bindgen]
pub fn verify(bundle_json: &str, directory_json: &str, now_secs: f64) -> String {
    // No audience declared ⇒ the fail-closed empty string ⇒ no instance credential is accepted. A page that
    // knows which service it is should call `verify_aud`.
    ainra_adapter::verify_bundle_json(bundle_json, directory_json, clamp_secs(now_secs))
}

/// Verify at the caller's clock AND the caller's audience (ADR-019).
///
/// Before M30 the browser had no way to supply an audience, so `ainra-wasm` took it from the bundle and any page
/// verifying an instance credential accepted one addressed to somebody else.
#[wasm_bindgen]
pub fn verify_aud(
    bundle_json: &str,
    directory_json: &str,
    now_secs: f64,
    audience: &str,
) -> String {
    ainra_adapter::verify_bundle_json_aud(
        bundle_json,
        directory_json,
        clamp_secs(now_secs),
        audience,
    )
}

/// Run one conformance vector exactly as the Rust core does — the entry the corpus harness drives.
#[wasm_bindgen]
pub fn run_vector(vector_json: &str) -> String {
    ainra_adapter::run_vector_json(vector_json)
}

/// Verify a root-signed directory ONCE and return the gate's trust (anchors + revoked delegates), or `{"ok":false}`.
#[cfg(feature = "edge")]
#[wasm_bindgen]
pub fn accredit(directory_json: &str, roots_json: &str) -> String {
    ainra_adapter::accredit_json(directory_json, roots_json)
}

/// The credential alone, under the gate's policy (its trust, clock, audience and freshness class).
#[cfg(feature = "edge")]
#[wasm_bindgen]
pub fn credential(
    bundle_json: &str,
    trust_json: &str,
    now_secs: f64,
    audience: &str,
    freshness: &str,
) -> String {
    ainra_adapter::credential_json(
        bundle_json,
        trust_json,
        clamp_secs(now_secs),
        audience,
        freshness,
    )
}

/// The edge gate's one call (PLAN-M34 Task 5): the credential under the gate's policy, then the request it arrived
/// on. Returns `{"allow","reason","event","nonce"}`; the host enforces single use of `nonce`.
#[cfg(feature = "edge")]
#[wasm_bindgen]
pub fn gate(
    bundle_json: &str,
    trust_json: &str,
    request_json: &str,
    now_secs: f64,
    audience: &str,
    freshness: &str,
) -> String {
    ainra_adapter::gate_json(
        bundle_json,
        trust_json,
        request_json,
        clamp_secs(now_secs),
        audience,
        freshness,
    )
}

/// The digest that names a bundle's stable part (D-065), or an empty string for anything unreadable.
#[cfg(feature = "edge")]
#[wasm_bindgen]
pub fn presentation_ref(bundle_json: &str) -> String {
    ainra_adapter::presentation_ref_json(bundle_json).unwrap_or_default()
}

/// Run one `vectors/v1-presentation` vector exactly as the core does — so the edge engine answers to the corpus.
#[cfg(feature = "edge")]
#[wasm_bindgen]
pub fn run_presentation_vector(vector_json: &str) -> String {
    ainra_adapter::run_presentation_vector_json(vector_json)
}

/// Run one `vectors/v1-gate` vector as the core does (D-073): the directory against its roots, then the bundle under
/// the gate's policy — status authenticated, freshness and revocations the verifier's.
#[cfg(feature = "edge")]
#[wasm_bindgen]
pub fn run_gate_vector(vector_json: &str) -> String {
    ainra_adapter::run_gate_vector_json(vector_json)
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
