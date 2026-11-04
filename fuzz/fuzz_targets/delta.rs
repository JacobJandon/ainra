// SPDX-License-Identifier: Apache-2.0 OR MIT
// Status deltas and fresh heads (ADR-016, D-021) must never panic on arbitrary bytes, through the one decode path.
// Seeded from vectors/v1-delta by tools/fuzz-smoke.sh.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = serde_json::from_slice::<ainra_adapter::WireDeltaVector>(data) {
        let _ = ainra_adapter::delta_verify(&v);
    }
});
