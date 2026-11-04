// SPDX-License-Identifier: Apache-2.0 OR MIT
// RFC 9421 request presentations (D-062, D-067) must never panic on arbitrary bytes: the signature base, the
// signature-input parameters and the bound bundle, through the one decode path. Seeded from vectors/v1-presentation
// by tools/fuzz-smoke.sh.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = ainra_adapter::run_presentation_vector_json(s);
        let _ = ainra_adapter::presentation_ref_json(s);
    }
});
