// SPDX-License-Identifier: Apache-2.0 OR MIT
// AINRA Link (D-078, ES256K since D-082) must never panic on arbitrary bytes: the claim parser, the presented-key
// parser (32-byte Ed25519 or 33-byte compressed secp256k1) and the whole vector path through the one decode path.
// Seeded from vectors/v1-link by tools/fuzz-smoke.sh.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ainra_core::link::LinkClaims::parse_checked(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = ainra_adapter::presented_key_of(s.trim());
        let _ = ainra_adapter::run_link_vector_json(s);
    }
});
