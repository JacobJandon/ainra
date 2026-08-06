// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Export freshly-signed material so the OTHER implementations can verify it.
//!
//! The conformance corpus is generated from a fixed seed, so it proves the upgraded `ml-dsa` reproduces what the
//! old one produced — necessary, but it says nothing about material that has never existed before. This writes a
//! hybrid public key, a novel message, and a signature made *now* by the upgraded Rust, for `@noble/post-quantum`
//! (TypeScript) and OpenSSL-backed `cryptography` (Python) to check independently.
//!
//! Run with `AINRA_INTEROP_OUT=<path>`; it is inert otherwise, so it costs nothing in a normal test run.

use ainra_core::b64;
use ainra_core::crypto::HybridKeypair;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[test]
fn export_fresh_signature_for_cross_implementation_check() {
    let Ok(out) = std::env::var("AINRA_INTEROP_OUT") else {
        return; // not requested — nothing to do
    };
    // A seed this corpus has never used, so the signature below has never existed before.
    let mut rng = ChaCha20Rng::seed_from_u64(0x_4D32_6001_u64);
    let kp = HybridKeypair::generate(&mut rng);
    let pk = kp.public();

    let mut cases = Vec::new();
    for (i, msg) in [
        b"M26 interop: freshly signed by ml-dsa 0.1.1".to_vec(),
        Vec::new(),       // empty message
        vec![0xFF; 4096], // long message
    ]
    .into_iter()
    .enumerate()
    {
        let sig = kp.sign(&msg).expect("sign");
        cases.push(format!(
            r#"{{"i":{i},"msg":"{}","ed25519":"{}","mldsa65":"{}"}}"#,
            b64::encode(&msg),
            b64::encode(&sig.ed25519),
            b64::encode(&sig.mldsa65),
        ));
    }
    let json = format!(
        r#"{{"pk_ed25519":"{}","pk_mldsa65":"{}","cases":[{}]}}"#,
        b64::encode(&pk.ed25519),
        b64::encode(&pk.mldsa65),
        cases.join(",")
    );
    std::fs::write(&out, json).expect("write interop export");
}
