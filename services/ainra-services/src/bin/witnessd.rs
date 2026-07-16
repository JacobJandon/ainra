// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `witnessd` daemon: POST /consider {origin,size,root_b64,consistency_proof_b64[]} → the outcome (and a cosignature
//! when it cosigns). Refuses forks + regressions. GET /key → the witness public key. Local, zero telemetry.

use std::sync::Mutex;

use ainra_core::checkpoint::Checkpoint;
use ainra_core::{b64, crypto};
use ainra_services::http::{serve, Request};
use ainra_services::witness::{Witness, WitnessOutcome};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn decode32(s: &str) -> Option<[u8; 32]> {
    b64::decode_array::<32>(s).ok()
}

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4883".to_string());
    let mut rng = ChaCha20Rng::seed_from_u64(0x717E_0001);
    let witness = Mutex::new(Witness::new(crypto::TestDelegate::generate(&mut rng)));

    serve(&addr, move |req: &Request| {
        let mut w = witness.lock().unwrap();
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/key") => (
                200,
                serde_json::json!({ "ed25519": b64::encode(&w.public()) }).to_string(),
            ),
            ("POST", "/consider") => {
                let v: serde_json::Value = match serde_json::from_str(&req.body) {
                    Ok(v) => v,
                    Err(_) => return (400, r#"{"error":"bad json"}"#.to_string()),
                };
                let root = match v
                    .get("root_b64")
                    .and_then(|s| s.as_str())
                    .and_then(decode32)
                {
                    Some(r) => r,
                    None => return (400, r#"{"error":"root_b64 required"}"#.to_string()),
                };
                let cp = Checkpoint {
                    origin: v
                        .get("origin")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string(),
                    tree_size: v.get("size").and_then(|x| x.as_u64()).unwrap_or(0),
                    root,
                };
                let proof: Vec<[u8; 32]> = v
                    .get("consistency_proof_b64")
                    .and_then(|a| a.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|s| s.as_str())
                            .filter_map(decode32)
                            .collect()
                    })
                    .unwrap_or_default();
                // The witness cosigns only checkpoints validly signed by the LOG's own key (review #11). The log's
                // root key is registered once (its accreditation) and the checkpoint carries its root-mode SLH sig.
                if let Some(k) = v
                    .get("log_root_key_b64")
                    .and_then(|s| s.as_str())
                    .and_then(|s| b64::decode(s).ok())
                {
                    w.register_log(&cp.origin, k);
                }
                let sig = match v
                    .get("checkpoint_sig_b64")
                    .and_then(|s| s.as_str())
                    .and_then(|s| b64::decode(s).ok())
                {
                    Some(s) => ainra_core::checkpoint::CheckpointSig::Root { slh: s },
                    None => {
                        return (
                            400,
                            r#"{"error":"checkpoint_sig_b64 required"}"#.to_string(),
                        )
                    }
                };
                let now = v.get("now").and_then(|x| x.as_u64()).unwrap_or(0);
                let outcome = w.consider(&cp, &sig, now, &proof);
                let cosig = matches!(
                    outcome,
                    WitnessOutcome::Cosigned | WitnessOutcome::CosignedFirstSight
                )
                .then(|| b64::encode(&w.cosign(&cp)));
                let name = match outcome {
                    WitnessOutcome::CosignedFirstSight => "cosigned_first_sight",
                    WitnessOutcome::Cosigned => "cosigned",
                    WitnessOutcome::RefusedRegression => "refused_regression",
                    WitnessOutcome::RefusedFork => "refused_fork",
                    WitnessOutcome::RefusedUnsigned => "refused_unsigned",
                };
                (
                    200,
                    serde_json::json!({ "outcome": name, "cosignature": cosig }).to_string(),
                )
            }
            _ => (404, r#"{"error":"not found"}"#.to_string()),
        }
    })
    .unwrap();
}
