// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `witnessd` daemon: POST /consider {origin,size,root_b64,consistency_proof_b64[]} → the outcome (and a cosignature
//! when it cosigns). Refuses forks + regressions. GET /key (alias /root) → the witness public key. GET /info → the
//! operator's SELF-DECLARED metadata (never verified by anyone). Local, zero telemetry.
//!
//! Usage:  witnessd <addr> [config.json]
//! The optional one-file config declares who runs this witness (all fields optional):
//!   { "seed": "<hex>", "operator": "…", "region": "…", "contact": "…", "note": "…" }
//! `seed` (if present) pins a persistent key; otherwise the key is derived from the address. Everything under
//! operator/region/contact/note is SELF-DECLARED — `/info` serves it with `self_declared: true`, and the verifier
//! and site render it as an unverified operator claim. Witnessing needs no accreditation; the metadata is courtesy.

use std::sync::Mutex;

use ainra_core::checkpoint::Checkpoint;
use ainra_core::{b64, crypto};
use ainra_services::http::{serve, Request};
use ainra_services::witness::{Witness, WitnessOutcome};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

fn decode32(s: &str) -> Option<[u8; 32]> {
    b64::decode_array::<32>(s).ok()
}

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4883".to_string());
    // Optional one-file config (arg 2). Absent / unreadable / a non-JSON path (e.g. a legacy data-dir arg) → no
    // declared metadata, key derived from the address. Never fails closed on a missing config — witnessing is open.
    let cfg: serde_json::Value = std::env::args()
        .nth(2)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::Value::Null);
    let field = |k: &str| {
        cfg.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };

    // Key: a config `seed` (hex) pins a persistent operator key; otherwise derive from the address (FNV-1a) so a
    // quorum of witnessd processes on different ports get cryptographically DISTINCT keys — independent witnesses,
    // never one key under many addresses (cf. the M8 registrar fix). A real deployment seeds from operator-held key.
    let mut rng = match cfg.get("seed").and_then(|v| v.as_str()) {
        Some(hex) if !hex.is_empty() => {
            let digest: [u8; 32] = Sha256::digest(hex.as_bytes()).into();
            ChaCha20Rng::from_seed(digest)
        }
        _ => {
            let mut seed = 0xcbf2_9ce4_8422_2325u64;
            for byte in addr.bytes() {
                seed ^= u64::from(byte);
                seed = seed.wrapping_mul(0x0000_0100_0000_01b3);
            }
            ChaCha20Rng::seed_from_u64(seed)
        }
    };
    let witness = Mutex::new(Witness::new(crypto::TestDelegate::generate(&mut rng)));

    serve(&addr, move |req: &Request| {
        let mut w = witness.lock().unwrap();
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/key") | ("GET", "/root") => (
                200,
                serde_json::json!({ "ed25519": b64::encode(&w.public()) }).to_string(),
            ),
            // SELF-DECLARED — the operator's own claim, verified by no one; the key is the only cryptographic fact.
            ("GET", "/info") => (
                200,
                serde_json::json!({
                    "self_declared": true,
                    "ed25519": b64::encode(&w.public()),
                    "operator": field("operator"),
                    "region": field("region"),
                    "contact": field("contact"),
                    "note": field("note"),
                })
                .to_string(),
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
