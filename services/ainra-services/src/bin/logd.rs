// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `logd` daemon: POST /submit {entry_b64} → {index}; GET /checkpoint → signed checkpoint; GET /proof?i=N →
//! inclusion proof; GET /consistency?first=M → consistency proof. Local, zero telemetry. State behind a Mutex.

use std::sync::Mutex;

use ainra_core::{b64, crypto};
use ainra_services::http::{serve, Request};
use ainra_services::log::Logd;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn qparam(path: &str, key: &str) -> Option<String> {
    let q = path.split('?').nth(1)?;
    q.split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
        .map(|s| s.to_string())
}

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4881".to_string());
    let dir = std::env::temp_dir().join("ainra-logd");
    let mut rng = ChaCha20Rng::seed_from_u64(0x106D_0001);
    let root = crypto::TestRootSlh::generate(&mut rng);
    let delegate = crypto::TestDelegate::generate(&mut rng);
    let now = 1_775_865_600u64;
    let log = Mutex::new(
        Logd::open(&dir, "ainra-log/registrar-07", &root, delegate, now, 86_400).unwrap(),
    );

    serve(&addr, move |req: &Request| {
        let mut log = log.lock().unwrap();
        match (req.method.as_str(), req.path.split('?').next().unwrap_or("")) {
            ("POST", "/submit") => {
                let v: serde_json::Value = match serde_json::from_str(&req.body) {
                    Ok(v) => v,
                    Err(_) => return (400, r#"{"error":"bad json"}"#.to_string()),
                };
                let entry = match v.get("entry_b64").and_then(|s| s.as_str()).and_then(|s| b64::decode(s).ok()) {
                    Some(e) => e,
                    None => return (400, r#"{"error":"entry_b64 required"}"#.to_string()),
                };
                let idx = log.append(&entry).expect("append");
                (200, serde_json::json!({ "index": idx, "size": log.size() }).to_string())
            }
            ("GET", "/checkpoint") => {
                let cp = log.signed_checkpoint();
                (200, serde_json::json!({
                    "origin": cp.origin, "size": cp.tree_size, "root": b64::encode(&cp.root)
                }).to_string())
            }
            ("GET", "/proof") => {
                let i: u64 = qparam(&req.path, "i").and_then(|s| s.parse().ok()).unwrap_or(u64::MAX);
                match log.inclusion_proof(i) {
                    Some(p) => (200, serde_json::json!({
                        "leaf_index": i, "proof": p.iter().map(|h| b64::encode(h)).collect::<Vec<_>>()
                    }).to_string()),
                    None => (404, r#"{"error":"no such leaf"}"#.to_string()),
                }
            }
            ("GET", "/consistency") => {
                let first: u64 = qparam(&req.path, "first").and_then(|s| s.parse().ok()).unwrap_or(u64::MAX);
                match log.consistency_proof(first) {
                    Some(p) => (200, serde_json::json!({
                        "first": first, "proof": p.iter().map(|h| b64::encode(h)).collect::<Vec<_>>()
                    }).to_string()),
                    None => (404, r#"{"error":"bad first"}"#.to_string()),
                }
            }
            _ => (404, r#"{"error":"not found"}"#.to_string()),
        }
    })
    .unwrap();
}
