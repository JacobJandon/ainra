// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `statusd` daemon — a Token Status List publisher with the M3 signed delta stream + fresh head. Local, zero
//! telemetry. The core has no clock, so `now` is an explicit query param.
//!
//! Endpoints:
//!   POST /revoke        {idx | idx:[..]}    → emit a signed, delegate-countersigned delta advancing the head
//!   GET  /publish?now=T                     → the full signed Token Status List
//!   GET  /fresh-head?now=T                  → the 30-second delegate-signed fresh head
//!   GET  /deltas?since=S                    → the signed delta stream a client at head S still needs
//!   GET  /key                               → the registrar hybrid public key (checks publications + deltas)
//!   GET  /root                              → the SLH-DSA root key + delegate cert (chains deltas + fresh heads)

use std::sync::Mutex;

use ainra_core::{b64, crypto};
use ainra_services::http::{serve, Request};
use ainra_services::status::{Statusd, WireDelegateCert, WireDelta, WireFreshHead};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::json;

// A coherent demo timeline (certs open just before NBF; delta window = 90 days per ADR-002).
const NBF: u64 = 1_775_865_600;
const VALIDITY: u64 = 90 * 24 * 60 * 60;

fn qparam(path: &str, key: &str) -> Option<String> {
    let q = path.split('?').nth(1)?;
    q.split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
        .map(|s| s.to_string())
}
fn qnum(path: &str, key: &str, default: u64) -> u64 {
    qparam(path, key)
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4882".to_string());
    let mut rng = ChaCha20Rng::seed_from_u64(0x57A7_05D0);
    let root = crypto::TestRootSlh::generate(&mut rng);
    let delegate = crypto::TestDelegate::generate(&mut rng);
    let signer = crypto::HybridKeypair::generate(&mut rng);
    let sd = Statusd::new("status://registrar-07/1", 4096, signer)
        .with_delegate(&root, delegate, NBF - 3600, VALIDITY)
        .expect("configure status delegate");
    let sd = Mutex::new(sd);

    serve(&addr, move |req: &Request| {
        let mut sd = sd.lock().unwrap();
        match (req.method.as_str(), req.path.split('?').next().unwrap_or("")) {
            ("POST", "/revoke") => {
                let v: serde_json::Value =
                    serde_json::from_str(&req.body).unwrap_or(serde_json::Value::Null);
                let now = v.get("now").and_then(|x| x.as_u64()).unwrap_or(NBF + 86_400);
                // Accept either {"idx": N} or {"idx": [..]}.
                let idxs: Vec<usize> = match v.get("idx") {
                    Some(serde_json::Value::Number(n)) => n.as_u64().map(|x| vec![x as usize]).unwrap_or_default(),
                    Some(serde_json::Value::Array(a)) => {
                        a.iter().filter_map(|x| x.as_u64()).map(|x| x as usize).collect()
                    }
                    _ => return (400, r#"{"error":"idx (number or array) required"}"#.to_string()),
                };
                if idxs.is_empty() {
                    return (400, r#"{"error":"idx required"}"#.to_string());
                }
                match sd.revoke_delta(&idxs, now) {
                    Some(Ok(delta)) => (200, serde_json::to_string(&WireDelta::from_core(&delta)).unwrap()),
                    Some(Err(r)) => (400, json!({ "error": format!("delta rejected: {r}") }).to_string()),
                    None => (500, r#"{"error":"no delegate configured"}"#.to_string()),
                }
            }
            ("GET", "/publish") => {
                (200, serde_json::to_string(&sd.publish(qnum(&req.path, "now", 0))).unwrap())
            }
            ("GET", "/fresh-head") => match sd.fresh_head(qnum(&req.path, "now", NBF + 86_400)) {
                Some(h) => (200, serde_json::to_string(&WireFreshHead::from_core(&h)).unwrap()),
                None => (500, r#"{"error":"no delegate"}"#.to_string()),
            },
            ("GET", "/deltas") => {
                let since = qnum(&req.path, "since", 0);
                let deltas: Vec<_> = sd.deltas_since(since).iter().map(WireDelta::from_core).collect();
                (200, json!({ "head_seq": sd.current_seq(), "since": since, "deltas": deltas }).to_string())
            }
            ("GET", "/key") => {
                let k = sd.public();
                (200, json!({ "ed25519": b64::encode(&k.ed25519), "mldsa65": b64::encode(&k.mldsa65) }).to_string())
            }
            ("GET", "/root") => {
                let root_pub = sd.root_public().map(b64::encode).unwrap_or_default();
                let cert = sd.delegate_cert().map(WireDelegateCert::from_core);
                (200, json!({ "root_pub_slh": root_pub, "delegate_cert": cert }).to_string())
            }
            _ => (404, r#"{"error":"not found"}"#.to_string()),
        }
    })
    .unwrap();
}
