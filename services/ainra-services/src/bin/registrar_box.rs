// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `registrar-box` daemon — a live AINRA registrar over HTTP (spec C5). Thin over [`RegistrarBox`]; every verdict is
//! the real verifier's. Local (127.0.0.1), zero telemetry. The core has no clock, so mutating/verifying endpoints
//! take an explicit `now` (unix seconds) — the caller supplies time, exactly as an offline verifier would.
//!
//! Endpoints:
//!   GET  /accreditation                 → the registrar's public keys (a signed-directory entry minus the M4 sig)
//!   POST /issue           {IssueSpec}   → the issued record (real hybrid signing + log inclusion)
//!   GET  /records                       → summaries of every issued credential
//!   GET  /record?sub=…                  → one full record
//!   GET  /verify?sub=…&now=T            → the live verdict (reflects revocations)
//!   POST /revoke          {sub, now}    → the emitted signed status delta
//!   GET  /status-list?now=T             → the full signed Token Status List
//!   GET  /fresh-head?now=T              → the 30-second delegate-signed fresh head
//!   GET  /deltas?since=S                → the signed deltas a client at head S still needs
//!   GET  /export?now=T                  → the whole registrar snapshot + live verdicts (for the explorer)
//!
//! Usage: `registrar-box [addr] [registrar-id] [data-dir]` (defaults 127.0.0.1:4900 / registrar-07 / ./rb-data).

use std::sync::Mutex;

use ainra_core::{b64, Verdict};
use ainra_services::http::{serve, Request};
use ainra_services::registrar::{IssueSpec, RegistrarBox};
use ainra_services::status::{WireDelta, WireFreshHead};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::json;

// A coherent demo timeline (issuance ≈ nbf; verification within the 90-day checkpoint-delegate window).
// The window is the ADR-017 default: 366 days from nbf, cited from the one constants module.
const NBF: u64 = 1_775_865_600; // 2026-04-11
const EXP: u64 = NBF + ainra_core::consts::PASSPORT_VALIDITY_DEFAULT_SECS;

fn qparam(path: &str, key: &str) -> Option<String> {
    let q = path.split('?').nth(1)?;
    q.split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
        .map(|s| s.to_string())
}
fn qnow(path: &str) -> u64 {
    qparam(path, "now")
        .and_then(|s| s.parse().ok())
        .unwrap_or(NBF + 10 * 24 * 60 * 60)
}

struct State {
    rb: RegistrarBox,
    rng: ChaCha20Rng,
}

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4900".to_string());
    let id = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "registrar-07".to_string());
    let dir = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "./rb-data".to_string());

    // Derive the seed from the registrar id (FNV-1a) so DISTINCT registrars get cryptographically DISTINCT keys —
    // two registrar *classes*, never one keypair under two names (M8 review HIGH). Deterministic per id, so a reload
    // reproduces the same registrar; a real deployment would seed from an HSM/ceremony, not a dev derivation.
    let mut seed = 0xcbf2_9ce4_8422_2325u64; // FNV-1a 64-bit offset basis
    for b in id.bytes() {
        seed ^= u64::from(b);
        seed = seed.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let rb = RegistrarBox::create(
        std::path::Path::new(&dir),
        &id,
        4096,
        NBF - 3600,
        NBF,
        EXP,
        &mut rng,
    )
    .expect("create registrar-box");
    let state = Mutex::new(State { rb, rng });
    eprintln!("registrar-box '{id}' data={dir}");

    serve(&addr, move |req: &Request| {
        let mut st = state.lock().unwrap();
        let route = req.path.split('?').next().unwrap_or("");
        match (req.method.as_str(), route) {
            ("GET", "/accreditation") => ok(&st.rb.accreditation()),

            ("POST", "/issue") => match serde_json::from_str::<IssueSpec>(&req.body) {
                Ok(spec) => {
                    let State { rb, rng } = &mut *st;
                    match rb.issue(&spec, &[], rng) {
                        Ok(rec) => ok(&rec),
                        Err(e) => (400, json!({ "error": e.to_string() }).to_string()),
                    }
                }
                Err(e) => (
                    400,
                    json!({ "error": format!("bad spec: {e}") }).to_string(),
                ),
            },

            ("GET", "/records") => {
                let list: Vec<_> = st
                    .rb
                    .records()
                    .map(|r| {
                        json!({
                            "sub": r.sub, "operator": r.operator, "lineage": r.lineage,
                            "version": r.version, "tier": r.tier, "auth_class": r.auth_class,
                            "status_idx": r.status_idx, "revoked": r.revoked,
                            "hops": r.hops.len(),
                        })
                    })
                    .collect();
                (
                    200,
                    json!({ "registrar": st.rb.id(), "records": list }).to_string(),
                )
            }

            ("GET", "/record") => {
                match qparam(&req.path, "sub").and_then(|s| st.rb.get(&urldecode(&s)).cloned()) {
                    Some(rec) => ok(&rec),
                    None => (404, r#"{"error":"unknown subject"}"#.to_string()),
                }
            }

            ("GET", "/verify") => {
                let now = qnow(&req.path);
                match qparam(&req.path, "sub").map(|s| urldecode(&s)) {
                    Some(sub) => {
                        let v = st.rb.verify_record(&sub, now);
                        (200, verdict_json(&sub, &v, now))
                    }
                    None => (400, r#"{"error":"sub required"}"#.to_string()),
                }
            }

            // The presentation bundle a verifier/middleware feeds to the sdk-ts Verifier (5-line verify).
            ("GET", "/present") => {
                let now = qnow(&req.path);
                match qparam(&req.path, "sub").map(|s| urldecode(&s)) {
                    Some(sub) => match st.rb.present(&sub, now, "F3") {
                        Some(bundle) => (200, bundle.to_string()),
                        None => (404, r#"{"error":"unknown subject"}"#.to_string()),
                    },
                    None => (400, r#"{"error":"sub required"}"#.to_string()),
                }
            }

            ("POST", "/revoke") => {
                let v: serde_json::Value =
                    serde_json::from_str(&req.body).unwrap_or(serde_json::Value::Null);
                let sub = v.get("sub").and_then(|x| x.as_str()).map(|s| s.to_string());
                let now = v
                    .get("now")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(NBF + 10 * 24 * 60 * 60);
                match sub {
                    Some(sub) => match st.rb.revoke(&sub, now) {
                        Ok(delta) => (
                            200,
                            serde_json::to_string(&WireDelta::from_core(&delta)).unwrap(),
                        ),
                        Err(e) => (400, json!({ "error": e.to_string() }).to_string()),
                    },
                    None => (400, r#"{"error":"sub required"}"#.to_string()),
                }
            }

            ("GET", "/status-list") => (
                200,
                serde_json::to_string(&st.rb.publish_status(qnow(&req.path))).unwrap(),
            ),

            ("GET", "/fresh-head") => match st.rb.fresh_head(qnow(&req.path)) {
                Some(h) => (
                    200,
                    serde_json::to_string(&WireFreshHead::from_core(&h)).unwrap(),
                ),
                None => (500, r#"{"error":"no delegate"}"#.to_string()),
            },

            ("GET", "/deltas") => {
                let since = qparam(&req.path, "since")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let deltas: Vec<_> = st
                    .rb
                    .deltas_since(since)
                    .iter()
                    .map(WireDelta::from_core)
                    .collect();
                (
                    200,
                    json!({ "head_seq": st.rb.status_seq(), "since": since, "deltas": deltas })
                        .to_string(),
                )
            }

            ("GET", "/export") => {
                let now = qnow(&req.path);
                (200, export_json(&st.rb, now))
            }

            _ => (404, r#"{"error":"not found"}"#.to_string()),
        }
    })
    .expect("serve");
}

fn ok<T: serde::Serialize>(v: &T) -> (u16, String) {
    (200, serde_json::to_string(v).unwrap())
}

fn verdict_json(sub: &str, v: &Verdict, now: u64) -> String {
    json!({
        "sub": sub, "now": now,
        "verdict": serde_json::to_value(v).unwrap(),
    })
    .to_string()
}

/// A self-contained snapshot the explorer loads: accreditation, the root key, every record, and a LIVE verdict per
/// record (so revocations show without re-verifying client-side). All real, all re-verifiable.
fn export_json(rb: &RegistrarBox, now: u64) -> String {
    let records: Vec<_> = rb
        .records()
        .map(|r| {
            let v = rb.verify_record(&r.sub, now);
            json!({ "record": r, "verdict": serde_json::to_value(&v).unwrap() })
        })
        .collect();
    json!({
        "registrar": rb.id(),
        "accreditation": rb.accreditation(),
        "root_pub_slh": b64::encode(&rb.root_public()),
        "status_seq": rb.status_seq(),
        "verified_at": now,
        "records": records,
    })
    .to_string()
}

fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
