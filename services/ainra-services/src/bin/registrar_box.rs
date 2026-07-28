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

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Instant;

use ainra_core::{b64, Verdict};
use ainra_services::http::{serve, Request};
use ainra_services::registrar::{AuditEvidence, IssueSpec, RegistrarBox};
use ainra_services::status::{WireDelta, WireFreshHead};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde_json::json;

// A coherent demo timeline (issuance ≈ nbf; verification within the 90-day checkpoint-delegate window).
// The window is the ADR-017 default: 366 days from nbf, cited from the one constants module.
const NBF: u64 = 1_775_865_600; // 2026-04-11
const EXP: u64 = NBF + ainra_core::consts::PASSPORT_VALIDITY_DEFAULT_SECS;

/// The open registrar console (M16 Task 5), baked into the binary so every registrar serves it with zero extra files.
const CONSOLE_HTML: &str = include_str!("../../../../apps/registrar-box/console.html");

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
    /// Online-exposure hardening (SECURITY-STAGING). When set (env `AINRA_STAGE_ISSUE_TOKEN`), the WRITE endpoints
    /// (`/issue`, `/revoke`, `/renew`) require `Authorization: Bearer <token>`. The READ path stays open (it is
    /// public static data). Unset ⇒ open (local dev). This is a bearer secret for a TEST-ROOT staging registrar,
    /// never production key control.
    issue_token: Option<String>,
    /// Coarse token bucket over the WRITE endpoints: at most `WRITE_BURST` in any `WRITE_WINDOW`. A blunt DoS/abuse
    /// guard for an internet-exposed staging registrar — not a substitute for real quotas.
    writes: VecDeque<Instant>,
    /// M17: a SEPARATE bucket over the public demo door (`/demo/issue`, `/demo/revoke`), so a visitor completing the
    /// lifecycle in the browser cannot exhaust the operator's own write budget, and vice versa.
    demo_writes: VecDeque<Instant>,
}

const WRITE_BURST: usize = 30;
const WRITE_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

/// `true` iff the request is authorized to write. Open when no token is configured; else requires the bearer token.
fn write_authorized(req: &Request, token: &Option<String>) -> bool {
    match token {
        None => true,
        Some(t) => req
            .headers
            .get("authorization")
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(|got| got == t)
            .unwrap_or(false),
    }
}
/// `true` iff a write is within the rate budget; records the write time when allowed.
fn rate_ok(writes: &mut VecDeque<Instant>) -> bool {
    let now = Instant::now();
    while writes
        .front()
        .is_some_and(|t| now.duration_since(*t) > WRITE_WINDOW)
    {
        writes.pop_front();
    }
    if writes.len() >= WRITE_BURST {
        return false;
    }
    writes.push_back(now);
    true
}

/// M17 public demo door — a CONSTRAINED specimen spec. The door mints only a low-tier `specimen:demo` credential with
/// a random version; it can never mint a high-assurance (L3/L4) or arbitrarily-named credential. This is the whole
/// point of a *door*: a stranger completes the real lifecycle without any secret, and cannot abuse issuance.
fn sanitize_label(s: &str, default: &str) -> String {
    // to the namespace grammar: lowercase ascii-alphanumerics + hyphen, bounded length, no leading/trailing hyphen.
    let cleaned: String = s.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').take(24).collect();
    let cleaned = cleaned.to_ascii_lowercase();
    let cleaned = cleaned.trim_matches('-').to_string();
    if cleaned.is_empty() { default.to_string() } else { cleaned }
}
/// A constrained specimen for the public door. The visitor may NAME their agent (operator/lineage), but the door
/// still mints only a low tier and stamps the reserved `demo:specimen` capability, which marks it as door-minted.
fn demo_spec(rng: &mut ChaCha20Rng, operator: &str, lineage: &str) -> IssueSpec {
    let n = rng.next_u32();
    IssueSpec {
        operator: sanitize_label(operator, "specimen"),
        lineage: sanitize_label(lineage, "demo"),
        version: format!("1.0.{}", n % 100_000),
        tier: "L1".to_string(), // low assurance — the public door cannot mint high tiers
        auth_class: "A2".to_string(),
        principal_proof: "specimen".to_string(),
        capabilities: vec!["demo:specimen".to_string()],
        scope_ceiling: vec!["demo:specimen".to_string()],
        hops: vec![],
        audit: None,
    }
}
/// `true` iff `sub` is a specimen THIS registrar minted through the public door (stamped `demo:specimen`) — the
/// public revoke door touches nothing else, whatever operator/lineage the visitor named it.
fn is_demo_specimen(rb: &RegistrarBox, sub: &str) -> bool {
    rb.get(sub).map(|r| r.capabilities.iter().any(|c| c == "demo:specimen")).unwrap_or(false)
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
    let issue_token = std::env::var("AINRA_STAGE_ISSUE_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());
    let staging = std::env::var("AINRA_STAGE").ok().as_deref() == Some("1");
    let state = Mutex::new(State {
        rb,
        rng,
        issue_token: issue_token.clone(),
        writes: VecDeque::new(),
        demo_writes: VecDeque::new(),
    });
    eprintln!(
        "registrar-box '{id}' data={dir}{}{}",
        if staging {
            " [STAGING · TEST-ROOT]"
        } else {
            ""
        },
        if issue_token.is_some() {
            " [write-auth: bearer token]"
        } else {
            " [write-auth: OPEN — dev]"
        }
    );

    serve(&addr, move |req: &Request| {
        let mut st = state.lock().unwrap();
        let route = req.path.split('?').next().unwrap_or("");
        match (req.method.as_str(), route) {
            // M16 Task 5 (D-034): the OPEN registrar console — neutral, unbranded, no pricing/accounts, zero telemetry.
            // Self-contained HTML that drives THIS registrar's read + rate-limited write API. Every registrar inherits it.
            ("GET", "/console") | ("GET", "/") => (200, CONSOLE_HTML.to_string()),

            // Staging health/board: network + root labels, checkpoint height, record count. Read-only, open.
            ("GET", "/health") => (
                200,
                json!({
                    "network": if staging { "staging" } else { "dev" },
                    "root": "test-root",
                    "registrar": st.rb.id(),
                    "records": st.rb.len(),
                    "status_seq": st.rb.status_seq(),
                    "write_auth": st.issue_token.is_some(),
                    "ok": true,
                })
                .to_string(),
            ),

            ("GET", "/accreditation") => ok(&st.rb.accreditation()),

            ("POST", "/issue") => {
                if !write_authorized(req, &st.issue_token) {
                    return (
                        401,
                        r#"{"error":"unauthorized (bearer token required)"}"#.to_string(),
                    );
                }
                if !rate_ok(&mut st.writes) {
                    return (429, r#"{"error":"rate limited"}"#.to_string());
                }
                match serde_json::from_str::<IssueSpec>(&req.body) {
                    Ok(spec) => {
                        let State { rb, rng, .. } = &mut *st;
                        match rb.issue(&spec, &[], rng) {
                            Ok(rec) => ok(&rec),
                            Err(e) => (400, json!({ "error": e.to_string() }).to_string()),
                        }
                    }
                    Err(e) => (
                        400,
                        json!({ "error": format!("bad spec: {e}") }).to_string(),
                    ),
                }
            }

            // M17 Task 2 — the PUBLIC demo door. No bearer token; rate-limited (its own bucket); TEST-ROOT/staging only.
            // A visitor completes the whole lifecycle from the browser with no secret: the door mints only a low-tier
            // `specimen:demo` credential and only revokes one it minted. The root grows no product surface — issuance
            // and revocation stay in the registrar layer, exactly where the model puts them; this is that door, opened.
            ("POST", "/demo/issue") => {
                if !staging {
                    return (403, r#"{"error":"the demo door is staging-only"}"#.to_string());
                }
                if !rate_ok(&mut st.demo_writes) {
                    return (429, r#"{"error":"demo door rate limited — try again shortly"}"#.to_string());
                }
                // The visitor may name their agent: optional {operator, lineage} (sanitized to the grammar).
                let body: serde_json::Value =
                    serde_json::from_str(&req.body).unwrap_or(serde_json::Value::Null);
                let operator = body.get("operator").and_then(|x| x.as_str()).unwrap_or("specimen");
                let lineage = body.get("lineage").and_then(|x| x.as_str()).unwrap_or("demo");
                let State { rb, rng, .. } = &mut *st;
                let spec = demo_spec(rng, operator, lineage);
                match rb.issue(&spec, &[], rng) {
                    Ok(rec) => ok(&rec),
                    Err(e) => (400, json!({ "error": e.to_string() }).to_string()),
                }
            }
            ("POST", "/demo/revoke") => {
                if !staging {
                    return (403, r#"{"error":"the demo door is staging-only"}"#.to_string());
                }
                if !rate_ok(&mut st.demo_writes) {
                    return (429, r#"{"error":"demo door rate limited — try again shortly"}"#.to_string());
                }
                let v: serde_json::Value =
                    serde_json::from_str(&req.body).unwrap_or(serde_json::Value::Null);
                let Some(sub) = v.get("sub").and_then(|x| x.as_str()).map(String::from) else {
                    return (400, r#"{"error":"sub required"}"#.to_string());
                };
                if !is_demo_specimen(&st.rb, &sub) {
                    return (
                        403,
                        r#"{"error":"the public door only revokes demo specimens it minted"}"#.to_string(),
                    );
                }
                let now = v
                    .get("now")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(NBF + 10 * 24 * 60 * 60);
                match st.rb.revoke(&sub, now) {
                    Ok(_) => (200, json!({ "revoked": sub, "now": now }).to_string()),
                    Err(e) => (400, json!({ "error": e.to_string() }).to_string()),
                }
            }

            // ADR-017 renewal over HTTP: reissue `sub` (fresh window, prev_leaf continuity). Body:
            // {sub, new_version?, now, audit?{reference,expires}}. Write endpoint (auth + rate limited).
            ("POST", "/renew") => {
                if !write_authorized(req, &st.issue_token) {
                    return (
                        401,
                        r#"{"error":"unauthorized (bearer token required)"}"#.to_string(),
                    );
                }
                if !rate_ok(&mut st.writes) {
                    return (429, r#"{"error":"rate limited"}"#.to_string());
                }
                let v: serde_json::Value =
                    serde_json::from_str(&req.body).unwrap_or(serde_json::Value::Null);
                let Some(sub) = v.get("sub").and_then(|x| x.as_str()).map(String::from) else {
                    return (400, r#"{"error":"sub required"}"#.to_string());
                };
                let now = v
                    .get("now")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(NBF + 5 * 24 * 3600);
                let new_version = v.get("new_version").and_then(|x| x.as_str());
                let audit = v.get("audit").and_then(|a| {
                    Some(AuditEvidence {
                        reference: a.get("reference")?.as_str()?.to_string(),
                        expires: a.get("expires")?.as_u64()?,
                    })
                });
                let State { rb, rng, .. } = &mut *st;
                match rb.reissue(&sub, new_version, now, audit.as_ref(), rng) {
                    Ok(rec) => ok(&rec),
                    Err(e) => (400, json!({ "error": e.to_string() }).to_string()),
                }
            }

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
                if !write_authorized(req, &st.issue_token) {
                    return (
                        401,
                        r#"{"error":"unauthorized (bearer token required)"}"#.to_string(),
                    );
                }
                if !rate_ok(&mut st.writes) {
                    return (429, r#"{"error":"rate limited"}"#.to_string());
                }
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
        // The signed status list travels WITH the export so a client can recheck revocation offline (mirrors the
        // CLI seed export). Published to the static artifact surface for AINRAscan / mirrors.
        "status_list": serde_json::to_value(rb.publish_status(now.saturating_sub(1))).unwrap(),
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
