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
use ainra_services::registrar::{AuditEvidence, HybridB64, IssueSpec, RegistrarBox};
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
/// The operator's real time (M35). A request may name any `now` it likes — the core has no clock, by design — but a
/// request that names none, and every delegate renewal, uses this. The default used to be `NBF + 10 days`, a fixed
/// instant in April 2026, so the daemon's own clock was frozen along with everything that trusted it.
fn wall_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `AINRA_CLOCK=pinned` keeps a HERMETIC drill at the fixed genesis instant, exactly as every drill ran before M35.
/// Anything else — including unset — is the wall clock. The default is the safe direction on purpose: forgetting the
/// variable in production yields a registrar that keeps time; forgetting it in a drill yields a loud test failure.
/// The reverse default is how the staging network sat dead at the real clock for months while every board was green.
fn clock_pinned() -> bool {
    std::env::var("AINRA_CLOCK").ok().as_deref() == Some("pinned")
}

/// The instant a request that names none is served at. Pinned mode reproduces the old defaults to the second.
fn default_now() -> u64 {
    if clock_pinned() {
        NBF + 10 * 24 * 60 * 60
    } else {
        wall_now()
    }
}
fn default_renew_now() -> u64 {
    if clock_pinned() {
        NBF + 5 * 24 * 3600
    } else {
        wall_now()
    }
}

/// Per-request randomness: demo-door versions, and key material for any passport issued without a caller key.
///
/// It was seeded from the registrar id — a leftover from when the same generator also derived the registrar's
/// identity keys (those now come from `create_seeded`). A seeded generator replays on every restart, so after a
/// redeploy the public door re-drew versions it had already issued and refused its first visitors with `duplicate
/// subject` — and would have re-drawn the same holder keys for any passport minted without one. The live registrar
/// therefore reads the operating system's entropy, and refuses to run on a replayable seed if it cannot. Pinned,
/// hermetic drills keep the seed: their transcripts are meant to reproduce.
fn operational_rng(id_seed: u64, id: &str) -> ChaCha20Rng {
    if clock_pinned() {
        return ChaCha20Rng::seed_from_u64(id_seed);
    }
    let mut seed = [0u8; 32];
    let read = std::fs::File::open("/dev/urandom").and_then(|mut f| {
        use std::io::Read;
        f.read_exact(&mut seed)
    });
    if let Err(e) = read {
        eprintln!("registrar-box '{id}': no OS entropy ({e}) — refusing to run a live registrar on a replayable seed");
        std::process::exit(2);
    }
    ChaCha20Rng::from_seed(seed)
}

fn qnow(path: &str) -> u64 {
    qparam(path, "now")
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(default_now)
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
/// May this request write (`/issue`, `/revoke`, `/renew`)?
///
/// FAIL CLOSED (M35). With no token configured this used to answer `true` — so a registrar started without one
/// accepted unauthenticated issuance at any tier AND unauthenticated revocation of anyone's passport. It was only
/// ever reachable on 127.0.0.1, but the live network exists to be deployed, and a door that opens by forgetting a
/// variable is not a door. Unauthenticated writes now require `AINRA_OPEN_WRITES=1`, which `main` refuses to honour
/// on any address but loopback. The public demo door is separate, rate-limited, and mints only specimens.
fn write_authorized(req: &Request, token: &Option<String>, open_writes: bool) -> bool {
    match token {
        None => open_writes,
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
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(24)
        .collect();
    let cleaned = cleaned.to_ascii_lowercase();
    let cleaned = cleaned.trim_matches('-').to_string();
    if cleaned.is_empty() {
        default.to_string()
    } else {
        cleaned
    }
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
        holder_key: None,
        holder_pop: None,
    }
}
/// `true` iff `sub` is a specimen THIS registrar minted through the public door (stamped `demo:specimen`) — the
/// public revoke door touches nothing else, whatever operator/lineage the visitor named it.
fn is_demo_specimen(rb: &RegistrarBox, sub: &str) -> bool {
    rb.get(sub)
        .map(|r| r.capabilities.iter().any(|c| c == "demo:specimen"))
        .unwrap_or(false)
}

/// Persist after every mutation. Without this the reload added above would have nothing to reload: `save()` writes
/// `registrar.json` (shareable snapshot) plus `registrar.secret` (0600, the reload seed). A failure to persist is
/// logged, never fatal — the in-memory network keeps serving; but it must be VISIBLE, because a silent persist
/// failure is how you get a daemon that looks healthy and loses everything on the next restart.
fn persist(rb: &RegistrarBox, id: &str) {
    if let Err(e) = rb.save() {
        eprintln!("registrar-box '{id}': WARNING — state not persisted: {e:?}");
    }
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
    let rng = operational_rng(seed, &id);
    // RELOAD BEFORE CREATE. This binary used to call `create` unconditionally, which meant the daemon started with
    // an EMPTY set of issued records on every single start — for the whole life of the systemd stage. The keys are
    // derived deterministically from the id above, so `/accreditation` always matched the published directory and
    // every health probe passed; only `/present` knew, and it answered `unknown subject` for passports the
    // published record listed. `RegistrarBox::{save,load}` were fully implemented — the 0600 secret, the snapshot,
    // the delta replay — and nothing ever called them. Implemented-but-unreachable, the same shape as a soak report
    // no consumer could read.
    //
    // Fail LOUDLY, never silently: if a snapshot exists but will not load, that is corruption or a missing secret,
    // and quietly re-creating an empty registrar over it is how you lose a network and publish a record you cannot
    // honour. Only an absent snapshot means "new registrar".
    let data_dir = std::path::Path::new(&dir);
    let snapshot = data_dir.join("registrar.json");
    let rb = if snapshot.exists() {
        match RegistrarBox::load(data_dir) {
            Ok(rb) => {
                eprintln!("registrar-box '{id}' RELOADED from {dir}");
                rb
            }
            Err(e) => {
                eprintln!("registrar-box '{id}': {snapshot:?} exists but will not load: {e:?}");
                eprintln!("refusing to start an empty registrar over existing state — fix or move the snapshot.");
                std::process::exit(2);
            }
        }
    } else {
        // `create_seeded`, NOT `create`. `create` takes an rng and records no seed, so `save()` writes
        // `"seed": 0` and `load()` refuses the snapshot outright — "created by the daemon, not the CLI". The
        // daemon was already deriving exactly the right seed and then throwing it away into an rng, which is why
        // its state was structurally unreloadable no matter how often it was saved.
        RegistrarBox::create_seeded(data_dir, &id, 4096, seed, NBF - 3600, NBF, EXP)
            .expect("create registrar-box")
    };
    // M35: certify the delegates at the WALL CLOCK before serving anything. A registrar reloaded from a snapshot —
    // or created at the fixed genesis instant below — would otherwise sign with certs that lapsed long ago.
    let mut rb = rb;
    match if clock_pinned() {
        Ok(false)
    } else {
        rb.ensure_delegates(wall_now())
    } {
        Ok(true) => {
            let (nbf, exp) = rb.delegate_window();
            eprintln!("registrar-box '{id}': delegates re-certified at the wall clock, valid {nbf}..{exp}");
        }
        Ok(false) => {}
        Err(e) => {
            eprintln!("registrar-box '{id}': could not re-certify delegates: {e:?}");
            std::process::exit(2);
        }
    }
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
        // States the policy `write_authorized` actually enforces (M35). It used to print "OPEN — dev" whenever no
        // token was set, which became false the moment writes started failing closed.
        if issue_token.is_some() {
            " [write-auth: bearer token]"
        } else if std::env::var("AINRA_OPEN_WRITES").ok().as_deref() == Some("1") {
            " [write-auth: OPEN — loopback drill only]"
        } else {
            " [write-auth: CLOSED — no token, every write refused]"
        }
    );

    // Unauthenticated writes are a hermetic-drill convenience and nothing else. Refuse them anywhere a stranger could
    // reach: a config copied from a drill into a deployment must fail at start, not open the registrar.
    let open_writes = std::env::var("AINRA_OPEN_WRITES").ok().as_deref() == Some("1");
    let loopback =
        addr.starts_with("127.") || addr.starts_with("[::1]") || addr.starts_with("localhost:");
    if open_writes && !loopback {
        eprintln!("registrar-box '{id}': refusing AINRA_OPEN_WRITES=1 on {addr} — unauthenticated writes are loopback-only");
        std::process::exit(2);
    }
    if issue_token.is_none() && !open_writes {
        eprintln!("registrar-box '{id}': no AINRA_STAGE_ISSUE_TOKEN — /issue, /revoke and /renew will refuse every request");
    }
    if open_writes {
        eprintln!("registrar-box '{id}': OPEN WRITES (AINRA_OPEN_WRITES=1, loopback only) — hermetic drills only, never a deployment");
    }
    serve(&addr, move |req: &Request| {
        let mut st = state.lock().unwrap();
        // Before anything can be signed: renew if the delegate is near or past its window. A cheap comparison on
        // every request, so a registrar that stays up for months never signs with a lapsed cert — the write path
        // must never produce state the read path will refuse (M35, PLAN-M34 Task 7 finding 4).
        if !clock_pinned() {
            if let Err(e) = st.rb.ensure_delegates(wall_now()) {
                return (
                    503,
                    json!({ "error": format!("delegate renewal failed: {e}") }).to_string(),
                );
            }
        }
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
                if !write_authorized(req, &st.issue_token, open_writes) {
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
                            Ok(rec) => {
                                persist(rb, &id);
                                ok(&rec)
                            }
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
                    return (
                        403,
                        r#"{"error":"the demo door is staging-only"}"#.to_string(),
                    );
                }
                if !rate_ok(&mut st.demo_writes) {
                    return (
                        429,
                        r#"{"error":"demo door rate limited — try again shortly"}"#.to_string(),
                    );
                }
                // The visitor may name their agent: optional {operator, lineage} (sanitized to the grammar).
                let body: serde_json::Value =
                    serde_json::from_str(&req.body).unwrap_or(serde_json::Value::Null);
                let operator = body
                    .get("operator")
                    .and_then(|x| x.as_str())
                    .unwrap_or("specimen");
                let lineage = body
                    .get("lineage")
                    .and_then(|x| x.as_str())
                    .unwrap_or("demo");
                let State { rb, rng, .. } = &mut *st;
                let mut spec = demo_spec(rng, operator, lineage);
                // D-063: a visitor's agent may bring its OWN key, with a proof it holds it. Then the specimen it
                // receives is one it can actually use — prove possession of, and mint instance credentials under —
                // instead of one bound to a key the registrar generated and threw away. Omit both and the door
                // behaves exactly as before.
                let hybrid = |k: &str| {
                    body.get(k)
                        .and_then(|v| serde_json::from_value::<HybridB64>(v.clone()).ok())
                };
                spec.holder_key = hybrid("holder_key");
                spec.holder_pop = hybrid("holder_pop");
                // The door's version space is 100 000, so two specimens under one lineage name collide by the birthday
                // bound after a few hundred issuances even with perfect randomness. A collision is the door's problem,
                // not the visitor's: draw again, a bounded number of times.
                let mut attempt = rb.issue(&spec, &[], rng);
                for _ in 0..8 {
                    if !matches!(
                        attempt,
                        Err(ainra_services::registrar::IssueError::Duplicate(_))
                    ) {
                        break;
                    }
                    spec.version = format!("1.0.{}", rng.next_u32() % 100_000);
                    attempt = rb.issue(&spec, &[], rng);
                }
                match attempt {
                    Ok(rec) => {
                        persist(rb, &id);
                        ok(&rec)
                    }
                    Err(e) => (400, json!({ "error": e.to_string() }).to_string()),
                }
            }
            ("POST", "/demo/revoke") => {
                if !staging {
                    return (
                        403,
                        r#"{"error":"the demo door is staging-only"}"#.to_string(),
                    );
                }
                if !rate_ok(&mut st.demo_writes) {
                    return (
                        429,
                        r#"{"error":"demo door rate limited — try again shortly"}"#.to_string(),
                    );
                }
                let v: serde_json::Value =
                    serde_json::from_str(&req.body).unwrap_or(serde_json::Value::Null);
                let Some(sub) = v.get("sub").and_then(|x| x.as_str()).map(String::from) else {
                    return (400, r#"{"error":"sub required"}"#.to_string());
                };
                if !is_demo_specimen(&st.rb, &sub) {
                    return (
                        403,
                        r#"{"error":"the public door only revokes demo specimens it minted"}"#
                            .to_string(),
                    );
                }
                let now = v
                    .get("now")
                    .and_then(|x| x.as_u64())
                    .unwrap_or_else(default_now);
                match st.rb.revoke(&sub, now) {
                    Ok(_) => {
                        persist(&st.rb, &id);
                        (200, json!({ "revoked": sub, "now": now }).to_string())
                    }
                    Err(e) => (400, json!({ "error": e.to_string() }).to_string()),
                }
            }

            // ADR-017 renewal over HTTP: reissue `sub` (fresh window, prev_leaf continuity). Body:
            // {sub, new_version?, now, audit?{reference,expires}}. Write endpoint (auth + rate limited).
            ("POST", "/renew") => {
                if !write_authorized(req, &st.issue_token, open_writes) {
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
                    .unwrap_or_else(default_renew_now);
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
                if !write_authorized(req, &st.issue_token, open_writes) {
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
                    .unwrap_or_else(default_now);
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
