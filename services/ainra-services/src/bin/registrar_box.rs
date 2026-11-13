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
//!   GET  /transfers                     → every move into this registrar, open and closed (D-102)
//!   GET  /operator-key?operator=&lineage= → a logged operator key with its inclusion proof (D-102)
//!   POST /operator-key    {operator, lineage, key, pop}            → log it (write-authorized)
//!   POST /transfer-in      {request, passport, operator_key, directory, status, now?} → open a move (public)
//!   POST /transfer-consent {id, operator_sig, now?}                 → the operator signs it (public)
//!   POST /transfer-contest {id, by, reason, sig, directory, now?}   → stop it (public; signature-checked)
//!   POST /transfer-complete {id, passport, directory, status, now?} → issue here after the window (write-authorized)
//!   POST /transfer-out     {passport, request, directory, status, now?} → revoke the passport that moved away (public)
//!   GET  /ownership-changes             → every change of owner at this registrar, open and closed (D-103)
//!   POST /ownership-open    {request, now?}                         → the old owner gives a lineage away (public)
//!   POST /ownership-contest {id, reason, sig, now?}                 → the old operator key stops it (public)
//!   POST /ownership-complete {id, assurance, now?}                  → issue to the new owner after the window (write-authorized)
//!   The `/transfer-*` doors read a signed directory under the roots in `AINRA_ROOTS_FILE`; without it they refuse.
//!
//! Usage: `registrar-box [addr] [registrar-id] [data-dir]` (defaults 127.0.0.1:4900 / registrar-07 / ./rb-data).

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Instant;

use ainra_core::{b64, Verdict};
use ainra_services::http::{serve, Request};
use ainra_services::registrar::principal::PrincipalPolicy;
use ainra_services::registrar::transfer::{
    NewOwnerAssurance, OperatorKeyReceipt, OwnershipRequest, PeerRegistrar, TransferRequest,
};
use ainra_services::registrar::IssuedRecord;
use ainra_services::registrar::{
    AuditEvidence, HybridB64, IssueSpec, LinkSpec, RegistrarBox, RevocationKind,
};
use ainra_services::status::{SignedStatusList, WireDelta, WireFreshHead};
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

/// The time a READ endpoint signs at: a status list, a fresh head, a presentation bundle, an export. On a registrar
/// keeping real time it is the registrar's clock, whatever the caller asks for. A caller-chosen `now` let anyone
/// collect status lists signed for a future instant while a passport was still clear, and present them as fresh after
/// it was revoked (2026-11-07 review). Only a pinned clock (`AINRA_CLOCK=pinned`, hermetic drills and the TEST-ROOT
/// staging network) names the time, as it always has.
fn qnow(path: &str) -> u64 {
    if clock_pinned() {
        caller_now(path)
    } else {
        wall_now()
    }
}

/// A caller-chosen time, for an endpoint that signs nothing (`/verify`): any instant may be asked about.
fn caller_now(path: &str) -> u64 {
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
    /// M17: a SEPARATE bucket over the public demo door (`/demo/issue`, `/demo/revoke`, `/demo/link`,
    /// `/demo/link/revoke`), so a visitor completing the lifecycle in the browser cannot exhaust the operator's own
    /// write budget, and vice versa.
    demo_writes: VecDeque<Instant>,
    /// D-081: logged decision heads are an open write (each statement is self-authenticating), so they get a bucket
    /// of their own — a busy gate cannot starve issuance, and the demo door cannot starve a gate.
    head_writes: VecDeque<Instant>,
    /// D-102: the transfer doors' own bucket.
    transfer_writes: VecDeque<Instant>,
    /// D-102: the roots a caller-supplied directory must verify under (`AINRA_ROOTS_FILE`), and the newest directory
    /// epoch seen, kept in `directory.epoch` so an older directory (before a distrust cutoff) is refused after a
    /// restart too.
    roots: Option<([u8; 32], Vec<u8>)>,
    dir_epoch: u64,
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
        principal_evidence: None,
    }
}
/// `true` iff `sub` is a specimen THIS registrar minted through the public door (stamped `demo:specimen`) — the
/// public revoke door touches nothing else, whatever operator/lineage the visitor named it.
fn is_demo_specimen(rb: &RegistrarBox, sub: &str) -> bool {
    rb.get(sub).is_some_and(|r| {
        r.capabilities.iter().any(|c| c == "demo:specimen")
            && demo_lineage_clean(rb, &r.operator, &r.lineage)
    })
}

/// Has the door minted EVERY passport of `operator:lineage` here (or none exists)? The door used to check only the
/// passport it was asked about, so a visitor could mint a specimen under a real customer's name and then revoke or
/// renew it — and, revocation being lineage-wide, revoke the real passport with it (2026-11-07 review).
fn demo_lineage_clean(rb: &RegistrarBox, operator: &str, lineage: &str) -> bool {
    rb.records()
        .chain(rb.superseded_records())
        .filter(|r| r.operator == operator && r.lineage == lineage)
        .all(|r| r.capabilities.iter().any(|c| c == "demo:specimen"))
}

/// Status indices the public door may never take: they stay for the registrar's own issuance. The segment is fixed,
/// and every specimen takes one for good, so an unbounded door could exhaust it (2026-11-07 review).
const DEMO_RESERVE: usize = 1024;

fn demo_room(rb: &RegistrarBox) -> Option<(u16, String)> {
    (rb.status_room() <= DEMO_RESERVE).then(|| {
        (
            503,
            r#"{"error":"the demo door is full; the remaining status indices are reserved for issuance"}"#
                .to_string(),
        )
    })
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
        // A live registrar's keys come from the OS CSPRNG, 32 bytes, kept in `registrar.secret`. The id-derived seed
        // above is public — anyone could recompute every key from it (2026-11-07 review) — so only a pinned, hermetic
        // drill may use it, where reproducible keys are the point.
        let test_derived_new = std::env::var("AINRA_TEST_DERIVED_KEYS").ok().as_deref()
            == Some("1")
            && std::env::var("AINRA_NETWORK").ok().as_deref() != Some("production");
        // `AINRA_FRESH_KEYS=1` asks for CSPRNG keys even on a pinned clock (PLAN-M53 step R3, D-107). A pinned
        // clock used to mean "a hermetic drill", and a drill wants reproducible keys; the standing staging network
        // is pinned too (its record is a reference world dated 2026-04-21), and its registrars are not a drill:
        // their record is published, so their keys must not be something anyone can recompute. Off by default, so
        // every hermetic drill keeps the keys it has always had.
        let fresh_keys = std::env::var("AINRA_FRESH_KEYS").ok().as_deref() == Some("1");
        if (clock_pinned() || test_derived_new) && !fresh_keys {
            RegistrarBox::create_seeded(data_dir, &id, 4096, seed, NBF - 3600, NBF, EXP)
                .expect("create registrar-box")
        } else {
            let mut key_seed = [0u8; 32];
            if let Err(e) = std::fs::File::open("/dev/urandom").and_then(|mut f| {
                use std::io::Read;
                f.read_exact(&mut key_seed)
            }) {
                eprintln!("registrar-box '{id}': no OS entropy for the registrar keys ({e}) — refusing to start");
                std::process::exit(2);
            }
            RegistrarBox::create_seeded32(data_dir, &id, 4096, key_seed, NBF - 3600, NBF, EXP)
                .expect("create registrar-box")
        }
    };
    // A registrar keeping real time refuses to run on keys anyone can recompute from its public id. Such a snapshot is
    // from before the 2026-11-07 fix, or from a drill; it must be re-keyed (a new data directory, re-accredited).
    // `AINRA_TEST_DERIVED_KEYS=1` is the one exception: the TEST-ROOT wall-clock drill (`make live-up`) runs
    // registrar-07 on purpose with the key the published TEST directory accredits. Never on a production network.
    let test_derived = std::env::var("AINRA_TEST_DERIVED_KEYS").ok().as_deref() == Some("1")
        && std::env::var("AINRA_NETWORK").ok().as_deref() != Some("production");
    if test_derived && !clock_pinned() && rb.seed_u64() == Some(seed) {
        eprintln!(
            "registrar-box '{id}': TEST ONLY — keys derive from the public id (AINRA_TEST_DERIVED_KEYS=1); anyone can recompute them"
        );
    }
    if !test_derived && !clock_pinned() && rb.seed_u64() == Some(seed) {
        eprintln!(
            "registrar-box '{id}': this registrar's keys derive from its public id, so anyone can recompute them — \
             refusing to run it on a real clock. Start it with a new data directory (fresh keys) and re-accredit it."
        );
        std::process::exit(2);
    }
    // M35: certify the delegates at the WALL CLOCK before serving anything. A registrar reloaded from a snapshot —
    // or created at the fixed genesis instant below — would otherwise sign with certs that lapsed long ago.
    let mut rb = rb;
    // PLAN-M51 step 3: an A1 request is issued only on evidence this checker accepts; without one, A1 is refused.
    let principal = PrincipalPolicy::from_env();
    eprintln!(
        "registrar-box '{id}': A1 issuance {}",
        if matches!(principal, PrincipalPolicy::Checked(_)) {
            "checked by AINRA_PRINCIPAL_CHECKER"
        } else {
            "refused (no principal checker configured)"
        }
    );
    rb.set_principal_policy(principal);
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
    // `make probe-drill`'s dishonest registrar (PLAN-M50 step 4). Asked for by name, honoured only by a build with the
    // `drill-sabotage` feature and only on staging; any other combination refuses to start rather than run honestly
    // while the drill believes it is running a cheat (or the reverse).
    if let Ok(mode) = std::env::var("AINRA_DRILL_SABOTAGE") {
        if mode != "revoke-one-generation" || !staging || !cfg!(feature = "drill-sabotage") {
            eprintln!(
                "registrar-box: AINRA_DRILL_SABOTAGE={mode} needs AINRA_STAGE=1 and a build with the drill-sabotage \
                 feature (mode: revoke-one-generation) — refusing to start"
            );
            std::process::exit(2);
        }
        #[cfg(feature = "drill-sabotage")]
        ainra_services::registrar::sabotage::set_revoke_one_generation();
        eprintln!("registrar-box '{id}': DRILL SABOTAGE — revocation flips only the generation named (D-055 broken)");
    }
    let state = Mutex::new(State {
        rb,
        rng,
        issue_token: issue_token.clone(),
        writes: VecDeque::new(),
        demo_writes: VecDeque::new(),
        head_writes: VecDeque::new(),
        transfer_writes: VecDeque::new(),
        roots: roots_from_env(&id),
        dir_epoch: std::fs::read_to_string(data_dir.join("directory.epoch"))
            .ok()
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(0),
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

            // D-102 portability: the public record of moves, logged operator keys, and the transfer doors.
            (_, r)
                if r == "/transfers"
                    || r == "/operator-key"
                    || r.starts_with("/transfer-")
                    || r.starts_with("/ownership-") =>
            {
                transfer_door(&mut st, req, r, &dir, &id, open_writes)
            }

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
                if let Some(full) = demo_room(rb) {
                    return full;
                }
                if !demo_lineage_clean(rb, &spec.operator, &spec.lineage) {
                    return (
                        403,
                        r#"{"error":"that name belongs to a passport the demo door did not mint"}"#
                            .to_string(),
                    );
                }
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

            // PLAN-M50 step 4 — renewal through the public demo door, so the compliance probe (which holds no
            // credential) can follow a lineage across generations and check that revoking it reaches all of them
            // (D-055). Staging only, the demo bucket, demo specimens only; a version is required so that every
            // generation stays presentable under its own name.
            ("POST", "/demo/renew") => {
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
                let (Some(sub), Some(version)) = (
                    v.get("sub").and_then(|x| x.as_str()).map(String::from),
                    v.get("new_version")
                        .and_then(|x| x.as_str())
                        .map(String::from),
                ) else {
                    return (
                        400,
                        r#"{"error":"sub and new_version required"}"#.to_string(),
                    );
                };
                if !is_demo_specimen(&st.rb, &sub) {
                    return (
                        403,
                        r#"{"error":"the public door only renews demo specimens it minted"}"#
                            .to_string(),
                    );
                }
                if let Some(full) = demo_room(&st.rb) {
                    return full;
                }
                let now = v
                    .get("now")
                    .and_then(|x| x.as_u64())
                    .unwrap_or_else(default_renew_now);
                let State { rb, rng, .. } = &mut *st;
                match rb.reissue(&sub, Some(&version), now, None, rng) {
                    Ok(rec) => {
                        persist(rb, &id);
                        ok(&rec)
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
                    Ok(rec) => {
                        // Persisted like every other write: an unsaved renewal vanished on the next restart.
                        persist(rb, &id);
                        ok(&rec)
                    }
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
                let now = caller_now(&req.path);
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
                        Ok(delta) => {
                            // A revocation that is not on disk is undone by the next restart: the snapshot still
                            // loads (its delta log and status_seq agree with each other), so the passport silently
                            // comes back valid. This route answered 200 without saving until 2026-10-26.
                            persist(&st.rb, &id);
                            (
                                200,
                                serde_json::to_string(&WireDelta::from_core(&delta)).unwrap(),
                            )
                        }
                        Err(e) => (400, json!({ "error": e.to_string() }).to_string()),
                    },
                    None => (400, r#"{"error":"sub required"}"#.to_string()),
                }
            }

            // PLAN-M47 § Later — the public demo door, for links: what `/demo/issue` is for passports. No bearer
            // token; staging only; the demo bucket; and it only touches demo specimens — it links a key to a
            // specimen the door minted, and revokes only links to one. The proof of control is checked exactly as on
            // `/link`, so a visitor still cannot link a key they do not hold.
            ("POST", "/demo/link") => {
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
                let spec = match serde_json::from_str::<LinkSpec>(&req.body) {
                    Ok(spec) => spec,
                    Err(e) => {
                        return (
                            400,
                            json!({ "error": format!("bad link spec: {e}") }).to_string(),
                        )
                    }
                };
                if let Some(full) = demo_room(&st.rb) {
                    return full;
                }
                if !is_demo_specimen(&st.rb, &spec.passport) {
                    return (
                        403,
                        r#"{"error":"the public door only links keys to demo specimens"}"#
                            .to_string(),
                    );
                }
                match st.rb.link(&spec) {
                    Ok(rec) => {
                        persist(&st.rb, &id);
                        ok(&rec)
                    }
                    Err(e) => (400, json!({ "error": e.to_string() }).to_string()),
                }
            }
            ("POST", "/demo/link/revoke") => {
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
                let Some(tp) = v
                    .get("thumbprint")
                    .and_then(|x| x.as_str())
                    .map(String::from)
                else {
                    return (400, r#"{"error":"thumbprint required"}"#.to_string());
                };
                let Ok(kind) = serde_json::from_value::<RevocationKind>(
                    v.get("kind").cloned().unwrap_or(serde_json::Value::Null),
                ) else {
                    return (
                        400,
                        r#"{"error":"kind must be link, operator or compromise"}"#.to_string(),
                    );
                };
                let passport = st.rb.get_link(&tp).map(|l| l.passport.clone());
                if !passport.is_some_and(|p| is_demo_specimen(&st.rb, &p)) {
                    return (
                        403,
                        r#"{"error":"the public door only revokes links to demo specimens"}"#
                            .to_string(),
                    );
                }
                let suspect_since = v.get("suspect_since").and_then(|x| x.as_u64());
                let now = v
                    .get("now")
                    .and_then(|x| x.as_u64())
                    .unwrap_or_else(default_now);
                match st.rb.revoke_link(&tp, kind, suspect_since, now) {
                    Ok(rev) => {
                        persist(&st.rb, &id);
                        ok(&rev)
                    }
                    Err(e) => (400, json!({ "error": e.to_string() }).to_string()),
                }
            }

            // D-081: log a gate's decision head. Body {statement, gate_key}: the statement line exactly as the gate
            // signed it, and the gate's base64url Ed25519 key. Open (the statement authenticates itself) and rate
            // limited on its own bucket; answers a receipt — the statement, its leaf, and an inclusion proof under a
            // signed checkpoint — that anyone can later hold a decision log against.
            ("POST", "/decision-head") => {
                if !rate_ok(&mut st.head_writes) {
                    return (429, r#"{"error":"rate limited"}"#.to_string());
                }
                let v: serde_json::Value =
                    serde_json::from_str(&req.body).unwrap_or(serde_json::Value::Null);
                let (Some(statement), Some(gate_key)) = (
                    v.get("statement").and_then(|x| x.as_str()),
                    v.get("gate_key").and_then(|x| x.as_str()),
                ) else {
                    return (
                        400,
                        r#"{"error":"statement and gate_key required"}"#.to_string(),
                    );
                };
                match st.rb.log_head(statement, gate_key) {
                    Ok(receipt) => {
                        persist(&st.rb, &id);
                        (200, receipt.to_string())
                    }
                    Err(e) => (400, json!({ "error": e.to_string() }).to_string()),
                }
            }

            // Every logged head, each proven under one checkpoint. Read-only, open, fetched whole.
            ("GET", "/decision-heads") => match st.rb.decision_heads_index() {
                Some(idx) => (200, idx.to_string()),
                None => (
                    500,
                    r#"{"error":"inclusion proof unavailable"}"#.to_string(),
                ),
            },

            // D-078 AINRA Link: link a key the agent already has to one of this registrar's passports. Body: a
            // LinkSpec {passport, key, pop, scope?, nbf, exp}; `pop` is the key's own signature over the frozen
            // consent bytes, so nobody can link a key they do not hold. Write endpoint (auth + rate limited).
            ("POST", "/link") => {
                if !write_authorized(req, &st.issue_token, open_writes) {
                    return (
                        401,
                        r#"{"error":"unauthorized (bearer token required)"}"#.to_string(),
                    );
                }
                if !rate_ok(&mut st.writes) {
                    return (429, r#"{"error":"rate limited"}"#.to_string());
                }
                match serde_json::from_str::<LinkSpec>(&req.body) {
                    Ok(spec) => match st.rb.link(&spec) {
                        Ok(rec) => {
                            persist(&st.rb, &id);
                            ok(&rec)
                        }
                        Err(e) => (400, json!({ "error": e.to_string() }).to_string()),
                    },
                    Err(e) => (
                        400,
                        json!({ "error": format!("bad link spec: {e}") }).to_string(),
                    ),
                }
            }

            // The whole link index (D-079: whole-list download, no lookup by key). Read-only, open, cacheable.
            // PLAN-M51 witness work — what an independent witness polls: the current signed checkpoint and, given the
            // size it last cosigned (`?from=N`), the consistency proof to here. Public read, like /present.
            ("GET", "/witness-feed") => {
                let from = qparam(&req.path, "from").and_then(|s| s.parse::<u64>().ok());
                match st.rb.witness_feed(from) {
                    Ok(feed) => (200, feed.to_string()),
                    Err(e) => (400, json!({ "error": e }).to_string()),
                }
            }

            ("GET", "/links") => match st.rb.link_index(qnow(&req.path)) {
                Some(idx) => (200, idx.to_string()),
                None => (
                    500,
                    r#"{"error":"inclusion proof unavailable"}"#.to_string(),
                ),
            },

            // Revoke a link. Body: {thumbprint, kind: link|operator|compromise, suspect_since? (compromise only),
            // now?}. Write endpoint (auth + rate limited); every revocation is appended to the log.
            ("POST", "/link/revoke") => {
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
                let Some(tp) = v
                    .get("thumbprint")
                    .and_then(|x| x.as_str())
                    .map(String::from)
                else {
                    return (400, r#"{"error":"thumbprint required"}"#.to_string());
                };
                let Ok(kind) = serde_json::from_value::<RevocationKind>(
                    v.get("kind").cloned().unwrap_or(serde_json::Value::Null),
                ) else {
                    return (
                        400,
                        r#"{"error":"kind must be link, operator or compromise"}"#.to_string(),
                    );
                };
                let suspect_since = v.get("suspect_since").and_then(|x| x.as_u64());
                let now = v
                    .get("now")
                    .and_then(|x| x.as_u64())
                    .unwrap_or_else(default_now);
                match st.rb.revoke_link(&tp, kind, suspect_since, now) {
                    Ok(rev) => {
                        persist(&st.rb, &id);
                        ok(&rev)
                    }
                    Err(e) => (400, json!({ "error": e.to_string() }).to_string()),
                }
            }

            // The same bits in the IETF Token Status List form (statuslist+jwt), for standard libraries. AINRA's own
            // hybrid-signed /status-list stays authoritative.
            ("GET", "/status-list.jwt") => match st.rb.publish_status_jwt(qnow(&req.path)) {
                Some(jwt) => (200, jwt),
                None => (500, r#"{"error":"status token unavailable"}"#.to_string()),
            },

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

/// D-102: the roots every caller-supplied directory must verify under, from `AINRA_ROOTS_FILE`
/// (`{"root_ed25519": b64, "root_slh": b64}`, the file `ainra ctl` reads). None ⇒ the transfer doors refuse.
fn roots_from_env(id: &str) -> Option<([u8; 32], Vec<u8>)> {
    let path = std::env::var("AINRA_ROOTS_FILE").ok()?;
    let parsed = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| {
            let ed = b64::decode_array::<32>(v["root_ed25519"].as_str()?).ok()?;
            let slh = b64::decode(v["root_slh"].as_str()?).ok()?;
            Some((ed, slh))
        });
    match &parsed {
        Some(_) => eprintln!("registrar-box '{id}': transfer doors read directories under the roots in {path}"),
        None => eprintln!("registrar-box '{id}': AINRA_ROOTS_FILE={path} does not name root_ed25519 and root_slh — transfer doors closed"),
    }
    parsed
}

fn err(code: u16, msg: impl std::fmt::Display) -> (u16, String) {
    (code, json!({ "error": msg.to_string() }).to_string())
}

/// What a transfer door knows about the other registrar: the directory the caller sent, authenticated under the
/// pinned roots and no older than the newest one seen — its anchors, its revoked delegate certificates, and that
/// registrar's status key from its entry.
/// The anchors, revoked delegate fingerprints and the peer's status key, all from one authenticated directory.
type PeerTrust = (
    ainra_core::verify::TrustAnchors,
    std::collections::BTreeSet<[u8; 32]>,
    ainra_core::crypto::HybridPublic,
);

fn peer_from(
    st: &mut State,
    data_dir: &str,
    body: &serde_json::Value,
    peer: &str,
) -> Result<PeerTrust, (u16, String)> {
    let Some((ed, slh)) = st.roots.clone() else {
        return Err(err(
            503,
            "this registrar has no pinned roots (AINRA_ROOTS_FILE); the transfer doors are closed",
        ));
    };
    let d: ainra_core::directory::Directory = serde_json::from_value(body["directory"].clone())
        .map_err(|e| err(400, format!("directory: {e}")))?;
    let set = d.accredit(&ed, &slh).map_err(|_| {
        err(
            400,
            "the directory does not verify under this registrar's pinned roots",
        )
    })?;
    if set.epoch < st.dir_epoch {
        return Err(err(
            409,
            format!(
                "directory epoch {} is older than {} already seen",
                set.epoch, st.dir_epoch
            ),
        ));
    }
    if set.epoch > st.dir_epoch {
        st.dir_epoch = set.epoch;
        let _ = std::fs::write(
            std::path::Path::new(data_dir).join("directory.epoch"),
            set.epoch.to_string(),
        );
    }
    let entry = d
        .entries
        .iter()
        .find(|e| e.registrar == peer)
        .ok_or_else(|| err(400, format!("{peer} is not in the directory")))?;
    let status_key = ainra_core::crypto::HybridPublic {
        ed25519: b64::decode_array::<32>(&entry.status_ed25519)
            .map_err(|_| err(400, "status key"))?,
        mldsa65: b64::decode(&entry.status_mldsa65).map_err(|_| err(400, "status key"))?,
    };
    Ok((set.anchors, set.revoked_delegates, status_key))
}

fn field<T: serde::de::DeserializeOwned>(
    body: &serde_json::Value,
    k: &str,
) -> Result<T, (u16, String)> {
    serde_json::from_value(body[k].clone()).map_err(|e| err(400, format!("{k}: {e}")))
}

/// The other registrar's signed status list, if the caller sent one. A distrusted or defunct registrar may publish
/// none: its list counts for nothing then (D-102), so its absence must not block the door; for any other registrar an
/// absent list fails authentication in the engine, as a forged one would.
fn status_field(body: &serde_json::Value) -> SignedStatusList {
    field(body, "status").unwrap_or_else(|_| SignedStatusList {
        uri: String::new(),
        status_list_b64: String::new(),
        bit_len: 0,
        issued_at: 0,
        sig_ed25519: String::new(),
        sig_mldsa65: String::new(),
    })
}

/// The subject a record's SIGNED claims name. `IssuedRecord.sub` is an unsigned copy a presenter can edit.
fn signed_sub(rec: &IssuedRecord) -> String {
    serde_json::from_str::<serde_json::Value>(&rec.claims)
        .ok()
        .and_then(|c| c["sub"].as_str().map(String::from))
        .unwrap_or_default()
}

fn registrar_of(sub: &str) -> Result<String, (u16, String)> {
    ainra_core::AinraName::parse(sub)
        .map(|n| n.registrar().to_string())
        .map_err(|_| err(400, "not an ainra name"))
}

/// D-102: every transfer route. Reads are open; `/operator-key` (POST) and `/transfer-complete` are the registrar's
/// own acts and need write authorization; the other doors are public, rate-limited, and decided by signatures.
fn transfer_door(
    st: &mut State,
    req: &Request,
    route: &str,
    data_dir: &str,
    id: &str,
    open_writes: bool,
) -> (u16, String) {
    let method = req.method.as_str();
    if method == "GET" {
        return match route {
            "/ownership-changes" => (
                200,
                json!({ "registrar": st.rb.id(), "ownership_changes": st.rb.ownerships() })
                    .to_string(),
            ),
            "/transfers" => (
                200,
                json!({ "registrar": st.rb.id(), "transfers": st.rb.transfers() }).to_string(),
            ),
            "/operator-key" => {
                let (Some(op), Some(lin)) =
                    (qparam(&req.path, "operator"), qparam(&req.path, "lineage"))
                else {
                    return err(400, "operator and lineage required");
                };
                match st
                    .rb
                    .operator_key_receipt(&urldecode(&op), &urldecode(&lin))
                {
                    Some(r) => ok(&r),
                    None => err(404, "no operator key logged for that lineage"),
                }
            }
            _ => err(404, "not found"),
        };
    }
    if method != "POST" {
        return err(405, "method not allowed");
    }
    let privileged =
        route == "/operator-key" || route == "/transfer-complete" || route == "/ownership-complete";
    if privileged && !write_authorized(req, &st.issue_token, open_writes) {
        return err(401, "unauthorized (bearer token required)");
    }
    if !rate_ok(if privileged {
        &mut st.writes
    } else {
        &mut st.transfer_writes
    }) {
        return err(429, "rate limited");
    }
    let body: serde_json::Value =
        serde_json::from_str(&req.body).unwrap_or(serde_json::Value::Null);
    // The registrar's OWN clock decides every time in a move: the window, the lock, the request's age, the freshness of
    // a status list. A caller-chosen `now` would let anyone backdate a stale (pre-revocation) status list into
    // freshness, or close a five-day window at once. Only a hermetic drill (`AINRA_CLOCK=pinned`) may name the time.
    let now = if clock_pinned() {
        body["now"].as_u64().unwrap_or_else(default_now)
    } else {
        wall_now()
    };
    let result: Result<(u16, String), (u16, String)> = (|| {
        Ok(match route {
            "/operator-key" => {
                let (op, lin): (String, String) =
                    (field(&body, "operator")?, field(&body, "lineage")?);
                let (key, pop): (HybridB64, HybridB64) =
                    (field(&body, "key")?, field(&body, "pop")?);
                let r = st
                    .rb
                    .register_operator_key(&op, &lin, &key, &pop)
                    .map_err(|e| err(400, e))?;
                ok(&r)
            }
            "/transfer-in" => {
                let request: TransferRequest = field(&body, "request")?;
                let passport: IssuedRecord = field(&body, "passport")?;
                let receipt: OperatorKeyReceipt = field(&body, "operator_key")?;
                let status: SignedStatusList = status_field(&body);
                let (anchors, revoked, status_key) =
                    peer_from(st, data_dir, &body, &registrar_of(&request.from_sub)?)?;
                let side = PeerRegistrar {
                    anchors: &anchors,
                    revoked_delegates: &revoked,
                    status_key: &status_key,
                    status: &status,
                };
                let t = st
                    .rb
                    .transfer_in(request, &passport, &receipt, &side, now)
                    .map_err(|e| err(400, e))?;
                ok(&t)
            }
            "/transfer-consent" => {
                let (tid, sig): (String, HybridB64) =
                    (field(&body, "id")?, field(&body, "operator_sig")?);
                st.rb
                    .transfer_consent(&tid, &sig, now)
                    .map_err(|e| err(400, e))?;
                (
                    200,
                    json!({ "id": tid, "operator_signed": true }).to_string(),
                )
            }
            "/transfer-contest" => {
                let (tid, by, reason): (String, String, String) = (
                    field(&body, "id")?,
                    field(&body, "by")?,
                    field(&body, "reason")?,
                );
                let sig: HybridB64 = field(&body, "sig")?;
                let peer = st
                    .rb
                    .transfers()
                    .iter()
                    .find(|t| t.id == tid)
                    .map(|t| t.from_registrar.clone())
                    .ok_or_else(|| err(404, "no such move"))?;
                let (anchors, _, _) = peer_from(st, data_dir, &body, &peer)?;
                let t = st
                    .rb
                    .transfer_contest(&tid, &by, &reason, &sig, &anchors, now)
                    .map_err(|e| err(400, e))?;
                ok(&t)
            }
            "/transfer-complete" => {
                let tid: String = field(&body, "id")?;
                let passport: IssuedRecord = field(&body, "passport")?;
                let status: SignedStatusList = status_field(&body);
                let audit: Option<AuditEvidence> = field(&body, "audit").unwrap_or(None);
                let evidence = body.get("principal_evidence").cloned();
                let (anchors, revoked, status_key) = peer_from(
                    st,
                    data_dir,
                    &body,
                    &st.rb
                        .transfers()
                        .iter()
                        .find(|t| t.id == tid)
                        .map(|t| t.from_registrar.clone())
                        .ok_or_else(|| err(404, "no such move"))?,
                )?;
                let side = PeerRegistrar {
                    anchors: &anchors,
                    revoked_delegates: &revoked,
                    status_key: &status_key,
                    status: &status,
                };
                let State { rb, rng, .. } = st;
                let rec = rb
                    .transfer_complete(&tid, &passport, &side, audit.as_ref(), evidence, now, rng)
                    .map_err(|e| err(400, e))?;
                ok(&rec)
            }
            "/ownership-open" => {
                let request: OwnershipRequest = field(&body, "request")?;
                let o = st
                    .rb
                    .ownership_open(request, now)
                    .map_err(|e| err(400, e))?;
                ok(&o)
            }
            "/ownership-contest" => {
                let (oid, reason): (String, String) =
                    (field(&body, "id")?, field(&body, "reason")?);
                let sig: HybridB64 = field(&body, "sig")?;
                let o = st
                    .rb
                    .ownership_contest(&oid, &reason, &sig, now)
                    .map_err(|e| err(400, e))?;
                ok(&o)
            }
            "/ownership-complete" => {
                let oid: String = field(&body, "id")?;
                let assurance: NewOwnerAssurance = field(&body, "assurance")?;
                let State { rb, rng, .. } = st;
                let rec = rb
                    .ownership_complete(&oid, &assurance, now, rng)
                    .map_err(|e| err(400, e))?;
                ok(&rec)
            }
            "/transfer-out" => {
                let passport: IssuedRecord = field(&body, "passport")?;
                let request: TransferRequest = field(&body, "request")?;
                let status: SignedStatusList = status_field(&body);
                let (anchors, revoked, status_key) =
                    peer_from(st, data_dir, &body, &registrar_of(&signed_sub(&passport))?)?;
                let side = PeerRegistrar {
                    anchors: &anchors,
                    revoked_delegates: &revoked,
                    status_key: &status_key,
                    status: &status,
                };
                let delta = st
                    .rb
                    .transfer_out(&passport, &request, &side, now)
                    .map_err(|e| err(400, e))?;
                ok(&WireDelta::from_core(&delta))
            }
            _ => err(404, "not found"),
        })
    })();
    let out = result.unwrap_or_else(|e| e);
    // D-080: a write that changed state is on disk before it is answered — refusals included, since a refused
    // completion records why.
    persist(&st.rb, id);
    out
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
