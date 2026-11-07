// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The transfer doors over HTTP (D-102), against two real `registrar-box` daemons and a TEST-ROOT directory signed
//! by both roots. The engine's rules are witnessed in `transfer_door.rs`; this proves the daemon reaches them only
//! through a directory it authenticated itself, and that a move survives a restart.
//!
//! WITNESS: a lineage moves from registrar-07 to registrar-08 over HTTP and the old passport ends revoked; a
//! directory signed by other roots is refused, an older epoch than one already seen is refused (also after a
//! restart), and a daemon with no pinned roots keeps the doors closed.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ainra_core::directory::{Directory, DirectoryEntry};
use ainra_core::{b64, crypto};
use ainra_services::http::{http_get, http_post};
use ainra_services::registrar::holder_pop_message;
use ainra_services::registrar::transfer::{
    operator_key_message, request_message, sign_b64, wire_of, CONTEST_WINDOW_SECS,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{json, Value};

const NBF: u64 = 1_775_865_600;
const T0: u64 = NBF + 2 * 86_400;

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ainra-transfer-http-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn start(addr: &str, id: &str, data: &Path, roots: Option<&Path>) -> Daemon {
    start_clock(addr, id, data, roots, true)
}

fn start_clock(addr: &str, id: &str, data: &Path, roots: Option<&Path>, pinned: bool) -> Daemon {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_registrar-box"));
    if pinned {
        cmd.env("AINRA_CLOCK", "pinned");
    } else {
        cmd.env_remove("AINRA_CLOCK");
    }
    cmd.args([addr, id, data.to_str().unwrap()])
        .env("AINRA_OPEN_WRITES", "1")
        .env_remove("AINRA_STAGE_ISSUE_TOKEN")
        .env_remove("AINRA_STAGE")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match roots {
        Some(r) => cmd.env("AINRA_ROOTS_FILE", r),
        None => cmd.env_remove("AINRA_ROOTS_FILE"),
    };
    let d = Daemon(cmd.spawn().expect("spawn registrar-box"));
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if http_get(addr, "/health").is_ok_and(|b| b.contains("\"ok\":true")) {
            return d;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("registrar-box did not come up on {addr}");
}

fn get(addr: &str, path: &str) -> Value {
    serde_json::from_str(&http_get(addr, path).unwrap()).unwrap()
}
fn post(addr: &str, path: &str, body: &Value) -> Value {
    serde_json::from_str(&http_post(addr, path, &body.to_string()).unwrap()).unwrap()
}
fn error_of(v: &Value) -> String {
    v["error"].as_str().unwrap_or("").to_string()
}

/// TEST roots: an Ed25519 key standing in for the FROST group key (it emits the same standard signatures) and the
/// SLH-DSA ceremony root.
struct Roots {
    ed: crypto::TestDelegate,
    slh: crypto::TestRootSlh,
}

impl Roots {
    fn new(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        Self {
            ed: crypto::TestDelegate::generate(&mut rng),
            slh: crypto::TestRootSlh::generate(&mut rng),
        }
    }
    fn file(&self, at: &Path) -> PathBuf {
        let p = at.join("roots.json");
        let v = json!({ "root_ed25519": b64::encode(&self.ed.public()), "root_slh": b64::encode(&self.slh.public()) });
        std::fs::write(&p, v.to_string()).unwrap();
        p
    }
    fn directory(&self, epoch: u64, accreditations: &[Value]) -> Value {
        let mut entries: Vec<DirectoryEntry> = accreditations
            .iter()
            .map(|a| DirectoryEntry {
                registrar: a["registrar"].as_str().unwrap().into(),
                issuer_ed25519: a["issuer_key"]["ed25519"].as_str().unwrap().into(),
                issuer_mldsa65: a["issuer_key"]["mldsa65"].as_str().unwrap().into(),
                log_root_slh: a["log_root_key"].as_str().unwrap().into(),
                status_ed25519: a["status_key"]["ed25519"].as_str().unwrap().into(),
                status_mldsa65: a["status_key"]["mldsa65"].as_str().unwrap().into(),
                distrust_from_leaf: None,
                status_uri: a["status_uri"].as_str().unwrap().into(),
            })
            .collect();
        entries.sort_by(|a, b| a.registrar.cmp(&b.registrar));
        let mut d = Directory {
            epoch,
            issued_at: T0 - 3600,
            entries,
            revoked_delegates: vec![],
            sig_root_ed25519: String::new(),
            sig_root_slh: String::new(),
        };
        let msg = d.signing_bytes().unwrap();
        d.sig_root_ed25519 = b64::encode(&self.ed.sign(&msg));
        d.sig_root_slh = b64::encode(&self.slh.sign(&msg).unwrap());
        serde_json::to_value(d).unwrap()
    }
}

#[test]
fn a_lineage_moves_over_http_through_an_authenticated_directory() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xD1_02_77);
    let (da, db) = (dir("a"), dir("b"));
    let roots = Roots::new(0x2007);
    let roots_file = roots.file(&da);
    let (a, b) = (
        format!("127.0.0.1:{}", free_port()),
        format!("127.0.0.1:{}", free_port()),
    );
    let _ga = start(&a, "registrar-07", &da, Some(&roots_file));
    let gb = start(&b, "registrar-08", &db, Some(&roots_file));

    // A passport at registrar-07 bound to the agent's own key, and the operator's key logged beside it.
    let agent = crypto::HybridKeypair::generate(&mut rng);
    let operator = crypto::HybridKeypair::generate(&mut rng);
    let akey = wire_of(&agent.public());
    let apop = sign_b64(&agent, &holder_pop_message("registrar-07", &akey).unwrap()).unwrap();
    let rec = post(
        &a,
        "/issue",
        &json!({
            "operator": "acme", "lineage": "billing", "version": "1.0.0", "tier": "L2", "auth_class": "A2",
            "principal_proof": "deadbeef", "capabilities": ["read:invoices"], "scope_ceiling": ["read:invoices"],
            "holder_key": akey, "holder_pop": apop,
        }),
    );
    let old_sub = rec["sub"].as_str().expect("issued").to_string();
    let okey = wire_of(&operator.public());
    let opop = sign_b64(
        &operator,
        &operator_key_message("registrar-07", "acme", "billing", &okey).unwrap(),
    )
    .unwrap();
    let receipt = post(
        &a,
        "/operator-key",
        &json!({ "operator": "acme", "lineage": "billing", "key": okey, "pop": opop }),
    );
    assert_eq!(receipt["registrar"], "registrar-07", "{receipt}");
    assert_eq!(
        get(&a, "/operator-key?operator=acme&lineage=billing")["leaf_index"],
        receipt["leaf_index"]
    );

    let accs = [get(&a, "/accreditation"), get(&b, "/accreditation")];
    let dir2 = roots.directory(2, &accs);
    let passport = get(&a, &format!("/record?sub={old_sub}"));

    // The move, asked by the agent, signed by the operator.
    let (nkey, npop) = (
        akey.clone(),
        sign_b64(&agent, &holder_pop_message("registrar-08", &akey).unwrap()).unwrap(),
    );
    let msg = request_message(&old_sub, "registrar-08", T0, &nkey).unwrap();
    let request = json!({
        "from_sub": old_sub, "to_registrar": "registrar-08", "requested_at": T0,
        "new_holder_key": nkey, "new_holder_pop": npop,
        "holder_sig": sign_b64(&agent, &msg).unwrap(), "operator_sig": sign_b64(&operator, &msg).unwrap(),
    });
    let body_in = |directory: &Value| {
        json!({ "request": request, "passport": passport, "operator_key": receipt, "directory": directory,
                "status": get(&a, &format!("/status-list?now={T0}")), "now": T0 })
    };
    // A directory signed by other roots is refused.
    let forged = Roots::new(0xBAD).directory(3, &accs);
    assert!(
        error_of(&post(&b, "/transfer-in", &body_in(&forged))).contains("does not verify under")
    );
    let opened = post(&b, "/transfer-in", &body_in(&dir2));
    let id = opened["id"]
        .as_str()
        .unwrap_or_else(|| panic!("opened: {opened}"))
        .to_string();
    assert_eq!(opened["state"], "open");
    // An older directory than one already seen is refused (the cutoff cannot be rolled back).
    let dir1 = roots.directory(1, &accs);
    assert!(error_of(&post(&b, "/transfer-in", &body_in(&dir1))).contains("older than"));

    // Not before the window closes; then it completes.
    let done_at = T0 + CONTEST_WINDOW_SECS;
    let body_done = |now: u64| {
        json!({ "id": id, "passport": passport, "directory": dir2,
                "status": get(&a, &format!("/status-list?now={now}")), "now": now })
    };
    assert!(
        error_of(&post(&b, "/transfer-complete", &body_done(done_at - 1)))
            .contains("open to contest")
    );
    let new = post(&b, "/transfer-complete", &body_done(done_at));
    assert_eq!(new["sub"], "ainra:registrar-08:acme:billing@1.0.0", "{new}");
    let claims: Value = serde_json::from_str(new["claims"].as_str().unwrap()).unwrap();
    assert_eq!(claims["transfer_history"][0]["from"], old_sub.as_str());

    // registrar-07 is shown the new passport and revokes the old one.
    let out = post(
        &a,
        "/transfer-out",
        &json!({ "passport": new, "request": request, "directory": dir2,
        "status": get(&b, &format!("/status-list?now={}", done_at + 60)), "now": done_at + 60 }),
    );
    assert!(out.get("error").is_none(), "{out}");
    let v = get(&a, &format!("/verify?sub={old_sub}&now={}", done_at + 120));
    assert_eq!(v["verdict"]["reason"], "revoked", "{v}");
    let v = get(
        &b,
        &format!(
            "/verify?sub=ainra:registrar-08:acme:billing@1.0.0&now={}",
            done_at + 120
        ),
    );
    assert_eq!(v["verdict"]["verdict"], "valid", "{v}");

    // A restart keeps the record of the move and the newest epoch seen.
    drop(gb);
    let _gb = start(&b, "registrar-08", &db, Some(&roots_file));
    let t = get(&b, "/transfers");
    assert_eq!(t["transfers"][0]["state"], "completed", "{t}");
    assert!(error_of(&post(&b, "/transfer-in", &body_in(&dir1))).contains("older than"));

    // No pinned roots: the doors stay closed.
    let dc = dir("c");
    let c = format!("127.0.0.1:{}", free_port());
    let _gc = start(&c, "registrar-09", &dc, None);
    assert!(error_of(&post(&c, "/transfer-in", &body_in(&dir2))).contains("no pinned roots"));
}

/// On a registrar keeping real time, the caller cannot name the time of a move: a status list stamped in the past
/// (from before a revocation) is stale by the registrar's own clock, and a `now` placed after the window does not
/// close it.
#[test]
fn the_registrars_own_clock_decides_not_the_caller() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xC10C);
    let (da, db) = (dir("clock-a"), dir("clock-b"));
    let roots = Roots::new(0x2008);
    let roots_file = roots.file(&da);
    let (a, b) = (
        format!("127.0.0.1:{}", free_port()),
        format!("127.0.0.1:{}", free_port()),
    );
    let _ga = start_clock(&a, "registrar-07", &da, Some(&roots_file), false);
    let _gb = start_clock(&b, "registrar-08", &db, Some(&roots_file), false);
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let agent = crypto::HybridKeypair::generate(&mut rng);
    let operator = crypto::HybridKeypair::generate(&mut rng);
    let akey = wire_of(&agent.public());
    let apop = sign_b64(&agent, &holder_pop_message("registrar-07", &akey).unwrap()).unwrap();
    let rec = post(
        &a,
        "/issue",
        &json!({
            "operator": "acme", "lineage": "billing", "version": "1.0.0", "tier": "L2", "auth_class": "A2",
            "principal_proof": "deadbeef", "capabilities": ["read:invoices"], "scope_ceiling": ["read:invoices"],
            "holder_key": akey, "holder_pop": apop,
        }),
    );
    let old_sub = rec["sub"]
        .as_str()
        .unwrap_or_else(|| panic!("issued: {rec}"))
        .to_string();
    let okey = wire_of(&operator.public());
    let opop = sign_b64(
        &operator,
        &operator_key_message("registrar-07", "acme", "billing", &okey).unwrap(),
    )
    .unwrap();
    let receipt = post(
        &a,
        "/operator-key",
        &json!({ "operator": "acme", "lineage": "billing", "key": okey, "pop": opop }),
    );
    let directory = roots.directory(1, &[get(&a, "/accreditation"), get(&b, "/accreditation")]);
    let passport = get(&a, &format!("/record?sub={old_sub}"));
    let npop = sign_b64(&agent, &holder_pop_message("registrar-08", &akey).unwrap()).unwrap();
    let msg = request_message(&old_sub, "registrar-08", wall, &akey).unwrap();
    let request = json!({
        "from_sub": old_sub, "to_registrar": "registrar-08", "requested_at": wall,
        "new_holder_key": akey, "new_holder_pop": npop,
        "holder_sig": sign_b64(&agent, &msg).unwrap(), "operator_sig": sign_b64(&operator, &msg).unwrap(),
    });
    let body = |status: Value| {
        json!({ "request": request, "passport": passport, "operator_key": receipt, "directory": directory,
                "status": status, "now": T0 })
    };
    // A registrar keeping real time will not sign a status list for an instant the caller names: asked for one at T0
    // (months ago), it signs at its own clock. So a back-dated (pre-revocation) list cannot be had at all, and a
    // forward-dated one cannot be stockpiled (2026-11-07 review).
    let asked = get(&a, &format!("/status-list?now={T0}"));
    assert!(
        asked["issued_at"].as_u64().unwrap() >= wall,
        "signed at the registrar's clock, not at ?now: {asked}"
    );
    let ahead = get(&a, &format!("/status-list?now={}", wall + 400 * 86_400));
    assert!(
        ahead["issued_at"].as_u64().unwrap() < wall + 3600,
        "a future instant is not signed either: {ahead}"
    );
    // A current list opens the move, at the registrar's time, not the caller's.
    let opened = post(&b, "/transfer-in", &body(get(&a, "/status-list")));
    let id = opened["id"]
        .as_str()
        .unwrap_or_else(|| panic!("opened: {opened}"))
        .to_string();
    assert!(
        opened["opened_at"].as_u64().unwrap() >= wall,
        "opened at the registrar's clock, not at the body's now"
    );
    let done = post(
        &b,
        "/transfer-complete",
        &json!({ "id": id, "passport": passport, "directory": directory,
        "status": get(&a, "/status-list"), "now": wall + 30 * 86_400 }),
    );
    assert!(
        error_of(&done).contains("open to contest"),
        "a future `now` does not close the window: {done}"
    );
}

/// A change of owner over HTTP (D-103): opened publicly with the old operator key, completed by the registrar after the
/// window with the new owner's assurance; the public record lists it and survives a restart.
#[test]
fn a_change_of_owner_over_http() {
    use ainra_services::registrar::transfer::ownership_message;
    let mut rng = ChaCha20Rng::seed_from_u64(0xD1_03_77);
    let da = dir("own-a");
    let a = format!("127.0.0.1:{}", free_port());
    let ga = start(&a, "registrar-07", &da, None);
    let agent = crypto::HybridKeypair::generate(&mut rng);
    let old_op = crypto::HybridKeypair::generate(&mut rng);
    let new_op = crypto::HybridKeypair::generate(&mut rng);
    let akey = wire_of(&agent.public());
    let apop = sign_b64(&agent, &holder_pop_message("registrar-07", &akey).unwrap()).unwrap();
    let rec = post(
        &a,
        "/issue",
        &json!({
            "operator": "acme", "lineage": "billing", "version": "1.0.0", "tier": "L2", "auth_class": "A2",
            "principal_proof": "deadbeef", "capabilities": ["read:invoices"], "scope_ceiling": ["read:invoices"],
            "holder_key": akey, "holder_pop": apop,
        }),
    );
    let old_sub = rec["sub"].as_str().unwrap().to_string();
    let okey = wire_of(&old_op.public());
    let opop = sign_b64(
        &old_op,
        &operator_key_message("registrar-07", "acme", "billing", &okey).unwrap(),
    )
    .unwrap();
    post(
        &a,
        "/operator-key",
        &json!({ "operator": "acme", "lineage": "billing", "key": okey, "pop": opop }),
    );
    let nkey = wire_of(&new_op.public());
    let npop = sign_b64(
        &new_op,
        &operator_key_message("registrar-07", "globex", "billing", &nkey).unwrap(),
    )
    .unwrap();
    let hpop = sign_b64(&new_op, &holder_pop_message("registrar-07", &nkey).unwrap()).unwrap();
    let msg = ownership_message(&old_sub, "globex", T0, &nkey, &nkey).unwrap();
    let opened = post(
        &a,
        "/ownership-open",
        &json!({ "now": T0, "request": {
            "from_sub": old_sub, "new_operator": "globex", "requested_at": T0,
            "new_operator_key": nkey, "new_operator_pop": npop, "new_holder_key": nkey, "new_holder_pop": hpop,
            "old_operator_sig": sign_b64(&old_op, &msg).unwrap(),
        }}),
    );
    let id = opened["id"]
        .as_str()
        .unwrap_or_else(|| panic!("opened: {opened}"))
        .to_string();
    let assurance = json!({ "tier": "L1", "auth_class": "A3", "principal_proof": "c0ffee",
        "capabilities": ["read:invoices"], "scope_ceiling": ["read:invoices"] });
    let early = post(
        &a,
        "/ownership-complete",
        &json!({ "id": id, "assurance": assurance, "now": T0 + 60 }),
    );
    assert!(error_of(&early).contains("open to contest"), "{early}");
    let done_at = T0 + CONTEST_WINDOW_SECS;
    let new = post(
        &a,
        "/ownership-complete",
        &json!({ "id": id, "assurance": assurance, "now": done_at }),
    );
    assert_eq!(
        new["sub"], "ainra:registrar-07:globex:billing@1.0.0",
        "{new}"
    );
    let v = get(&a, &format!("/verify?sub={old_sub}&now={}", done_at + 60));
    assert_eq!(v["verdict"]["reason"], "revoked", "{v}");
    drop(ga);
    let _ga = start(&a, "registrar-07", &da, None);
    let rec = get(&a, "/ownership-changes");
    assert_eq!(rec["ownership_changes"][0]["state"], "completed", "{rec}");
}
