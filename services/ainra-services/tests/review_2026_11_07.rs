// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Witnesses for the 2026-11-07 independent review (D-104), against the real `registrar-box` binary. Each test is an
//! attack the review confirmed, and it must now be refused.
//!
//! WITNESS: the public demo door cannot mint under, revoke or renew a name a real passport holds; one idle connection
//! no longer stops the registrar; a registrar on a real clock refuses keys anyone can recompute from its public id
//! unless it is told it is a TEST drill.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ainra_services::http::{http_get, http_post};
use serde_json::{json, Value};

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
    let d = std::env::temp_dir().join(format!("ainra-review-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn command(addr: &str, data: &Path, pinned: bool, staging: bool) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_registrar-box"));
    cmd.args([addr, "registrar-07", data.to_str().unwrap()])
        .env("AINRA_OPEN_WRITES", "1")
        .env_remove("AINRA_STAGE_ISSUE_TOKEN")
        .env_remove("AINRA_TEST_DERIVED_KEYS")
        .env_remove("AINRA_ROOTS_FILE")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if pinned {
        cmd.env("AINRA_CLOCK", "pinned");
    } else {
        cmd.env_remove("AINRA_CLOCK");
    }
    if staging {
        cmd.env("AINRA_STAGE", "1");
    } else {
        cmd.env_remove("AINRA_STAGE");
    }
    cmd
}

fn up(addr: &str, cmd: &mut Command) -> Daemon {
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

fn post(addr: &str, path: &str, body: &Value) -> Value {
    serde_json::from_str(&http_post(addr, path, &body.to_string()).unwrap()).unwrap()
}

fn error_of(v: &Value) -> String {
    v["error"].as_str().unwrap_or("").to_string()
}

#[test]
fn the_demo_door_cannot_touch_a_real_passport() {
    let data = dir("demo");
    let addr = format!("127.0.0.1:{}", free_port());
    let _d = up(&addr, &mut command(&addr, &data, true, true));
    // A real passport, issued through the registrar's own (here: open, loopback) door.
    let real = post(
        &addr,
        "/issue",
        &json!({
            "operator": "acme", "lineage": "agent", "version": "1.0.0", "tier": "L2", "auth_class": "A2",
            "principal_proof": "deadbeef", "capabilities": ["read:invoices"], "scope_ceiling": ["read:invoices"],
        }),
    );
    let real_sub = real["sub"].as_str().expect("issued").to_string();
    // The attack: mint a specimen under the same name, then revoke it (revocation is lineage-wide).
    let squat = post(
        &addr,
        "/demo/issue",
        &json!({ "operator": "acme", "lineage": "agent" }),
    );
    assert!(
        error_of(&squat).contains("did not mint"),
        "squatting a real name is refused: {squat}"
    );
    let renew = post(
        &addr,
        "/demo/renew",
        &json!({ "sub": real_sub, "new_version": "9.0.0" }),
    );
    assert!(
        error_of(&renew).contains("only renews demo specimens"),
        "{renew}"
    );
    let revoke = post(&addr, "/demo/revoke", &json!({ "sub": real_sub }));
    assert!(
        !error_of(&revoke).is_empty(),
        "the real passport cannot be revoked through the door: {revoke}"
    );
    let v: Value =
        serde_json::from_str(&http_get(&addr, &format!("/verify?sub={real_sub}")).unwrap())
            .unwrap();
    assert_eq!(
        v["verdict"]["verdict"], "valid",
        "the real passport stands: {v}"
    );
    // The door still works for its own names.
    let own = post(
        &addr,
        "/demo/issue",
        &json!({ "operator": "visitor", "lineage": "demo" }),
    );
    assert!(own["sub"].as_str().is_some(), "{own}");
}

#[test]
fn one_idle_connection_does_not_stop_the_registrar() {
    let data = dir("idle");
    let addr = format!("127.0.0.1:{}", free_port());
    let _d = up(&addr, &mut command(&addr, &data, true, false));
    // Open connections that send nothing at all, and one that sends half a request line, and hold them.
    let mut held: Vec<TcpStream> = (0..5).map(|_| TcpStream::connect(&addr).unwrap()).collect();
    let mut half = TcpStream::connect(&addr).unwrap();
    half.write_all(b"GET /health HT").unwrap();
    held.push(half);
    let t = Instant::now();
    let health = http_get(&addr, "/health").unwrap();
    assert!(health.contains("\"ok\":true"), "{health}");
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "answered while idle sockets were held: {:?}",
        t.elapsed()
    );
    drop(held);
}

#[test]
fn a_registrar_on_a_real_clock_refuses_keys_derived_from_its_id() {
    let data = dir("keys");
    let addr = format!("127.0.0.1:{}", free_port());
    {
        // A pinned drill creates the registrar with the id-derived (reproducible) seed, as drills always have.
        let _d = up(&addr, &mut command(&addr, &data, true, false));
        // A write, so the snapshot (and its seed) is on disk.
        let rec = post(
            &addr,
            "/issue",
            &json!({
                "operator": "acme", "lineage": "keys", "version": "1.0.0", "tier": "L1", "auth_class": "A2",
                "principal_proof": "x", "capabilities": [], "scope_ceiling": [],
            }),
        );
        assert!(rec["sub"].as_str().is_some(), "{rec}");
    }
    assert!(data.join("registrar.json").exists());
    // The same data directory on a real clock: refused, the process exits.
    let mut child = command(&addr, &data, false, false).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(
            Instant::now() < deadline,
            "a real-clock registrar on derived keys must refuse to start"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(status.code(), Some(2));
    // Told it is a TEST drill, it runs.
    let mut cmd = command(&addr, &data, false, false);
    cmd.env("AINRA_TEST_DERIVED_KEYS", "1");
    let _d = up(&addr, &mut cmd);
    // A NEW registrar on a real clock gets random keys: two fresh ones never share an issuer key.
    let (d1, d2) = (dir("fresh-1"), dir("fresh-2"));
    let (a1, a2) = (
        format!("127.0.0.1:{}", free_port()),
        format!("127.0.0.1:{}", free_port()),
    );
    let _r1 = up(&a1, &mut command(&a1, &d1, false, false));
    let _r2 = up(&a2, &mut command(&a2, &d2, false, false));
    let k1: Value = serde_json::from_str(&http_get(&a1, "/accreditation").unwrap()).unwrap();
    let k2: Value = serde_json::from_str(&http_get(&a2, "/accreditation").unwrap()).unwrap();
    assert_ne!(
        k1["issuer_key"], k2["issuer_key"],
        "same id, fresh directories: different keys"
    );
    post(
        &a1,
        "/issue",
        &json!({
            "operator": "acme", "lineage": "fresh", "version": "1.0.0", "tier": "L1", "auth_class": "A2",
            "principal_proof": "x", "capabilities": [], "scope_ceiling": [],
        }),
    );
    let secret: Value =
        serde_json::from_str(&std::fs::read_to_string(d1.join("registrar.secret")).unwrap())
            .unwrap();
    assert_eq!(
        secret["seed32"].as_str().map(str::len),
        Some(64),
        "a 32-byte seed is kept for reload"
    );
}
