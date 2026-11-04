// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A1 means a checked principal proof (PLAN-M51 step 3), against the real binary. The checker here is a shell stub,
//! so the test needs nothing outside the repository; the personhood kit's own `check-stdin` mode is held to the same
//! contract by `make personhood-test`.
//!
//! WITNESS: an A1 request with junk evidence must be refused with the checker's reason; with no checker configured,
//! A1 must be refused by name, not issued under another class; and an accepted A1 passport carries the checker's
//! proof, not the request's.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ainra_core::{b64, crypto};
use ainra_services::http::{http_get, http_post};
use ainra_services::registrar::{holder_pop_message, HybridB64};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{json, Value};

const PROOF: &str = "5a1d0f7e6c1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4";

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
    let d = std::env::temp_dir().join(format!("ainra-a1-door-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The stub checker: accepts evidence whose message is "good", refuses anything else with `binding_malformed`.
const STUB: &str = r#"read -r line; case "$line" in *'"message":"good"'*) echo '{"ok":true,"principal_proof":"PROOF"}';; *) echo '{"ok":false,"reason":"binding_malformed"}';; esac"#;

fn start(addr: &str, dir: &Path, checker: Option<&Path>) -> Daemon {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_registrar-box"));
    cmd.args([addr, "registrar-07", dir.to_str().unwrap()])
        .env("AINRA_CLOCK", "pinned")
        .env("AINRA_OPEN_WRITES", "1")
        .env_remove("AINRA_STAGE_ISSUE_TOKEN")
        .env_remove("AINRA_DRILL_SABOTAGE")
        .env_remove("AINRA_STAGE")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match checker {
        Some(script) => cmd.env(
            "AINRA_PRINCIPAL_CHECKER",
            format!("sh {}", script.display()),
        ),
        None => cmd.env_remove("AINRA_PRINCIPAL_CHECKER"),
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

fn a1_request(message: &str, claimed: &str) -> Value {
    let kp = crypto::HybridKeypair::generate(&mut ChaCha20Rng::seed_from_u64(0xA1));
    let p = kp.public();
    let key = HybridB64 {
        ed25519: b64::encode(&p.ed25519),
        mldsa65: b64::encode(&p.mldsa65),
    };
    let sig = kp
        .sign(holder_pop_message("registrar-07", &key).unwrap().as_bytes())
        .unwrap();
    let pop = HybridB64 {
        ed25519: b64::encode(&sig.ed25519),
        mldsa65: b64::encode(&sig.mldsa65),
    };
    json!({
        "operator": "globex", "lineage": format!("human-{message}"), "version": "1.0.0", "tier": "L2",
        "auth_class": "A1", "principal_proof": claimed,
        "capabilities": ["read:invoices"], "scope_ceiling": ["read:invoices"], "hops": [],
        "holder_key": key, "holder_pop": pop,
        "principal_evidence": { "message": message, "signature": "0x00" },
    })
}

fn post(addr: &str, body: &Value) -> Value {
    serde_json::from_str(&http_post(addr, "/issue", &body.to_string()).unwrap()).unwrap()
}

fn records(addr: &str) -> usize {
    let v: Value = serde_json::from_str(&http_get(addr, "/records").unwrap()).unwrap();
    v["records"].as_array().map_or(0, |a| a.len())
}

#[test]
fn a1_is_issued_only_on_evidence_the_registrars_checker_accepts() {
    let d = dir("checked");
    let script = d.join("checker.sh");
    std::fs::write(&script, STUB.replace("PROOF", PROOF)).unwrap();
    let addr = format!("127.0.0.1:{}", free_port());
    let _daemon = start(&addr, &d.join("data"), Some(&script));

    let junk = post(&addr, &a1_request("junk", ""));
    let e = junk["error"].as_str().unwrap_or("");
    assert!(
        e.contains("principal proof refused") && e.contains("binding_malformed"),
        "junk evidence: {junk}"
    );

    let claimed = post(&addr, &a1_request("good", &"f".repeat(64)));
    assert!(
        claimed["error"]
            .as_str()
            .unwrap_or("")
            .contains("not the one the checker derived"),
        "a request named its own proof and got it: {claimed}"
    );
    assert_eq!(records(&addr), 0, "a refused A1 request issued something");

    let ok = post(&addr, &a1_request("good", ""));
    assert_eq!(ok["auth_class"], json!("A1"), "checked A1: {ok}");
    let claims: Value = serde_json::from_str(ok["claims"].as_str().unwrap()).unwrap();
    assert_eq!(
        claims["authority"]["principal_proof"],
        json!(PROOF),
        "the passport carries the checker's proof"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn without_a_checker_a1_is_refused_by_name_not_downgraded() {
    let d = dir("none");
    let addr = format!("127.0.0.1:{}", free_port());
    let _daemon = start(&addr, &d, None);
    let r = post(&addr, &a1_request("good", PROOF));
    assert!(
        r["error"]
            .as_str()
            .unwrap_or("")
            .contains("no principal checker configured"),
        "{r}"
    );
    assert_eq!(
        records(&addr),
        0,
        "A1 without a checker issued something, under some class"
    );
    let _ = std::fs::remove_dir_all(&d);
}
