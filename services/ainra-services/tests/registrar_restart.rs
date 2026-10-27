// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Every write the registrar daemon answers 200 to must survive a restart. Until 2026-10-26 the authenticated
//! `POST /revoke` and `POST /renew` changed memory only: the snapshot on disk still loaded cleanly after a restart, so a
//! revoked passport came back valid. These tests run the real binary, write, kill it, start it again, and read back.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ainra_services::http::{http_get, http_post};
use serde_json::Value;

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

fn start(addr: &str, dir: &Path) -> Daemon {
    let child = Command::new(env!("CARGO_BIN_EXE_registrar-box"))
        .args([addr, "registrar-07", dir.to_str().unwrap()])
        .env("AINRA_CLOCK", "pinned")
        .env("AINRA_OPEN_WRITES", "1")
        .env_remove("AINRA_STAGE_ISSUE_TOKEN")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn registrar-box");
    let d = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if http_get(addr, "/health").is_ok_and(|b| b.contains("\"ok\":true")) {
            return d;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("registrar-box did not come up on {addr}");
}

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ainra-restart-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn post(addr: &str, path: &str, body: &str) -> Value {
    serde_json::from_str(&http_post(addr, path, body).unwrap()).unwrap()
}

fn verdict(addr: &str, sub: &str) -> Value {
    let b = http_get(
        addr,
        &format!(
            "/verify?sub={}",
            sub.replace(':', "%3A").replace('@', "%40")
        ),
    )
    .unwrap();
    serde_json::from_str::<Value>(&b).unwrap()["verdict"].clone()
}

const SPEC: &str = r#"{"operator":"globex","lineage":"billing","version":"1.0.0","tier":"L2","auth_class":"A2",
"principal_proof":"deadbeef","capabilities":["read:invoices"],"scope_ceiling":["read:invoices"],"hops":[]}"#;

#[test]
fn a_revocation_survives_a_restart() {
    let d = dir("revoke");
    let addr = format!("127.0.0.1:{}", free_port());
    let sub = {
        let _rb = start(&addr, &d);
        let sub = post(&addr, "/issue", SPEC)["sub"]
            .as_str()
            .unwrap()
            .to_string();
        post(&addr, "/revoke", &format!(r#"{{"sub":"{sub}"}}"#));
        assert_eq!(verdict(&addr, &sub)["reason"], "revoked");
        sub
    };
    let _rb = start(&addr, &d);
    assert_eq!(
        verdict(&addr, &sub)["reason"],
        "revoked",
        "a revoked passport must stay revoked across a restart"
    );
}

#[test]
fn a_renewal_survives_a_restart() {
    let d = dir("renew");
    let addr = format!("127.0.0.1:{}", free_port());
    let sub = {
        let _rb = start(&addr, &d);
        let sub = post(&addr, "/issue", SPEC)["sub"]
            .as_str()
            .unwrap()
            .to_string();
        let renewed = post(
            &addr,
            "/renew",
            &format!(r#"{{"sub":"{sub}","new_version":"1.0.1"}}"#),
        );
        renewed["sub"]
            .as_str()
            .expect("renewal answered")
            .to_string()
    };
    let _rb = start(&addr, &d);
    assert_eq!(
        verdict(&addr, &sub)["verdict"],
        "valid",
        "the renewed generation must still exist"
    );
}
