// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The public renewal door (`POST /demo/renew`, PLAN-M50 step 4), against the real binary. The compliance probe holds
//! no credential, so this is how it follows a lineage across generations; it must be bounded the way every demo door
//! is: staging only, and only demo specimens.
//!
//! WITNESS: each refusal is asserted by its message, and the sweep by the status of every generation — a door that
//! renews a real passport, opens outside staging, or a revocation that leaves an earlier generation alive fails here.

use std::net::TcpListener;
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
    let d = std::env::temp_dir().join(format!("ainra-demo-renew-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn start(addr: &str, dir: &Path, staging: bool) -> Daemon {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_registrar-box"));
    cmd.args([addr, "registrar-07", dir.to_str().unwrap()])
        .env("AINRA_CLOCK", "pinned")
        .env("AINRA_OPEN_WRITES", "1")
        .env_remove("AINRA_STAGE_ISSUE_TOKEN")
        .env_remove("AINRA_DRILL_SABOTAGE")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if staging {
        cmd.env("AINRA_STAGE", "1");
    } else {
        cmd.env_remove("AINRA_STAGE");
    }
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

fn revoked(addr: &str, sub: &str) -> bool {
    let records: Value = serde_json::from_str(&http_get(addr, "/records").unwrap()).unwrap();
    records["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["sub"] == json!(sub))
        .unwrap_or_else(|| panic!("{sub} is not listed"))["revoked"]
        == json!(true)
}

#[test]
fn the_demo_door_renews_only_specimens_and_revocation_reaches_every_generation() {
    let d = dir("staging");
    let addr = format!("127.0.0.1:{}", free_port());
    let _daemon = start(&addr, &d, true);

    let g1 = post(&addr, "/demo/issue", &json!({ "lineage": "renewal" }));
    let g1 = g1["sub"].as_str().expect("demo issue").to_string();

    // A version is required, so every generation stays presentable under its own name.
    let missing = post(&addr, "/demo/renew", &json!({ "sub": g1 }));
    assert!(
        error_of(&missing).contains("new_version required"),
        "{missing}"
    );

    let g2 = post(
        &addr,
        "/demo/renew",
        &json!({ "sub": g1, "new_version": "2.0.0" }),
    );
    let g2 = g2["sub"]
        .as_str()
        .unwrap_or_else(|| panic!("renew: {g2}"))
        .to_string();
    let g3 = post(
        &addr,
        "/demo/renew",
        &json!({ "sub": g2, "new_version": "3.0.0" }),
    );
    let g3 = g3["sub"]
        .as_str()
        .unwrap_or_else(|| panic!("renew: {g3}"))
        .to_string();
    assert!(g1 != g2 && g2 != g3);

    // Only the head renews: renewing a superseded generation would fork the chain.
    let fork = post(
        &addr,
        "/demo/renew",
        &json!({ "sub": g1, "new_version": "9.0.0" }),
    );
    assert!(
        error_of(&fork).contains("prev_leaf"),
        "a superseded generation renewed: {fork}"
    );

    // A real passport is out of the door's reach.
    let real = post(
        &addr,
        "/issue",
        &serde_json::from_str::<Value>(
            r#"{"operator":"globex","lineage":"billing","version":"1.0.0","tier":"L2","auth_class":"A2",
               "principal_proof":"deadbeef","capabilities":["read:invoices"],"scope_ceiling":["read:invoices"],"hops":[]}"#,
        )
        .unwrap(),
    );
    let refused = post(
        &addr,
        "/demo/renew",
        &json!({ "sub": real["sub"], "new_version": "2.0.0" }),
    );
    assert!(
        error_of(&refused).contains("only renews demo specimens"),
        "the door renewed a real passport: {refused}"
    );

    // D-055 through the door: revoking the newest generation revokes the lineage.
    let r = post(&addr, "/demo/revoke", &json!({ "sub": g3 }));
    assert!(error_of(&r).is_empty(), "revoke: {r}");
    for g in [&g1, &g2, &g3] {
        assert!(revoked(&addr, g), "{g} survived the lineage's revocation");
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_renew_door_is_closed_outside_staging_and_sabotage_needs_its_build() {
    let d = dir("dev");
    let addr = format!("127.0.0.1:{}", free_port());
    {
        let _daemon = start(&addr, &d, false);
        let r = post(&addr, "/demo/renew", &json!({}));
        assert!(
            error_of(&r).contains("staging-only"),
            "/demo/renew answered outside staging: {r}"
        );
    }
    // The drill's cheat cannot be switched on in an ordinary build: the daemon refuses to start instead.
    if !cfg!(feature = "drill-sabotage") {
        let out = Command::new(env!("CARGO_BIN_EXE_registrar-box"))
            .args([
                format!("127.0.0.1:{}", free_port()).as_str(),
                "registrar-07",
                d.to_str().unwrap(),
            ])
            .env("AINRA_CLOCK", "pinned")
            .env("AINRA_STAGE", "1")
            .env("AINRA_DRILL_SABOTAGE", "revoke-one-generation")
            .output()
            .expect("run registrar-box");
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("refusing to start"));
    }
    let _ = std::fs::remove_dir_all(&d);
}
