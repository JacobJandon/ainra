// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The public demo door for links (`POST /demo/link`, `POST /demo/link/revoke`), against the real binary. It needs no
//! token, so everything it may do has to be bounded by what it is: staging only, and only demo specimens.
//!
//! WITNESS: each refusal below is asserted by its message — a door that links a key to a real passport, revokes a real
//! passport's link, accepts a key the visitor does not hold, or opens outside staging fails this test.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ainra_core::b64;
use ainra_core::crypto::TestDelegate;
use ainra_core::link::{jwk_thumbprint_ed25519, pop_signing_bytes};
use ainra_services::http::{http_get, http_post};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
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
    let d = std::env::temp_dir().join(format!("ainra-demo-link-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The door must work without any write credential, so the daemon has none. `AINRA_OPEN_WRITES` is set only so the
/// test can also create what the door must refuse to touch (a real passport, and a link to it) through `/issue` and
/// `/link`; the demo routes never consult it.
fn start(addr: &str, dir: &Path, staging: bool) -> Daemon {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_registrar-box"));
    cmd.args([addr, "registrar-07", dir.to_str().unwrap()])
        .env("AINRA_CLOCK", "pinned")
        .env("AINRA_OPEN_WRITES", "1")
        .env_remove("AINRA_STAGE_ISSUE_TOKEN")
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

/// A link request for `key`, consented to by `signer` (the same key unless a test is forging consent).
fn link_spec(passport: &Value, key: &TestDelegate, signer: &TestDelegate) -> Value {
    let pk = key.public();
    let tp = jwk_thumbprint_ed25519(&pk);
    let nbf = passport["nbf"].as_u64().unwrap();
    let pop = signer.sign(&pop_signing_bytes(
        "registrar-07",
        passport["sub"].as_str().unwrap(),
        &tp,
        nbf,
    ));
    json!({ "passport": passport["sub"], "key": b64::encode(&pk), "pop": b64::encode(&pop),
            "nbf": nbf, "exp": passport["exp"] })
}

fn error_of(v: &Value) -> String {
    v["error"].as_str().unwrap_or("").to_string()
}

#[test]
fn the_demo_door_links_and_revokes_only_specimens() {
    let d = dir("staging");
    let addr = format!("127.0.0.1:{}", free_port());
    let _daemon = start(&addr, &d, true);
    let mut rng = ChaCha20Rng::seed_from_u64(0xD0_0D);

    // A specimen from the passport door, and a key the visitor's agent already has.
    let specimen = post(&addr, "/demo/issue", &json!({ "lineage": "door" }));
    assert!(specimen["sub"].is_string(), "demo issue: {specimen}");
    let key = TestDelegate::generate(&mut rng);
    let tp = jwk_thumbprint_ed25519(&key.public());

    // Consent signed by a different key is refused: nobody links a key they do not hold.
    let other = TestDelegate::generate(&mut rng);
    let forged = post(&addr, "/demo/link", &link_spec(&specimen, &key, &other));
    assert!(forged["thumbprint"].is_null(), "linked without the key's consent: {forged}");

    // With the key's own consent, the door links it — no token.
    let linked = post(&addr, "/demo/link", &link_spec(&specimen, &key, &key));
    assert_eq!(linked["thumbprint"], json!(tp), "demo link: {linked}");

    // A real passport (not a specimen) is out of the door's reach, for linking and for revoking.
    let real = post(
        &addr,
        "/issue",
        &serde_json::from_str::<Value>(
            r#"{"operator":"globex","lineage":"billing","version":"1.0.0","tier":"L2","auth_class":"A2",
               "principal_proof":"deadbeef","capabilities":["read:invoices"],"scope_ceiling":["read:invoices"],"hops":[]}"#,
        )
        .unwrap(),
    );
    assert!(real["sub"].is_string(), "issue: {real}");
    let real_key = TestDelegate::generate(&mut rng);
    let refused = post(&addr, "/demo/link", &link_spec(&real, &real_key, &real_key));
    assert!(
        error_of(&refused).contains("only links keys to demo specimens"),
        "the door linked a key to a real passport: {refused}"
    );
    let real_link = post(&addr, "/link", &link_spec(&real, &real_key, &real_key));
    let real_tp = real_link["thumbprint"].as_str().expect("operator link").to_string();
    let refused = post(
        &addr,
        "/demo/link/revoke",
        &json!({ "thumbprint": real_tp, "kind": "link" }),
    );
    assert!(
        error_of(&refused).contains("only revokes links to demo specimens"),
        "the door revoked a real passport's link: {refused}"
    );
    let unknown = post(
        &addr,
        "/demo/link/revoke",
        &json!({ "thumbprint": "AAAA", "kind": "link" }),
    );
    assert!(
        error_of(&unknown).contains("only revokes links to demo specimens"),
        "{unknown}"
    );

    // The specimen's own link it does revoke.
    let revoked = post(
        &addr,
        "/demo/link/revoke",
        &json!({ "thumbprint": tp, "kind": "link" }),
    );
    assert!(
        error_of(&revoked).is_empty() && revoked.get("kind") == Some(&json!("link")),
        "demo revoke: {revoked}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_demo_door_is_closed_outside_staging() {
    let d = dir("dev");
    let addr = format!("127.0.0.1:{}", free_port());
    let _daemon = start(&addr, &d, false);
    for path in ["/demo/link", "/demo/link/revoke"] {
        let r = post(&addr, path, &json!({}));
        assert!(
            error_of(&r).contains("staging-only"),
            "{path} answered outside staging: {r}"
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}
