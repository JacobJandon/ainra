// SPDX-License-Identifier: Apache-2.0 OR MIT
//! D-072 — a gate believes only status the registrar signed.
//!
//! Until this decision the Rust gate path (`credential_json` / `gate_json`, which `@ainra/edge` and `ainra
//! verify-request` run) took the status list and its issue time from the presenter and checked nothing about where
//! they came from: a REVOKED agent could present the list from before its revocation, claim it was issued a second
//! ago, and be let in. The TypeScript and Python verifiers had authenticated status since D-020.
//!
//! WITNESS — could these tests fail? Each forgery below was accepted by this path before the fix (`make gate-parity`
//! shows the edge gate storing them when `authenticate_status` is skipped). The fixtures are the signed sample a
//! stranger verifies in `kits/verifier`: a real directory under both roots, a real status publication.

use serde_json::{json, Value};

fn fixture(name: &str) -> String {
    let path = format!(
        "{}/../../kits/verifier/sample-artifacts/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

struct Gate {
    trust: String,
    now: u64,
}

impl Gate {
    fn new() -> Self {
        let acc: Value = serde_json::from_str(&ainra_adapter::accredit_json(
            &fixture("directory.json"),
            &fixture("roots.json"),
        ))
        .unwrap();
        assert_eq!(
            acc["ok"],
            json!(true),
            "the sample directory must verify against its roots"
        );
        let clock: Value = serde_json::from_str(&fixture("meta.json")).unwrap();
        Gate {
            trust: acc["trust"].to_string(),
            now: clock["now"].as_u64().unwrap(),
        }
    }
    /// The credential verdict under the gate's policy: "valid", or the named reason.
    fn verdict(&self, bundle: &Value) -> String {
        self.verdict_with(&self.trust, bundle)
    }
    fn verdict_with(&self, trust: &str, bundle: &Value) -> String {
        let e: Value = serde_json::from_str(&ainra_adapter::credential_json(
            &bundle.to_string(),
            trust,
            self.now,
            "",
            "F2",
        ))
        .unwrap();
        match e["status"].as_str() {
            Some("valid") => "valid".into(),
            _ => e["reason"].as_str().unwrap_or("?").to_string(),
        }
    }
}

fn bundle(name: &str) -> Value {
    serde_json::from_str(&fixture(name)).unwrap()
}

#[test]
fn the_honest_bundles_read_as_they_are() {
    let g = Gate::new();
    assert_eq!(g.verdict(&bundle("bundle-valid.json")), "valid");
    assert_eq!(g.verdict(&bundle("bundle-revoked.json")), "revoked");
}

/// One edit a presenter can make to the status material of a genuine bundle, and what to call it.
type Edit = (&'static str, fn(&mut Value));

#[test]
fn status_the_registrar_did_not_sign_is_no_status() {
    let g = Gate::new();
    let edits: [Edit; 8] = [
        ("the issue time moved", |b| {
            b["status_issued_at"] = json!(b["status_issued_at"].as_u64().unwrap() + 1)
        }),
        ("a byte appended to the list", |b| {
            b["status_list"] = json!(format!("{}A", b["status_list"].as_str().unwrap()))
        }),
        ("the declared length changed", |b| {
            b["status_len"] = json!(b["status_len"].as_u64().unwrap() + 8)
        }),
        ("the signature removed", |b| {
            b.as_object_mut().unwrap().remove("status_sig_ed25519");
            b.as_object_mut().unwrap().remove("status_sig_mldsa65");
        }),
        ("the post-quantum half removed", |b| {
            b.as_object_mut().unwrap().remove("status_sig_mldsa65");
        }),
        ("the classical half zeroed", |b| {
            b["status_sig_ed25519"] = json!("A".repeat(86))
        }),
        ("published under another URI", |b| {
            b["status_uri"] = json!("status://someone-else/1")
        }),
        ("no URI at all", |b| {
            b.as_object_mut().unwrap().remove("status_uri");
        }),
    ];
    for (what, edit) in edits {
        let mut b = bundle("bundle-valid.json");
        edit(&mut b);
        assert_eq!(g.verdict(&b), "stale_status", "{what}");
    }
}

#[test]
fn a_revoked_agent_cannot_bring_its_own_all_clear() {
    let g = Gate::new();
    let mut b = bundle("bundle-revoked.json");
    assert_eq!(g.verdict(&b), "revoked");
    // The attack this fix closes: an all-clear list of the presenter's own making, "issued" now.
    b["status_list"] = json!("eJztwAEBAAAAQCD_VxtCsDIBAgAAAQ"); // 4096 clear bits
    b["status_issued_at"] = json!(g.now);
    assert_eq!(
        g.verdict(&b),
        "stale_status",
        "an all-clear list nobody signed"
    );
}

#[test]
fn a_genuine_old_publication_lasts_only_as_long_as_the_freshness_class() {
    // What authentication does NOT close, said in a test so nobody reads more into it: the sample's two bundles are
    // the same passport before and after its revocation. Moving the earlier, genuinely signed publication into the
    // later bundle is a replay of a real snapshot, and every implementation accepts it until it is older than the
    // verifier's freshness class — F2, five minutes. `@ainra/sdk` answers the same at each of these clocks. A
    // presenter can no longer extend that window by a second, because it cannot re-date what it did not sign.
    let g = Gate::new();
    let clear = bundle("bundle-valid.json");
    let mut b = bundle("bundle-revoked.json");
    for k in [
        "status_list",
        "status_len",
        "status_issued_at",
        "status_sig_ed25519",
        "status_sig_mldsa65",
        "status_uri",
    ] {
        b[k] = clear[k].clone();
    }
    let at = |b: &Value, now: u64| {
        Gate {
            trust: g.trust.clone(),
            now,
        }
        .verdict(b)
    };
    assert_eq!(at(&b, g.now), "valid");
    assert_eq!(at(&b, g.now + 299), "valid");
    assert_eq!(at(&b, g.now + 301), "stale_status");
    b["status_issued_at"] = json!(g.now + 300); // re-dating it is forging it
    assert_eq!(at(&b, g.now + 301), "stale_status");
}

#[test]
fn the_presenter_does_not_supply_mandate_revocations() {
    let g = Gate::new();
    let mut b = bundle("bundle-valid.json");
    b["mandate_revocations"] = json!(["m-anything"]);
    assert_eq!(g.verdict(&b), "valid");
}

#[test]
fn a_trust_object_with_no_status_authorities_refuses_everything() {
    let g = Gate::new();
    let mut t: Value = serde_json::from_str(&g.trust).unwrap();
    // One registrar's authority missing: its passports cannot have their status authenticated.
    t["status"] = json!({});
    assert_eq!(
        g.verdict_with(&t.to_string(), &bundle("bundle-valid.json")),
        "stale_status"
    );
    // The pre-D-072 shape, with no `status` member at all: not a trust object — fail closed.
    t.as_object_mut().unwrap().remove("status");
    assert_eq!(
        g.verdict_with(&t.to_string(), &bundle("bundle-valid.json")),
        "schema_violation"
    );
}
