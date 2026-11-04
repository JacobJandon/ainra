// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A1 means a checked principal proof (PLAN-M51 step 3). A child module of `registrar`, like `heads` and `link`.
//!
//! An A1 passport says a verified human stands behind the agent (Standard §6, D-066). Until this step the reference
//! registrar wrote whatever string the request carried into `authority.principal_proof`, so "A1" meant only that
//! someone typed A1. Now a new A1 issuance has exactly three outcomes:
//!   * **no checker configured** — refused, by name. Never downgraded to another class: a caller who asked for A1
//!     and silently got A2 would publish a passport that says less than they think it does, and never know.
//!   * **a checker refuses the evidence** — refused, with the checker's own reason.
//!   * **a checker accepts it** — the passport carries the proof the CHECKER derived from the evidence, never a value
//!     the request supplied. A request may name the proof it expects; if it differs, that is a refusal too.
//!
//! The evidence binds the agent's own key (its thumbprint), so an A1 request must bring that key with its proof of
//! possession (D-063), and the key is checked before the checker is ever asked. What the checker is — a personhood
//! registry lookup, a KYB desk, anything — is the registrar's choice (D-066); the root never sees it. The reference
//! checker is a command: `AINRA_PRINCIPAL_CHECKER="node kits/personhood/personhood.mjs check-stdin"`.
//!
//! Renewals keep the class and proof of the generation they renew, which was checked when it was issued.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ainra_core::b64;
use sha2::{Digest, Sha256};

use super::{verify_holder, HybridB64, IssueError, IssueSpec};

/// What a checker is asked about one A1 request.
pub struct PrincipalRequest<'a> {
    /// This registrar's id: evidence made out to another registrar must not pass here.
    pub registrar: &'a str,
    /// SHA-256 (hex) over the agent's Ed25519 ‖ ML-DSA-65 public keys — the key the evidence must name.
    pub holder: &'a str,
    /// The request's `principal_evidence`, untouched.
    pub evidence: &'a serde_json::Value,
}

/// Something that checks principal evidence. `Ok` is the principal proof (a SHA-256 hex digest) the passport will
/// carry; `Err` is a named reason, passed to the requester as it is.
pub trait PrincipalChecker: Send + Sync {
    fn check(&self, req: &PrincipalRequest<'_>) -> Result<String, String>;
}

/// How this registrar treats a request for an A1 passport.
#[derive(Clone, Default)]
pub enum PrincipalPolicy {
    /// No checker: every A1 request is refused. The default for every registrar the engine opens.
    #[default]
    Refuse,
    /// A1 needs evidence this checker accepts.
    Checked(Arc<dyn PrincipalChecker>),
    /// Only for the offline seed, which builds labelled TEST-ROOT specimen networks: their A1 lineages carry a
    /// deterministic reference that no checker produced. No daemon and no CLI command installs this.
    Specimen,
}

impl PrincipalPolicy {
    /// `AINRA_PRINCIPAL_CHECKER` names a command (split on whitespace) run once per A1 request; unset means Refuse.
    pub fn from_env() -> Self {
        match std::env::var("AINRA_PRINCIPAL_CHECKER") {
            Ok(c) if !c.trim().is_empty() => PrincipalPolicy::Checked(Arc::new(
                CommandChecker::new(c.split_whitespace().map(String::from).collect()),
            )),
            _ => PrincipalPolicy::Refuse,
        }
    }
}

/// The thumbprint the evidence binds: SHA-256 over the raw Ed25519 (32 B) ‖ ML-DSA-65 (1952 B) public keys, as the
/// personhood kit computes it.
pub fn holder_thumbprint(key: &HybridB64) -> Result<String, IssueError> {
    let bad = |why: &str| IssueError::HolderProof(why.to_string());
    let ed = b64::decode(&key.ed25519).map_err(|_| bad("holder key ed25519 is not base64url"))?;
    let ml = b64::decode(&key.mldsa65).map_err(|_| bad("holder key mldsa65 is not base64url"))?;
    if ed.len() != 32 || ml.len() != 1952 {
        return Err(bad("holder key must be ed25519 32 B and ml-dsa-65 1952 B"));
    }
    let mut h = Sha256::new();
    h.update(&ed);
    h.update(&ml);
    Ok(hex(&h.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn is_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The principal proof a NEW issuance will carry, or the refusal. Classes other than A1 are untouched.
pub(super) fn principal_for(
    policy: &PrincipalPolicy,
    registrar: &str,
    spec: &IssueSpec,
) -> Result<String, IssueError> {
    if spec.auth_class != "A1" {
        return Ok(spec.principal_proof.clone());
    }
    let refuse = |why: String| Err(IssueError::PrincipalRefused(why));
    let checker = match policy {
        PrincipalPolicy::Specimen => return Ok(spec.principal_proof.clone()),
        PrincipalPolicy::Refuse => {
            return refuse(
                "an A1 (human-delegated) passport needs a checked principal proof, and this registrar has no \
                 principal checker configured (AINRA_PRINCIPAL_CHECKER); the request is refused, not downgraded"
                    .into(),
            )
        }
        PrincipalPolicy::Checked(c) => c,
    };
    let Some(evidence) = spec.principal_evidence.as_ref() else {
        return refuse(
            "an A1 request must carry `principal_evidence` for this registrar's checker; a principal_proof on its \
             own is a claim nobody checked"
                .into(),
        );
    };
    let Some(key) = spec.holder_key.as_ref() else {
        return refuse(
            "an A1 request must bring the agent's own key (`holder_key` + `holder_pop`): the evidence binds it".into(),
        );
    };
    verify_holder(registrar, key, spec.holder_pop.as_ref())?;
    let holder = holder_thumbprint(key)?;
    let proof = match checker.check(&PrincipalRequest {
        registrar,
        holder: &holder,
        evidence,
    }) {
        Ok(p) => p,
        Err(reason) => {
            return refuse(format!(
                "the principal checker refused the evidence: {reason}"
            ))
        }
    };
    if !is_digest(&proof) {
        return refuse(
            "the principal checker returned something that is not a SHA-256 hex digest".into(),
        );
    }
    if !spec.principal_proof.is_empty() && spec.principal_proof != proof {
        return refuse(
            "the request's principal_proof is not the one the checker derived from its evidence"
                .into(),
        );
    }
    Ok(proof)
}

/// Runs a command per request: `{"registrar","holder","evidence"}` as JSON on stdin; on stdout either
/// `{"ok":true,"principal_proof":"<hex>"}` or `{"ok":false,"reason":"<name>"}`. Anything else — a crash, a timeout,
/// output that is not that shape — is a refusal, never an acceptance.
pub struct CommandChecker {
    argv: Vec<String>,
    timeout: Duration,
}

impl CommandChecker {
    pub fn new(argv: Vec<String>) -> Self {
        Self {
            argv,
            timeout: Duration::from_secs(20),
        }
    }
}

impl PrincipalChecker for CommandChecker {
    fn check(&self, req: &PrincipalRequest<'_>) -> Result<String, String> {
        let (prog, args) = self
            .argv
            .split_first()
            .ok_or("checker_unavailable: empty command")?;
        let mut child = Command::new(prog)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("checker_unavailable: {e}"))?;
        let input = serde_json::json!({ "registrar": req.registrar, "holder": req.holder, "evidence": req.evidence });
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input.to_string().as_bytes());
        }
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if started.elapsed() > self.timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("checker_timeout".into());
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => return Err(format!("checker_unavailable: {e}")),
            }
        }
        let mut out = String::new();
        if let Some(mut stdout) = child.stdout.take() {
            let _ = stdout.read_to_string(&mut out);
        }
        let v: serde_json::Value =
            serde_json::from_str(out.trim()).map_err(|_| "checker_malformed_output".to_string())?;
        match (
            v.get("ok").and_then(|x| x.as_bool()),
            v.get("principal_proof").and_then(|x| x.as_str()),
        ) {
            (Some(true), Some(p)) => Ok(p.to_string()),
            (Some(false), _) => Err(v
                .get("reason")
                .and_then(|x| x.as_str())
                .unwrap_or("refused")
                .to_string()),
            _ => Err("checker_malformed_output".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{engine, holder_csr, spec};
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    struct Stub(Result<String, String>);
    impl PrincipalChecker for Stub {
        fn check(&self, _: &PrincipalRequest<'_>) -> Result<String, String> {
            self.0.clone()
        }
    }
    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ainra-principal-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }
    const GOOD: &str = "1f7e6c1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6";

    fn a1(_rb: &crate::registrar::RegistrarBox) -> IssueSpec {
        let mut s = spec("acme", "assistant", "1.0.0");
        s.auth_class = "A1".into();
        s.principal_proof = String::new();
        s.principal_evidence = Some(serde_json::json!({ "message": "junk", "signature": "0x00" }));
        let (_kp, key, pop) = holder_csr("registrar-07", &mut ChaCha20Rng::seed_from_u64(11));
        s.holder_key = Some(key);
        s.holder_pop = Some(pop);
        s
    }

    fn reason(r: Result<crate::registrar::IssuedRecord, IssueError>) -> String {
        match r {
            Err(IssueError::PrincipalRefused(m)) => m,
            Err(e) => panic!("refused for another reason: {e}"),
            Ok(_) => panic!("issued"),
        }
    }

    #[test]
    fn a1_without_a_checker_is_refused_never_downgraded() {
        let dir = scratch("0");
        let mut rb = engine(&dir);
        let s = a1(&rb);
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        assert!(reason(rb.issue(&s, &[], &mut rng)).contains("no principal checker"));
        assert_eq!(
            rb.len(),
            0,
            "nothing was issued, under A1 or any other class"
        );
    }

    #[test]
    fn a1_with_junk_evidence_is_refused_with_the_checkers_reason() {
        let dir = scratch("1");
        let mut rb = engine(&dir);
        rb.set_principal_policy(PrincipalPolicy::Checked(Arc::new(Stub(Err(
            "binding_malformed".into(),
        )))));
        let s = a1(&rb);
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        assert!(reason(rb.issue(&s, &[], &mut rng)).contains("binding_malformed"));
        assert_eq!(rb.len(), 0);
    }

    #[test]
    fn a1_needs_evidence_and_the_agents_own_key() {
        let dir = scratch("2");
        let mut rb = engine(&dir);
        rb.set_principal_policy(PrincipalPolicy::Checked(Arc::new(Stub(Ok(GOOD.into())))));
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let mut no_evidence = a1(&rb);
        no_evidence.principal_evidence = None;
        assert!(reason(rb.issue(&no_evidence, &[], &mut rng)).contains("principal_evidence"));
        let mut no_key = a1(&rb);
        no_key.holder_key = None;
        no_key.holder_pop = None;
        assert!(reason(rb.issue(&no_key, &[], &mut rng)).contains("holder_key"));
    }

    #[test]
    fn the_passport_carries_the_checkers_proof_not_the_requests() {
        let dir = scratch("3");
        let mut rb = engine(&dir);
        rb.set_principal_policy(PrincipalPolicy::Checked(Arc::new(Stub(Ok(GOOD.into())))));
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let mut claimed = a1(&rb);
        claimed.principal_proof = "f".repeat(64);
        assert!(
            reason(rb.issue(&claimed, &[], &mut rng)).contains("not the one the checker derived")
        );
        let rec = rb
            .issue(&a1(&rb), &[], &mut rng)
            .expect("checked A1 issues");
        assert_eq!(rec.auth_class, "A1");
        assert_eq!(
            crate::registrar::passport_field(&rec, "/authority/principal_proof").as_deref(),
            Some(GOOD)
        );
    }

    #[test]
    fn a_checker_that_returns_garbage_is_a_refusal() {
        let dir = scratch("4");
        let mut rb = engine(&dir);
        rb.set_principal_policy(PrincipalPolicy::Checked(Arc::new(Stub(Ok("yes".into())))));
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        assert!(reason(rb.issue(&a1(&rb), &[], &mut rng)).contains("not a SHA-256"));
    }

    #[test]
    fn other_classes_are_untouched() {
        let dir = scratch("5");
        let mut rb = engine(&dir);
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        assert!(
            rb.issue(&spec("acme", "assistant", "1.0.0"), &[], &mut rng)
                .is_ok(),
            "A2 needs no checker"
        );
    }

    #[test]
    fn a_command_checker_refuses_on_crash_and_on_malformed_output() {
        let req = |c: &CommandChecker| {
            c.check(&PrincipalRequest {
                registrar: "registrar-07",
                holder: "00",
                evidence: &serde_json::json!({}),
            })
        };
        let sh = |script: &str| CommandChecker::new(vec!["sh".into(), "-c".into(), script.into()]);
        assert_eq!(req(&sh("exit 3")), Err("checker_malformed_output".into()));
        assert_eq!(
            req(&sh("echo not-json")),
            Err("checker_malformed_output".into())
        );
        assert_eq!(
            req(&sh(r#"echo '{"ok":false,"reason":"not_human_backed"}'"#)),
            Err("not_human_backed".into())
        );
        assert_eq!(
            req(&sh(&format!(
                r#"cat >/dev/null; echo '{{"ok":true,"principal_proof":"{GOOD}"}}'"#
            ))),
            Ok(GOOD.into())
        );
        assert!(
            req(&CommandChecker::new(vec!["/nonexistent/checker".into()]))
                .unwrap_err()
                .starts_with("checker_unavailable")
        );
    }
}
