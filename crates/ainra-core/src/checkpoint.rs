// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Signed log checkpoints, the ADR-002 delegate signer, and the "logged-before-valid" inclusion gate.
//!
//! Spec: MTS §13/§14 + ADR-002. A checkpoint commits `(origin, tree_size, root)`. Two signature modes:
//!   * **Root** — the SLH-DSA root signs the checkpoint directly (ceremony artifacts; TEST-ROOT in fixtures).
//!   * **Delegate** (ADR-002) — the root stays offline; it certifies a scope-limited, short-lived online Ed25519
//!     delegate (cert ≤ 92 days, scopes like `checkpoint-daily`), and the DELEGATE signs day-to-day checkpoints.
//!     Verifiers accept: valid root-signed cert (window + scope) + valid delegate signature. Any failure in that
//!     chain — cert forged, expired, wrong scope, bad delegate sig — is [`Reason::CheckpointInvalid`], fail closed.
//!     (In production the delegate is 2-of-3 FROST among ops nodes; FROST emits standard RFC 8032 signatures, so
//!     the single-key M2 stand-in is verification-identical — DECISIONS D-011.)
//!
//! Prime directive "logged-before-valid" (brief §0): a passport is never VALID without a Merkle inclusion proof of
//! its leaf under a checkpoint whose signature verifies. A bad/absent inclusion → [`Reason::NotLogged`]; a
//! checkpoint whose signature fails → [`Reason::CheckpointInvalid`]. Both fail closed.

use alloc::string::String;
use alloc::vec::Vec;

use serde::Serialize;

use crate::error::Result;
use crate::verdict::Reason;
use crate::{b64, canon, crypto, merkle};

/// The scope a checkpoint-signing delegate must carry (ADR-002's fixed vocabulary).
pub const SCOPE_CHECKPOINT: &str = "checkpoint-daily";
/// The scope a delegate must carry to countersign a status-list delta (ADR-002 / ADR-007, MTS §16).
pub const SCOPE_DELTA: &str = "delta-countersign";
/// The scope a delegate must carry to sign a 30-second fresh head (ADR-002 / ADR-007, MTS §16).
pub const SCOPE_FRESH_HEAD: &str = "fresh-head";
/// Maximum delegate certificate lifetime — ≤ 92 days (ADR-002).
pub const DELEGATE_CERT_MAX_SECS: u64 = 92 * 24 * 60 * 60;

/// A log checkpoint: the tree the log commits to at `tree_size`, rooted at `root`, for a named `origin`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Log identifier, e.g. `ainra-log/registrar-01`. No real hostnames (S7).
    pub origin: String,
    pub tree_size: u64,
    pub root: [u8; 32],
}

/// The exact struct that gets canonicalized for signing. Field names/order are frozen (they feed the signature).
#[derive(Serialize)]
struct CheckpointSigning<'a> {
    origin: &'a str,
    root: String, // base64url(root)
    size: u64,
}

impl Checkpoint {
    /// Canonical signing input for this checkpoint (sorted-key, no-whitespace JSON — same encoder as everything).
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let s = canon::canonicalize(&CheckpointSigning {
            origin: &self.origin,
            root: b64::encode(&self.root),
            size: self.tree_size,
        })?;
        Ok(s.into_bytes())
    }

    /// Sign with the labeled TEST-ROOT (fixtures only).
    pub fn sign_test_root(&self, root: &crypto::TestRootSlh) -> Result<Vec<u8>> {
        root.sign(&self.signing_bytes()?)
    }

    /// Verify the checkpoint's SLH-DSA signature against the known root public key. Fail closed → `CheckpointInvalid`.
    pub fn verify_sig(&self, root_pk_slh: &[u8], sig: &[u8]) -> core::result::Result<(), Reason> {
        let msg = self
            .signing_bytes()
            .map_err(|_| Reason::CheckpointInvalid)?;
        if crypto::slh_verify(root_pk_slh, &msg, sig) {
            Ok(())
        } else {
            Err(Reason::CheckpointInvalid)
        }
    }

    /// Sign with an (already-certified) delegate key — the ADR-002 day-to-day path.
    pub fn sign_delegate(&self, delegate: &crypto::TestDelegate) -> Result<Vec<u8>> {
        Ok(delegate.sign(&self.signing_bytes()?))
    }

    /// Verify either checkpoint-signature mode. Fixed, documented order so the failure reason is deterministic:
    /// Root → (1) SLH sig. Delegate → (1) cert root-signature, (2) cert validity window vs `now`,
    /// (3) required scope present, (4) delegate Ed25519 signature over the checkpoint bytes.
    /// Every failure is [`Reason::CheckpointInvalid`] (fail closed; the reason never leaks which link broke —
    /// operators diagnose from logs, verifiers only need INVALID).
    pub fn verify_sig_mode(
        &self,
        root_pk_slh: &[u8],
        sig: &CheckpointSig,
        now: u64,
    ) -> core::result::Result<(), Reason> {
        match sig {
            CheckpointSig::Root { slh } => self.verify_sig(root_pk_slh, slh),
            CheckpointSig::Delegate { cert, sig_ed25519 } => {
                cert.verify(root_pk_slh, now, SCOPE_CHECKPOINT)?;
                let msg = self
                    .signing_bytes()
                    .map_err(|_| Reason::CheckpointInvalid)?;
                if sig_ed25519.len() != crypto::ED25519_SIG {
                    return Err(Reason::CheckpointInvalid);
                }
                let sig_arr: [u8; 64] = sig_ed25519
                    .as_slice()
                    .try_into()
                    .map_err(|_| Reason::CheckpointInvalid)?;
                if crypto::ed25519_verify(&cert.delegate_ed25519, &msg, &sig_arr) {
                    Ok(())
                } else {
                    Err(Reason::CheckpointInvalid)
                }
            }
        }
    }
}

/// A checkpoint signature in one of the two ADR-002 modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointSig {
    /// Signed directly by the (TEST-)root's SLH-DSA key — ceremony artifacts.
    Root { slh: Vec<u8> },
    /// Signed by a root-certified, scope-limited online delegate — the day-to-day path.
    Delegate {
        cert: DelegateCert,
        sig_ed25519: Vec<u8>,
    },
}

/// ADR-002 delegate certificate: the root's SLH-DSA signature over `{delegate, exp, nbf, scopes}` (canonical).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegateCert {
    /// The online delegate's Ed25519 public key.
    pub delegate_ed25519: [u8; 32],
    /// What this delegate may sign (`checkpoint-daily`, `fresh-head`, `delta-countersign`).
    pub scopes: Vec<String>,
    pub nbf: u64,
    pub exp: u64,
    /// Root SLH-DSA signature over the canonical cert body.
    pub sig_slh: Vec<u8>,
}

/// The exact canonical body the root signs. Field names/order feed the signature — frozen.
#[derive(Serialize)]
struct DelegateCertSigning<'a> {
    delegate: String, // base64url(Ed25519 pk)
    exp: u64,
    nbf: u64,
    scopes: &'a [String],
}

impl DelegateCert {
    /// Canonical signing input for this cert.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let s = canon::canonicalize(&DelegateCertSigning {
            delegate: b64::encode(&self.delegate_ed25519),
            exp: self.exp,
            nbf: self.nbf,
            scopes: &self.scopes,
        })?;
        Ok(s.into_bytes())
    }

    /// A stable 32-byte fingerprint of this cert: `SHA-256` of its canonical signing bytes. This is what a
    /// **delegate revocation** names (ADR-002 "delegate compromise → root-signed revocation of the delegate cert,
    /// published in the directory"). Fingerprinting the signed body means a revocation targets exactly one cert
    /// (this delegate key + window + scopes) — re-certifying the same delegate later mints a *different* fingerprint.
    pub fn fingerprint(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        // A malformed cert cannot be signed/verified anyway; hash a stable marker so this never panics.
        let bytes = self.signing_bytes().unwrap_or_default();
        Sha256::digest(&bytes).into()
    }

    /// Issue a cert with the labeled TEST-ROOT (fixtures/services only). Enforces the ≤ 92-day lifetime at issue.
    pub fn issue_test_root(
        root: &crypto::TestRootSlh,
        delegate_ed25519: [u8; 32],
        scopes: Vec<String>,
        nbf: u64,
        exp: u64,
    ) -> Result<Self> {
        if exp <= nbf || exp - nbf > DELEGATE_CERT_MAX_SECS {
            return Err(crate::error::Error::malformed(
                "delegate cert lifetime out of range (ADR-002: ≤ 92 days)",
            ));
        }
        let mut cert = DelegateCert {
            delegate_ed25519,
            scopes,
            nbf,
            exp,
            sig_slh: Vec::new(),
        };
        cert.sig_slh = root.sign(&cert.signing_bytes()?)?;
        Ok(cert)
    }

    /// Verify this cert chains to the root, is inside its window at `now`, carries `required_scope`, AND respects
    /// the ≤ 92-day lifetime cap. The cert is presenter-supplied (untrusted), so the lifetime is re-checked here —
    /// not only at issuance — as defense in depth (review finding #9). All failures → `CheckpointInvalid`.
    pub fn verify(
        &self,
        root_pk_slh: &[u8],
        now: u64,
        required_scope: &str,
    ) -> core::result::Result<(), Reason> {
        let msg = self
            .signing_bytes()
            .map_err(|_| Reason::CheckpointInvalid)?;
        if !crypto::slh_verify(root_pk_slh, &msg, &self.sig_slh) {
            return Err(Reason::CheckpointInvalid);
        }
        if self.exp <= self.nbf || self.exp - self.nbf > DELEGATE_CERT_MAX_SECS {
            return Err(Reason::CheckpointInvalid); // lifetime out of ADR-002 range
        }
        if now < self.nbf || now >= self.exp {
            return Err(Reason::CheckpointInvalid);
        }
        if !self.scopes.iter().any(|s| s == required_scope) {
            return Err(Reason::CheckpointInvalid);
        }
        Ok(())
    }
}

/// The logged-before-valid gate: `leaf` at 0-based `index` must be included in the tree this checkpoint commits to.
/// Returns [`Reason::NotLogged`] on any inclusion failure (fail closed).
pub fn verify_logged(
    leaf: &[u8; 32],
    index: u64,
    cp: &Checkpoint,
    proof: &[[u8; 32]],
) -> core::result::Result<(), Reason> {
    if merkle::verify_inclusion(leaf, index, cp.tree_size, proof, &cp.root) {
        Ok(())
    } else {
        Err(Reason::NotLogged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::SeedableRng;

    fn seeded() -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::seed_from_u64(0xC4_EC_04_01)
    }

    #[test]
    fn sign_verify_and_inclusion() {
        let mut rng = seeded();
        let root_key = crypto::TestRootSlh::generate(&mut rng);

        // Build a small log; the passport-under-test is leaf 2.
        let mut log = merkle::TestLog::new();
        for k in 0..5 {
            log.append(alloc::format!("passport-{k}").as_bytes());
        }
        let cp = Checkpoint {
            origin: "ainra-log/registrar-01".into(),
            tree_size: log.size(),
            root: log.root(),
        };

        // Checkpoint signature verifies with the right key, fails with a tampered checkpoint.
        let sig = cp.sign_test_root(&root_key).unwrap();
        assert_eq!(cp.verify_sig(&root_key.public(), &sig), Ok(()));
        let mut tampered = cp.clone();
        tampered.tree_size += 1;
        assert_eq!(
            tampered.verify_sig(&root_key.public(), &sig),
            Err(Reason::CheckpointInvalid)
        );

        // Inclusion proof for leaf 2 verifies; a wrong leaf is NotLogged.
        let leaf = merkle::hash_leaf(b"passport-2");
        let proof = log.inclusion_proof(2).unwrap();
        assert_eq!(verify_logged(&leaf, 2, &cp, &proof), Ok(()));
        let wrong = merkle::hash_leaf(b"passport-elsewhere");
        assert_eq!(
            verify_logged(&wrong, 2, &cp, &proof),
            Err(Reason::NotLogged)
        );
    }

    #[test]
    fn delegate_signer_full_chain() {
        // ADR-002: root certifies a scoped delegate; the delegate signs checkpoints; verifiers accept the chain.
        let mut rng = seeded();
        let root = crypto::TestRootSlh::generate(&mut rng);
        let delegate = crypto::TestDelegate::generate(&mut rng);
        let cp = Checkpoint {
            origin: "ainra-log/registrar-01".into(),
            tree_size: 9,
            root: [3u8; 32],
        };
        let now = 1_000_000u64;
        let cert = DelegateCert::issue_test_root(
            &root,
            delegate.public(),
            alloc::vec![SCOPE_CHECKPOINT.into()],
            now - 100,
            now + 86_400, // 1 day — well inside the 92-day cap
        )
        .unwrap();
        let sig = CheckpointSig::Delegate {
            cert: cert.clone(),
            sig_ed25519: cp.sign_delegate(&delegate).unwrap(),
        };
        assert_eq!(cp.verify_sig_mode(&root.public(), &sig, now), Ok(()));

        // root mode still verifies through the same entrypoint
        let root_sig = CheckpointSig::Root {
            slh: cp.sign_test_root(&root).unwrap(),
        };
        assert_eq!(cp.verify_sig_mode(&root.public(), &root_sig, now), Ok(()));

        // (a) expired cert → invalid
        assert_eq!(
            cp.verify_sig_mode(&root.public(), &sig, cert.exp + 1),
            Err(Reason::CheckpointInvalid)
        );
        // (b) wrong scope → invalid
        let cert_wrong_scope = DelegateCert::issue_test_root(
            &root,
            delegate.public(),
            alloc::vec!["fresh-head".into()],
            now - 100,
            now + 86_400,
        )
        .unwrap();
        let sig_ws = CheckpointSig::Delegate {
            cert: cert_wrong_scope,
            sig_ed25519: cp.sign_delegate(&delegate).unwrap(),
        };
        assert_eq!(
            cp.verify_sig_mode(&root.public(), &sig_ws, now),
            Err(Reason::CheckpointInvalid)
        );
        // (c) a self-issued cert (signed by a DIFFERENT root) → invalid
        let evil_root = crypto::TestRootSlh::generate(&mut rng);
        let evil_cert = DelegateCert::issue_test_root(
            &evil_root,
            delegate.public(),
            alloc::vec![SCOPE_CHECKPOINT.into()],
            now - 100,
            now + 86_400,
        )
        .unwrap();
        let sig_ec = CheckpointSig::Delegate {
            cert: evil_cert,
            sig_ed25519: cp.sign_delegate(&delegate).unwrap(),
        };
        assert_eq!(
            cp.verify_sig_mode(&root.public(), &sig_ec, now),
            Err(Reason::CheckpointInvalid)
        );
        // (d) delegate signature by a DIFFERENT key than the certified one → invalid
        let other = crypto::TestDelegate::generate(&mut rng);
        let sig_ok_cert_bad_sig = CheckpointSig::Delegate {
            cert: cert.clone(),
            sig_ed25519: cp.sign_delegate(&other).unwrap(),
        };
        assert_eq!(
            cp.verify_sig_mode(&root.public(), &sig_ok_cert_bad_sig, now),
            Err(Reason::CheckpointInvalid)
        );
        // (e) tampered checkpoint under a valid delegate sig → invalid
        let mut cp2 = cp.clone();
        cp2.tree_size += 1;
        assert_eq!(
            cp2.verify_sig_mode(&root.public(), &sig, now),
            Err(Reason::CheckpointInvalid)
        );
        // (f) issuing a cert longer than 92 days is refused at issue time
        assert!(DelegateCert::issue_test_root(
            &root,
            delegate.public(),
            alloc::vec![SCOPE_CHECKPOINT.into()],
            now,
            now + DELEGATE_CERT_MAX_SECS + 1,
        )
        .is_err());
    }

    #[test]
    fn delegate_cert_overlong_lifetime_rejected_at_verify() {
        // Defense in depth (review #9): even a genuinely root-SIGNED cert with a > 92-day window must be refused at
        // verification, not only at issuance. Hand-craft such a cert and root-sign it directly.
        let mut rng = seeded();
        let root = crypto::TestRootSlh::generate(&mut rng);
        let delegate = crypto::TestDelegate::generate(&mut rng);
        let mut cert = DelegateCert {
            delegate_ed25519: delegate.public(),
            scopes: alloc::vec![SCOPE_CHECKPOINT.to_string()],
            nbf: 0,
            exp: DELEGATE_CERT_MAX_SECS + 10_000, // deliberately too long
            sig_slh: Vec::new(),
        };
        cert.sig_slh = root.sign(&cert.signing_bytes().unwrap()).unwrap(); // a REAL root signature
                                                                           // the cert signature verifies, but the lifetime is out of range → CheckpointInvalid
        assert_eq!(
            cert.verify(&root.public(), 1_000, SCOPE_CHECKPOINT),
            Err(Reason::CheckpointInvalid)
        );
    }

    #[test]
    fn wrong_root_key_is_checkpoint_invalid() {
        let mut rng = seeded();
        let real = crypto::TestRootSlh::generate(&mut rng);
        let other = crypto::TestRootSlh::generate(&mut rng);
        let cp = Checkpoint {
            origin: "ainra-log/registrar-02".into(),
            tree_size: 1,
            root: [7u8; 32],
        };
        let sig = cp.sign_test_root(&real).unwrap();
        // signed by `real`, verified against `other` → invalid
        assert_eq!(
            cp.verify_sig(&other.public(), &sig),
            Err(Reason::CheckpointInvalid)
        );
        assert_eq!(cp.verify_sig(&real.public(), &sig), Ok(()));
    }
}
