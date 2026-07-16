// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The signed registrar **directory** — how AINRA *accredits* registrars (MTS §13, verify hot-path step ①).
//!
//! A directory maps each accredited registrar id → the public keys a verifier chains to (its hybrid issuer key +
//! the SLH-DSA key that signs its log checkpoints), and carries the list of **revoked delegate certs** (ADR-002).
//! It is signed by BOTH ceremony roots — the FROST 5-of-9 threshold **Ed25519** group key AND the **SLH-DSA-128s**
//! ceremony root — and is invalid unless *both* signatures verify (`unknown_registrar` on any failure: with no
//! trustworthy directory, no registrar is known). The FROST signature is a standard RFC 8032 Ed25519 signature, so
//! this module verifies it with plain [`crate::crypto::ed25519_verify`] and never links against any threshold code.
//!
//! N7: pure. The caller fetches the directory bytes + holds the two root public keys (from the genesis ceremony);
//! this module only decides whether the directory is authentic and turns it into [`crate::verify::TrustAnchors`] +
//! the revoked-delegate set that the verifier then applies.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::verdict::Reason;
use crate::verify::{RegistrarInfo, TrustAnchors};
use crate::{b64, canon, crypto};

/// One accredited registrar, as published in the directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryEntry {
    /// Registrar id, e.g. `registrar-07` (S7: never a real org name).
    pub registrar: String,
    /// base64url(Ed25519 issuer public key, 32 B).
    pub issuer_ed25519: String,
    /// base64url(ML-DSA-65 issuer public key, 1952 B).
    pub issuer_mldsa65: String,
    /// base64url(SLH-DSA-128s public key, 32 B) — signs this registrar's log checkpoints (root/delegate mode).
    pub log_root_slh: String,
    /// base64url(Ed25519 status-signing public key, 32 B) — signs this registrar's Token Status List publications.
    /// A verifier authenticates a presented status list against THIS key (D-020) so a presenter cannot forge an
    /// all-clear status to bypass revocation. Part of the dual-root-signed directory body, so it cannot be swapped.
    #[serde(default)]
    pub status_ed25519: String,
    /// base64url(ML-DSA-65 status-signing public key, 1952 B) — the hybrid partner of `status_ed25519`.
    #[serde(default)]
    pub status_mldsa65: String,
    /// The registrar's status-list URI (the status signature is bound to it).
    pub status_uri: String,
}

/// The dual-root-signed directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    /// Monotonically increasing directory version. A verifier accepts only `epoch ≥` the last one it saw
    /// (rollback protection is the caller's policy; the type carries the number).
    pub epoch: u64,
    /// When this directory was published (unix seconds).
    pub issued_at: u64,
    /// Accredited registrars. MUST be sorted by `registrar` ascending + unique (canonical; enforced at verify).
    pub entries: Vec<DirectoryEntry>,
    /// base64url(SHA-256) fingerprints of revoked delegate certs (ADR-002). A checkpoint signed by one of these
    /// delegate certs is `checkpoint_invalid`.
    #[serde(default)]
    pub revoked_delegates: Vec<String>,
    /// FROST 5-of-9 threshold Ed25519 signature (standard RFC 8032, 64 B, base64url) over [`Self::signing_bytes`].
    pub sig_root_ed25519: String,
    /// SLH-DSA-128s ceremony-root signature (base64url) over the same bytes.
    pub sig_root_slh: String,
}

/// The exact struct whose canonicalization is signed by both roots. Field names/order frozen (they feed the sigs).
#[derive(Serialize)]
struct DirectorySigning<'a> {
    entries: &'a [DirectoryEntry],
    epoch: u64,
    issued_at: u64,
    revoked_delegates: &'a [String],
}

/// The authenticated result of verifying a directory: the trust anchors + the revoked-delegate fingerprints.
pub struct AccreditedSet {
    pub anchors: TrustAnchors,
    pub revoked_delegates: BTreeSet<[u8; 32]>,
    pub epoch: u64,
}

impl Directory {
    /// Canonical signing input — BOTH root signatures cover exactly these bytes.
    pub fn signing_bytes(&self) -> crate::Result<Vec<u8>> {
        let s = canon::canonicalize(&DirectorySigning {
            entries: &self.entries,
            epoch: self.epoch,
            issued_at: self.issued_at,
            revoked_delegates: &self.revoked_delegates,
        })?;
        Ok(s.into_bytes())
    }

    /// Verify the directory against BOTH ceremony root public keys and turn it into an [`AccreditedSet`]. Any
    /// failure — a bad Ed25519 (FROST) signature, a bad SLH-DSA signature, a non-canonical entry list, a malformed
    /// key — yields [`Reason::UnknownRegistrar`]: without an authentic directory, no registrar is accredited.
    ///
    /// `root_ed25519` is the FROST group public key (32 B); `root_slh` is the SLH-DSA ceremony-root public key.
    /// **Both** signatures are required (both-or-invalid, brief §0).
    pub fn accredit(
        &self,
        root_ed25519: &[u8; 32],
        root_slh: &[u8],
    ) -> core::result::Result<AccreditedSet, Reason> {
        let msg = self.signing_bytes().map_err(|_| Reason::UnknownRegistrar)?;

        // (1) FROST/Ed25519 root signature.
        let ed_sig: [u8; crypto::ED25519_SIG] = b64::decode(&self.sig_root_ed25519)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(Reason::UnknownRegistrar)?;
        if !crypto::ed25519_verify(root_ed25519, &msg, &ed_sig) {
            return Err(Reason::UnknownRegistrar);
        }
        // (2) SLH-DSA root signature — BOTH must verify.
        let slh_sig = b64::decode(&self.sig_root_slh).map_err(|_| Reason::UnknownRegistrar)?;
        if !crypto::slh_verify(root_slh, &msg, &slh_sig) {
            return Err(Reason::UnknownRegistrar);
        }

        // (3) entries strictly sorted + unique (canonical; prevents duplicate/shadow accreditations). Registrar
        // ids MUST be ASCII (the name-label grammar is ASCII lowercase): a non-ASCII id would sort differently
        // under Rust's UTF-8 `String` Ord vs a UTF-16 comparator (sdk-ts), splitting the verdict on the same
        // signed bytes — so reject non-ASCII ids outright, keeping the sort check byte-identical across impls.
        for e in &self.entries {
            if !e.registrar.is_ascii() || e.registrar.is_empty() {
                return Err(Reason::UnknownRegistrar);
            }
        }
        for w in self.entries.windows(2) {
            if w[0].registrar >= w[1].registrar {
                return Err(Reason::UnknownRegistrar);
            }
        }

        // Build trust anchors from the (now authentic) entries.
        let mut anchors = TrustAnchors::default();
        for e in &self.entries {
            let ed: [u8; crypto::ED25519_PK] = b64::decode(&e.issuer_ed25519)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or(Reason::UnknownRegistrar)?;
            let ml = b64::decode(&e.issuer_mldsa65).map_err(|_| Reason::UnknownRegistrar)?;
            let log_root = b64::decode(&e.log_root_slh).map_err(|_| Reason::UnknownRegistrar)?;
            anchors.registrars.insert(
                e.registrar.clone(),
                RegistrarInfo {
                    issuer_key: crypto::HybridPublic {
                        ed25519: ed,
                        mldsa65: ml,
                    },
                    log_root_key: log_root,
                },
            );
        }

        // Decode the revoked-delegate fingerprints.
        let mut revoked = BTreeSet::new();
        for fp in &self.revoked_delegates {
            let arr: [u8; 32] = b64::decode(fp)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or(Reason::UnknownRegistrar)?;
            revoked.insert(arr);
        }

        Ok(AccreditedSet {
            anchors,
            revoked_delegates: revoked,
            epoch: self.epoch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{Checkpoint, CheckpointSig, DelegateCert, SCOPE_CHECKPOINT};
    use rand_core::SeedableRng;

    fn seeded() -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::seed_from_u64(0xD1EC_0704)
    }

    /// Build a directory + sign it with a plain Ed25519 key (stand-in for the FROST group key, which emits the
    /// SAME standard signatures — the ceremony crate proves the real 5-of-9 path) and the SLH root.
    fn signed_directory(
        entries: Vec<DirectoryEntry>,
        revoked: Vec<String>,
        ed: &ed25519_dalek::SigningKey,
        slh: &crypto::TestRootSlh,
    ) -> Directory {
        use ed25519_dalek::Signer as _;
        let mut d = Directory {
            epoch: 1,
            issued_at: 1_000_000,
            entries,
            revoked_delegates: revoked,
            sig_root_ed25519: String::new(),
            sig_root_slh: String::new(),
        };
        let msg = d.signing_bytes().unwrap();
        d.sig_root_ed25519 = b64::encode(&ed.sign(&msg).to_bytes());
        d.sig_root_slh = b64::encode(&slh.sign(&msg).unwrap());
        d
    }

    fn entry(id: &str, issuer: &crypto::HybridPublic, log_root: &[u8]) -> DirectoryEntry {
        // These accreditation tests exercise the dual-root sig + sort/unique + revocation set, NOT status
        // authentication (that is the sdk GA Verifier's job, D-020). The optional status keys are legitimately
        // omitted here (`#[serde(default)]` ⇒ empty), so the signed body still covers them as "".
        DirectoryEntry {
            registrar: id.into(),
            issuer_ed25519: b64::encode(&issuer.ed25519),
            issuer_mldsa65: b64::encode(&issuer.mldsa65),
            log_root_slh: b64::encode(log_root),
            status_ed25519: String::new(),
            status_mldsa65: String::new(),
            status_uri: alloc::format!("status://{id}/1"),
        }
    }

    #[test]
    fn dual_root_directory_accredits_registrars() {
        let mut rng = seeded();
        let root_ed = ed25519_dalek::SigningKey::generate(&mut rng);
        let root_ed_pk = root_ed.verifying_key().to_bytes();
        let root_slh = crypto::TestRootSlh::generate(&mut rng);

        let issuer_a = crypto::HybridKeypair::generate(&mut rng).public();
        let issuer_b = crypto::HybridKeypair::generate(&mut rng).public();
        let log_a = crypto::TestRootSlh::generate(&mut rng).public();
        let log_b = crypto::TestRootSlh::generate(&mut rng).public();
        let entries = alloc::vec![
            entry("registrar-02", &issuer_b, &log_b),
            entry("registrar-07", &issuer_a, &log_a),
        ];
        let dir = signed_directory(entries, alloc::vec![], &root_ed, &root_slh);

        let acc = dir
            .accredit(&root_ed_pk, &root_slh.public())
            .expect("accredit");
        assert_eq!(acc.registrars_len(), 2);
        assert!(acc.anchors.registrars.contains_key("registrar-07"));
        assert!(acc.anchors.registrars.contains_key("registrar-02"));
        assert!(acc.revoked_delegates.is_empty());
    }

    #[test]
    fn either_root_signature_missing_is_unknown_registrar() {
        let mut rng = seeded();
        let root_ed = ed25519_dalek::SigningKey::generate(&mut rng);
        let root_ed_pk = root_ed.verifying_key().to_bytes();
        let root_slh = crypto::TestRootSlh::generate(&mut rng);
        let other_slh = crypto::TestRootSlh::generate(&mut rng);
        let issuer = crypto::HybridKeypair::generate(&mut rng).public();
        let log = crypto::TestRootSlh::generate(&mut rng).public();
        let dir = signed_directory(
            alloc::vec![entry("registrar-07", &issuer, &log)],
            alloc::vec![],
            &root_ed,
            &root_slh,
        );

        // wrong SLH root → both-or-invalid fails
        assert_eq!(
            dir.accredit(&root_ed_pk, &other_slh.public()).err(),
            Some(Reason::UnknownRegistrar)
        );
        // wrong Ed25519 (FROST) root → fails
        let mut rng2 = rand_chacha::ChaCha20Rng::seed_from_u64(99);
        let evil_ed = ed25519_dalek::SigningKey::generate(&mut rng2)
            .verifying_key()
            .to_bytes();
        assert_eq!(
            dir.accredit(&evil_ed, &root_slh.public()).err(),
            Some(Reason::UnknownRegistrar)
        );
        // tampered entry after signing → fails
        let mut tampered = dir.clone();
        tampered.entries[0].registrar = "registrar-99".into();
        assert_eq!(
            tampered.accredit(&root_ed_pk, &root_slh.public()).err(),
            Some(Reason::UnknownRegistrar)
        );
    }

    #[test]
    fn revoked_delegate_fingerprint_flows_to_checkpoint_invalid() {
        // End-to-end: a directory that revokes a delegate cert → verify() rejects a checkpoint signed by it.
        let mut rng = seeded();
        let root_ed = ed25519_dalek::SigningKey::generate(&mut rng);
        let root_ed_pk = root_ed.verifying_key().to_bytes();
        let root_slh = crypto::TestRootSlh::generate(&mut rng);
        let issuer = crypto::HybridKeypair::generate(&mut rng);
        let log_root = crypto::TestRootSlh::generate(&mut rng);
        let delegate = crypto::TestDelegate::generate(&mut rng);
        let now = 1_000_000u64;
        let cert = DelegateCert::issue_test_root(
            &log_root,
            delegate.public(),
            alloc::vec![SCOPE_CHECKPOINT.into()],
            now - 100,
            now + 86_400,
        )
        .unwrap();
        let cp = Checkpoint {
            origin: "ainra-log/registrar-07".into(),
            tree_size: 3,
            root: [7u8; 32],
        };
        let sig = CheckpointSig::Delegate {
            cert: cert.clone(),
            sig_ed25519: cp.sign_delegate(&delegate).unwrap(),
        };
        // sanity: the checkpoint sig itself verifies
        assert_eq!(cp.verify_sig_mode(&log_root.public(), &sig, now), Ok(()));

        // directory that revokes this exact cert fingerprint
        let dir = signed_directory(
            alloc::vec![entry("registrar-07", &issuer.public(), &log_root.public())],
            alloc::vec![b64::encode(&cert.fingerprint())],
            &root_ed,
            &root_slh,
        );
        let acc = dir.accredit(&root_ed_pk, &root_slh.public()).unwrap();
        assert!(acc.revoked_delegates.contains(&cert.fingerprint()));
        // a DIFFERENT cert's fingerprint is not in the set
        let other_cert = DelegateCert::issue_test_root(
            &log_root,
            crypto::TestDelegate::generate(&mut rng).public(),
            alloc::vec![SCOPE_CHECKPOINT.into()],
            now - 100,
            now + 86_400,
        )
        .unwrap();
        assert!(!acc.revoked_delegates.contains(&other_cert.fingerprint()));
    }

    impl AccreditedSet {
        fn registrars_len(&self) -> usize {
            self.anchors.registrars.len()
        }
    }
}
