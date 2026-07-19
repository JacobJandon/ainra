// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The genesis ceremony orchestration (rehearsal). Runs the dual root, accredits registrars into a signed
//! [`Directory`], certifies each registrar's checkpoint delegate, and — crucially — **verifies its own output** the
//! way a stranger would (`Directory::accredit`), so the ceremony proves the artifacts it emits are trust-anchored.
//!
//! Dual root (MTS §13 / ADR-001):
//!   * **FROST 5-of-9 Ed25519** (`crate::frost::ThresholdRoot`) — the group key + a real 5-signer threshold signature
//!     over the directory (standard RFC 8032; a verifier can't tell it's thresholded);
//!   * **SLH-DSA-SHA2-128s** ceremony root — post-quantum diversity; signs the same directory bytes.
//!
//! A verifier accepts the directory only if BOTH signatures verify (both-or-invalid).

use ainra_core::checkpoint::{DelegateCert, SCOPE_CHECKPOINT};
use ainra_core::crypto::{HybridKeypair, TestDelegate, TestRootSlh};
use ainra_core::directory::{Directory, DirectoryEntry};
use ainra_core::{b64, Reason};
use rand_core::CryptoRngCore;

use crate::frost::{FrostError, ThresholdRoot};

/// One accredited registrar's keys, as minted at the ceremony. Public halves go into the directory; the secret
/// halves would live in the registrar's own keystore (here they stay in-process for the rehearsal).
pub struct RegistrarKeys {
    pub id: String,
    pub issuer: HybridKeypair,
    pub log_root: TestRootSlh,
    pub delegate: TestDelegate,
    /// The registrar's Token Status List signing key (D-020) — its public half goes in the directory so a verifier
    /// authenticates presented status lists against it.
    pub status: HybridKeypair,
    /// The root-certified checkpoint-signing delegate cert (ADR-002) for this registrar's log.
    pub cert: DelegateCert,
}

/// The full genesis output: the two ceremony roots, the accredited registrars, and the dual-root-signed directory.
pub struct Genesis {
    pub root_ed: ThresholdRoot,
    pub root_slh: TestRootSlh,
    pub registrars: Vec<RegistrarKeys>,
    pub directory: Directory,
}

/// FROST quorum used to sign at the rehearsal (custodians 1..5 of 9). Production rotates the quorum.
const QUORUM_5_OF_9: &[u16] = &[1, 2, 3, 4, 5];
/// Delegate/cert validity for the rehearsal (90 days, inside the ADR-002 ≤ 92-day cap from
/// [`ainra_core::consts`] — the compile-time assert keeps the rehearsal honest to the cap).
const VALIDITY: u64 = 90 * 24 * 60 * 60;
const _: () = assert!(VALIDITY <= ainra_core::consts::DELEGATE_CERT_MAX_SECS);

impl Genesis {
    /// Run the whole genesis rehearsal. `registrar_ids` are accredited (each gets a fresh issuer key, log root, and
    /// certified delegate); `now` stamps the directory + certs; `revoked` fingerprints (usually empty at genesis)
    /// go into the directory's revocation list.
    pub fn run(
        registrar_ids: &[&str],
        now: u64,
        revoked: Vec<[u8; 32]>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, FrostError> {
        // 1. DKG the FROST 5-of-9 Ed25519 root (no dealer ever holds the whole secret).
        let root_ed = ThresholdRoot::dkg(9, 5, rng)?;
        // 2. Generate the SLH-DSA ceremony root (PQ diversity).
        let root_slh = TestRootSlh::generate(rng);

        // 3. Accredit each registrar: issuer key + its own log root + a certified checkpoint delegate.
        let mut registrars = Vec::new();
        let mut entries = Vec::new();
        for &id in registrar_ids {
            let issuer = HybridKeypair::generate(rng);
            let log_root = TestRootSlh::generate(rng);
            let delegate = TestDelegate::generate(rng);
            let status = HybridKeypair::generate(rng);
            let cert = DelegateCert::issue_test_root(
                &log_root,
                delegate.public(),
                vec![SCOPE_CHECKPOINT.to_string()],
                now,
                now + VALIDITY,
            )
            .map_err(|e| FrostError(format!("cert: {e:?}")))?;
            let ip = issuer.public();
            let sp = status.public();
            entries.push(DirectoryEntry {
                registrar: id.to_string(),
                issuer_ed25519: b64::encode(&ip.ed25519),
                issuer_mldsa65: b64::encode(&ip.mldsa65),
                log_root_slh: b64::encode(&log_root.public()),
                status_ed25519: b64::encode(&sp.ed25519),
                status_mldsa65: b64::encode(&sp.mldsa65),
                status_uri: format!("status://{id}/1"),
            });
            registrars.push(RegistrarKeys {
                id: id.to_string(),
                issuer,
                log_root,
                delegate,
                status,
                cert,
            });
        }
        // Directory entries MUST be sorted+unique (canonical; enforced at accredit).
        entries.sort_by(|a, b| a.registrar.cmp(&b.registrar));

        // 4. Build the directory and DUAL-sign it: FROST threshold Ed25519 + SLH-DSA, over the same canonical bytes.
        let mut directory = Directory {
            epoch: 1,
            issued_at: now,
            entries,
            revoked_delegates: revoked.iter().map(|f| b64::encode(f)).collect(),
            sig_root_ed25519: String::new(),
            sig_root_slh: String::new(),
        };
        let msg = directory
            .signing_bytes()
            .map_err(|e| FrostError(format!("signing bytes: {e:?}")))?;
        let ed_sig = root_ed.threshold_sign(&msg, QUORUM_5_OF_9, rng)?;
        directory.sig_root_ed25519 = b64::encode(&ed_sig);
        directory.sig_root_slh = b64::encode(
            &root_slh
                .sign(&msg)
                .map_err(|e| FrostError(format!("slh: {e:?}")))?,
        );

        Ok(Self {
            root_ed,
            root_slh,
            registrars,
            directory,
        })
    }

    /// The FROST group public key (32 B) — the Ed25519 root pubkey published with the ceremony.
    pub fn root_ed_public(&self) -> [u8; 32] {
        self.root_ed.group_public()
    }

    /// Build a dual-root-signed [`Directory`] over registrars accredited **externally** (a live registrar-box hands
    /// its published keys via `/accreditation`). DKGs a fresh FROST root + SLH root, sorts the entries canonically,
    /// dual-signs, and returns `(directory, root_ed_public, root_slh_public)`. This composes the real ceremony with
    /// the real registrar daemon for the M5 testbed; a production ceremony would persist the custodian shares.
    pub fn accredit_external(
        mut entries: Vec<DirectoryEntry>,
        revoked: Vec<[u8; 32]>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Directory, [u8; 32], Vec<u8>), FrostError> {
        entries.sort_by(|a, b| a.registrar.cmp(&b.registrar));
        let root_ed = ThresholdRoot::dkg(9, 5, rng)?;
        let root_slh = TestRootSlh::generate(rng);
        let mut d = Directory {
            epoch: 1,
            issued_at: now,
            entries,
            revoked_delegates: revoked.iter().map(|f| b64::encode(f)).collect(),
            sig_root_ed25519: String::new(),
            sig_root_slh: String::new(),
        };
        let msg = d
            .signing_bytes()
            .map_err(|e| FrostError(format!("signing bytes: {e:?}")))?;
        d.sig_root_ed25519 = b64::encode(&root_ed.threshold_sign(&msg, QUORUM_5_OF_9, rng)?);
        d.sig_root_slh = b64::encode(
            &root_slh
                .sign(&msg)
                .map_err(|e| FrostError(format!("slh: {e:?}")))?,
        );
        Ok((d, root_ed.group_public(), root_slh.public()))
    }

    /// Independently verify the directory the way a stranger would: dual-root `accredit`. Returns the number of
    /// accredited registrars, or the failure reason. This is the ceremony proving its output is trust-anchored.
    pub fn verify_output(&self) -> Result<usize, Reason> {
        let acc = self
            .directory
            .accredit(&self.root_ed_public(), &self.root_slh.public())?;
        Ok(acc.anchors.registrars.len())
    }

    /// Publish a NEW directory epoch that additionally revokes `fingerprints` (delegate-cert revocation / rotation).
    /// Re-signed by both roots. `now` stamps the new epoch.
    pub fn republish_with_revocations(
        &self,
        fingerprints: &[[u8; 32]],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Directory, FrostError> {
        let mut d = self.directory.clone();
        d.epoch += 1;
        d.issued_at = now;
        for f in fingerprints {
            let e = b64::encode(f);
            if !d.revoked_delegates.contains(&e) {
                d.revoked_delegates.push(e);
            }
        }
        d.revoked_delegates.sort();
        d.sig_root_ed25519 = String::new();
        d.sig_root_slh = String::new();
        let msg = d
            .signing_bytes()
            .map_err(|e| FrostError(format!("signing bytes: {e:?}")))?;
        d.sig_root_ed25519 = b64::encode(&self.root_ed.threshold_sign(&msg, QUORUM_5_OF_9, rng)?);
        d.sig_root_slh = b64::encode(
            &self
                .root_slh
                .sign(&msg)
                .map_err(|e| FrostError(format!("slh: {e:?}")))?,
        );
        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const NOW: u64 = 1_775_865_600;

    #[test]
    fn genesis_output_is_trust_anchored() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x006E_E515);
        let g = Genesis::run(
            &["registrar-02", "registrar-07", "registrar-11"],
            NOW,
            vec![],
            &mut rng,
        )
        .expect("genesis");
        assert_eq!(
            g.verify_output(),
            Ok(3),
            "the ceremony's directory must self-verify"
        );
        // A wrong SLH root breaks the dual-root check.
        let other = TestRootSlh::generate(&mut rng);
        assert_eq!(
            g.directory
                .accredit(&g.root_ed_public(), &other.public())
                .err(),
            Some(Reason::UnknownRegistrar)
        );
    }

    #[test]
    fn revocation_republish_kills_the_delegate() {
        use ainra_core::checkpoint::{Checkpoint, CheckpointSig};
        let mut rng = ChaCha20Rng::seed_from_u64(0x4E00_C500);
        let g = Genesis::run(&["registrar-07"], NOW, vec![], &mut rng).expect("genesis");
        let reg = &g.registrars[0];

        // A checkpoint the registrar's delegate signs — valid under the genesis directory.
        let cp = Checkpoint {
            origin: format!("ainra-log/{}", reg.id),
            tree_size: 5,
            root: [9u8; 32],
        };
        let sig = CheckpointSig::Delegate {
            cert: reg.cert.clone(),
            sig_ed25519: cp.sign_delegate(&reg.delegate).unwrap(),
        };
        let at = NOW + 10 * 24 * 3600;
        assert_eq!(cp.verify_sig_mode(&reg.log_root.public(), &sig, at), Ok(()));

        // Republish a new epoch revoking this delegate's cert; the revocation set now contains its fingerprint.
        let fp = reg.cert.fingerprint();
        let d2 = g
            .republish_with_revocations(&[fp], NOW + 3600, &mut rng)
            .expect("republish");
        let acc = d2
            .accredit(&g.root_ed_public(), &g.root_slh.public())
            .expect("accredit");
        assert!(
            acc.revoked_delegates.contains(&fp),
            "the delegate is now revoked in epoch 2"
        );
        assert_eq!(d2.epoch, 2);
    }
}
