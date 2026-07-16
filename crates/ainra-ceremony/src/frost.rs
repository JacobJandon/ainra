// SPDX-License-Identifier: Apache-2.0 OR MIT
//! FROST 5-of-9 threshold Ed25519 (audited ZF `frost-ed25519`, RFC 9591) — the ceremony's Ed25519 root component.
//!
//! Two properties matter for AINRA:
//!   1. the group **verifying key** is a standard 32-byte Ed25519 public key, and an aggregated 5-of-9 signature is
//!      a standard 64-byte RFC 8032 signature — so `ainra_core::crypto::ed25519_verify` accepts it and a verifier
//!      cannot tell the root is thresholdized (MTS §13, ADR-001);
//!   2. **any 4 of 9** shares cannot produce a valid signature (threshold enforced by the scheme).
//!
//! We run a real **distributed key generation** (DKG, `frost::keys::dkg`) among the 9 custodians — no trusted dealer
//! ever holds the whole secret — then a 2-round threshold signing with a 5-signer quorum.

use std::collections::BTreeMap;

use frost_ed25519 as frost;
use frost_ed25519::{keys::PublicKeyPackage, Identifier};
use rand_core::CryptoRngCore;

/// The 9 custodians' key material after DKG. `secret_shares` never reconstruct the group secret in one place.
pub struct ThresholdRoot {
    pub max_signers: u16,
    pub min_signers: u16,
    key_packages: BTreeMap<Identifier, frost::keys::KeyPackage>,
    pubkey_package: PublicKeyPackage,
}

/// Error surfaced from the FROST library (kept opaque; the ceremony logs then aborts on any of these).
#[derive(Debug)]
pub struct FrostError(pub String);
impl From<frost::Error> for FrostError {
    fn from(e: frost::Error) -> Self {
        FrostError(format!("{e:?}"))
    }
}
/// Map any FROST-library result into our error, with context.
fn fe<T, E: core::fmt::Debug>(r: Result<T, E>) -> Result<T, FrostError> {
    r.map_err(|e| FrostError(format!("{e:?}")))
}

impl ThresholdRoot {
    /// Run FROST DKG for `min`-of-`max` (5-of-9 for AINRA). Every participant runs all three rounds; the group
    /// secret is never assembled. Returns the custodians' key packages + the public key package.
    pub fn dkg(max: u16, min: u16, rng: &mut impl CryptoRngCore) -> Result<Self, FrostError> {
        let ids: Vec<Identifier> = (1..=max)
            .map(|i| Identifier::try_from(i).expect("nonzero identifier"))
            .collect();

        // ── Round 1: each participant broadcasts a commitment package + keeps a round-1 secret.
        let mut r1_secret = BTreeMap::new();
        let mut r1_pkg = BTreeMap::new();
        for id in &ids {
            let (secret, package) = fe(frost::keys::dkg::part1(*id, max, min, &mut *rng))?;
            r1_secret.insert(*id, secret);
            r1_pkg.insert(*id, package);
        }

        // ── Round 2: each participant consumes everyone else's round-1 package, producing per-recipient packages.
        let mut r2_secret = BTreeMap::new();
        let mut r2_pkg_by_sender = BTreeMap::new();
        for id in &ids {
            let others: BTreeMap<Identifier, _> = r1_pkg
                .iter()
                .filter(|(k, _)| *k != id)
                .map(|(k, v)| (*k, v.clone()))
                .collect();
            let (secret, packages) = fe(frost::keys::dkg::part2(
                r1_secret.remove(id).expect("r1 secret"),
                &others,
            ))?;
            r2_secret.insert(*id, secret);
            r2_pkg_by_sender.insert(*id, packages);
        }

        // ── Round 3: each participant assembles the round-2 packages addressed TO it → its key package.
        let mut key_packages = BTreeMap::new();
        let mut pubkey_package = None;
        for id in &ids {
            let r1_for_me: BTreeMap<Identifier, _> = r1_pkg
                .iter()
                .filter(|(k, _)| *k != id)
                .map(|(k, v)| (*k, v.clone()))
                .collect();
            let r2_for_me: BTreeMap<Identifier, _> = r2_pkg_by_sender
                .iter()
                .filter(|(sender, _)| *sender != id)
                .map(|(sender, pkgs)| (*sender, pkgs.get(id).expect("r2 package for me").clone()))
                .collect();
            let (key_package, pkp) = fe(frost::keys::dkg::part3(
                r2_secret.get(id).expect("r2 secret"),
                &r1_for_me,
                &r2_for_me,
            ))?;
            key_packages.insert(*id, key_package);
            pubkey_package = Some(pkp);
        }

        Ok(Self {
            max_signers: max,
            min_signers: min,
            key_packages,
            pubkey_package: pubkey_package.expect("dkg produced a public key package"),
        })
    }

    /// The group Ed25519 public key as 32 raw bytes — the root pubkey published in the directory. A standard
    /// Ed25519 verifying key.
    pub fn group_public(&self) -> [u8; 32] {
        let v = self
            .pubkey_package
            .verifying_key()
            .serialize()
            .expect("serialize verifying key");
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }

    /// Threshold-sign `msg` with a quorum of exactly `signers.len()` custodians (must be ≥ `min_signers`). Returns a
    /// standard 64-byte RFC 8032 Ed25519 signature. `signers` are 1-based custodian numbers.
    pub fn threshold_sign(
        &self,
        msg: &[u8],
        signers: &[u16],
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 64], FrostError> {
        // A signer id must be a valid 1-based custodian (nonzero). Reject bad input rather than panic.
        let quorum: Vec<Identifier> = signers
            .iter()
            .map(|&i| {
                Identifier::try_from(i).map_err(|_| FrostError(format!("invalid signer id {i}")))
            })
            .collect::<Result<_, _>>()?;

        // Round 1: each quorum member produces nonces (secret) + commitments (public).
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for id in &quorum {
            let kp = self
                .key_packages
                .get(id)
                .ok_or(FrostError("unknown signer".into()))?;
            let (n, c) = frost::round1::commit(kp.signing_share(), &mut *rng);
            nonces.insert(*id, n);
            commitments.insert(*id, c);
        }

        // Coordinator forms the signing package (commitments + message).
        let signing_package = frost::SigningPackage::new(commitments, msg);

        // Round 2: each quorum member signs → a signature share.
        let mut shares = BTreeMap::new();
        for id in &quorum {
            let kp = self.key_packages.get(id).expect("key package");
            let share = fe(frost::round2::sign(&signing_package, &nonces[id], kp))?;
            shares.insert(*id, share);
        }

        // Aggregate → one standard Ed25519 signature.
        let sig = fe(frost::aggregate(
            &signing_package,
            &shares,
            &self.pubkey_package,
        ))?;
        let bytes = fe(sig.serialize())?;
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn five_of_nine_signature_verifies_through_ainra_core() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xF305_7009);
        let root = ThresholdRoot::dkg(9, 5, &mut rng).expect("dkg");
        let pk = root.group_public();
        let msg = b"AINRA genesis directory v1";

        // A 5-of-9 quorum signs; ainra-core's PLAIN Ed25519 verifier accepts it (verifier can't tell it's threshold).
        let sig = root
            .threshold_sign(msg, &[1, 2, 3, 4, 5], &mut rng)
            .expect("sign");
        assert!(
            ainra_core::crypto::ed25519_verify(&pk, msg, &sig),
            "a 5-of-9 FROST signature must verify as a standard Ed25519 signature"
        );

        // A DIFFERENT quorum (still 5) produces a different-but-valid signature over the same key.
        let sig2 = root
            .threshold_sign(msg, &[5, 6, 7, 8, 9], &mut rng)
            .expect("sign2");
        assert!(ainra_core::crypto::ed25519_verify(&pk, msg, &sig2));

        // Tampered message → reject.
        assert!(!ainra_core::crypto::ed25519_verify(&pk, b"tampered", &sig));
    }

    #[test]
    fn four_of_nine_cannot_sign() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x4009);
        let root = ThresholdRoot::dkg(9, 5, &mut rng).expect("dkg");
        // Below threshold: the scheme must refuse to aggregate a valid signature.
        let r = root.threshold_sign(b"msg", &[1, 2, 3, 4], &mut rng);
        assert!(r.is_err(), "4-of-9 must not produce a valid signature");
    }
}
