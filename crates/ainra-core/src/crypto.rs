// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Hybrid signatures — the crux (brief §0: "both signatures or invalid").
//!
//! Registrar/lineage keys are **hybrid Ed25519 + ML-DSA-65, both mandatory** (MTS ADR-003): a credential missing
//! or failing *either* signature is INVALID with reason [`Reason::AlgDowngrade`] (missing) or [`Reason::SigInvalid`]
//! (present-but-wrong). The root/checkpoint layer additionally uses **SLH-DSA-SHA2-128s** (FIPS 205) for
//! post-quantum assumption diversity (MTS ADR-001) — verify + a clearly-labeled TEST-ROOT signer for fixtures.
//!
//! Only audited libraries are used (MTS §3): `ed25519-dalek`, RustCrypto `ml-dsa` (FIPS 204), `slh-dsa` (FIPS 205).
//! The exact key/sig byte sizes are asserted as conformance tests; a deviation is a broken dependency (brief §3),
//! never silently accepted.

use alloc::vec::Vec;

// ed25519-dalek re-exports the `signature` crate's Signer/Verifier; slh-dsa's SigningKey/VerifyingKey impl the
// same traits, so these two imports cover ed25519 AND slh-dsa sign/verify. `Keypair` is needed for
// `SigningKey::verifying_key()` (slh-dsa impls `KeypairRef` → blanket `Keypair`).
use ed25519_dalek::{Signer as _, Verifier as _};
use ml_dsa::{KeyGen, MlDsa65};
use rand_core::CryptoRngCore;
use signature::Keypair as _;
use slh_dsa::Sha2_128s;

use crate::error::{Error, Result};
use crate::verdict::Reason;

// ── Exact sizes (FIPS 204/205 + RFC 8032). Asserted in tests as conformance (brief §3). ────────────────────────
/// Ed25519 public-key length (bytes).
pub const ED25519_PK: usize = 32;
/// Ed25519 signature length (bytes).
pub const ED25519_SIG: usize = 64;
/// ML-DSA-65 public-key length (bytes) — FIPS 204.
pub const MLDSA65_PK: usize = 1952;
/// ML-DSA-65 secret-key length (bytes) — FIPS 204.
pub const MLDSA65_SK: usize = 4032;
/// ML-DSA-65 signature length (bytes) — FIPS 204.
pub const MLDSA65_SIG: usize = 3309;
/// SLH-DSA-SHA2-128s public-key length (bytes) — FIPS 205.
pub const SLHDSA128S_PK: usize = 32;
/// SLH-DSA-SHA2-128s signature length (bytes) — FIPS 205.
pub const SLHDSA128S_SIG: usize = 7856;

const MLDSA_CTX: &[u8] = b""; // empty context string; deterministic signing (reproducible vectors)

/// A hybrid keypair (Ed25519 + ML-DSA-65). Fixture/registrar-side; the verify path never needs the secret keys.
pub struct HybridKeypair {
    ed: ed25519_dalek::SigningKey,
    ml: ml_dsa::KeyPair<MlDsa65>,
}

/// A hybrid public key = the two public keys a verifier chains to.
#[derive(Clone)]
pub struct HybridPublic {
    pub ed25519: [u8; ED25519_PK],
    pub mldsa65: Vec<u8>, // 1952 bytes
}

/// A hybrid signature = BOTH signatures. Either being absent is an `alg_downgrade` at verify time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridSig {
    pub ed25519: Vec<u8>, // 64 bytes
    pub mldsa65: Vec<u8>, // 3309 bytes
}

impl HybridKeypair {
    /// Generate a fresh hybrid keypair. `rng` must be a CSPRNG; vector-gen passes a *seeded* CSPRNG for
    /// reproducibility (the seed is public and labeled TEST — never a production key).
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let ed = ed25519_dalek::SigningKey::generate(rng);
        let ml = MlDsa65::key_gen(rng);
        Self { ed, ml }
    }

    pub fn public(&self) -> HybridPublic {
        HybridPublic {
            ed25519: self.ed.verifying_key().to_bytes(),
            mldsa65: self.ml.verifying_key().encode().to_vec(),
        }
    }

    /// Sign `msg` with BOTH algorithms. ML-DSA uses the deterministic variant so vectors are reproducible;
    /// Ed25519 is deterministic by construction (RFC 8032).
    pub fn sign(&self, msg: &[u8]) -> Result<HybridSig> {
        let ed = self.ed.sign(msg).to_bytes().to_vec();
        let ml = self
            .ml
            .signing_key()
            .sign_deterministic(msg, MLDSA_CTX)
            .map_err(|_| Error::Canon("ml-dsa sign failed".into()))?
            .encode()
            .to_vec();
        Ok(HybridSig {
            ed25519: ed,
            mldsa65: ml,
        })
    }
}

/// Verify a hybrid signature over `msg`. Fail order is fixed + documented so the reason is deterministic across
/// implementations (needed for the diff-harness): (1) downgrade check → (2) Ed25519 → (3) ML-DSA-65.
///
/// Returns `Ok(())` iff BOTH signatures are present and valid; otherwise `Err(Reason)` with the closed reason.
pub fn verify_hybrid(
    pk: &HybridPublic,
    msg: &[u8],
    sig: &HybridSig,
) -> core::result::Result<(), Reason> {
    // (1) both-signatures-or-invalid: an absent/short signature is a downgrade attempt.
    if sig.ed25519.len() != ED25519_SIG || sig.mldsa65.len() != MLDSA65_SIG {
        return Err(Reason::AlgDowngrade);
    }
    // (2) Ed25519
    let edvk =
        ed25519_dalek::VerifyingKey::from_bytes(&pk.ed25519).map_err(|_| Reason::SigInvalid)?;
    let edsig_bytes: [u8; ED25519_SIG] = sig
        .ed25519
        .as_slice()
        .try_into()
        .map_err(|_| Reason::AlgDowngrade)?;
    let edsig = ed25519_dalek::Signature::from_bytes(&edsig_bytes);
    if edvk.verify(msg, &edsig).is_err() {
        return Err(Reason::SigInvalid);
    }
    // (3) ML-DSA-65
    let mlvk = decode_mldsa_pk(&pk.mldsa65).ok_or(Reason::SigInvalid)?;
    let mlsig = decode_mldsa_sig(&sig.mldsa65).ok_or(Reason::SigInvalid)?;
    if !mlvk.verify_with_context(msg, MLDSA_CTX, &mlsig) {
        return Err(Reason::SigInvalid);
    }
    Ok(())
}

fn decode_mldsa_pk(bytes: &[u8]) -> Option<ml_dsa::VerifyingKey<MlDsa65>> {
    let enc = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(bytes).ok()?;
    Some(ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc))
}
fn decode_mldsa_sig(bytes: &[u8]) -> Option<ml_dsa::Signature<MlDsa65>> {
    let enc = ml_dsa::EncodedSignature::<MlDsa65>::try_from(bytes).ok()?;
    ml_dsa::Signature::<MlDsa65>::decode(&enc)
}

// ── SLH-DSA-SHA2-128s (root / checkpoint PQ layer) — verify + labeled TEST-ROOT signer ─────────────────────────

/// A TEST-ROOT SLH-DSA signer for fixtures. **Never a production root key.** The single-key stand-in for the
/// FROST/SLH ceremony root that M1 does not implement (DECISIONS D-005).
pub struct TestRootSlh {
    sk: slh_dsa::SigningKey<Sha2_128s>,
}

impl TestRootSlh {
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        Self {
            sk: slh_dsa::SigningKey::<Sha2_128s>::new(rng),
        }
    }
    pub fn public(&self) -> Vec<u8> {
        self.sk.verifying_key().to_bytes().to_vec()
    }
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let sig = self
            .sk
            .try_sign(msg)
            .map_err(|_| Error::Canon("slh-dsa sign failed".into()))?;
        Ok(sig.to_bytes().to_vec())
    }
}

/// A TEST delegate Ed25519 keypair (ADR-002's online signer stand-in — in production this is 2-of-3 FROST among
/// ops nodes, which emits the SAME RFC 8032 signatures, so verification is identical). Never a production key.
pub struct TestDelegate {
    sk: ed25519_dalek::SigningKey,
}

impl TestDelegate {
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        Self {
            sk: ed25519_dalek::SigningKey::generate(rng),
        }
    }
    pub fn public(&self) -> [u8; ED25519_PK] {
        self.sk.verifying_key().to_bytes()
    }
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.sk.sign(msg).to_bytes().to_vec()
    }
}

/// Plain Ed25519 verification (delegate checkpoints, witness cosignatures). Fail closed on any decode error.
pub fn ed25519_verify(pk: &[u8; ED25519_PK], msg: &[u8], sig: &[u8; ED25519_SIG]) -> bool {
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(pk) else {
        return false;
    };
    vk.verify(msg, &ed25519_dalek::Signature::from_bytes(sig))
        .is_ok()
}

/// Verify an SLH-DSA-SHA2-128s signature (the checkpoint PQ layer). Fail closed on any decode/verify error.
pub fn slh_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let vk = match slh_dsa::VerifyingKey::<Sha2_128s>::try_from(pk) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let s = match slh_dsa::Signature::<Sha2_128s>::try_from(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify(msg, &s).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::SeedableRng;

    fn seeded() -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::seed_from_u64(0xA1_11_A2_02)
    }

    #[test]
    fn sizes_are_fips_exact() {
        // If any of these fail, the crypto dependency is broken — never silently accepted (brief §3).
        let mut rng = seeded();
        let kp = HybridKeypair::generate(&mut rng);
        let pk = kp.public();
        assert_eq!(pk.ed25519.len(), ED25519_PK);
        assert_eq!(pk.mldsa65.len(), MLDSA65_PK, "ML-DSA-65 pk must be 1952 B");
        assert_eq!(
            kp.ml.signing_key().encode().to_vec().len(),
            MLDSA65_SK,
            "ML-DSA-65 sk must be 4032 B"
        );
        let sig = kp.sign(b"m").unwrap();
        assert_eq!(sig.ed25519.len(), ED25519_SIG);
        assert_eq!(
            sig.mldsa65.len(),
            MLDSA65_SIG,
            "ML-DSA-65 sig must be 3309 B"
        );
        let root = TestRootSlh::generate(&mut rng);
        assert_eq!(
            root.public().len(),
            SLHDSA128S_PK,
            "SLH-DSA-128s pk must be 32 B"
        );
        assert_eq!(
            root.sign(b"cp").unwrap().len(),
            SLHDSA128S_SIG,
            "SLH-DSA-128s sig must be 7856 B"
        );
    }

    #[test]
    fn hybrid_sign_verify_roundtrip() {
        let mut rng = seeded();
        let kp = HybridKeypair::generate(&mut rng);
        let pk = kp.public();
        let msg = b"ainra:registrar-01:acme:invoicing@1.0.0";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(verify_hybrid(&pk, msg, &sig), Ok(()));
        // tampered message → sig_invalid (both present, one fails)
        assert_eq!(
            verify_hybrid(&pk, b"different", &sig),
            Err(Reason::SigInvalid)
        );
    }

    #[test]
    fn downgrade_is_rejected() {
        let mut rng = seeded();
        let kp = HybridKeypair::generate(&mut rng);
        let pk = kp.public();
        let msg = b"m";
        let good = kp.sign(msg).unwrap();
        // strip the ML-DSA signature → alg_downgrade
        let no_ml = HybridSig {
            ed25519: good.ed25519.clone(),
            mldsa65: Vec::new(),
        };
        assert_eq!(verify_hybrid(&pk, msg, &no_ml), Err(Reason::AlgDowngrade));
        // strip the Ed25519 signature → alg_downgrade
        let no_ed = HybridSig {
            ed25519: Vec::new(),
            mldsa65: good.mldsa65.clone(),
        };
        assert_eq!(verify_hybrid(&pk, msg, &no_ed), Err(Reason::AlgDowngrade));
        // a forged (wrong-key) ML-DSA sig of the right length → sig_invalid, not downgrade
        let other = HybridKeypair::generate(&mut rng).sign(msg).unwrap();
        let mixed = HybridSig {
            ed25519: good.ed25519.clone(),
            mldsa65: other.mldsa65.clone(),
        };
        assert_eq!(verify_hybrid(&pk, msg, &mixed), Err(Reason::SigInvalid));
    }

    #[test]
    fn slh_root_sign_verify() {
        let mut rng = seeded();
        let root = TestRootSlh::generate(&mut rng);
        let pk = root.public();
        let msg = b"checkpoint:origin size root";
        let sig = root.sign(msg).unwrap();
        assert!(slh_verify(&pk, msg, &sig));
        assert!(!slh_verify(&pk, b"tampered", &sig));
    }
}
