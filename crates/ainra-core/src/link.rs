// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AINRA Link (D-078): status and attribution for a credential the agent ALREADY has.
//!
//! An agent usually carries a key someone else issued or manages: a signature-agent key, a workload key. Its
//! issuer can withdraw it inside its own system, but nobody can tell a stranger's service that the key's agent has
//! been cut off, or who answers for it. A link record closes that gap without leaving the core:
//!
//! * an **accredited registrar** signs it with its hybrid key, exactly as it signs passports — both-or-invalid;
//! * it binds a key, named by its RFC 7638 thumbprint, to an **operator's passport** the same registrar issued;
//! * it carries **proof of control**: a signature by the linked key itself, so nobody can link a key they do not
//!   hold to a passport, and no key can be attributed to an operator without its holder's consent;
//! * it takes **two bits in the registrar's existing signed status list** — its own, and the passport's — so
//!   revoking the link, or the operator's whole lineage, refuses it everywhere;
//! * it is **logged before it is valid**, in the registrar's existing log, so the set of links can be audited.
//!
//! No new trust and no new list. The caller hands over the key it has ALREADY verified a signature with; this module
//! answers whether that key is linked, by whom, and whether it is still trusted.
//!
//! Order (each step's failure reason in parentheses), fixed so every implementation reports the same first failure:
//!   1. schema                                   (`schema_violation`, `name_malformed`)
//!   2. the registrar is accredited              (`unknown_registrar`)
//!   3. validity window                          (`not_yet_valid`, then `expired`)
//!   4. registrar hybrid signature               (`alg_downgrade`, then `sig_invalid`)
//!   5. the presented key IS the linked key, and it consented (`sig_invalid`)
//!   6. scope                                    (`ceiling_exceeded`)
//!   7. status: freshness, then the link's bit, then the passport's bit (`stale_status`, then `revoked`)
//!   8. logged-before-valid                      (`checkpoint_invalid`, then `not_logged`, then `registrar_distrusted`)

extern crate alloc;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::name::AinraName;
use crate::verdict::Reason;
use crate::verify::{prelog_leaf, TrustAnchors};
use crate::{b64, canon, checkpoint, crypto, status};

/// The link record's version tag. Frozen: it is inside what the registrar signs.
pub const LINK_V: &str = "ainra-link-1";
/// The purpose string the linked key signs over (proof of control). Frozen.
pub const LINK_POP_PURPOSE: &str = "ainra-link-pop-1";
/// The only subject kind in version 1: a JWK, named by its RFC 7638 thumbprint.
pub const SUBJECT_KIND_JWK: &str = "jwk";
/// Signature-agent keys and AINRA's own workload keys are Ed25519.
pub const SUBJECT_ALG_ED25519: &str = "Ed25519";
/// ES256K (RFC 8812): ECDSA over secp256k1 with SHA-256 — the keys agents that live on ledgers already hold (D-082).
/// Signatures are 64-byte `r || s` and must be low-S, so no signature can be re-encoded into a second valid one.
pub const SUBJECT_ALG_ES256K: &str = "ES256K";

/// A key a caller has already verified a signature with, as Link names it. By length: 32 bytes is an Ed25519 key,
/// 33 a compressed SEC1 secp256k1 point — so every caller that passes a 32-byte key keeps meaning Ed25519.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentedKey {
    Ed25519([u8; 32]),
    Es256k([u8; 33]),
}

impl PresentedKey {
    /// `None` for any other length.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        match b.len() {
            32 => b.try_into().ok().map(PresentedKey::Ed25519),
            33 => b.try_into().ok().map(PresentedKey::Es256k),
            _ => None,
        }
    }
    pub fn alg(&self) -> &'static str {
        match self {
            PresentedKey::Ed25519(_) => SUBJECT_ALG_ED25519,
            PresentedKey::Es256k(_) => SUBJECT_ALG_ES256K,
        }
    }
    /// The RFC 7638 thumbprint; `None` for bytes that are not a point on secp256k1.
    pub fn thumbprint(&self) -> Option<String> {
        match self {
            PresentedKey::Ed25519(k) => Some(jwk_thumbprint_ed25519(k)),
            PresentedKey::Es256k(k) => jwk_thumbprint_es256k(k),
        }
    }
    /// Verify a 64-byte signature by this key over `msg`, in the key's own algorithm.
    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> bool {
        match self {
            PresentedKey::Ed25519(k) => crypto::ed25519_verify(k, msg, sig),
            PresentedKey::Es256k(k) => es256k_verify(k, msg, sig),
        }
    }
}

impl From<[u8; 32]> for PresentedKey {
    fn from(k: [u8; 32]) -> Self {
        PresentedKey::Ed25519(k)
    }
}
/// Most capabilities a link may name (the same bound as an instance credential, D-053).
pub const MAX_LINK_SCOPE: usize = crate::instance::MAX_CAPABILITIES;

/// Which key the link is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkSubject {
    pub kind: String,
    pub alg: String,
    /// base64url(SHA-256(canonical JWK)), RFC 7638.
    pub thumbprint: String,
}

/// A status-list position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusRef {
    pub uri: String,
    pub idx: u64,
}

/// The log back-reference, as on a passport: it points INTO the log, so it is not part of what was logged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkLog {
    pub leaf: String,
}

/// The signed link claims. Field names are frozen: they are what the registrar signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkClaims {
    pub v: String,
    pub registrar: String,
    /// The operator's passport this key acts under (an AINRA name, e.g. `ainra:registrar-07:acme:invoicing@1.0.0`).
    pub passport: String,
    pub subject: LinkSubject,
    /// Capabilities the linked key may exercise. Empty means: whatever the passport allows.
    pub scope: Vec<String>,
    pub nbf: u64,
    pub exp: u64,
    pub status: StatusRef,
    pub passport_status: StatusRef,
    /// base64url Ed25519 signature by the linked key over [`pop_signing_bytes`].
    pub pop: String,
    pub log: LinkLog,
}

impl LinkClaims {
    /// Parse the exact signed bytes, refusing anything that is not a well-formed version-1 link.
    pub fn parse_checked(bytes: &[u8]) -> core::result::Result<Self, Reason> {
        let c: LinkClaims = serde_json::from_slice(bytes).map_err(|_| Reason::SchemaViolation)?;
        // The signed bytes must already be canonical: one record, one byte string, everywhere (D-029).
        let again = canon::canonicalize(&c).map_err(|_| Reason::SchemaViolation)?;
        if again.as_bytes() != bytes {
            return Err(Reason::SchemaViolation);
        }
        if c.v != LINK_V
            || c.subject.kind != SUBJECT_KIND_JWK
            || !(c.subject.alg == SUBJECT_ALG_ED25519 || c.subject.alg == SUBJECT_ALG_ES256K)
        {
            return Err(Reason::SchemaViolation);
        }
        b64::decode_array::<32>(&c.subject.thumbprint).map_err(|_| Reason::SchemaViolation)?;
        b64::decode_array::<64>(&c.pop).map_err(|_| Reason::SchemaViolation)?;
        b64::decode_array::<32>(&c.log.leaf).map_err(|_| Reason::SchemaViolation)?;
        if c.scope.len() > MAX_LINK_SCOPE || c.scope.iter().any(|s| s.is_empty() || s.len() > 128) {
            return Err(Reason::SchemaViolation);
        }
        // Both bits live in the one list the registrar signs; a link pointing at two lists cannot be checked whole.
        if c.status.uri != c.passport_status.uri || c.status.idx == c.passport_status.idx {
            return Err(Reason::SchemaViolation);
        }
        if c.nbf >= c.exp {
            return Err(Reason::SchemaViolation);
        }
        let name = AinraName::parse(&c.passport).map_err(|_| Reason::NameMalformed)?;
        // A registrar links only passports it issued itself.
        if name.registrar() != c.registrar {
            return Err(Reason::SchemaViolation);
        }
        Ok(c)
    }
}

/// RFC 7638 thumbprint of an Ed25519 public key: base64url(SHA-256(`{"crv":"Ed25519","kty":"OKP","x":"…"}`)).
/// The core's canonical encoder sorts keys and drops whitespace, which is exactly the RFC's required form.
pub fn jwk_thumbprint_ed25519(pk: &[u8; 32]) -> String {
    #[derive(Serialize)]
    struct Jwk<'a> {
        crv: &'a str,
        kty: &'a str,
        x: String,
    }
    use sha2::{Digest, Sha256};
    let j = Jwk {
        crv: "Ed25519",
        kty: "OKP",
        x: b64::encode(pk),
    };
    // canonicalize cannot fail on three ASCII strings; an empty input would only ever fail a later comparison.
    let s = canon::canonicalize(&j).unwrap_or_default();
    b64::encode(&Sha256::digest(s.as_bytes()))
}

/// RFC 7638 thumbprint of a secp256k1 key given as a compressed SEC1 point: base64url(SHA-256(
/// `{"crv":"secp256k1","kty":"EC","x":"…","y":"…"}`)), the member names and curve name RFC 8812 registers. `None`
/// when the bytes are not a compressed point on the curve.
pub fn jwk_thumbprint_es256k(sec1: &[u8; 33]) -> Option<String> {
    use k256::elliptic_curve::sec1::ToSec1Point;
    #[derive(Serialize)]
    struct Jwk<'a> {
        crv: &'a str,
        kty: &'a str,
        x: String,
        y: String,
    }
    use sha2::{Digest, Sha256};
    if !matches!(sec1[0], 0x02 | 0x03) {
        return None;
    }
    let pk = k256::PublicKey::from_sec1_bytes(sec1).ok()?;
    let p = pk.to_sec1_point(false);
    let j = Jwk {
        crv: "secp256k1",
        kty: "EC",
        x: b64::encode(p.x()?),
        y: b64::encode(p.y()?),
    };
    let s = canon::canonicalize(&j).ok()?;
    Some(b64::encode(&Sha256::digest(s.as_bytes())))
}

/// ES256K verification (RFC 8812): ECDSA over secp256k1 with SHA-256 of `msg`, the signature as 64-byte `r || s`.
/// A high-S signature is refused even though the curve math accepts it: its low-S twin is the canonical form, and
/// accepting both would give every consent two valid encodings.
pub fn es256k_verify(sec1: &[u8; 33], msg: &[u8], sig: &[u8; 64]) -> bool {
    use k256::ecdsa::signature::Verifier as _;
    use k256::ecdsa::{Signature, VerifyingKey};
    if !matches!(sec1[0], 0x02 | 0x03) {
        return false;
    }
    let (Ok(vk), Ok(s)) = (
        VerifyingKey::from_sec1_bytes(sec1),
        Signature::from_slice(sig),
    ) else {
        return false;
    };
    // High-S when normalising changes it: the same test on every k256 line (0.13 returned an Option here, 0.14 the
    // signature itself).
    if s.normalize_s() != s {
        return false;
    }
    vk.verify(msg, &s).is_ok()
}

/// What the linked key signs to consent to the link. Frozen.
pub fn pop_signing_bytes(registrar: &str, passport: &str, thumbprint: &str, nbf: u64) -> Vec<u8> {
    #[derive(Serialize)]
    struct Pop<'a> {
        purpose: &'a str,
        registrar: &'a str,
        passport: &'a str,
        thumbprint: &'a str,
        nbf: u64,
    }
    canon::canonicalize(&Pop {
        purpose: LINK_POP_PURPOSE,
        registrar,
        passport,
        thumbprint,
        nbf,
    })
    .unwrap_or_default()
    .into_bytes()
}

/// Everything a verifier hands over to check one link. Like [`crate::verify::Presentation`], the core has no clock
/// and no network: the caller supplies `now` and every fetched artefact, and the status list it supplies must
/// already be AUTHENTICATED against the registrar's status key (D-072) — this module trusts the bits it is given.
pub struct LinkCheck<'a> {
    /// The exact signed link claims.
    pub claims: &'a [u8],
    pub registrar_sig: crypto::HybridSig,
    /// The key the caller ALREADY verified the request's signature with, in its algorithm.
    pub presented_key: PresentedKey,
    pub now: u64,
    pub status_list: &'a status::StatusList,
    pub status_issued_at: u64,
    pub freshness: status::Freshness,
    pub checkpoint: &'a checkpoint::Checkpoint,
    pub checkpoint_sig: &'a checkpoint::CheckpointSig,
    pub leaf_index: u64,
    pub inclusion_proof: &'a [[u8; 32]],
    pub revoked_delegates: &'a BTreeSet<[u8; 32]>,
    /// The capability the request exercises, if the verifier checks one.
    pub capability: Option<&'a str>,
}

/// Who a valid link attributes the key to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    pub registrar: String,
    pub operator: String,
    pub passport: String,
    pub scope: Vec<String>,
}

/// Check one link. Never panics. `Ok` carries the attribution; `Err` the first failing reason in the fixed order.
pub fn verify_link(
    chk: &LinkCheck,
    anchors: &TrustAnchors,
) -> core::result::Result<Attribution, Reason> {
    // 1. schema
    let c = LinkClaims::parse_checked(chk.claims)?;
    let name = AinraName::parse(&c.passport).map_err(|_| Reason::NameMalformed)?;

    // 2. the registrar is accredited
    let reg = anchors
        .registrars
        .get(&c.registrar)
        .ok_or(Reason::UnknownRegistrar)?;

    // 3. validity window, exact (ADR-017)
    if chk.now < c.nbf {
        return Err(Reason::NotYetValid);
    }
    if chk.now >= c.exp {
        return Err(Reason::Expired);
    }

    // 4. the registrar signed exactly these bytes, with both halves of its key
    crypto::verify_hybrid(&reg.issuer_key, chk.claims, &chk.registrar_sig)?;

    // 5. the key the caller verified is the linked key — same algorithm, same thumbprint — and that key consented
    if chk.presented_key.alg() != c.subject.alg
        || chk.presented_key.thumbprint().as_deref() != Some(c.subject.thumbprint.as_str())
    {
        return Err(Reason::SigInvalid);
    }
    let pop: [u8; 64] = b64::decode_array(&c.pop).map_err(|_| Reason::SchemaViolation)?;
    let msg = pop_signing_bytes(&c.registrar, &c.passport, &c.subject.thumbprint, c.nbf);
    if !chk.presented_key.verify(&msg, &pop) {
        return Err(Reason::SigInvalid);
    }

    // 6. scope: a narrowed link refuses anything it does not name
    if let Some(cap) = chk.capability {
        if !c.scope.is_empty() && !c.scope.iter().any(|s| s == cap) {
            return Err(Reason::CeilingExceeded);
        }
    }

    // 7. status: fresh first, then the link's own bit, then the operator's lineage
    chk.freshness.check(chk.now, chk.status_issued_at)?;
    if chk.status_list.status_of(c.status.idx) == status::LineageStatus::Revoked {
        return Err(Reason::Revoked);
    }
    if chk.status_list.status_of(c.passport_status.idx) == status::LineageStatus::Revoked {
        return Err(Reason::Revoked);
    }

    // 8. logged before valid — the same machinery, and the same order, as a passport (verify.rs step 9)
    chk.checkpoint
        .verify_sig_mode(&reg.log_root_key, chk.checkpoint_sig, chk.now)?;
    if let checkpoint::CheckpointSig::Delegate { cert, .. } = chk.checkpoint_sig {
        if chk.revoked_delegates.contains(&cert.fingerprint()) {
            return Err(Reason::CheckpointInvalid);
        }
    }
    let expected_leaf = prelog_leaf(chk.claims)?;
    let claimed_leaf: [u8; 32] = b64::decode_array(&c.log.leaf).map_err(|_| Reason::NotLogged)?;
    if claimed_leaf != expected_leaf {
        return Err(Reason::NotLogged);
    }
    checkpoint::verify_logged(
        &claimed_leaf,
        chk.leaf_index,
        chk.checkpoint,
        chk.inclusion_proof,
    )?;
    if let Some(cut) = reg.distrust_from_leaf {
        if chk.leaf_index >= cut {
            return Err(Reason::RegistrarDistrusted);
        }
    }

    Ok(Attribution {
        registrar: c.registrar,
        operator: String::from(name.operator()),
        passport: c.passport,
        scope: c.scope,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle;
    use crate::verify::RegistrarInfo;
    use alloc::collections::BTreeMap;
    use alloc::string::ToString;
    use rand_core::SeedableRng;
    use serde_json::json;

    // A genuinely valid link — real registrar signature, real proof of control, a real Merkle log — plus knobs, so
    // each test flips exactly one thing and asserts the verdict. Nothing is mocked.
    struct Fx {
        anchors: TrustAnchors,
        claims: Vec<u8>,
        sig: crypto::HybridSig,
        key: [u8; 32],
        cp: checkpoint::Checkpoint,
        cp_sig: checkpoint::CheckpointSig,
        proof: Vec<[u8; 32]>,
        leaf_index: u64,
        list: status::StatusList,
        issuer: crypto::HybridKeypair,
        agent: ed25519_dalek::SigningKey,
        /// A genuine inclusion proof for a DIFFERENT leaf of the same log (index 0, the first filler).
        other_proof: Vec<[u8; 32]>,
    }

    const REG: &str = "registrar-01";
    const PASSPORT: &str = "ainra:registrar-01:acme:invoicing@1.0.0";

    fn body(thumb: &str, pop: &str, scope: &[&str]) -> serde_json::Value {
        json!({
            "v": LINK_V, "registrar": REG, "passport": PASSPORT,
            "subject": { "kind": "jwk", "alg": "Ed25519", "thumbprint": thumb },
            "scope": scope, "nbf": 1_000u64, "exp": 2_000u64,
            "status": { "uri": "status://registrar-01/1", "idx": 5u64 },
            "passport_status": { "uri": "status://registrar-01/1", "idx": 0u64 },
            "pop": pop,
        })
    }

    fn build_scoped(scope: &[&str]) -> Fx {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x11_4E_00_78);
        let issuer = crypto::HybridKeypair::generate(&mut rng);
        let root = crypto::TestRootSlh::generate(&mut rng);
        let agent = ed25519_dalek::SigningKey::generate(&mut rng);
        let key = agent.verifying_key().to_bytes();
        let thumb = jwk_thumbprint_ed25519(&key);
        use ed25519_dalek::Signer as _;
        let pop = agent
            .sign(&pop_signing_bytes(REG, PASSPORT, &thumb, 1_000))
            .to_bytes();

        let pre = body(&thumb, &b64::encode(&pop), scope);
        let pre_bytes = canon::canonicalize(&pre).unwrap().into_bytes();
        let leaf = merkle::hash_leaf(&pre_bytes);
        let mut log = merkle::TestLog::new();
        log.append(&[9u8]);
        let leaf_index = log.append(&pre_bytes);
        log.append(&[8u8]);
        let cp = checkpoint::Checkpoint {
            origin: "ainra-log/registrar-01".to_string(),
            tree_size: log.size(),
            root: log.root(),
        };
        let cp_sig = checkpoint::CheckpointSig::Root {
            slh: cp.sign_test_root(&root).unwrap(),
        };
        let proof = log.inclusion_proof(leaf_index).unwrap();
        let other_proof = log.inclusion_proof(0).unwrap();

        let mut full = pre;
        full["log"] = json!({ "leaf": b64::encode(&leaf) });
        let claims = canon::canonicalize(&full).unwrap().into_bytes();
        assert_eq!(prelog_leaf(&claims).unwrap(), leaf);
        let sig = issuer.sign(&claims).unwrap();

        let mut registrars = BTreeMap::new();
        registrars.insert(
            REG.to_string(),
            RegistrarInfo {
                issuer_key: issuer.public(),
                log_root_key: root.public(),
                distrust_from_leaf: None,
            },
        );
        Fx {
            anchors: TrustAnchors { registrars },
            claims,
            sig,
            key,
            cp,
            cp_sig,
            proof,
            leaf_index,
            list: status::StatusList::from_bits(alloc::vec![false; 16]),
            issuer,
            agent,
            other_proof,
        }
    }
    fn build() -> Fx {
        build_scoped(&[])
    }

    fn run(
        f: &Fx,
        now: u64,
        issued_at: u64,
        cap: Option<&str>,
    ) -> core::result::Result<Attribution, Reason> {
        let none = BTreeSet::new();
        verify_link(
            &LinkCheck {
                claims: &f.claims,
                registrar_sig: f.sig.clone(),
                presented_key: f.key.into(),
                now,
                status_list: &f.list,
                status_issued_at: issued_at,
                freshness: status::Freshness::F1,
                checkpoint: &f.cp,
                checkpoint_sig: &f.cp_sig,
                leaf_index: f.leaf_index,
                inclusion_proof: &f.proof,
                revoked_delegates: &none,
                capability: cap,
            },
            &f.anchors,
        )
    }

    #[test]
    fn a_genuine_link_attributes_the_key_to_its_operator() {
        let f = build();
        let a = run(&f, 1_500, 1_495, None).unwrap();
        assert_eq!(a.operator, "acme");
        assert_eq!(a.passport, PASSPORT);
        assert_eq!(a.registrar, REG);
    }

    #[test]
    fn the_thumbprint_is_rfc_7638() {
        // RFC 8037 §A.3: the JWK thumbprint of the RFC's example Ed25519 key.
        let x = b64::decode_array::<32>("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo").unwrap();
        assert_eq!(
            jwk_thumbprint_ed25519(&x),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    #[test]
    fn revoking_the_link_or_the_operators_lineage_refuses_it() {
        let mut f = build();
        let mut bits = alloc::vec![false; 16];
        bits[5] = true;
        f.list = status::StatusList::from_bits(bits);
        assert_eq!(
            run(&f, 1_500, 1_495, None),
            Err(Reason::Revoked),
            "the link's own bit"
        );
        let mut bits = alloc::vec![false; 16];
        bits[0] = true;
        f.list = status::StatusList::from_bits(bits);
        assert_eq!(
            run(&f, 1_500, 1_495, None),
            Err(Reason::Revoked),
            "the passport's bit: every link of it flips"
        );
    }

    #[test]
    fn stale_status_fails_closed() {
        let f = build();
        assert_eq!(run(&f, 1_500, 1_400, None), Err(Reason::StaleStatus));
    }

    #[test]
    fn another_key_is_not_this_link() {
        let mut f = build();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
        f.key = ed25519_dalek::SigningKey::generate(&mut rng)
            .verifying_key()
            .to_bytes();
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::SigInvalid));
    }

    #[test]
    fn a_link_without_the_keys_consent_is_refused() {
        // The registrar signs a record whose proof of control was made by a DIFFERENT key for the same thumbprint
        // claim: the record is genuinely registrar-signed, and still refused.
        let mut f = build();
        let mut v: serde_json::Value = serde_json::from_slice(&f.claims).unwrap();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(8);
        let other = ed25519_dalek::SigningKey::generate(&mut rng);
        use ed25519_dalek::Signer as _;
        let thumb = v["subject"]["thumbprint"].as_str().unwrap().to_string();
        v["pop"] = json!(b64::encode(
            &other
                .sign(&pop_signing_bytes(REG, PASSPORT, &thumb, 1_000))
                .to_bytes()
        ));
        f.claims = canon::canonicalize(&v).unwrap().into_bytes();
        f.sig = f.issuer.sign(&f.claims).unwrap();
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::SigInvalid));
        let _ = &f.agent;
    }

    #[test]
    fn a_forged_or_half_signed_record_is_refused() {
        let mut f = build();
        let mut s = f.sig.clone();
        s.ed25519[0] ^= 1;
        f.sig = s;
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::SigInvalid));
        let mut f = build();
        f.sig.mldsa65.clear();
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::AlgDowngrade));
    }

    #[test]
    fn the_window_is_exact() {
        let f = build();
        assert_eq!(run(&f, 999, 995, None), Err(Reason::NotYetValid));
        assert_eq!(run(&f, 2_000, 1_995, None), Err(Reason::Expired));
    }

    #[test]
    fn a_narrowed_link_refuses_what_it_does_not_name() {
        let f = build_scoped(&["read:invoices"]);
        assert!(run(&f, 1_500, 1_495, Some("read:invoices")).is_ok());
        assert_eq!(
            run(&f, 1_500, 1_495, Some("pay:invoices")),
            Err(Reason::CeilingExceeded)
        );
        let open = build();
        assert!(
            run(&open, 1_500, 1_495, Some("pay:invoices")).is_ok(),
            "an unscoped link defers to the passport"
        );
    }

    #[test]
    fn an_unlogged_or_unaccredited_link_is_refused() {
        let mut f = build();
        f.leaf_index += 1;
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::NotLogged));
        let mut f = build();
        f.anchors.registrars.clear();
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::UnknownRegistrar));
        let mut f = build();
        f.anchors
            .registrars
            .get_mut(REG)
            .unwrap()
            .distrust_from_leaf = Some(0);
        assert_eq!(
            run(&f, 1_500, 1_495, None),
            Err(Reason::RegistrarDistrusted)
        );
    }

    #[test]
    fn a_registrar_cannot_link_another_registrars_passport() {
        let mut f = build();
        let mut v: serde_json::Value = serde_json::from_slice(&f.claims).unwrap();
        v["passport"] = json!("ainra:registrar-02:acme:invoicing@1.0.0");
        f.claims = canon::canonicalize(&v).unwrap().into_bytes();
        f.sig = f.issuer.sign(&f.claims).unwrap();
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::SchemaViolation));
    }

    #[test]
    fn non_canonical_bytes_are_not_a_link() {
        let mut f = build();
        let mut s = String::from_utf8(f.claims.clone()).unwrap();
        s.insert(1, ' ');
        f.claims = s.into_bytes();
        f.sig = f.issuer.sign(&f.claims).unwrap();
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::SchemaViolation));
    }

    #[test]
    fn a_record_naming_someone_elses_key_is_refused_even_with_a_valid_consent() {
        // The attack the thumbprint check alone stops: a record (genuinely registrar-signed) names victim key A,
        // but its consent signature was made by attacker key B — and B is the key the attacker presents. The
        // consent verifies under B; only binding the presented key to the record's thumbprint refuses it.
        let mut f = build();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(9);
        let attacker = ed25519_dalek::SigningKey::generate(&mut rng);
        use ed25519_dalek::Signer as _;
        let mut v: serde_json::Value = serde_json::from_slice(&f.claims).unwrap();
        let victim_thumb = v["subject"]["thumbprint"].as_str().unwrap().to_string();
        v["pop"] = json!(b64::encode(
            &attacker
                .sign(&pop_signing_bytes(REG, PASSPORT, &victim_thumb, 1_000))
                .to_bytes()
        ));
        f.claims = canon::canonicalize(&v).unwrap().into_bytes();
        f.sig = f.issuer.sign(&f.claims).unwrap();
        f.key = attacker.verifying_key().to_bytes();
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::SigInvalid));
    }

    #[test]
    fn a_record_pointing_at_another_logged_leaf_is_not_logged() {
        // The attack the leaf binding alone stops: the record's `log.leaf` names a leaf that really IS in the log
        // (a different entry), with that entry's genuine index and proof. Inclusion verifies; binding refuses.
        let mut f = build();
        let mut v: serde_json::Value = serde_json::from_slice(&f.claims).unwrap();
        v["log"]["leaf"] = json!(b64::encode(&merkle::hash_leaf(&[9u8])));
        f.claims = canon::canonicalize(&v).unwrap().into_bytes();
        f.sig = f.issuer.sign(&f.claims).unwrap();
        f.leaf_index = 0;
        f.proof = f.other_proof.clone();
        assert_eq!(run(&f, 1_500, 1_495, None), Err(Reason::NotLogged));
    }

    // ── D-082 ES256K ───────────────────────────────────────────────────────────────────────────────────────────────

    fn k1(seed: u8) -> (k256::ecdsa::SigningKey, [u8; 33]) {
        let sk = k256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let pk: [u8; 33] = sk
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        (sk, pk)
    }

    fn k1_sign(sk: &k256::ecdsa::SigningKey, msg: &[u8]) -> [u8; 64] {
        use k256::ecdsa::signature::Signer as _;
        let s: k256::ecdsa::Signature = sk.sign(msg);
        s.to_bytes().into()
    }

    #[test]
    fn an_es256k_signature_verifies_and_its_high_s_twin_does_not() {
        let (sk, pk) = k1(7);
        let msg = b"consent";
        let sig = k1_sign(&sk, msg);
        assert!(es256k_verify(&pk, msg, &sig));
        assert!(!es256k_verify(&pk, b"something else", &sig));
        // The same (r, s) with s replaced by n - s: valid curve math, refused as non-canonical.
        let parsed = k256::ecdsa::Signature::from_slice(&sig).unwrap();
        let (r, s_) = parsed.split_scalars();
        let high = k256::ecdsa::Signature::from_scalars(r, -*s_).unwrap();
        let high: [u8; 64] = high.to_bytes().into();
        assert_ne!(high, sig);
        assert!(!es256k_verify(&pk, msg, &high));
        let (_, other) = k1(8);
        assert!(!es256k_verify(&other, msg, &sig));
    }

    #[test]
    fn an_es256k_key_is_a_compressed_point_on_the_curve() {
        let (_, pk) = k1(7);
        let tp = jwk_thumbprint_es256k(&pk).unwrap();
        assert_eq!(b64::decode_array::<32>(&tp).unwrap().len(), 32);
        assert_eq!(
            PresentedKey::from_bytes(&pk).unwrap().thumbprint(),
            Some(tp)
        );
        let mut not_compressed = pk;
        not_compressed[0] = 0x04;
        assert_eq!(jwk_thumbprint_es256k(&not_compressed), None);
        let mut off_curve = pk;
        off_curve[32] ^= 1;
        off_curve[1] ^= 0xff;
        let maybe = jwk_thumbprint_es256k(&off_curve);
        // Flipping bits either leaves a point (another key, another thumbprint) or not a point at all.
        assert_ne!(maybe, jwk_thumbprint_es256k(&pk));
        assert_eq!(PresentedKey::from_bytes(&[0u8; 65]), None);
        assert_eq!(PresentedKey::from_bytes(&[0u8; 31]), None);
        assert_eq!(
            PresentedKey::from_bytes(&[1u8; 32]).unwrap().alg(),
            SUBJECT_ALG_ED25519
        );
    }

    #[test]
    fn an_ed25519_key_never_answers_for_an_es256k_link_or_the_reverse() {
        let f = build();
        let (_, k1pk) = k1(7);
        let none = BTreeSet::new();
        // An ES256K key presented for this (Ed25519) link: refused on the algorithm before the thumbprint.
        let r = verify_link(
            &LinkCheck {
                claims: &f.claims,
                registrar_sig: f.sig.clone(),
                presented_key: PresentedKey::Es256k(k1pk),
                now: 1_500,
                status_list: &f.list,
                status_issued_at: 1_495,
                freshness: status::Freshness::F1,
                checkpoint: &f.cp,
                checkpoint_sig: &f.cp_sig,
                leaf_index: f.leaf_index,
                inclusion_proof: &f.proof,
                revoked_delegates: &none,
                capability: None,
            },
            &f.anchors,
        );
        assert_eq!(r, Err(Reason::SigInvalid));
    }
}
