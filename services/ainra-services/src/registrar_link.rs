// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AINRA Link at the registrar (D-078): link a key an agent already has to one of this registrar's passports, list
//! the links, revoke them. A child module of `registrar`, so it works on the same log, status segment and issuer key
//! as passports do; it invents no checks of its own — every link it issues is re-read by
//! [`ainra_core::link::LinkClaims::parse_checked`] before it is signed, and its tests verify through
//! [`ainra_core::link::verify_link`].
//!
//! Three rules, kept deliberately few:
//!   * **one link per key, ever.** A key that was linked and revoked stays revoked; rotation is a new key linked and
//!     the old one revoked. So a thumbprint names exactly one record, and a verifier never has to choose.
//!   * **a link never outlives or outranks its passport.** Its window sits inside the passport's, its scope inside
//!     the passport's capabilities, and the passport's own bit is in every link.
//!   * **everything is logged.** The link body is appended before it is valid, and every revocation is appended
//!     too, so the log alone says which keys were ever attributable and when that ended.

use ainra_core::link::{
    pop_signing_bytes, Attribution, LinkCheck, LinkClaims, PresentedKey, LINK_V,
    SUBJECT_ALG_ED25519, SUBJECT_KIND_JWK,
};
use ainra_core::{b64, canon, crypto, merkle, status, Reason};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{decode_proof, IssueError, RegistrarBox, WireCheckpointSig};

/// The version tag of a revocation entry in the log. Frozen once published.
pub const LINK_REVOCATION_V: &str = "ainra-link-revocation-1";

/// What a caller sends to link a key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkSpec {
    /// The passport the key acts under (its `sub`), issued by this registrar.
    pub passport: String,
    /// The key's algorithm: `Ed25519` (the default, so every existing caller is unchanged) or `ES256K` (D-082).
    #[serde(default = "default_alg")]
    pub alg: String,
    /// The public key, base64url: 32 bytes for Ed25519 (the JWK `x` member), the 33-byte compressed SEC1 point for
    /// ES256K.
    pub key: String,
    /// base64url 64-byte signature by that key, in its own algorithm, over [`pop_signing_bytes`]. ES256K signatures
    /// are `r || s`, low-S.
    pub pop: String,
    /// Narrower than the passport's capabilities, or empty for "whatever the passport allows".
    #[serde(default)]
    pub scope: Vec<String>,
    pub nbf: u64,
    pub exp: u64,
}

fn default_alg() -> String {
    SUBJECT_ALG_ED25519.to_string()
}

/// Why a link stopped being attributable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationKind {
    /// This key is no longer the operator's. Its own bit flips.
    Link,
    /// The operator is suspended: the passport's lineage bit flips, and with it every link to it.
    Operator,
    /// The key was stolen. Its own bit flips, and `suspect_since` marks when actions stop being the operator's.
    Compromise,
}

impl RevocationKind {
    fn as_str(self) -> &'static str {
        match self {
            RevocationKind::Link => "link",
            RevocationKind::Operator => "operator",
            RevocationKind::Compromise => "compromise",
        }
    }
    /// Whether this kind flips the link's own bit (an operator suspension flips the passport's instead).
    fn flips_link_bit(self) -> bool {
        !matches!(self, RevocationKind::Operator)
    }
}

/// A revocation, as recorded beside the link and appended to the log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkRevocation {
    pub kind: RevocationKind,
    pub at: u64,
    /// Only for [`RevocationKind::Compromise`]: actions signed by this key at or after this instant are not the
    /// operator's. Actions before it were.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspect_since: Option<u64>,
    /// Where the revocation entry sits in the log.
    pub leaf_index: u64,
}

/// One issued link, as the registrar keeps it. All binary is base64url.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LinkRecord {
    pub thumbprint: String,
    pub passport: String,
    pub status_idx: u64,
    pub nbf: u64,
    pub exp: u64,
    /// The canonical signed claims, exactly as signed, as UTF-8.
    pub claims: String,
    pub sig_ed25519: String,
    pub sig_mldsa65: String,
    pub leaf_index: u64,
    /// Every revocation of this link, oldest first: a `link` revocation may later be upgraded to `compromise`.
    #[serde(default)]
    pub revocations: Vec<LinkRevocation>,
}

impl LinkRecord {
    fn link_bit_flipped(&self) -> bool {
        self.revocations.iter().any(|r| r.kind.flips_link_bit())
    }
}

impl RegistrarBox {
    /// Link `spec.key` to `spec.passport`. Refused, with nothing logged, unless the key signed its consent, the
    /// passport is this registrar's and in good standing, and the link fits inside it.
    pub fn link(&mut self, spec: &LinkSpec) -> Result<LinkRecord, IssueError> {
        let key = b64::decode(&spec.key)
            .ok()
            .and_then(|b| PresentedKey::from_bytes(&b))
            .filter(|k| k.alg() == spec.alg)
            .ok_or_else(|| {
                IssueError::Malformed(
                    "key must be base64url: a 32-byte Ed25519 key with alg Ed25519, or a 33-byte compressed \
                     secp256k1 point with alg ES256K"
                        .into(),
                )
            })?;
        let pop: [u8; 64] = b64::decode_array(&spec.pop).map_err(|_| {
            IssueError::HolderProof("pop must be a base64url 64-byte signature".into())
        })?;
        let thumbprint = key
            .thumbprint()
            .ok_or_else(|| IssueError::Malformed("key is not a point on secp256k1".into()))?;
        if self.links.contains_key(&thumbprint) {
            return Err(IssueError::Duplicate(format!(
                "key {thumbprint} is already linked (one link per key, ever: link a new key instead)"
            )));
        }
        let rec = self
            .records
            .get(&spec.passport)
            .ok_or_else(|| IssueError::Malformed(format!("unknown passport: {}", spec.passport)))?;
        if rec.revoked {
            return Err(IssueError::LineageRevoked(spec.passport.clone()));
        }
        if spec.nbf >= spec.exp || spec.nbf < rec.nbf || spec.exp > rec.exp {
            return Err(IssueError::Malformed(format!(
                "the link window [{}, {}) must be non-empty and inside the passport's [{}, {})",
                spec.nbf, spec.exp, rec.nbf, rec.exp
            )));
        }
        if let Some(extra) = spec
            .scope
            .iter()
            .find(|s| !rec.capabilities.iter().any(|c| c == *s))
        {
            return Err(IssueError::Malformed(format!(
                "scope '{extra}' is not one of the passport's capabilities"
            )));
        }
        let msg = pop_signing_bytes(&self.id, &spec.passport, &thumbprint, spec.nbf);
        if !key.verify(&msg, &pop) {
            return Err(IssueError::HolderProof(
                "the key did not sign this link (pop must cover registrar, passport, thumbprint and nbf)".into(),
            ));
        }
        if self.next_status_idx >= self.status_capacity {
            return Err(IssueError::StatusFull);
        }
        let status_idx = self.next_status_idx as u64;
        let (passport_idx, passport_uri) = (rec.status_idx, rec.status_uri.clone());

        // The body without its log back-reference: that is what is logged, exactly as for a passport.
        let mut body = json!({
            "v": LINK_V,
            "registrar": self.id,
            "passport": spec.passport,
            "subject": { "kind": SUBJECT_KIND_JWK, "alg": key.alg(), "thumbprint": thumbprint },
            "scope": spec.scope,
            "nbf": spec.nbf,
            "exp": spec.exp,
            "status": { "uri": self.status_uri(), "idx": status_idx },
            "passport_status": { "uri": passport_uri, "idx": passport_idx },
            "pop": spec.pop,
        });
        let body_bytes = canon::canonicalize(&body)
            .map_err(|e| IssueError::Malformed(format!("canon link body: {e:?}")))?
            .into_bytes();
        let leaf = merkle::hash_leaf(&body_bytes);
        body["log"] = json!({ "leaf": b64::encode(&leaf) });
        let claims = canon::canonicalize(&body)
            .map_err(|e| IssueError::Malformed(format!("canon link: {e:?}")))?
            .into_bytes();
        // Read it back the way every verifier will before anything is logged or signed, so the registrar can never
        // issue a link the verifiers refuse.
        LinkClaims::parse_checked(&claims)
            .map_err(|r| IssueError::Malformed(format!("link would not verify: {r}")))?;

        let leaf_index = self
            .log
            .append(&body_bytes)
            .map_err(|e| IssueError::Io(e.to_string()))?;
        let sig = self
            .issuer
            .sign(&claims)
            .map_err(|e| IssueError::Malformed(format!("issuer sign: {e:?}")))?;
        self.next_status_idx += 1;
        let record = LinkRecord {
            thumbprint: thumbprint.clone(),
            passport: spec.passport.clone(),
            status_idx,
            nbf: spec.nbf,
            exp: spec.exp,
            claims: String::from_utf8(claims)
                .map_err(|e| IssueError::Malformed(format!("claims utf8: {e}")))?,
            sig_ed25519: b64::encode(&sig.ed25519),
            sig_mldsa65: b64::encode(&sig.mldsa65),
            leaf_index,
            revocations: Vec::new(),
        };
        self.links.insert(thumbprint, record.clone());
        Ok(record)
    }

    /// Revoke the link of `thumbprint`. `suspect_since` is required for a compromise and refused otherwise. A `link`
    /// revocation may later be upgraded to `compromise` (the theft is often found after the key is retired); nothing
    /// else repeats. Every revocation is appended to the log.
    pub fn revoke_link(
        &mut self,
        thumbprint: &str,
        kind: RevocationKind,
        suspect_since: Option<u64>,
        now: u64,
    ) -> Result<LinkRevocation, IssueError> {
        self.refuse_outside_delegate_window(now)?;
        let link = self
            .links
            .get(thumbprint)
            .ok_or_else(|| IssueError::Malformed(format!("unknown link: {thumbprint}")))?;
        match (kind, suspect_since) {
            (RevocationKind::Compromise, None) => {
                return Err(IssueError::Malformed(
                    "a compromise names suspect_since: the instant from which this key's actions are not the operator's"
                        .into(),
                ))
            }
            (RevocationKind::Compromise, Some(t)) if t > now => {
                return Err(IssueError::Malformed(
                    "suspect_since cannot be in the future".into(),
                ))
            }
            (RevocationKind::Link | RevocationKind::Operator, Some(_)) => {
                return Err(IssueError::Malformed(
                    "suspect_since belongs to a compromise only".into(),
                ))
            }
            _ => {}
        }
        if link.revocations.iter().any(|r| r.kind == kind) {
            return Err(IssueError::Malformed(format!(
                "link already revoked as {}",
                kind.as_str()
            )));
        }
        if kind == RevocationKind::Link && link.link_bit_flipped() {
            return Err(IssueError::Malformed(
                "link already revoked (a compromise is stronger than a link revocation)".into(),
            ));
        }
        let passport = link.passport.clone();
        let (status_idx, link_bit_flipped) = (link.status_idx, link.link_bit_flipped());

        // Flip the bit first: if the signed delta is refused, nothing is logged and nothing changes.
        match kind {
            RevocationKind::Operator => {
                self.revoke(&passport, now)?;
            }
            _ if !link_bit_flipped => {
                self.status
                    .revoke_delta(&[status_idx as usize], now)
                    .ok_or_else(|| IssueError::Malformed("status delegate not configured".into()))?
                    .map_err(|r| IssueError::Malformed(format!("delta rejected: {r}")))?;
            }
            // Upgrading a `link` revocation to `compromise`: the bit is already set; only the record grows.
            _ => {}
        }

        // An operator suspension reaches every link to any generation of that lineage, as the bit does.
        let affected: Vec<String> = if kind == RevocationKind::Operator {
            let lineage_of = |sub: &str| {
                self.records
                    .get(sub)
                    .map(|r| (r.operator.clone(), r.lineage.clone()))
            };
            let target = lineage_of(&passport);
            self.links
                .values()
                .filter(|l| {
                    l.passport == passport
                        || (target.is_some() && lineage_of(&l.passport) == target)
                })
                .filter(|l| {
                    !l.revocations
                        .iter()
                        .any(|r| r.kind == RevocationKind::Operator)
                })
                .map(|l| l.thumbprint.clone())
                .collect()
        } else {
            vec![thumbprint.to_string()]
        };
        let mut this = None;
        for tp in affected {
            let link = &self.links[&tp];
            let mut entry = json!({
                "v": LINK_REVOCATION_V,
                "registrar": self.id,
                "passport": link.passport,
                "thumbprint": tp,
                "kind": kind.as_str(),
                "at": now,
            });
            if let Some(t) = suspect_since {
                entry["suspect_since"] = json!(t);
            }
            let bytes = canon::canonicalize(&entry)
                .map_err(|e| IssueError::Malformed(format!("canon revocation: {e:?}")))?
                .into_bytes();
            let leaf_index = self
                .log
                .append(&bytes)
                .map_err(|e| IssueError::Io(e.to_string()))?;
            let rev = LinkRevocation {
                kind,
                at: now,
                suspect_since,
                leaf_index,
            };
            if tp == thumbprint {
                this = Some(rev.clone());
            }
            if let Some(l) = self.links.get_mut(&tp) {
                l.revocations.push(rev);
            }
        }
        this.ok_or_else(|| IssueError::Malformed("link already suspended with its operator".into()))
    }

    pub fn links(&self) -> impl Iterator<Item = &LinkRecord> {
        self.links.values()
    }
    pub fn get_link(&self, thumbprint: &str) -> Option<&LinkRecord> {
        self.links.get(thumbprint)
    }

    /// The whole link index, for download (D-079: whole-list download is the privacy model, so there is no lookup
    /// by key). Each entry is registrar-signed and proven against the one current checkpoint, which is delegate-
    /// signed; the bits are in the separately published, signed status list. The container itself is not signed:
    /// nothing in it is trusted unless its own signature checks, and a missing entry is a refusal, never an
    /// acceptance — and keeping the issuer key to credentials alone is worth more than a signature here would add.
    pub fn link_index(&self, now: u64) -> Option<serde_json::Value> {
        let cp = self.log.signed_checkpoint();
        let signed = self.log.sign_checkpoint(&cp);
        let mut links = Vec::with_capacity(self.links.len());
        for l in self.links.values() {
            let proof = self.log.inclusion_proof(l.leaf_index)?;
            links.push(json!({
                "thumbprint": l.thumbprint,
                "passport": l.passport,
                "claims": b64::encode(l.claims.as_bytes()),
                "registrar_sig": { "ed25519": l.sig_ed25519, "mldsa65": l.sig_mldsa65 },
                "leaf_index": l.leaf_index,
                "inclusion_proof": proof.iter().map(|h| b64::encode(h)).collect::<Vec<_>>(),
                "revocations": l.revocations,
            }));
        }
        Some(json!({
            "v": "ainra-link-index-1",
            "registrar": self.id,
            "now": now,
            "checkpoint": { "origin": self.log_origin(), "size": cp.tree_size, "root": b64::encode(&cp.root) },
            "checkpoint_sig": WireCheckpointSig::from_core(&signed.sig),
            "links": links,
        }))
    }

    /// Check a request signed by `presented_key` against this registrar's links, through the core verifier, with the
    /// current signed status and checkpoint — what a gate does after downloading the index and the status list.
    /// `None` means the key is not linked here: an outcome, not a reason, and a gate in link mode refuses it.
    pub fn verify_link_for(
        &self,
        presented_key: &PresentedKey,
        now: u64,
        freshness: status::Freshness,
        capability: Option<&str>,
    ) -> Option<Result<Attribution, Reason>> {
        let link = self.links.get(&presented_key.thumbprint()?)?;
        let published = self.status.publish(now.saturating_sub(1));
        let compressed = b64::decode(&published.status_list_b64).unwrap_or_default();
        let Ok(list) = status::StatusList::decode(&compressed, published.bit_len as usize) else {
            return Some(Err(Reason::StaleStatus));
        };
        let cp = self.log.signed_checkpoint();
        let signed = self.log.sign_checkpoint(&cp);
        let Some(proof) = self
            .log
            .inclusion_proof(link.leaf_index)
            .map(|p| p.iter().map(|h| b64::encode(h)).collect::<Vec<_>>())
            .and_then(|p| decode_proof(&p))
        else {
            return Some(Err(Reason::NotLogged));
        };
        let sig = crypto::HybridSig {
            ed25519: b64::decode(&link.sig_ed25519).unwrap_or_default(),
            mldsa65: b64::decode(&link.sig_mldsa65).unwrap_or_default(),
        };
        let chk = LinkCheck {
            claims: link.claims.as_bytes(),
            registrar_sig: sig,
            presented_key: *presented_key,
            now,
            status_list: &list,
            status_issued_at: published.issued_at,
            freshness,
            checkpoint: &cp,
            checkpoint_sig: &signed.sig,
            leaf_index: link.leaf_index,
            inclusion_proof: &proof,
            revoked_delegates: &Default::default(),
            capability,
        };
        Some(ainra_core::link::verify_link(&chk, &self.trust_anchors()))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{engine, spec, EXP, NBF, VERIFY_NOW};
    use super::*;
    use ainra_core::link::jwk_thumbprint_ed25519;
    use crypto::TestDelegate as AgentKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    // An agent's own Ed25519 key, as a signature-agent or a workload already has one.
    fn agent_key(seed: u64) -> AgentKey {
        AgentKey::generate(&mut ChaCha20Rng::seed_from_u64(seed))
    }

    fn tp_of(sk: &AgentKey) -> String {
        jwk_thumbprint_ed25519(&sk.public())
    }

    fn spec_for(rb: &RegistrarBox, passport: &str, sk: &AgentKey) -> LinkSpec {
        let pk = sk.public();
        let tp = jwk_thumbprint_ed25519(&pk);
        let nbf = NBF;
        let pop = sk.sign(&pop_signing_bytes(rb.id(), passport, &tp, nbf));
        LinkSpec {
            passport: passport.into(),
            alg: SUBJECT_ALG_ED25519.into(),
            key: b64::encode(&pk),
            pop: b64::encode(&pop),
            scope: vec![],
            nbf,
            exp: NBF + 30 * 24 * 60 * 60,
        }
    }

    fn setup(name: &str) -> (RegistrarBox, String) {
        let tmp = std::env::temp_dir().join(format!("ainra-rb-link-{name}"));
        let _ = std::fs::remove_dir_all(&tmp);
        let mut rb = engine(&tmp);
        let mut rng = ChaCha20Rng::seed_from_u64(0x11AA);
        let rec = rb
            .issue(&spec("acme", "invoicing", "1.0.0"), &[], &mut rng)
            .unwrap();
        (rb, rec.sub)
    }

    fn check(rb: &RegistrarBox, sk: &AgentKey) -> Option<Result<Attribution, Reason>> {
        rb.verify_link_for(&sk.public().into(), VERIFY_NOW, status::Freshness::F3, None)
    }

    #[test]
    fn a_linked_key_is_attributed_to_its_operator() {
        let (mut rb, passport) = setup("ok");
        let sk = agent_key(1);
        rb.link(&spec_for(&rb, &passport, &sk)).unwrap();
        let a = check(&rb, &sk).unwrap().unwrap();
        assert_eq!(a.operator, "acme");
        assert_eq!(a.passport, passport);
        assert_eq!(a.registrar, "registrar-07");
    }

    #[test]
    fn an_unlinked_key_is_not_linked_not_valid() {
        let (mut rb, passport) = setup("unlinked");
        rb.link(&spec_for(&rb, &passport, &agent_key(1))).unwrap();
        assert!(check(&rb, &agent_key(2)).is_none());
    }

    #[test]
    fn a_consent_signed_by_another_key_is_refused_and_nothing_is_logged() {
        let (mut rb, passport) = setup("wrongpop");
        let victim = agent_key(1);
        let attacker = agent_key(2);
        let mut s = spec_for(&rb, &passport, &victim);
        s.pop = spec_for(&rb, &passport, &attacker).pop;
        let before = rb.log.size();
        assert!(matches!(rb.link(&s), Err(IssueError::HolderProof(_))));
        assert_eq!(
            rb.log.size(),
            before,
            "a refused link must leave the log untouched"
        );
        assert!(check(&rb, &victim).is_none());
    }

    #[test]
    fn a_consent_for_another_passport_is_refused() {
        let (mut rb, passport) = setup("otherpassport");
        let mut rng = ChaCha20Rng::seed_from_u64(0x22BB);
        let other = rb
            .issue(&spec("globex", "billing", "1.0.0"), &[], &mut rng)
            .unwrap();
        let sk = agent_key(1);
        let mut s = spec_for(&rb, &passport, &sk);
        s.passport = other.sub;
        assert!(matches!(rb.link(&s), Err(IssueError::HolderProof(_))));
    }

    #[test]
    fn one_link_per_key_ever() {
        let (mut rb, passport) = setup("once");
        let sk = agent_key(1);
        let s = spec_for(&rb, &passport, &sk);
        rb.link(&s).unwrap();
        assert!(matches!(rb.link(&s), Err(IssueError::Duplicate(_))));
        let tp = tp_of(&sk);
        rb.revoke_link(&tp, RevocationKind::Link, None, VERIFY_NOW - 10)
            .unwrap();
        assert!(matches!(rb.link(&s), Err(IssueError::Duplicate(_))));
    }

    #[test]
    fn a_link_cannot_outlive_or_outrank_its_passport() {
        let (mut rb, passport) = setup("bounds");
        let sk = agent_key(1);
        let mut late = spec_for(&rb, &passport, &sk);
        late.exp = EXP + 1;
        assert!(matches!(rb.link(&late), Err(IssueError::Malformed(_))));
        let mut wide = spec_for(&rb, &passport, &sk);
        wide.scope = vec!["sign:invoice".into()]; // in the ceiling, not in the capabilities
        assert!(matches!(rb.link(&wide), Err(IssueError::Malformed(_))));
    }

    #[test]
    fn a_revoked_passport_cannot_gain_links() {
        let (mut rb, passport) = setup("revokedpassport");
        rb.revoke(&passport, VERIFY_NOW - 10).unwrap();
        assert!(matches!(
            rb.link(&spec_for(&rb, &passport, &agent_key(1))),
            Err(IssueError::LineageRevoked(_))
        ));
    }

    #[test]
    fn revoking_a_link_refuses_that_key_only() {
        let (mut rb, passport) = setup("revokelink");
        let (a, b) = (agent_key(1), agent_key(2));
        rb.link(&spec_for(&rb, &passport, &a)).unwrap();
        rb.link(&spec_for(&rb, &passport, &b)).unwrap();
        let tp = tp_of(&a);
        let size = rb.log.size();
        rb.revoke_link(&tp, RevocationKind::Link, None, VERIFY_NOW - 10)
            .unwrap();
        assert_eq!(rb.log.size(), size + 1, "the revocation is logged");
        assert_eq!(check(&rb, &a).unwrap(), Err(Reason::Revoked));
        assert!(
            check(&rb, &b).unwrap().is_ok(),
            "the other key stays attributable"
        );
        assert_eq!(
            rb.verify_record(&passport, VERIFY_NOW),
            ainra_core::Verdict::Valid
        );
    }

    #[test]
    fn suspending_the_operator_refuses_every_link() {
        let (mut rb, passport) = setup("operator");
        let (a, b) = (agent_key(1), agent_key(2));
        rb.link(&spec_for(&rb, &passport, &a)).unwrap();
        rb.link(&spec_for(&rb, &passport, &b)).unwrap();
        let tp = tp_of(&a);
        let size = rb.log.size();
        rb.revoke_link(&tp, RevocationKind::Operator, None, VERIFY_NOW - 10)
            .unwrap();
        assert_eq!(rb.log.size(), size + 2, "one entry per link reached");
        assert_eq!(check(&rb, &a).unwrap(), Err(Reason::Revoked));
        assert_eq!(check(&rb, &b).unwrap(), Err(Reason::Revoked));
        assert!(!rb.verify_record(&passport, VERIFY_NOW).is_valid());
    }

    #[test]
    fn revoking_the_passport_directly_also_refuses_its_links() {
        let (mut rb, passport) = setup("passportbit");
        let sk = agent_key(1);
        rb.link(&spec_for(&rb, &passport, &sk)).unwrap();
        rb.revoke(&passport, VERIFY_NOW - 10).unwrap();
        assert_eq!(check(&rb, &sk).unwrap(), Err(Reason::Revoked));
    }

    #[test]
    fn a_compromise_needs_suspect_since_and_can_upgrade_a_link_revocation() {
        let (mut rb, passport) = setup("compromise");
        let sk = agent_key(1);
        rb.link(&spec_for(&rb, &passport, &sk)).unwrap();
        let tp = tp_of(&sk);
        let now = VERIFY_NOW - 10;
        assert!(rb
            .revoke_link(&tp, RevocationKind::Compromise, None, now)
            .is_err());
        assert!(rb
            .revoke_link(&tp, RevocationKind::Compromise, Some(now + 1), now)
            .is_err());
        assert!(rb
            .revoke_link(&tp, RevocationKind::Link, Some(now), now)
            .is_err());
        rb.revoke_link(&tp, RevocationKind::Link, None, now)
            .unwrap();
        let seq = rb.status_seq();
        let r = rb
            .revoke_link(&tp, RevocationKind::Compromise, Some(NBF + 3600), now)
            .unwrap();
        assert_eq!(r.suspect_since, Some(NBF + 3600));
        assert_eq!(
            rb.status_seq(),
            seq,
            "the bit was already set: no second delta"
        );
        assert!(rb
            .revoke_link(&tp, RevocationKind::Compromise, Some(NBF), now)
            .is_err());
        assert!(rb
            .revoke_link(&tp, RevocationKind::Link, None, now)
            .is_err());
        assert_eq!(check(&rb, &sk).unwrap(), Err(Reason::Revoked));
    }

    #[test]
    fn a_compromise_is_never_downgraded_to_a_link_revocation() {
        let (mut rb, passport) = setup("nodowngrade");
        let sk = agent_key(1);
        rb.link(&spec_for(&rb, &passport, &sk)).unwrap();
        let now = VERIFY_NOW - 10;
        rb.revoke_link(&tp_of(&sk), RevocationKind::Compromise, Some(NBF), now)
            .unwrap();
        assert!(rb
            .revoke_link(&tp_of(&sk), RevocationKind::Link, None, now)
            .is_err());
        assert_eq!(rb.get_link(&tp_of(&sk)).unwrap().revocations.len(), 1);
    }

    #[test]
    fn links_survive_persist_and_reload() {
        let tmp = std::env::temp_dir().join("ainra-rb-link-reload");
        let _ = std::fs::remove_dir_all(&tmp);
        let mut rb =
            RegistrarBox::create_seeded(&tmp, "registrar-07", 64, 77, NBF - 1000, NBF, EXP)
                .unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(0x33CC);
        let passport = rb
            .issue(&spec("acme", "invoicing", "1.0.0"), &[], &mut rng)
            .unwrap()
            .sub;
        let (a, b) = (agent_key(1), agent_key(2));
        rb.link(&spec_for(&rb, &passport, &a)).unwrap();
        rb.link(&spec_for(&rb, &passport, &b)).unwrap();
        let tp = tp_of(&a);
        rb.revoke_link(&tp, RevocationKind::Compromise, Some(NBF), VERIFY_NOW - 10)
            .unwrap();
        rb.save().unwrap();
        let back = RegistrarBox::load(&tmp).unwrap();
        assert_eq!(back.links().count(), 2);
        assert_eq!(
            back.get_link(&tp).unwrap().revocations[0].kind,
            RevocationKind::Compromise
        );
        assert_eq!(check(&back, &a).unwrap(), Err(Reason::Revoked));
        assert!(check(&back, &b).unwrap().is_ok());
    }

    #[test]
    fn the_index_carries_every_link_proven_against_one_checkpoint() {
        let (mut rb, passport) = setup("index");
        rb.link(&spec_for(&rb, &passport, &agent_key(1))).unwrap();
        rb.link(&spec_for(&rb, &passport, &agent_key(2))).unwrap();
        let idx = rb.link_index(VERIFY_NOW).unwrap();
        let links = idx["links"].as_array().unwrap();
        assert_eq!(links.len(), 2);
        let size = idx["checkpoint"]["size"].as_u64().unwrap();
        assert_eq!(size, rb.log.size());
        for l in links {
            let claims = b64::decode(l["claims"].as_str().unwrap()).unwrap();
            let leaf = ainra_core::verify::prelog_leaf(&claims).unwrap();
            let proof: Vec<[u8; 32]> = l["inclusion_proof"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| b64::decode_array(h.as_str().unwrap()).unwrap())
                .collect();
            let root: [u8; 32] =
                b64::decode_array(idx["checkpoint"]["root"].as_str().unwrap()).unwrap();
            let cp = ainra_core::checkpoint::Checkpoint {
                origin: rb.log_origin(),
                tree_size: size,
                root,
            };
            ainra_core::checkpoint::verify_logged(
                &leaf,
                l["leaf_index"].as_u64().unwrap(),
                &cp,
                &proof,
            )
            .unwrap();
        }
    }

    // ── D-082: a secp256k1 key, linked and attributed through the same path ───────────────────────────────────────

    #[test]
    fn an_es256k_key_links_and_is_attributed() {
        use k256::ecdsa::signature::Signer as _;
        let (mut rb, passport) = setup("es256k");
        let sk = k256::ecdsa::SigningKey::from_bytes(&[0x4B; 32].into()).unwrap();
        let pk: [u8; 33] = sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let tp = ainra_core::link::jwk_thumbprint_es256k(&pk).unwrap();
        let sign = |msg: &[u8]| -> [u8; 64] {
            let s: k256::ecdsa::Signature = sk.sign(msg);
            s.to_bytes().into()
        };
        let consent = pop_signing_bytes(rb.id(), &passport, &tp, NBF);
        let spec = |alg: &str, pop: &[u8]| LinkSpec {
            passport: passport.clone(),
            alg: alg.into(),
            key: b64::encode(&pk),
            pop: b64::encode(pop),
            scope: vec![],
            nbf: NBF,
            exp: NBF + 30 * 24 * 60 * 60,
        };
        // A 33-byte key claimed as Ed25519 is refused before anything else.
        assert!(matches!(
            rb.link(&spec("Ed25519", &sign(&consent))),
            Err(IssueError::Malformed(_))
        ));
        // The high-S twin of the key's own consent is refused, like a signature by another key.
        let low = sign(&consent);
        let s = k256::ecdsa::Signature::from_slice(&low).unwrap();
        let (r, s_) = s.split_scalars();
        let high: [u8; 64] = k256::ecdsa::Signature::from_scalars(r, -*s_)
            .unwrap()
            .to_bytes()
            .into();
        assert!(matches!(
            rb.link(&spec("ES256K", &high)),
            Err(IssueError::HolderProof(_))
        ));
        let rec = rb.link(&spec("ES256K", &low)).unwrap();
        assert_eq!(rec.thumbprint, tp);
        let a = rb
            .verify_link_for(
                &PresentedKey::Es256k(pk),
                VERIFY_NOW,
                status::Freshness::F3,
                None,
            )
            .expect("linked")
            .expect("valid");
        assert_eq!(a.operator, "acme");
    }
}
