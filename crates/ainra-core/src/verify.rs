// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The verification orchestrator — the product's single entrypoint (MTS §8).
//!
//! [`verify`] runs every check in a FIXED, documented order so the first-failure [`Reason`] is deterministic and
//! byte-identical across the Rust core, the TS SDK, and the P0 CLI (property P-5 / the diff-harness). It returns a
//! [`Verdict`] — a domain result, never a panic. Fail closed everywhere: any check that cannot be completed yields
//! INVALID, never VALID.
//!
//! Order (each step's failure reason in parentheses):
//!   1. schema gate                         (`schema_violation` / `name_malformed` — incl. chain linkage + dual-sig/log_leaf presence)
//!   2. issuer registrar is accredited      (`unknown_registrar`)
//!   3. validity window                     (`not_yet_valid`, then `expired`)
//!   4. issuer hybrid signature             (`alg_downgrade`, then `sig_invalid`)
//!   5. scope ceiling                       (`ceiling_exceeded`)
//!   6. delegation chain                    (`schema_violation` on key/proof-count mismatch; then per hop `alg_downgrade`/`sig_invalid` — BOTH parties (D-012); then `chain_widening`, `chain_expired`)
//!   7. status freshness then revocation    (`stale_status`, then `revoked`)
//!   8. mandate subtree                     (static in-passport path, or dynamic w/ inclusion to `mandates_root` (D-013): `schema_violation`, then `mandate_revoked`)
//!   9. logged-before-valid                 (`checkpoint_invalid` (root OR delegate mode, ADR-002); then credential leaf binding+inclusion, then EVERY hop's `log_leaf` binding+inclusion — all `not_logged`)
//!
//! All nine pass ⇒ VALID.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::name::AinraName;
use crate::passport::Passport;
use crate::verdict::{Reason, Verdict};
use crate::{b64, chain, checkpoint, crypto, mandate, merkle, status};

/// What a verifier knows about one accredited registrar (from the signed directory — the directory itself is not
/// modeled in M1; callers construct this from trusted config / test fixtures).
#[derive(Clone)]
pub struct RegistrarInfo {
    /// Hybrid public key the registrar signs passports with.
    pub issuer_key: crypto::HybridPublic,
    /// SLH-DSA public key that signs this registrar's log checkpoints.
    pub log_root_key: Vec<u8>,
}

/// The set of accredited registrars, keyed by registrar id (`registrar-01`, …).
#[derive(Clone, Default)]
pub struct TrustAnchors {
    pub registrars: BTreeMap<alloc::string::String, RegistrarInfo>,
}

/// One hop's transparency-log evidence: where its `log_leaf` sits in the tree the checkpoint commits to.
#[derive(Debug, Clone)]
pub struct HopLogProof {
    pub leaf_index: u64,
    pub proof: Vec<[u8; 32]>,
}

/// One dynamic-mandate node's inclusion evidence against the passport's `mandates_root` (D-013).
#[derive(Debug, Clone)]
pub struct MandateInclusion {
    pub leaf_index: u64,
    pub proof: Vec<[u8; 32]>,
}

/// Everything a verifier is handed for one credential presentation. The core has no clock and no network, so the
/// caller supplies `now` and all fetched material (status list, checkpoint, proofs) explicitly (N7).
pub struct Presentation<'a> {
    /// Canonical passport claim bytes (exactly the bytes the issuer signed).
    pub claims: &'a [u8],
    /// Issuer's hybrid signature over `claims`.
    pub issuer_sig: crypto::HybridSig,
    /// Verifier's current unix time (seconds).
    pub now: u64,
    /// The chain parties' hybrid keys, one per PARTY: `chain_keys[i]` is hop i's delegator, `chain_keys[i+1]` is
    /// hop i's delegatee (which IS hop i+1's delegator — continuity by construction). Length MUST be hops + 1
    /// when a chain is present; empty otherwise. (D-012.)
    pub chain_keys: Vec<crypto::HybridPublic>,
    /// Per-hop inclusion proofs for each hop's `log_leaf`, hop-aligned, against the same checkpoint below.
    pub hop_proofs: Vec<HopLogProof>,
    /// Decoded status list covering the passport's status index.
    pub status_list: status::StatusList,
    /// When the status material was issued (unix seconds) + the required freshness class.
    pub status_issued_at: u64,
    pub freshness: status::Freshness,
    /// The signed checkpoint the passport's log root belongs to, and its signature (root or delegate mode).
    pub checkpoint: checkpoint::Checkpoint,
    pub checkpoint_sig: checkpoint::CheckpointSig,
    /// Inclusion proof of the passport leaf at `leaf_index` under the checkpoint root.
    pub leaf_index: u64,
    pub inclusion_proof: Vec<[u8; 32]>,
    /// DYNAMIC mandates only (passport commits `mandates_root`): the operative path root→…→operative, plus one
    /// inclusion proof per node binding it into the committed tree. Ignored/must-be-empty for static mandates.
    pub mandate_path: Vec<mandate::MandateNode>,
    pub mandate_proofs: Vec<MandateInclusion>,
    /// The current mandate revocation set (a trusted verifier input, like the status list).
    pub mandate_revocations: mandate::RevocationSet,
    /// Revoked delegate-cert fingerprints (M4). A trusted verifier input obtained from the dual-root-signed
    /// [`crate::directory::Directory`]: a checkpoint signed by a revoked delegate is `checkpoint_invalid`. Empty =
    /// no delegate revocations known (the M1–M3 behaviour).
    pub revoked_delegates: alloc::collections::BTreeSet<[u8; 32]>,
}

/// Verify one presentation against the trust anchors. Never panics; returns [`Verdict::Valid`] or the first
/// [`Verdict::Invalid`] reason in the fixed order documented on this module.
pub fn verify(pres: &Presentation, anchors: &TrustAnchors) -> Verdict {
    match verify_inner(pres, anchors) {
        Ok(()) => Verdict::Valid,
        Err(reason) => Verdict::invalid(reason),
    }
}

fn verify_inner(pres: &Presentation, anchors: &TrustAnchors) -> core::result::Result<(), Reason> {
    // 1. schema gate
    let p = Passport::parse_checked(pres.claims)?;

    // 2. issuer registrar is accredited
    let (registrar, _op, _lin) = AinraName::parse_did(&p.iss).map_err(|_| Reason::NameMalformed)?;
    let reg = anchors
        .registrars
        .get(&registrar)
        .ok_or(Reason::UnknownRegistrar)?;

    // 3. validity window (nbf ≤ now < exp)
    if pres.now < p.nbf {
        return Err(Reason::NotYetValid);
    }
    if pres.now >= p.exp {
        return Err(Reason::Expired);
    }

    // 4. issuer hybrid signature over the exact claim bytes
    crypto::verify_hybrid(&reg.issuer_key, pres.claims, &pres.issuer_sig)?;

    // 5. scope ceiling: capabilities ⊆ scope_ceiling
    if !p.capabilities.iter().all(|c| p.scope_ceiling.contains(c)) {
        return Err(Reason::CeilingExceeded);
    }

    // 6. delegation chain (if any): every hop DUAL-signed (delegator + delegatee, D-012), then monotone
    //    ∩-narrowing, and the passport's own (capabilities, exp) must fit within the chain's effective result.
    //    (Structural linkage — from[i+1]==to[i], last.to==sub — was already enforced at the schema gate.)
    if !p.act_chain.is_empty() {
        if pres.chain_keys.len() != p.act_chain.len() + 1 {
            return Err(Reason::SchemaViolation); // one key per chain PARTY (hops + 1)
        }
        if pres.hop_proofs.len() != p.act_chain.len() {
            return Err(Reason::SchemaViolation); // one log proof per hop
        }
        for (i, hop) in p.act_chain.iter().enumerate() {
            chain::verify_hop_sig(hop, &pres.chain_keys[i], &pres.chain_keys[i + 1])?;
        }
        let head = &p.act_chain[0];
        let eff = chain::narrow(&head.granted, head.exp, &p.act_chain[1..])?;
        if !p.capabilities.iter().all(|c| eff.capabilities.contains(c)) {
            return Err(Reason::ChainWidening);
        }
        if p.exp > eff.exp {
            return Err(Reason::ChainExpired);
        }
    } else if !pres.chain_keys.is_empty() || !pres.hop_proofs.is_empty() {
        return Err(Reason::SchemaViolation); // keys/proofs supplied for a chain that does not exist
    }

    // 7. status: freshness first (fail closed if stale), then revocation
    pres.freshness.check(pres.now, pres.status_issued_at)?;
    if pres.status_list.status_of(p.status.status_list.idx) == status::LineageStatus::Revoked {
        return Err(Reason::Revoked);
    }

    // 8. mandate subtree — the STATIC authenticated path carried in the signed passport (never presenter-trusted).
    //    Dynamic post-issue mandates are M3 (D-013); the schema gate already rejects any `mandates_root`, so no
    //    presenter-supplied mandate path is honoured here — it must be empty.
    if !pres.mandate_path.is_empty() || !pres.mandate_proofs.is_empty() {
        return Err(Reason::SchemaViolation);
    }
    mandate::check_path(&p.mandates, &pres.mandate_revocations)?;

    // 9. logged-before-valid. The log commits the *pre-log credential body* — the canonical claims with the `log`
    //    back-reference removed (the `log` object points INTO the log, so it cannot be part of what was logged; this
    //    also avoids a leaf-is-hash-of-bytes-containing-itself fixpoint). Order: (a) checkpoint signature (root or
    //    ADR-002 delegate mode), (b) credential leaf binding + inclusion, (c) EVERY hop's `log_leaf` binding +
    //    inclusion — delegation events are logged-before-valid too (D-012).
    pres.checkpoint
        .verify_sig_mode(&reg.log_root_key, &pres.checkpoint_sig, pres.now)?;
    // Delegate revocation (M4, ADR-002): the root can publish a revocation of a specific delegate cert in the
    // signed directory. A checkpoint whose delegate cert is revoked is `checkpoint_invalid` even though the cert's
    // own signature + window still verify — the online key is dead. Fail closed.
    if let checkpoint::CheckpointSig::Delegate { cert, .. } = &pres.checkpoint_sig {
        if pres.revoked_delegates.contains(&cert.fingerprint()) {
            return Err(Reason::CheckpointInvalid);
        }
    }
    let expected_leaf = prelog_leaf(pres.claims)?;
    let claimed_leaf: [u8; 32] = b64::decode_array(&p.log.leaf).map_err(|_| Reason::NotLogged)?;
    if claimed_leaf != expected_leaf {
        return Err(Reason::NotLogged); // the echoed leaf is not this credential's body
    }
    checkpoint::verify_logged(
        &claimed_leaf,
        pres.leaf_index,
        &pres.checkpoint,
        &pres.inclusion_proof,
    )?;
    for (hop, hp) in p.act_chain.iter().zip(pres.hop_proofs.iter()) {
        let anchored: [u8; 32] = b64::decode_array(&hop.log_leaf).map_err(|_| Reason::NotLogged)?;
        let recomputed = chain::hop_leaf(hop).map_err(|_| Reason::NotLogged)?;
        if anchored != recomputed {
            return Err(Reason::NotLogged); // the anchored leaf is not THIS hop's canonical bytes
        }
        checkpoint::verify_logged(&anchored, hp.leaf_index, &pres.checkpoint, &hp.proof)?;
    }

    Ok(())
}

/// The RFC 6962 leaf for a credential = `hash_leaf(canonical(claims without the `log` object))`.
/// Shared by the issuer (when logging) and the verifier (when checking inclusion) so both hash identical bytes.
pub fn prelog_leaf(claims: &[u8]) -> core::result::Result<[u8; 32], Reason> {
    let mut body: serde_json::Value =
        serde_json::from_slice(claims).map_err(|_| Reason::SchemaViolation)?;
    if let Some(obj) = body.as_object_mut() {
        obj.remove("log");
    }
    let body_bytes = crate::canon::canonicalize(&body)
        .map_err(|_| Reason::SchemaViolation)?
        .into_bytes();
    Ok(merkle::hash_leaf(&body_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};
    use rand_core::SeedableRng;
    use serde_json::json;

    // A fully-wired, genuinely-valid presentation, plus its anchors and mutable knobs, so each test flips exactly
    // one thing and asserts the resulting verdict. Nothing here is mocked — real signatures, a real Merkle log.
    struct Fixture {
        anchors: TrustAnchors,
        claims: Vec<u8>,
        issuer_sig: crypto::HybridSig,
        checkpoint: checkpoint::Checkpoint,
        checkpoint_sig: Vec<u8>,
        proof: Vec<[u8; 32]>,
        leaf_index: u64,
    }

    fn build() -> Fixture {
        build_with(None)
    }

    fn build_with(mandates: Option<serde_json::Value>) -> Fixture {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x5E_EA_11_ED);
        let issuer = crypto::HybridKeypair::generate(&mut rng);
        let root = crypto::TestRootSlh::generate(&mut rng);

        // The pre-log credential BODY (no `log` object) — this is what the transparency log commits.
        let mut body = json!({
            "vct": crate::PASSPORT_VCT,
            "iss": "did:ainra:registrar-01:acme:invoicing",
            "sub": "ainra:registrar-01:acme:invoicing@1.0.0",
            "nbf": 1_000u64,
            "exp": 2_000u64,
            "authority": { "class": "A2", "principal_proof": "deadbeef" },
            "tier": "L1",
            "capabilities": ["read:invoices"],
            "scope_ceiling": ["read:invoices", "sign:invoice"],
            "keys": [ { "ed25519": "AAAA", "mldsa65": "BBBB" } ],
            "cnf": { "jkt": "thumb" },
            "status": { "status_list": { "idx": 0u64, "uri": "status://registrar-01/1" } }
        });
        if let Some(m) = mandates {
            body["mandates"] = m; // authenticated by the issuer signature below
        }
        let body_bytes = crate::canon::canonicalize(&body).unwrap().into_bytes();
        let leaf = merkle::hash_leaf(&body_bytes);

        // Log the body leaf among some fillers, sign a checkpoint over the resulting root.
        let mut log = merkle::TestLog::new();
        for k in 0..3u8 {
            log.append(&[k]); // filler leaves
        }
        let leaf_index = log.append(&body_bytes); // append() hashes with 0x00 → exactly `leaf`
        let cp = checkpoint::Checkpoint {
            origin: "ainra-log/registrar-01".to_string(),
            tree_size: log.size(),
            root: log.root(),
        };
        let cp_sig = cp.sign_test_root(&root).unwrap();
        let proof = log.inclusion_proof(leaf_index).unwrap();

        // Attach the `log` back-reference and sign the FULL claims — this is the presented credential.
        let mut full = body;
        full["log"] = json!({ "leaf": b64::encode(&leaf), "root": b64::encode(&cp.root), "checkpoint": "cp-1" });
        let claims = crate::canon::canonicalize(&full).unwrap().into_bytes();
        // sanity: the verifier's derived pre-log leaf matches what we logged
        assert_eq!(prelog_leaf(&claims).unwrap(), leaf);
        let issuer_sig = issuer.sign(&claims).unwrap();

        let mut registrars = BTreeMap::new();
        registrars.insert(
            "registrar-01".to_string(),
            RegistrarInfo {
                issuer_key: issuer.public(),
                log_root_key: root.public(),
            },
        );

        Fixture {
            anchors: TrustAnchors { registrars },
            claims,
            issuer_sig,
            checkpoint: cp,
            checkpoint_sig: cp_sig,
            proof,
            leaf_index,
        }
    }

    impl Fixture {
        fn present(&self) -> Presentation<'_> {
            Presentation {
                claims: &self.claims,
                issuer_sig: self.issuer_sig.clone(),
                now: 1_500,
                chain_keys: Vec::new(),
                hop_proofs: Vec::new(),
                status_list: status::StatusList::from_bits(alloc::vec![false, false, false]),
                status_issued_at: 1_490,
                freshness: status::Freshness::F2,
                checkpoint: self.checkpoint.clone(),
                checkpoint_sig: checkpoint::CheckpointSig::Root {
                    slh: self.checkpoint_sig.clone(),
                },
                leaf_index: self.leaf_index,
                inclusion_proof: self.proof.clone(),
                mandate_path: Vec::new(),
                mandate_proofs: Vec::new(),
                mandate_revocations: mandate::RevocationSet::default(),
                revoked_delegates: Default::default(),
            }
        }
    }

    #[test]
    fn fully_valid_presentation_is_valid() {
        let f = build();
        assert_eq!(verify(&f.present(), &f.anchors), Verdict::Valid);
    }

    // End-to-end M2 delegated chain: two DUAL-signed hops, each `log_leaf` logged under the same checkpoint, the
    // subject bound as the last hop's delegatee. Valid → then confirm the orchestrator rejects the exact M2 tampers.
    #[test]
    fn delegated_chain_end_to_end() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xDE_1E_6A_7E);
        let issuer = crypto::HybridKeypair::generate(&mut rng);
        let root = crypto::TestRootSlh::generate(&mut rng);
        let owner = crypto::HybridKeypair::generate(&mut rng);
        let agent = crypto::HybridKeypair::generate(&mut rng);

        let mk_hop = |from: &str,
                      to: &str,
                      granted: &[&str],
                      del: &crypto::HybridKeypair,
                      chi: &crypto::HybridKeypair| {
            let mut l = crate::passport::ActLink {
                from: from.into(),
                to: to.into(),
                granted: granted.iter().map(|s| s.to_string()).collect(),
                exp: 2_000,
                sig_ed25519: String::new(),
                sig_mldsa65: String::new(),
                sig_child_ed25519: String::new(),
                sig_child_mldsa65: String::new(),
                log_leaf: String::new(),
            };
            let msg = chain::hop_signing_bytes(&l).unwrap();
            let ps = del.sign(&msg).unwrap();
            l.sig_ed25519 = b64::encode(&ps.ed25519);
            l.sig_mldsa65 = b64::encode(&ps.mldsa65);
            let cs = chi.sign(&msg).unwrap();
            l.sig_child_ed25519 = b64::encode(&cs.ed25519);
            l.sig_child_mldsa65 = b64::encode(&cs.mldsa65);
            l.log_leaf = b64::encode(&chain::hop_leaf(&l).unwrap());
            l
        };
        let sub = "ainra:registrar-01:acme:bot@1.0.0";
        let hop1 = mk_hop(
            "ainra:registrar-01:acme:owner@1.0.0",
            "ainra:registrar-01:acme:agent@1.0.0",
            &["read:x", "sign:x"],
            &owner,
            &agent,
        );
        let hop2 = mk_hop(
            "ainra:registrar-01:acme:agent@1.0.0",
            sub,
            &["read:x"],
            &agent,
            &issuer,
        );
        let act_chain = alloc::vec![hop1.clone(), hop2.clone()];

        let body = json!({
            "vct": crate::PASSPORT_VCT,
            "iss": "did:ainra:registrar-01:acme:bot",
            "sub": sub,
            "nbf": 1_000u64, "exp": 2_000u64,
            "authority": { "class": "A2", "principal_proof": "deadbeef" },
            "tier": "L1",
            "capabilities": ["read:x"],
            "scope_ceiling": ["read:x", "sign:x"],
            "keys": [ { "ed25519": "AAAA", "mldsa65": "BBBB" } ],
            "cnf": { "jkt": "thumb" },
            "status": { "status_list": { "idx": 0u64, "uri": "status://registrar-01/1" } },
            "act_chain": serde_json::to_value(&act_chain).unwrap()
        });
        let body_bytes = crate::canon::canonicalize(&body).unwrap().into_bytes();
        let cred_leaf = merkle::hash_leaf(&body_bytes);

        let mut log = merkle::TestLog::new();
        log.append(&[9u8]);
        let cred_index = log.append(&body_bytes);
        let i1 = log.append(&chain::hop_signing_bytes(&hop1).unwrap());
        let i2 = log.append(&chain::hop_signing_bytes(&hop2).unwrap());
        let cp = checkpoint::Checkpoint {
            origin: "ainra-log/registrar-01".into(),
            tree_size: log.size(),
            root: log.root(),
        };
        let cp_sig = cp.sign_test_root(&root).unwrap();

        let mut full = body;
        full["log"] = json!({ "leaf": b64::encode(&cred_leaf), "root": b64::encode(&cp.root), "checkpoint": "cp-1" });
        let claims = crate::canon::canonicalize(&full).unwrap().into_bytes();
        let issuer_sig = issuer.sign(&claims).unwrap();

        let mut registrars = BTreeMap::new();
        registrars.insert(
            "registrar-01".to_string(),
            RegistrarInfo {
                issuer_key: issuer.public(),
                log_root_key: root.public(),
            },
        );
        let anchors = TrustAnchors { registrars };

        let present =
            |chain_keys: Vec<crypto::HybridPublic>, hop_proofs: Vec<HopLogProof>| Presentation {
                claims: &claims,
                issuer_sig: issuer_sig.clone(),
                now: 1_500,
                chain_keys,
                hop_proofs,
                status_list: status::StatusList::from_bits(alloc::vec![false, false, false]),
                status_issued_at: 1_490,
                freshness: status::Freshness::F2,
                checkpoint: cp.clone(),
                checkpoint_sig: checkpoint::CheckpointSig::Root {
                    slh: cp_sig.clone(),
                },
                leaf_index: cred_index,
                inclusion_proof: log.inclusion_proof(cred_index).unwrap(),
                mandate_path: Vec::new(),
                mandate_proofs: Vec::new(),
                mandate_revocations: mandate::RevocationSet::default(),
                revoked_delegates: Default::default(),
            };
        let good_keys = alloc::vec![owner.public(), agent.public(), issuer.public()];
        let good_proofs = alloc::vec![
            HopLogProof {
                leaf_index: i1,
                proof: log.inclusion_proof(i1).unwrap()
            },
            HopLogProof {
                leaf_index: i2,
                proof: log.inclusion_proof(i2).unwrap()
            },
        ];
        assert_eq!(
            verify(&present(good_keys.clone(), good_proofs.clone()), &anchors),
            Verdict::Valid
        );

        // wrong number of party keys → schema_violation
        assert_eq!(
            verify(
                &present(
                    alloc::vec![owner.public(), agent.public()],
                    good_proofs.clone()
                ),
                &anchors
            ),
            Verdict::invalid(Reason::SchemaViolation)
        );
        // a party key that isn't the real delegatee → the hop counter-signature fails → sig_invalid
        let bad_keys = alloc::vec![owner.public(), root_hybrid(&mut rng), issuer.public()];
        assert_eq!(
            verify(&present(bad_keys, good_proofs.clone()), &anchors),
            Verdict::invalid(Reason::SigInvalid)
        );
        // a hop proof for the wrong leaf → not_logged (the credential + sigs are fine, the hop isn't logged here)
        let bad_proofs = alloc::vec![
            HopLogProof {
                leaf_index: cred_index,
                proof: log.inclusion_proof(cred_index).unwrap()
            },
            HopLogProof {
                leaf_index: i2,
                proof: log.inclusion_proof(i2).unwrap()
            },
        ];
        assert_eq!(
            verify(&present(good_keys, bad_proofs), &anchors),
            Verdict::invalid(Reason::NotLogged)
        );
    }

    fn root_hybrid(rng: &mut rand_chacha::ChaCha20Rng) -> crypto::HybridPublic {
        crypto::HybridKeypair::generate(rng).public()
    }

    #[test]
    fn expired_and_not_yet_valid() {
        let f = build();
        let mut p = f.present();
        p.now = 2_500; // past exp=2000
        assert_eq!(verify(&p, &f.anchors), Verdict::invalid(Reason::Expired));
        let mut p2 = f.present();
        p2.now = 500; // before nbf=1000
        assert_eq!(
            verify(&p2, &f.anchors),
            Verdict::invalid(Reason::NotYetValid)
        );
    }

    #[test]
    fn unknown_registrar() {
        let f = build();
        let empty = TrustAnchors::default();
        assert_eq!(
            verify(&f.present(), &empty),
            Verdict::invalid(Reason::UnknownRegistrar)
        );
    }

    #[test]
    fn bad_issuer_signature_and_downgrade() {
        let f = build();
        let mut p = f.present();
        p.issuer_sig.mldsa65.clear(); // strip PQ sig → downgrade
        assert_eq!(
            verify(&p, &f.anchors),
            Verdict::invalid(Reason::AlgDowngrade)
        );

        let mut p2 = f.present();
        p2.issuer_sig.ed25519[0] ^= 0xff; // corrupt classical sig → sig_invalid
        assert_eq!(
            verify(&p2, &f.anchors),
            Verdict::invalid(Reason::SigInvalid)
        );
    }

    #[test]
    fn revoked_and_stale_status() {
        let f = build();
        let mut p = f.present();
        p.status_list = status::StatusList::from_bits(alloc::vec![true, false, false]); // idx 0 revoked
        assert_eq!(verify(&p, &f.anchors), Verdict::invalid(Reason::Revoked));

        let mut p2 = f.present();
        p2.status_issued_at = 1_000; // 500s old under F2 (max 300s) → stale
        assert_eq!(
            verify(&p2, &f.anchors),
            Verdict::invalid(Reason::StaleStatus)
        );
    }

    #[test]
    fn tampered_checkpoint_and_missing_inclusion() {
        let f = build();
        let mut p = f.present();
        p.checkpoint.tree_size += 1; // checkpoint no longer matches its signature
        assert_eq!(
            verify(&p, &f.anchors),
            Verdict::invalid(Reason::CheckpointInvalid)
        );

        let mut p2 = f.present();
        p2.inclusion_proof = Vec::new(); // empty proof cannot justify a multi-leaf tree
        assert_eq!(verify(&p2, &f.anchors), Verdict::invalid(Reason::NotLogged));
    }

    #[test]
    fn mandate_revocation() {
        // The mandate path is AUTHENTICATED (in the signed body); the presenter only supplies the revocation set.
        // Revoking the root mandate kills the whole subtree even though the presenter cannot alter the path.
        let f = build_with(Some(json!([
            { "id": "m-root", "parent": null },
            { "id": "m-op", "parent": "m-root" }
        ])));
        // clean: no revocations → valid
        assert_eq!(verify(&f.present(), &f.anchors), Verdict::Valid);
        // revoke the ancestor → MandateRevoked
        let mut p = f.present();
        p.mandate_revocations = mandate::RevocationSet::from_ids([String::from("m-root")]);
        assert_eq!(
            verify(&p, &f.anchors),
            Verdict::invalid(Reason::MandateRevoked)
        );
    }

    #[test]
    fn presenter_cannot_forge_or_drop_mandate_path() {
        // A presenter has NO mandate_path input at all — the path is in the signed claims. So a credential whose
        // signed body commits [m-root -> m-op] with m-root revoked is MandateRevoked no matter what the presenter
        // does; there is no field through which to drop the revoked ancestor. (Contrast the old presenter-supplied
        // path, which could omit m-root.) This encodes the fix for the subtree-revocation bypass.
        let f = build_with(Some(json!([
            { "id": "m-root", "parent": null },
            { "id": "m-op", "parent": "m-root" }
        ])));
        let mut p = f.present();
        p.mandate_revocations = mandate::RevocationSet::from_ids([String::from("m-root")]);
        assert_eq!(
            verify(&p, &f.anchors),
            Verdict::invalid(Reason::MandateRevoked)
        );
    }

    #[test]
    fn logged_leaf_must_bind_to_claims() {
        // A validly-signed credential whose `log.leaf` references a REAL in-tree leaf that is NOT its own body must
        // be NotLogged. The inclusion proof below is genuinely valid — only the binding check stops it. If the
        // binding is ever removed, verify_logged passes on the stand-in leaf and this credential wrongly verifies
        // VALID, gutting "logged-before-valid". This test is the guard against exactly that regression.
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xB17D_1235);
        let issuer = crypto::HybridKeypair::generate(&mut rng);
        let root = crypto::TestRootSlh::generate(&mut rng);

        let body = json!({
            "vct": crate::PASSPORT_VCT,
            "iss": "did:ainra:registrar-01:acme:invoicing",
            "sub": "ainra:registrar-01:acme:invoicing@1.0.0",
            "nbf": 1_000u64, "exp": 2_000u64,
            "authority": { "class": "A2", "principal_proof": "deadbeef" },
            "tier": "L1",
            "capabilities": ["read:invoices"],
            "scope_ceiling": ["read:invoices"],
            "keys": [ { "ed25519": "AAAA", "mldsa65": "BBBB" } ],
            "cnf": { "jkt": "thumb" },
            "status": { "status_list": { "idx": 0u64, "uri": "status://registrar-01/1" } }
        });
        let body_bytes = crate::canon::canonicalize(&body).unwrap().into_bytes();

        // Log: three fillers + the real body leaf. The credential will falsely point at filler #0.
        let mut log = merkle::TestLog::new();
        for k in 0..3u8 {
            log.append(&[k]);
        }
        log.append(&body_bytes);
        let cp = checkpoint::Checkpoint {
            origin: "ainra-log/registrar-01".to_string(),
            tree_size: log.size(),
            root: log.root(),
        };
        let cp_sig = cp.sign_test_root(&root).unwrap();

        // filler #0 is genuinely in the tree with a valid proof — but it is not this credential's body.
        let filler0 = merkle::hash_leaf(&[0u8]);
        let filler0_proof = log.inclusion_proof(0).unwrap();

        let mut full = body;
        full["log"] = json!({ "leaf": b64::encode(&filler0), "root": b64::encode(&cp.root), "checkpoint": "cp-1" });
        let claims = crate::canon::canonicalize(&full).unwrap().into_bytes();
        let issuer_sig = issuer.sign(&claims).unwrap(); // validly signed over the mis-pointing claims

        let mut registrars = BTreeMap::new();
        registrars.insert(
            "registrar-01".to_string(),
            RegistrarInfo {
                issuer_key: issuer.public(),
                log_root_key: root.public(),
            },
        );
        let anchors = TrustAnchors { registrars };

        let pres = Presentation {
            claims: &claims,
            issuer_sig,
            now: 1_500,
            chain_keys: Vec::new(),
            hop_proofs: Vec::new(),
            status_list: status::StatusList::from_bits(alloc::vec![false, false, false]),
            status_issued_at: 1_490,
            freshness: status::Freshness::F2,
            checkpoint: cp,
            checkpoint_sig: checkpoint::CheckpointSig::Root { slh: cp_sig },
            leaf_index: 0,                  // filler #0's index
            inclusion_proof: filler0_proof, // a genuinely VALID inclusion proof for filler #0
            mandate_path: Vec::new(),
            mandate_proofs: Vec::new(),
            mandate_revocations: mandate::RevocationSet::default(),
            revoked_delegates: Default::default(),
        };
        assert_eq!(verify(&pres, &anchors), Verdict::invalid(Reason::NotLogged));
    }
}
