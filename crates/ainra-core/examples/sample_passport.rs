// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Generates ONE illustrative, fully-real signed passport per invocation, for `ainra/samples/`.
//!
//! Deliberately separate from `ainra-vector-gen` (the CC0 conformance corpus, optimized for coverage): a sample is
//! optimized for a human looking at a rendered card — sensible dates, memorable capabilities — but the crypto is
//! identical M2: real Ed25519 + ML-DSA-65 hybrid signing, a real RFC 6962 log with a signed SLH-DSA checkpoint,
//! **dual-signed delegation hops** (delegator + delegatee) each anchored by its own logged `log_leaf`, and a verdict
//! produced by actually calling [`ainra_core::verify::verify`] — never hand-written (brief §0 "nothing fake").
//!
//! Usage: `cargo run --release -p ainra-core --example sample_passport -- <valid|delegated|revoked>`
//! Output: a single JSON object on stdout.

use std::collections::BTreeMap;

use ainra_core::passport::ActLink;
use ainra_core::{b64, canon, chain, checkpoint, crypto, mandate, merkle, status, verify};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::json;

// A readable, fixed one-year window (2026-04-11 .. 2027-04-11 UTC). A plain constant — no runtime clock.
const NBF: u64 = 1_775_865_600;
const EXP: u64 = 1_807_401_600;

fn main() {
    let which = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "valid".to_string());
    let out = match which.as_str() {
        "valid" => build(BuildSpec::valid()),
        "delegated" => build(BuildSpec::delegated()),
        "revoked" => build(BuildSpec::revoked()),
        other => {
            eprintln!("unknown sample kind '{other}' — expected valid|delegated|revoked");
            std::process::exit(2);
        }
    };
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

/// One hop of the delegation chain, as authored (before signing).
struct HopSpec {
    from: String,
    to: String,
    granted: Vec<String>,
}

struct BuildSpec {
    kind: &'static str,
    seed: u64,
    registrar: &'static str,
    operator: &'static str,
    lineage: &'static str,
    version: &'static str,
    tier: &'static str,
    principal_proof: &'static str,
    capabilities: Vec<&'static str>,
    scope_ceiling: Vec<&'static str>,
    status_idx: u64,
    revoke: bool,
    hops: Vec<HopSpec>,
}

impl BuildSpec {
    fn valid() -> Self {
        BuildSpec {
            kind: "valid",
            seed: 1,
            registrar: "registrar-07",
            operator: "acme",
            lineage: "invoicing",
            version: "4.2.1",
            tier: "L3",
            principal_proof: "deadbeef7f3a2c1d",
            capabilities: vec!["read:invoices", "sign:invoice"],
            scope_ceiling: vec!["read:invoices", "sign:invoice", "read:payments"],
            status_idx: 0,
            revoke: false,
            hops: vec![],
        }
    }
    fn revoked() -> Self {
        BuildSpec {
            kind: "revoked",
            seed: 3,
            registrar: "registrar-07",
            operator: "acme",
            lineage: "data-export",
            version: "2.0.0",
            tier: "L2",
            principal_proof: "deadbeefc7591fa3",
            capabilities: vec!["export:data"],
            scope_ceiling: vec!["export:data"],
            status_idx: 2,
            revoke: true,
            hops: vec![],
        }
    }
    fn delegated() -> Self {
        let reg = "registrar-07";
        BuildSpec {
            kind: "delegated",
            seed: 2,
            registrar: reg,
            operator: "acme",
            lineage: "support-bot",
            version: "1.0.0",
            tier: "L1",
            principal_proof: "deadbeef91a4e0b2",
            capabilities: vec!["read:tickets"],
            scope_ceiling: vec!["read:tickets", "reply:ticket"],
            status_idx: 1,
            revoke: false,
            hops: vec![
                HopSpec {
                    from: format!("ainra:{reg}:acme:owner@1.0.0"),
                    to: format!("ainra:{reg}:acme:support-desk@1.0.0"),
                    granted: vec!["read:tickets".into(), "reply:ticket".into()],
                },
                HopSpec {
                    from: format!("ainra:{reg}:acme:support-desk@1.0.0"),
                    to: format!("ainra:{reg}:acme:support-bot@1.0.0"),
                    granted: vec!["read:tickets".into()],
                },
            ],
        }
    }
}

fn build(spec: BuildSpec) -> serde_json::Value {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5A_4D_50_4C_45 ^ spec.seed); // "SAMPLE" ⊕ seed — never a prod key
    let issuer = crypto::HybridKeypair::generate(&mut rng);
    let root = crypto::TestRootSlh::generate(&mut rng);
    // The HOLDER's hybrid keypair — REAL keys, so the rendered card's fingerprint/keyprint is a genuine
    // fingerprint of a genuine Ed25519 key (and `cnf.jkt` a real thumbprint), not placeholder bytes.
    let holder = crypto::HybridKeypair::generate(&mut rng);
    let holder_pub = holder.public();
    let holder_ed = b64::encode(&holder_pub.ed25519);
    let holder_ml = b64::encode(&holder_pub.mldsa65);
    let jkt = {
        use sha2::{Digest, Sha256};
        let canon_key = canon::canonicalize(&json!({ "ed25519": holder_ed, "mldsa65": holder_ml }))
            .expect("canon holder key");
        let digest: [u8; 32] = Sha256::digest(canon_key.as_bytes()).into();
        b64::encode(&digest)
    };

    // One keypair per chain PARTY (hops + 1). chain_keys[i] signs hop i as delegator; chain_keys[i+1] counter-signs.
    let n_parties = if spec.hops.is_empty() {
        0
    } else {
        spec.hops.len() + 1
    };
    let party_keys: Vec<crypto::HybridKeypair> = (0..n_parties)
        .map(|_| crypto::HybridKeypair::generate(&mut rng))
        .collect();

    // Build + dual-sign each hop, computing its log_leaf.
    let mut act_chain: Vec<ActLink> = Vec::new();
    for (i, h) in spec.hops.iter().enumerate() {
        let mut link = ActLink {
            from: h.from.clone(),
            to: h.to.clone(),
            granted: h.granted.clone(),
            exp: EXP,
            sig_ed25519: String::new(),
            sig_mldsa65: String::new(),
            sig_child_ed25519: String::new(),
            sig_child_mldsa65: String::new(),
            log_leaf: String::new(),
        };
        let msg = chain::hop_signing_bytes(&link).expect("hop bytes");
        let ps = party_keys[i].sign(&msg).expect("delegator sign");
        link.sig_ed25519 = b64::encode(&ps.ed25519);
        link.sig_mldsa65 = b64::encode(&ps.mldsa65);
        let cs = party_keys[i + 1].sign(&msg).expect("delegatee sign");
        link.sig_child_ed25519 = b64::encode(&cs.ed25519);
        link.sig_child_mldsa65 = b64::encode(&cs.mldsa65);
        link.log_leaf = b64::encode(&chain::hop_leaf(&link).expect("hop leaf"));
        act_chain.push(link);
    }

    // Credential body (no `log` back-reference yet).
    let mut body = json!({
        "vct": ainra_core::PASSPORT_VCT,
        "iss": format!("did:ainra:{}:{}:{}", spec.registrar, spec.operator, spec.lineage),
        "sub": format!("ainra:{}:{}:{}@{}", spec.registrar, spec.operator, spec.lineage, spec.version),
        "nbf": NBF, "exp": EXP,
        "authority": { "class": "A2", "principal_proof": spec.principal_proof },
        "tier": spec.tier,
        "capabilities": spec.capabilities,
        "scope_ceiling": spec.scope_ceiling,
        "keys": [ { "ed25519": holder_ed, "mldsa65": holder_ml } ],
        "cnf": { "jkt": jkt },
        "status": { "status_list": { "idx": spec.status_idx, "uri": format!("status://{}/1", spec.registrar) } },
    });
    if !act_chain.is_empty() {
        body["act_chain"] = serde_json::to_value(&act_chain).expect("act_chain");
    }
    let body_bytes = canon::canonicalize(&body).expect("canon body").into_bytes();
    let cred_leaf = merkle::hash_leaf(&body_bytes);

    // ONE log commits the credential body AND every hop leaf, under one signed checkpoint.
    let mut log = merkle::TestLog::new();
    for k in 0..3u8 {
        log.append(&[k]); // filler neighbors
    }
    let cred_index = log.append(&body_bytes);
    // append() hashes each entry with the 0x00 leaf prefix — i.e. it stores exactly hop_leaf(hop). So we append
    // each hop's canonical bytes and the resulting leaf equals the hop's `log_leaf`.
    let hop_indices: Vec<u64> = act_chain
        .iter()
        .map(|h| log.append(&chain::hop_signing_bytes(h).expect("hop bytes")))
        .collect();
    let cp = checkpoint::Checkpoint {
        origin: format!("ainra-log/{}", spec.registrar),
        tree_size: log.size(),
        root: log.root(),
    };
    let cp_sig = cp.sign_test_root(&root).expect("checkpoint sig");
    let cred_proof = log.inclusion_proof(cred_index).expect("cred proof");
    let hop_proofs: Vec<(u64, Vec<[u8; 32]>)> = hop_indices
        .iter()
        .map(|&i| (i, log.inclusion_proof(i).expect("hop proof")))
        .collect();

    // Attach the log back-reference + sign the full claims.
    let mut full = body;
    full["log"] = json!({ "leaf": b64::encode(&cred_leaf), "root": b64::encode(&cp.root), "checkpoint": "cp-1" });
    let claims = canon::canonicalize(&full).expect("canon full").into_bytes();
    let issuer_sig = issuer.sign(&claims).expect("sign claims");

    // Status list; set the lineage bit iff revoked.
    let mut bits = vec![false; 16];
    if spec.revoke {
        bits[spec.status_idx as usize] = true;
    }

    // Run the REAL verifier to get the shipped verdict.
    let now = NBF + (EXP - NBF) / 4;
    let mut registrars = BTreeMap::new();
    registrars.insert(
        spec.registrar.to_string(),
        verify::RegistrarInfo {
            issuer_key: issuer.public(),
            log_root_key: root.public(),
        },
    );
    let anchors = verify::TrustAnchors { registrars };
    let pres = verify::Presentation {
        claims: &claims,
        issuer_sig: issuer_sig.clone(),
        now,
        chain_keys: party_keys.iter().map(|k| k.public()).collect(),
        hop_proofs: hop_proofs
            .iter()
            .map(|(i, p)| verify::HopLogProof {
                leaf_index: *i,
                proof: p.clone(),
            })
            .collect(),
        status_list: status::StatusList::from_bits(bits.clone()),
        status_issued_at: now.saturating_sub(5),
        freshness: status::Freshness::F3,
        checkpoint: cp.clone(),
        checkpoint_sig: checkpoint::CheckpointSig::Root {
            slh: cp_sig.clone(),
        },
        leaf_index: cred_index,
        inclusion_proof: cred_proof.clone(),
        mandate_path: Vec::new(),
        mandate_proofs: Vec::new(),
        mandate_revocations: mandate::RevocationSet::default(),
        revoked_delegates: Default::default(),
    };
    let verdict = verify::verify(&pres, &anchors);

    json!({
        "kind": spec.kind,
        "claims": String::from_utf8(claims.clone()).unwrap(),
        "claims_b64": b64::encode(&claims),
        "issuer_pub": key_json(&issuer.public()),
        "issuer_sig": { "ed25519": b64::encode(&issuer_sig.ed25519), "mldsa65": b64::encode(&issuer_sig.mldsa65) },
        "root_pub_slh": b64::encode(&root.public()),
        "checkpoint": { "origin": cp.origin, "size": cp.tree_size, "root": b64::encode(&cp.root) },
        "checkpoint_sig": b64::encode(&cp_sig),
        "leaf_index": cred_index,
        "inclusion_proof": cred_proof.iter().map(|h| b64::encode(h)).collect::<Vec<_>>(),
        "chain_keys": party_keys.iter().map(|k| key_json(&k.public())).collect::<Vec<_>>(),
        "hop_proofs": hop_proofs.iter().map(|(i, p)| json!({
            "leaf_index": i, "proof": p.iter().map(|h| b64::encode(h)).collect::<Vec<_>>()
        })).collect::<Vec<_>>(),
        "status_bits": bits,
        "verify_now": now,
        "verdict": serde_json::to_value(&verdict).unwrap(),
    })
}

fn key_json(k: &crypto::HybridPublic) -> serde_json::Value {
    json!({ "ed25519": b64::encode(&k.ed25519), "mldsa65": b64::encode(&k.mldsa65) })
}
