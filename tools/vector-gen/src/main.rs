// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Conformance-vector generator + replay checker.
//!
//! `ainra-vector-gen --out DIR --min N` writes ≥N CC0 conformance vectors to DIR. Each vector is a REAL signed
//! credential presentation plus the expected [`Verdict`] — no mocked crypto, no invented outcomes (brief §0). The
//! corpus covers a VALID credential (many parameter variants) and every closed [`Reason`], so any implementation
//! (this core, the TS SDK, the P0 CLI) can be checked against the exact same bytes (property P-5 / the diff-harness).
//!
//! `ainra-vector-gen --check DIR` reloads every vector, reconstructs the presentation, runs [`verify`], and asserts
//! the produced verdict equals the recorded one. This is the generator holding ITSELF honest: a drift between the
//! signed bytes and the recorded verdict fails the build.
//!
//! Determinism: keys come from a seeded ChaCha CSPRNG (seed = fixed constant ⊕ index). No wall-clock, no OS entropy,
//! so `make vectors` is byte-reproducible. The seeds are public and labeled TEST — never production keys.

use std::collections::BTreeMap;
use std::path::Path;

use ainra_core::passport::ActLink;
use ainra_core::verdict::{Reason, Verdict};
use ainra_core::{b64, canon, chain, checkpoint, crypto, mandate, merkle, status, verify};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ── Wire format (stable; the TS SDK mirrors these exact field names) ───────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
struct WireKey {
    ed25519: String,
    mldsa65: String,
}
#[derive(Serialize, Deserialize, Clone)]
struct WireSig {
    ed25519: String,
    mldsa65: String,
}
#[derive(Serialize, Deserialize, Clone)]
struct WireRegistrar {
    issuer_key: WireKey,
    log_root_key: String,
}
#[derive(Serialize, Deserialize, Clone)]
struct WireCheckpoint {
    origin: String,
    size: u64,
    root: String,
}
/// One hop's transparency-log inclusion evidence (M2 D-012).
#[derive(Serialize, Deserialize, Clone)]
struct WireHopProof {
    leaf_index: u64,
    proof: Vec<String>,
}
/// A checkpoint signature in one of the two ADR-002 modes.
#[derive(Serialize, Deserialize, Clone)]
struct WireCheckpointSig {
    mode: String, // "root" | "delegate"
    #[serde(skip_serializing_if = "Option::is_none")]
    slh: Option<String>, // root mode
    #[serde(skip_serializing_if = "Option::is_none")]
    cert: Option<WireDelegateCert>, // delegate mode
    #[serde(skip_serializing_if = "Option::is_none")]
    sig_ed25519: Option<String>, // delegate mode
}
#[derive(Serialize, Deserialize, Clone)]
struct WireDelegateCert {
    delegate_ed25519: String,
    scopes: Vec<String>,
    nbf: u64,
    exp: u64,
    sig_slh: String,
}
#[derive(Serialize, Deserialize, Clone)]
struct WirePresentation {
    claims: String,
    issuer_sig: WireSig,
    now: u64,
    // One key per chain PARTY (hops + 1): [delegator_0, delegatee_0=delegator_1, …, subject] (M2 D-012).
    chain_keys: Vec<WireKey>,
    hop_proofs: Vec<WireHopProof>,
    status_list: String,
    status_len: u64,
    status_issued_at: u64,
    freshness: String,
    checkpoint: WireCheckpoint,
    checkpoint_sig: WireCheckpointSig,
    leaf_index: u64,
    inclusion_proof: Vec<String>,
    // The operative mandate path is inside the signed `claims` (authenticated); only the revocation set is here.
    mandate_revocations: Vec<String>,
    /// Revoked delegate-cert fingerprints (base64url SHA-256), M4. Omitted (default empty) for pre-M4 vectors so
    /// the existing corpus is byte-unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    revoked_delegates: Vec<String>,
}
#[derive(Serialize, Deserialize, Clone)]
struct WireExpect {
    verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}
#[derive(Serialize, Deserialize, Clone)]
struct Vector {
    name: String,
    description: String,
    expect: WireExpect,
    anchors: BTreeMap<String, WireRegistrar>,
    presentation: WirePresentation,
}

// ── Credential construction (issuer side, full control incl. secret keys) ──────────────────────────────────────

/// A delegation hop to bake into `act_chain`.
struct HopSpec {
    from: String,
    to: String,
    granted: Vec<String>,
    exp: u64,
}

struct CredParams {
    seed: u64,
    registrar: String,
    operator: String,
    lineage: String,
    version: String,
    nbf: u64,
    exp: u64,
    capabilities: Vec<String>,
    scope_ceiling: Vec<String>,
    status_idx: u64,
    status_len: usize,
    status_revoked: bool,
    chain: Vec<HopSpec>,
    /// Operative mandate path (id, parent) baked into the signed body. Empty = no mandate gate.
    mandates: Vec<(String, Option<String>)>,
    /// Sign the checkpoint via the ADR-002 delegate (root-certified Ed25519) instead of the root directly.
    delegate_checkpoint: bool,
    /// Override the delegate cert window `[0, exp]` (properly signed). Used to build a GENUINELY-expired cert so the
    /// expiry branch of `verify_sig_mode` actually fires (not a signature mismatch). `None` = the default long window.
    delegate_cert_exp: Option<u64>,
}

/// Everything needed to emit a wire vector AND to run verify locally.
struct Built {
    claims: Vec<u8>,
    issuer_pub: crypto::HybridPublic,
    issuer_sig: crypto::HybridSig,
    root_pub: Vec<u8>,
    registrar: String,
    cp: checkpoint::Checkpoint,
    cp_sig: WireCheckpointSig,
    proof: Vec<[u8; 32]>,
    leaf_index: u64,
    status_list: status::StatusList,
    status_len: usize,
    /// Chain PARTIES (hops + 1): [delegator_0, delegatee_0, …, subject]. Empty for a root-issued passport.
    chain_keys: Vec<crypto::HybridPublic>,
    /// Per-hop inclusion evidence, hop-aligned.
    hop_proofs: Vec<(u64, Vec<[u8; 32]>)>,
    nbf: u64,
    exp: u64,
}

/// Sign a checkpoint in root mode, or (if `delegate`) via a root-certified ADR-002 delegate valid over [nbf, exp].
fn checkpoint_sig(
    cp: &checkpoint::Checkpoint,
    root: &crypto::TestRootSlh,
    rng: &mut ChaCha20Rng,
    delegate: bool,
    cert_exp: Option<u64>,
) -> WireCheckpointSig {
    if !delegate {
        return WireCheckpointSig {
            mode: "root".into(),
            slh: Some(b64::encode(&cp.sign_test_root(root).expect("cp sig"))),
            cert: None,
            sig_ed25519: None,
        };
    }
    let del = crypto::TestDelegate::generate(rng);
    // Default window covers any verify `now` (0 .. 92 days), lifetime exactly at the ADR-002 cap; `cert_exp`
    // overrides it (properly SIGNED over the shorter window) to build a genuinely-expired cert.
    let cert = checkpoint::DelegateCert::issue_test_root(
        root,
        del.public(),
        vec![checkpoint::SCOPE_CHECKPOINT.to_string()],
        0,
        cert_exp.unwrap_or(checkpoint::DELEGATE_CERT_MAX_SECS),
    )
    .expect("delegate cert");
    WireCheckpointSig {
        mode: "delegate".into(),
        slh: None,
        cert: Some(WireDelegateCert {
            delegate_ed25519: b64::encode(&cert.delegate_ed25519),
            scopes: cert.scopes.clone(),
            nbf: cert.nbf,
            exp: cert.exp,
            sig_slh: b64::encode(&cert.sig_slh),
        }),
        sig_ed25519: Some(b64::encode(&cp.sign_delegate(&del).expect("delegate sign"))),
    }
}

fn build(p: &CredParams) -> Built {
    let mut rng = ChaCha20Rng::seed_from_u64(0x4149_4E52_4100_0000 ^ p.seed); // "AINRA" ⊕ seed
    let issuer = crypto::HybridKeypair::generate(&mut rng);
    let root = crypto::TestRootSlh::generate(&mut rng);

    // One keypair per chain PARTY (hops + 1): party[i] delegates hop i, party[i+1] counter-signs (D-012).
    let n_parties = if p.chain.is_empty() {
        0
    } else {
        p.chain.len() + 1
    };
    let party_keys: Vec<crypto::HybridKeypair> = (0..n_parties)
        .map(|_| crypto::HybridKeypair::generate(&mut rng))
        .collect();

    // Build + DUAL-sign each hop, computing its log_leaf.
    let mut act_chain: Vec<ActLink> = Vec::new();
    for (i, hop) in p.chain.iter().enumerate() {
        let mut link = ActLink {
            from: hop.from.clone(),
            to: hop.to.clone(),
            granted: hop.granted.clone(),
            exp: hop.exp,
            sig_ed25519: String::new(),
            sig_mldsa65: String::new(),
            sig_child_ed25519: String::new(),
            sig_child_mldsa65: String::new(),
            log_leaf: String::new(),
        };
        let msg = chain::hop_signing_bytes(&link).expect("hop signing bytes");
        let ps = party_keys[i].sign(&msg).expect("delegator sign");
        link.sig_ed25519 = b64::encode(&ps.ed25519);
        link.sig_mldsa65 = b64::encode(&ps.mldsa65);
        let cs = party_keys[i + 1].sign(&msg).expect("delegatee sign");
        link.sig_child_ed25519 = b64::encode(&cs.ed25519);
        link.sig_child_mldsa65 = b64::encode(&cs.mldsa65);
        link.log_leaf = b64::encode(&chain::hop_leaf(&link).expect("hop leaf"));
        act_chain.push(link);
    }

    // Pre-log credential body (no `log` object).
    let mut body = json!({
        "vct": ainra_core::PASSPORT_VCT,
        "iss": format!("did:ainra:{}:{}:{}", p.registrar, p.operator, p.lineage),
        "sub": format!("ainra:{}:{}:{}@{}", p.registrar, p.operator, p.lineage, p.version),
        "nbf": p.nbf,
        "exp": p.exp,
        "authority": { "class": "A2", "principal_proof": "deadbeef" },
        "tier": "L1",
        "capabilities": p.capabilities.clone(),
        "scope_ceiling": p.scope_ceiling.clone(),
        "keys": [ { "ed25519": "AAAA", "mldsa65": "BBBB" } ],
        "cnf": { "jkt": "thumb" },
        "status": { "status_list": { "idx": p.status_idx, "uri": format!("status://{}/1", p.registrar) } },
        "act_chain": serde_json::to_value(&act_chain).expect("act_chain")
    });
    if !p.mandates.is_empty() {
        let arr: Vec<Value> = p
            .mandates
            .iter()
            .map(|(id, parent)| json!({ "id": id, "parent": parent }))
            .collect();
        body["mandates"] = Value::Array(arr); // authenticated by the issuer signature below
    }
    let body_bytes = canon::canonicalize(&body).expect("canon body").into_bytes();
    let leaf = merkle::hash_leaf(&body_bytes);

    // ONE log commits the credential body AND every hop leaf, under one signed checkpoint.
    let mut log = merkle::TestLog::new();
    for k in 0..3u8 {
        log.append(&[k]);
    }
    let leaf_index = log.append(&body_bytes);
    let hop_indices: Vec<u64> = act_chain
        .iter()
        .map(|h| log.append(&chain::hop_signing_bytes(h).expect("hop bytes")))
        .collect();
    let cp = checkpoint::Checkpoint {
        origin: format!("ainra-log/{}", p.registrar),
        tree_size: log.size(),
        root: log.root(),
    };
    let cp_sig = checkpoint_sig(
        &cp,
        &root,
        &mut rng,
        p.delegate_checkpoint,
        p.delegate_cert_exp,
    );
    let proof = log.inclusion_proof(leaf_index).expect("proof");
    let hop_proofs: Vec<(u64, Vec<[u8; 32]>)> = hop_indices
        .iter()
        .map(|&i| (i, log.inclusion_proof(i).expect("hop proof")))
        .collect();

    // Attach the log back-reference, sign the full claims.
    let mut full = body;
    full["log"] =
        json!({ "leaf": b64::encode(&leaf), "root": b64::encode(&cp.root), "checkpoint": "cp-1" });
    let claims = canon::canonicalize(&full).expect("canon full").into_bytes();
    debug_assert_eq!(verify::prelog_leaf(&claims).expect("prelog"), leaf);
    let issuer_sig = issuer.sign(&claims).expect("sign claims");

    // Status list of `status_len` bits; set the lineage bit iff revoked.
    let mut bits = vec![false; p.status_len];
    if p.status_revoked && (p.status_idx as usize) < bits.len() {
        bits[p.status_idx as usize] = true;
    }
    let status_list = status::StatusList::from_bits(bits);

    Built {
        claims,
        issuer_pub: issuer.public(),
        issuer_sig,
        root_pub: root.public(),
        registrar: p.registrar.clone(),
        cp,
        cp_sig,
        proof,
        leaf_index,
        status_list,
        status_len: p.status_len,
        chain_keys: party_keys.iter().map(|k| k.public()).collect(),
        hop_proofs,
        nbf: p.nbf,
        exp: p.exp,
    }
}

/// A validly-signed credential whose `log.leaf` references a REAL in-tree leaf that is NOT its own body. Every check
/// through step 8 passes and the inclusion proof is genuinely valid — only the body↔leaf binding stops it, so the
/// expected verdict is NotLogged. Guards the binding across implementations (review finding #4).
fn build_binding_mismatch(seed: u64) -> Built {
    let mut rng = ChaCha20Rng::seed_from_u64(0x4149_4E52_4142_0000 ^ seed);
    let issuer = crypto::HybridKeypair::generate(&mut rng);
    let root = crypto::TestRootSlh::generate(&mut rng);
    let p = valid_params(seed as usize);
    let body = json!({
        "vct": ainra_core::PASSPORT_VCT,
        "iss": format!("did:ainra:{}:{}:{}", p.registrar, p.operator, p.lineage),
        "sub": format!("ainra:{}:{}:{}@{}", p.registrar, p.operator, p.lineage, p.version),
        "nbf": p.nbf, "exp": p.exp,
        "authority": { "class": "A2", "principal_proof": "deadbeef" },
        "tier": "L1",
        "capabilities": p.capabilities.clone(),
        "scope_ceiling": p.scope_ceiling.clone(),
        "keys": [ { "ed25519": "AAAA", "mldsa65": "BBBB" } ],
        "cnf": { "jkt": "thumb" },
        "status": { "status_list": { "idx": p.status_idx, "uri": format!("status://{}/1", p.registrar) } },
        "act_chain": []
    });
    let body_bytes = canon::canonicalize(&body).expect("canon").into_bytes();
    let mut log = merkle::TestLog::new();
    for k in 0..3u8 {
        log.append(&[k]);
    }
    log.append(&body_bytes); // real body leaf at index 3
    let cp = checkpoint::Checkpoint {
        origin: format!("ainra-log/{}", p.registrar),
        tree_size: log.size(),
        root: log.root(),
    };
    let cp_sig = checkpoint_sig(&cp, &root, &mut rng, false, None);
    // Present filler #0 (genuinely in-tree, valid proof) as the log.leaf — mismatched to the body.
    let filler0 = merkle::hash_leaf(&[0u8]);
    let proof = log.inclusion_proof(0).expect("proof");
    let mut full = body;
    full["log"] = json!({ "leaf": b64::encode(&filler0), "root": b64::encode(&cp.root), "checkpoint": "cp-1" });
    let claims = canon::canonicalize(&full).expect("canon").into_bytes();
    let issuer_sig = issuer.sign(&claims).expect("sign");
    Built {
        claims,
        issuer_pub: issuer.public(),
        issuer_sig,
        root_pub: root.public(),
        registrar: p.registrar.clone(),
        cp,
        cp_sig,
        proof,
        leaf_index: 0,
        status_list: status::StatusList::from_bits(vec![false; p.status_len]),
        status_len: p.status_len,
        chain_keys: Vec::new(),
        hop_proofs: Vec::new(),
        nbf: p.nbf,
        exp: p.exp,
    }
}

// ── Wire assembly ──────────────────────────────────────────────────────────────────────────────────────────────

fn wire_key(k: &crypto::HybridPublic) -> WireKey {
    WireKey {
        ed25519: b64::encode(&k.ed25519),
        mldsa65: b64::encode(&k.mldsa65),
    }
}

/// Assemble a wire vector for a HAPPY-PATH presentation over `built`. Failure variants clone this and tweak.
fn wire_valid(name: &str, description: &str, built: &Built) -> Vector {
    let mut anchors = BTreeMap::new();
    anchors.insert(
        built.registrar.clone(),
        WireRegistrar {
            issuer_key: wire_key(&built.issuer_pub),
            log_root_key: b64::encode(&built.root_pub),
        },
    );
    let now = built.nbf + (built.exp - built.nbf) / 2;
    let pres = WirePresentation {
        claims: b64::encode(&built.claims),
        issuer_sig: WireSig {
            ed25519: b64::encode(&built.issuer_sig.ed25519),
            mldsa65: b64::encode(&built.issuer_sig.mldsa65),
        },
        now,
        chain_keys: built.chain_keys.iter().map(wire_key).collect(),
        hop_proofs: built
            .hop_proofs
            .iter()
            .map(|(i, p)| WireHopProof {
                leaf_index: *i,
                proof: p.iter().map(|h| b64::encode(h)).collect(),
            })
            .collect(),
        status_list: b64::encode(&built.status_list.encode().expect("encode status")),
        status_len: built.status_len as u64,
        status_issued_at: now - 10,
        freshness: "F2".to_string(),
        checkpoint: WireCheckpoint {
            origin: built.cp.origin.clone(),
            size: built.cp.tree_size,
            root: b64::encode(&built.cp.root),
        },
        checkpoint_sig: built.cp_sig.clone(),
        leaf_index: built.leaf_index,
        inclusion_proof: built.proof.iter().map(|h| b64::encode(h)).collect(),
        mandate_revocations: Vec::new(),
        revoked_delegates: Default::default(),
    };
    Vector {
        name: name.to_string(),
        description: description.to_string(),
        expect: WireExpect {
            verdict: "valid".to_string(),
            reason: None,
        },
        anchors,
        presentation: pres,
    }
}

/// The base64url SHA-256 fingerprint of a wire delegate cert — the value a directory lists to revoke it. Computed
/// via the real core `DelegateCert::fingerprint`, so the vector's revoked-fingerprint matches exactly what a
/// verifier recomputes from the presented cert.
fn wire_cert_fingerprint(c: &WireDelegateCert) -> String {
    let core = checkpoint::DelegateCert {
        delegate_ed25519: b64::decode_array::<32>(&c.delegate_ed25519).expect("delegate pk"),
        scopes: c.scopes.clone(),
        nbf: c.nbf,
        exp: c.exp,
        sig_slh: b64::decode(&c.sig_slh).expect("cert sig"),
    };
    b64::encode(&core.fingerprint())
}

fn invalid(mut v: Vector, reason: Reason, description: &str) -> Vector {
    v.expect = WireExpect {
        verdict: "invalid".to_string(),
        reason: Some(reason.as_str().to_string()),
    };
    v.description = description.to_string();
    v
}

// ── Replay (the --check path) ──────────────────────────────────────────────────────────────────────────────────

fn decode32(s: &str) -> [u8; 32] {
    b64::decode_array::<32>(s).expect("32-byte field")
}

fn run(v: &Vector) -> Verdict {
    let claims = b64::decode(&v.presentation.claims).expect("claims");
    let issuer_sig = crypto::HybridSig {
        ed25519: b64::decode(&v.presentation.issuer_sig.ed25519).expect("sig ed"),
        mldsa65: b64::decode(&v.presentation.issuer_sig.mldsa65).expect("sig ml"),
    };
    let chain_keys: Vec<crypto::HybridPublic> = v
        .presentation
        .chain_keys
        .iter()
        .map(|k| crypto::HybridPublic {
            ed25519: decode32(&k.ed25519),
            mldsa65: b64::decode(&k.mldsa65).expect("ml"),
        })
        .collect();
    let hop_proofs: Vec<verify::HopLogProof> = v
        .presentation
        .hop_proofs
        .iter()
        .map(|hp| verify::HopLogProof {
            leaf_index: hp.leaf_index,
            proof: hp.proof.iter().map(|s| decode32(s)).collect(),
        })
        .collect();
    let checkpoint_sig = decode_cp_sig(&v.presentation.checkpoint_sig);
    let status_list = status::StatusList::decode(
        &b64::decode(&v.presentation.status_list).expect("status bytes"),
        v.presentation.status_len as usize,
    )
    .expect("decode status list");
    let checkpoint = checkpoint::Checkpoint {
        origin: v.presentation.checkpoint.origin.clone(),
        tree_size: v.presentation.checkpoint.size,
        root: decode32(&v.presentation.checkpoint.root),
    };
    let inclusion_proof: Vec<[u8; 32]> = v
        .presentation
        .inclusion_proof
        .iter()
        .map(|s| decode32(s))
        .collect();
    let freshness = match v.presentation.freshness.as_str() {
        "F1" => status::Freshness::F1,
        "F2" => status::Freshness::F2,
        "F3" => status::Freshness::F3,
        other => panic!("unknown freshness {other}"),
    };
    let mandate_revocations =
        mandate::RevocationSet::from_ids(v.presentation.mandate_revocations.clone());

    let mut registrars = BTreeMap::new();
    for (id, r) in &v.anchors {
        registrars.insert(
            id.clone(),
            verify::RegistrarInfo {
                issuer_key: crypto::HybridPublic {
                    ed25519: decode32(&r.issuer_key.ed25519),
                    mldsa65: b64::decode(&r.issuer_key.mldsa65).expect("issuer ml"),
                },
                log_root_key: b64::decode(&r.log_root_key).expect("log root"),
            },
        );
    }
    let anchors = verify::TrustAnchors { registrars };

    let revoked_delegates: std::collections::BTreeSet<[u8; 32]> = v
        .presentation
        .revoked_delegates
        .iter()
        .map(|fp| decode32(fp))
        .collect();
    let pres = verify::Presentation {
        claims: &claims,
        issuer_sig,
        now: v.presentation.now,
        chain_keys,
        hop_proofs,
        status_list,
        status_issued_at: v.presentation.status_issued_at,
        freshness,
        checkpoint,
        checkpoint_sig,
        leaf_index: v.presentation.leaf_index,
        inclusion_proof,
        mandate_path: Vec::new(),
        mandate_proofs: Vec::new(),
        mandate_revocations,
        revoked_delegates,
    };
    verify::verify(&pres, &anchors)
}

/// Reconstruct a `CheckpointSig` from its wire form (root or ADR-002 delegate mode).
fn decode_cp_sig(w: &WireCheckpointSig) -> checkpoint::CheckpointSig {
    match w.mode.as_str() {
        "root" => checkpoint::CheckpointSig::Root {
            slh: b64::decode(w.slh.as_deref().unwrap_or("")).expect("slh"),
        },
        "delegate" => {
            let c = w.cert.as_ref().expect("delegate cert");
            checkpoint::CheckpointSig::Delegate {
                cert: checkpoint::DelegateCert {
                    delegate_ed25519: decode32(&c.delegate_ed25519),
                    scopes: c.scopes.clone(),
                    nbf: c.nbf,
                    exp: c.exp,
                    sig_slh: b64::decode(&c.sig_slh).expect("cert slh"),
                },
                sig_ed25519: b64::decode(w.sig_ed25519.as_deref().unwrap_or("")).expect("del sig"),
            }
        }
        other => panic!("unknown checkpoint sig mode {other}"),
    }
}

fn expected(v: &Vector) -> Verdict {
    if v.expect.verdict == "valid" {
        Verdict::Valid
    } else {
        let r = v.expect.reason.as_deref().expect("invalid needs reason");
        let reason: Reason =
            serde_json::from_value(Value::String(r.to_string())).expect("parse reason");
        Verdict::invalid(reason)
    }
}

// ── Generation ─────────────────────────────────────────────────────────────────────────────────────────────────

const OPERATORS: &[&str] = &[
    "acme",
    "globex",
    "operator-03",
    "operator-04",
    "operator-05",
];
const LINEAGES: &[&str] = &[
    "invoicing",
    "payments-read",
    "support-bot",
    "data-export",
    "scheduler",
];
const VERSIONS: &[&str] = &["1.0.0", "1.2.0", "2.0.1", "0.9.0", "3.1.4"];
const CAP_POOL: &[&str] = &[
    "read:invoices",
    "sign:invoice",
    "read:payments",
    "export:data",
    "schedule:job",
];

fn caps(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn valid_params(i: usize) -> CredParams {
    let registrar = format!("registrar-{:02}", (i % 5) + 1);
    let operator = OPERATORS[i % OPERATORS.len()].to_string();
    let lineage = LINEAGES[(i / 5) % LINEAGES.len()].to_string();
    let version = VERSIONS[(i / 3) % VERSIONS.len()].to_string();
    let n_caps = 1 + (i % CAP_POOL.len());
    let capabilities: Vec<String> = CAP_POOL[..n_caps].iter().map(|s| s.to_string()).collect();
    let scope_ceiling = caps(CAP_POOL);
    let nbf = 1_000 + (i as u64 % 7) * 100;
    let exp = nbf + 1_000 + (i as u64 % 5) * 200;
    CredParams {
        seed: i as u64,
        registrar,
        operator,
        lineage,
        version,
        nbf,
        exp,
        capabilities,
        scope_ceiling,
        status_idx: (i % 12) as u64,
        status_len: 16,
        status_revoked: false,
        chain: Vec::new(),
        mandates: Vec::new(),
        // Every 4th credential exercises the ADR-002 delegate checkpoint-signing path (still VALID).
        delegate_checkpoint: i % 4 == 3,
        delegate_cert_exp: None,
    }
}

/// A valid credential that carries a genuine narrowing delegation chain (exercises the happy chain path).
fn valid_chain_params(i: usize) -> CredParams {
    let mut p = valid_params(i);
    p.seed = 100_000 + i as u64;
    let owner = format!("ainra:{}:{}:owner@1.0.0", p.registrar, p.operator);
    let agent = format!("ainra:{}:{}:agent@1.0.0", p.registrar, p.operator);
    let sub = format!(
        "ainra:{}:{}:{}@{}",
        p.registrar, p.operator, p.lineage, p.version
    );
    p.capabilities = caps(&["read:invoices"]);
    p.scope_ceiling = caps(&["read:invoices", "sign:invoice"]);
    p.chain = vec![
        HopSpec {
            from: owner,
            to: agent.clone(),
            granted: caps(&["read:invoices", "sign:invoice"]),
            exp: p.exp,
        },
        HopSpec {
            from: agent,
            to: sub,
            granted: caps(&["read:invoices"]),
            exp: p.exp,
        },
    ];
    p
}

fn generate() -> Vec<Vector> {
    let mut out: Vec<Vector> = Vec::new();

    // ── VALID: plain (150) + with-chain (30) ──
    for i in 0..150 {
        let b = build(&valid_params(i));
        out.push(wire_valid(
            &format!("valid-{:04}", i),
            "valid credential, all nine checks pass",
            &b,
        ));
    }
    for i in 0..30 {
        let b = build(&valid_chain_params(i));
        out.push(wire_valid(
            &format!("valid-chain-{:04}", i),
            "valid credential with a narrowing delegation chain",
            &b,
        ));
    }

    // ── INVALID: ~24 of each reason (verifier-side tweaks over a fresh valid build) ──
    let per = 24usize;

    // time
    for i in 0..per {
        let b = build(&valid_params(200 + i));
        let mut v = wire_valid(&format!("expired-{:04}", i), "", &b);
        v.presentation.now = b.exp + 50;
        out.push(invalid(v, Reason::Expired, "now is past exp"));
    }
    for i in 0..per {
        let b = build(&valid_params(300 + i));
        let mut v = wire_valid(&format!("not-yet-valid-{:04}", i), "", &b);
        v.presentation.now = b.nbf.saturating_sub(50);
        out.push(invalid(v, Reason::NotYetValid, "now is before nbf"));
    }

    // registrar
    for i in 0..per {
        let b = build(&valid_params(400 + i));
        let mut v = wire_valid(&format!("unknown-registrar-{:04}", i), "", &b);
        // replace the (correct) anchor with a stranger registrar id → issuer's registrar is not accredited
        let stranger = WireRegistrar {
            issuer_key: v.anchors.values().next().unwrap().issuer_key.clone(),
            log_root_key: v.anchors.values().next().unwrap().log_root_key.clone(),
        };
        v.anchors.clear();
        v.anchors.insert("registrar-99".to_string(), stranger);
        out.push(invalid(
            v,
            Reason::UnknownRegistrar,
            "issuer registrar absent from anchors",
        ));
    }

    // signatures
    for i in 0..per {
        let b = build(&valid_params(500 + i));
        let mut v = wire_valid(&format!("sig-invalid-{:04}", i), "", &b);
        // corrupt one byte of the classical signature but keep it 64 bytes (so it's not a downgrade)
        let mut raw = b64::decode(&v.presentation.issuer_sig.ed25519).unwrap();
        raw[0] ^= 0xff;
        v.presentation.issuer_sig.ed25519 = b64::encode(&raw);
        out.push(invalid(
            v,
            Reason::SigInvalid,
            "issuer Ed25519 signature corrupted",
        ));
    }
    for i in 0..per {
        let b = build(&valid_params(600 + i));
        let mut v = wire_valid(&format!("alg-downgrade-{:04}", i), "", &b);
        v.presentation.issuer_sig.mldsa65 = String::new(); // strip the PQ signature entirely
        out.push(invalid(
            v,
            Reason::AlgDowngrade,
            "ML-DSA-65 signature missing (hybrid means both)",
        ));
    }

    // status
    for i in 0..per {
        let mut p = valid_params(700 + i);
        p.status_revoked = true;
        let b = build(&p);
        let v = wire_valid(&format!("revoked-{:04}", i), "", &b);
        out.push(invalid(v, Reason::Revoked, "lineage status bit is set"));
    }
    for i in 0..per {
        let b = build(&valid_params(800 + i));
        let mut v = wire_valid(&format!("stale-status-{:04}", i), "", &b);
        v.presentation.status_issued_at = v.presentation.now.saturating_sub(10_000); // >> F2's 300s
        out.push(invalid(
            v,
            Reason::StaleStatus,
            "status material older than F2 allows",
        ));
    }

    // ceiling (baked: capabilities ⊄ scope_ceiling, still validly signed)
    for i in 0..per {
        let mut p = valid_params(900 + i);
        p.capabilities = caps(&["read:invoices", "admin:everything"]);
        p.scope_ceiling = caps(&["read:invoices"]);
        let b = build(&p);
        let v = wire_valid(&format!("ceiling-exceeded-{:04}", i), "", &b);
        out.push(invalid(
            v,
            Reason::CeilingExceeded,
            "capability outside scope_ceiling",
        ));
    }

    // chain (baked, validly-signed hops that violate narrowing)
    for i in 0..per {
        let mut p = valid_params(1000 + i);
        let owner = format!("ainra:{}:{}:owner@1.0.0", p.registrar, p.operator);
        let agent = format!("ainra:{}:{}:agent@1.0.0", p.registrar, p.operator);
        let sub = format!(
            "ainra:{}:{}:{}@{}",
            p.registrar, p.operator, p.lineage, p.version
        );
        p.capabilities = caps(&["read:invoices"]);
        p.scope_ceiling = caps(&["read:invoices", "sign:invoice"]);
        // hop 2 grants MORE than hop 1 held → widening inside the chain
        p.chain = vec![
            HopSpec {
                from: owner,
                to: agent.clone(),
                granted: caps(&["read:invoices"]),
                exp: p.exp,
            },
            HopSpec {
                from: agent,
                to: sub,
                granted: caps(&["read:invoices", "sign:invoice"]),
                exp: p.exp,
            },
        ];
        let b = build(&p);
        let v = wire_valid(&format!("chain-widening-{:04}", i), "", &b);
        out.push(invalid(
            v,
            Reason::ChainWidening,
            "delegation hop grants more than its delegator held",
        ));
    }
    for i in 0..per {
        let mut p = valid_params(1100 + i);
        let owner = format!("ainra:{}:{}:owner@1.0.0", p.registrar, p.operator);
        let agent = format!("ainra:{}:{}:agent@1.0.0", p.registrar, p.operator);
        let sub = format!(
            "ainra:{}:{}:{}@{}",
            p.registrar, p.operator, p.lineage, p.version
        );
        p.capabilities = caps(&["read:invoices"]);
        p.scope_ceiling = caps(&["read:invoices"]);
        // hop 2 expires AFTER hop 1 → expiry extension
        p.chain = vec![
            HopSpec {
                from: owner,
                to: agent.clone(),
                granted: caps(&["read:invoices"]),
                exp: p.nbf + 500,
            },
            HopSpec {
                from: agent,
                to: sub,
                granted: caps(&["read:invoices"]),
                exp: p.nbf + 900,
            },
        ];
        let b = build(&p);
        let v = wire_valid(&format!("chain-expired-{:04}", i), "", &b);
        out.push(invalid(
            v,
            Reason::ChainExpired,
            "delegation hop expiry exceeds its delegator's",
        ));
    }

    // mandate (path is AUTHENTICATED in the signed body; presenter supplies only the revocation set)
    for i in 0..per {
        let mut p = valid_params(1200 + i);
        p.mandates = vec![
            ("m-root".to_string(), None),
            ("m-op".to_string(), Some("m-root".to_string())),
        ];
        let b = build(&p);
        let mut v = wire_valid(&format!("mandate-revoked-{:04}", i), "", &b);
        v.presentation.mandate_revocations = vec!["m-root".to_string()];
        out.push(invalid(
            v,
            Reason::MandateRevoked,
            "an ancestor mandate is revoked (kills subtree)",
        ));
    }

    // M2 dual-signed-chain failures (review finding #6): the corpus must exercise a broken hop signature so a
    // regression in either implementation's dual-sig verification is caught. All are verifier-side tweaks over a
    // valid chain — the delegator's + delegatee's signatures live in the (issuer-signed) claims and are left intact,
    // so the failure surfaces at step 6, not step 4.
    for i in 0..per {
        let b = build(&valid_chain_params(300 + i));
        let mut v = wire_valid(&format!("hop-sig-invalid-{:04}", i), "", &b);
        // corrupt the SECOND party key so hop-1's counter-signature no longer verifies against it
        if v.presentation.chain_keys.len() >= 2 {
            let mut raw = b64::decode(&v.presentation.chain_keys[1].ed25519).unwrap();
            raw[0] ^= 0xff;
            v.presentation.chain_keys[1].ed25519 = b64::encode(&raw);
        }
        out.push(invalid(
            v,
            Reason::SigInvalid,
            "a delegation hop's counter-signature key is wrong",
        ));
    }
    for i in 0..per {
        let b = build(&valid_chain_params(400 + i));
        let mut v = wire_valid(&format!("hop-key-count-{:04}", i), "", &b);
        v.presentation.chain_keys.pop(); // one fewer key than parties (hops + 1) → schema_violation
        out.push(invalid(
            v,
            Reason::SchemaViolation,
            "delegator/delegatee key count != chain parties",
        ));
    }

    // log — two distinct NotLogged causes: a broken inclusion proof, and a body↔leaf binding mismatch (finding #4)
    for i in 0..per {
        let b = build(&valid_params(1300 + i));
        let mut v = wire_valid(&format!("not-logged-{:04}", i), "", &b);
        v.presentation.inclusion_proof = Vec::new(); // empty proof cannot justify a multi-leaf tree
        out.push(invalid(
            v,
            Reason::NotLogged,
            "inclusion proof does not reconstruct the checkpoint root",
        ));
    }
    for i in 0..per {
        let b = build_binding_mismatch(1700 + i as u64);
        let v = wire_valid(&format!("not-logged-binding-{:04}", i), "", &b);
        out.push(invalid(
            v,
            Reason::NotLogged,
            "log.leaf references a real in-tree leaf that is not this credential's body",
        ));
    }
    for i in 0..per {
        let b = build(&valid_params(1400 + i));
        let mut v = wire_valid(&format!("checkpoint-invalid-{:04}", i), "", &b);
        v.presentation.checkpoint.size += 1; // checkpoint no longer matches its signature
        out.push(invalid(
            v,
            Reason::CheckpointInvalid,
            "checkpoint contents changed after signing",
        ));
    }

    // M2: a delegation hop whose `log_leaf` is not actually logged → not_logged (drop the last hop's proof).
    for i in 0..per {
        let b = build(&valid_chain_params(200 + i));
        let mut v = wire_valid(&format!("chain-hop-not-logged-{:04}", i), "", &b);
        if let Some(last) = v.presentation.hop_proofs.last_mut() {
            last.proof = Vec::new(); // empty proof cannot justify the hop leaf
        }
        out.push(invalid(
            v,
            Reason::NotLogged,
            "a delegation hop's log_leaf does not prove inclusion under the checkpoint",
        ));
    }

    // M2: an ADR-002 delegate certificate that has EXPIRED before the verify time → checkpoint_invalid.
    for i in 0..per {
        let mut p = valid_params(1800 + i);
        p.delegate_checkpoint = true;
        // A cert PROPERLY SIGNED over a short window `[0, 100]` — genuinely expired at the verify `now`
        // (~mid the passport's [~1000, ~2000] window), so `verify_sig_mode`'s EXPIRY branch fires (not a signature
        // mismatch). Review finding: mutating `exp` after signing would fail the SLH-sig check first, never the
        // expiry branch it claims to test.
        p.delegate_cert_exp = Some(100);
        let b = build(&p);
        let v = wire_valid(
            &format!("checkpoint-invalid-delegate-expired-{:04}", i),
            "",
            &b,
        );
        out.push(invalid(
            v,
            Reason::CheckpointInvalid,
            "delegate certificate expired before verification (ADR-002)",
        ));
    }

    // M4: a valid delegate-signed checkpoint whose delegate cert is REVOKED in the dual-root-signed directory →
    // checkpoint_invalid. The cert + delegate signature still verify; the fingerprint being in `revoked_delegates`
    // (a trusted verifier input from the directory) is what kills it. Exercises the M4 delegate-revocation path.
    for i in 0..per {
        let mut p = valid_params(1900 + i);
        p.delegate_checkpoint = true;
        let b = build(&p);
        let mut v = wire_valid(
            &format!("checkpoint-invalid-delegate-revoked-{:04}", i),
            "",
            &b,
        );
        if let Some(cert) = v.presentation.checkpoint_sig.cert.as_ref() {
            v.presentation.revoked_delegates = vec![wire_cert_fingerprint(cert)];
        }
        out.push(invalid(
            v,
            Reason::CheckpointInvalid,
            "checkpoint delegate cert revoked in the signed directory (M4, ADR-002)",
        ));
    }

    // schema + name (mutate claims after signing; caught before the signature is ever checked)
    for i in 0..per {
        let b = build(&valid_params(1500 + i));
        let mut v = wire_valid(&format!("schema-violation-{:04}", i), "", &b);
        let mut claims: Value =
            serde_json::from_slice(&b64::decode(&v.presentation.claims).unwrap()).unwrap();
        claims
            .as_object_mut()
            .unwrap()
            .insert("score".to_string(), json!(99)); // forbidden field
        v.presentation.claims = b64::encode(canon::canonicalize(&claims).unwrap().as_bytes());
        out.push(invalid(
            v,
            Reason::SchemaViolation,
            "forbidden field present (score)",
        ));
    }
    for i in 0..per {
        let b = build(&valid_params(1600 + i));
        let mut v = wire_valid(&format!("name-malformed-{:04}", i), "", &b);
        let mut claims: Value =
            serde_json::from_slice(&b64::decode(&v.presentation.claims).unwrap()).unwrap();
        claims["sub"] = json!("ainra:REGISTRAR:acme:x@1.0.0"); // uppercase label → malformed
        v.presentation.claims = b64::encode(canon::canonicalize(&claims).unwrap().as_bytes());
        out.push(invalid(
            v,
            Reason::NameMalformed,
            "subject name violates the grammar",
        ));
    }

    out
}

// ── main ───────────────────────────────────────────────────────────────────────────────────────────────────────

// ── Delta / fresh-head conformance vectors (M3, MTS §16) ───────────────────────────────────────────────────────
//
// A SECOND small corpus (`vectors/v1-delta/`) exercising the signed status delta stream + fresh head. Each vector
// is real crypto (Ed25519 + ML-DSA-65 + SLH-DSA delegate cert), and its expected accept/reject + reason is computed
// by the REAL core (`StatusDelta::verify` / `FreshHead::verify`) — never hand-written. The sdk-ts `runDeltaVector`
// re-derives the same accept/reason; the diff harness compares (a core↔sdk cross-check on the delta codec).

#[derive(Serialize, Deserialize, Clone)]
struct WireDeltaCert {
    delegate_ed25519: String,
    scopes: Vec<String>,
    nbf: u64,
    exp: u64,
    sig_slh: String,
}
#[derive(Serialize, Deserialize, Clone)]
struct WireDeltaExpect {
    accept: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}
#[derive(Serialize, Deserialize, Clone)]
struct WireDeltaVector {
    name: String,
    kind: String, // "delta" | "fresh_head"
    expect: WireDeltaExpect,
    root_pub_slh: String,
    cert: WireDeltaCert,
    now: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    registrar_pub: Option<WireKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    idx: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_status: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sig_registrar: Option<WireKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    countersig_delegate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sig_delegate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    freshness: Option<String>,
}

fn cert_wire(c: &checkpoint::DelegateCert) -> WireDeltaCert {
    WireDeltaCert {
        delegate_ed25519: b64::encode(&c.delegate_ed25519),
        scopes: c.scopes.clone(),
        nbf: c.nbf,
        exp: c.exp,
        sig_slh: b64::encode(&c.sig_slh),
    }
}
fn reason_str(r: Reason) -> String {
    r.as_str().to_string()
}

fn generate_delta_vectors() -> Vec<WireDeltaVector> {
    let mut rng = ChaCha20Rng::seed_from_u64(0x00DE_17A0);
    let registrar = crypto::HybridKeypair::generate(&mut rng);
    let reg_pub = registrar.public();
    let root = crypto::TestRootSlh::generate(&mut rng);
    let root_pub = root.public();
    let delegate = crypto::TestDelegate::generate(&mut rng);
    let now = 1_000_000u64;
    let uri = "status://registrar-07/1";

    let cert_delta = checkpoint::DelegateCert::issue_test_root(
        &root,
        delegate.public(),
        vec![checkpoint::SCOPE_DELTA.into()],
        now - 100,
        now + 86_400,
    )
    .expect("delta cert");
    let cert_fresh = checkpoint::DelegateCert::issue_test_root(
        &root,
        delegate.public(),
        vec![checkpoint::SCOPE_FRESH_HEAD.into()],
        now - 100,
        now + 86_400,
    )
    .expect("fresh cert");

    let mut out = Vec::new();

    // A tiny helper closure to build + record a delta vector, with the expected outcome computed by the core.
    let mut push_delta = |name: &str,
                          mut d: status::StatusDelta,
                          cert: &checkpoint::DelegateCert,
                          at: u64,
                          resign: bool| {
        if resign {
            // rebuild both signatures over the (possibly mutated) canonical body
            let msg = d.signing_bytes().expect("delta bytes");
            d.sig_registrar = registrar.sign(&msg).expect("reg sign");
            d.countersig_delegate = delegate.sign(&msg);
        }
        let res = d.verify(&reg_pub, &root_pub, cert, at);
        out.push(WireDeltaVector {
            name: name.into(),
            kind: "delta".into(),
            expect: WireDeltaExpect {
                accept: res.is_ok(),
                reason: res.err().map(reason_str),
            },
            root_pub_slh: b64::encode(&root_pub),
            cert: cert_wire(cert),
            now: at,
            registrar_pub: Some(WireKey {
                ed25519: b64::encode(&reg_pub.ed25519),
                mldsa65: b64::encode(&reg_pub.mldsa65),
            }),
            uri: Some(d.uri.clone()),
            from_seq: Some(d.from_seq),
            seq: Some(d.seq),
            ts: Some(d.ts),
            idx: Some(d.idx.clone()),
            new_status: Some(d.new_status),
            sig_registrar: Some(WireKey {
                ed25519: b64::encode(&d.sig_registrar.ed25519),
                mldsa65: b64::encode(&d.sig_registrar.mldsa65),
            }),
            countersig_delegate: Some(b64::encode(&d.countersig_delegate)),
            status_hash: None,
            sig_delegate: None,
            freshness: None,
        });
    };

    let mk = |from_seq, idx: Vec<u64>| {
        status::StatusDelta::build(uri, from_seq, now, idx, true, &registrar, &delegate)
            .expect("build delta")
    };

    // 1. valid delta
    push_delta(
        "delta-valid-single",
        mk(0, vec![2]),
        &cert_delta,
        now,
        false,
    );
    push_delta(
        "delta-valid-batch",
        mk(0, vec![1, 4, 9]),
        &cert_delta,
        now,
        false,
    );
    // 2. wrong-scope cert (fresh-head cert cannot authorize a delta) → checkpoint_invalid
    push_delta(
        "delta-wrong-scope-cert",
        mk(0, vec![3]),
        &cert_fresh,
        now,
        false,
    );
    // 3. expired cert → checkpoint_invalid
    push_delta(
        "delta-expired-cert",
        mk(0, vec![3]),
        &cert_delta,
        cert_delta.exp + 1,
        false,
    );
    // 4. corrupted countersignature → checkpoint_invalid
    {
        let mut d = mk(0, vec![3]);
        d.countersig_delegate[0] ^= 0xff;
        push_delta("delta-bad-countersig", d, &cert_delta, now, false);
    }
    // 5. stripped ML-DSA half of the registrar sig → alg_downgrade
    {
        let mut d = mk(0, vec![3]);
        d.sig_registrar.mldsa65.clear();
        push_delta("delta-downgrade", d, &cert_delta, now, false);
    }
    // 6. tampered index after signing (idx moved, signature no longer matches) → sig_invalid
    {
        let mut d = mk(0, vec![3]);
        d.idx = vec![7];
        push_delta("delta-tampered-idx", d, &cert_delta, now, false);
    }
    // 7. non-single-step advance (gap) → stale_status
    {
        let mut d = mk(0, vec![3]);
        d.seq = 5;
        push_delta("delta-seq-gap", d, &cert_delta, now, true);
    }
    // 8. non-ascending / duplicate indices → stale_status (structural)
    {
        let mut d = mk(0, vec![3]);
        d.idx = vec![5, 5];
        push_delta("delta-dup-idx", d, &cert_delta, now, true);
    }
    // 9. DESCENDING indices → stale_status (same guard, distinct shape — coverage review #8)
    {
        let mut d = mk(0, vec![3]);
        d.idx = vec![5, 3];
        push_delta("delta-descending-idx", d, &cert_delta, now, true);
    }
    // 10. seq==0 wrap-around (from_seq = u64::MAX, seq = 0) → stale_status. The structural gate fires before any
    // signature check in both implementations, so the (stale) signatures from the base delta are fine as-is.
    {
        let mut d = mk(0, vec![3]);
        d.from_seq = u64::MAX;
        d.seq = 0;
        push_delta("delta-seq-zero-wrap", d, &cert_delta, now, false);
    }

    // ── fresh-head vectors ──
    let mut push_head = |name: &str,
                         list: &status::StatusList,
                         seq: u64,
                         ts: u64,
                         cert: &checkpoint::DelegateCert,
                         at: u64,
                         freshness: status::Freshness,
                         corrupt: bool| {
        let mut h = status::FreshHead::build(uri, seq, ts, list, &delegate).expect("fresh head");
        if corrupt {
            h.sig_delegate[0] ^= 0xff;
        }
        let res = h.verify(&root_pub, cert, at, freshness);
        let fname = match freshness {
            status::Freshness::F1 => "F1",
            status::Freshness::F2 => "F2",
            status::Freshness::F3 => "F3",
        };
        out.push(WireDeltaVector {
            name: name.into(),
            kind: "fresh_head".into(),
            expect: WireDeltaExpect {
                accept: res.is_ok(),
                reason: res.err().map(reason_str),
            },
            root_pub_slh: b64::encode(&root_pub),
            cert: cert_wire(cert),
            now: at,
            registrar_pub: None,
            uri: Some(h.uri.clone()),
            from_seq: None,
            seq: Some(h.seq),
            ts: Some(h.ts),
            idx: None,
            new_status: None,
            sig_registrar: None,
            countersig_delegate: None,
            status_hash: Some(b64::encode(&h.status_hash)),
            sig_delegate: Some(b64::encode(&h.sig_delegate)),
            freshness: Some(fname.into()),
        });
    };
    let list = status::StatusList::from_bits(vec![false, true, false, false, false]);
    // 9. valid fresh head within F1
    push_head(
        "head-valid-f1",
        &list,
        1,
        now,
        &cert_fresh,
        now + 10,
        status::Freshness::F1,
        false,
    );
    // 10. stale past F1 (100 s old > 30 s) → stale_status
    push_head(
        "head-stale-f1",
        &list,
        1,
        now,
        &cert_fresh,
        now + 100,
        status::Freshness::F1,
        false,
    );
    // 11. same 100 s old but F2 (≤5 min) → accept
    push_head(
        "head-ok-f2",
        &list,
        1,
        now,
        &cert_fresh,
        now + 100,
        status::Freshness::F2,
        false,
    );
    // 12. wrong-scope cert (delta cert cannot sign a fresh head) → checkpoint_invalid
    push_head(
        "head-wrong-scope",
        &list,
        1,
        now,
        &cert_delta,
        now + 10,
        status::Freshness::F1,
        false,
    );
    // 13. corrupted delegate signature → checkpoint_invalid
    push_head(
        "head-bad-sig",
        &list,
        1,
        now,
        &cert_fresh,
        now + 10,
        status::Freshness::F1,
        true,
    );
    // 14. FUTURE-DATED head (ts > now) → stale_status (a clock/forgery anomaly is suspect, never trusted —
    // coverage review #8: exercises the future-date branch of the freshness check)
    push_head(
        "head-future-dated",
        &list,
        1,
        now + 500,
        &cert_fresh,
        now,
        status::Freshness::F1,
        false,
    );

    out
}

fn emit_delta(dir: &str) {
    let vectors = generate_delta_vectors();
    std::fs::create_dir_all(dir).expect("create delta out dir");
    for v in &vectors {
        let path = Path::new(dir).join(format!("{}.json", v.name));
        std::fs::write(
            &path,
            serde_json::to_string_pretty(v).expect("ser delta vector"),
        )
        .expect("write delta vector");
    }
    let accept = vectors.iter().filter(|v| v.expect.accept).count();
    let manifest = json!({
        "version": "v1-delta",
        "count": vectors.len(),
        "accept": accept,
        "reject": vectors.len() - accept,
        "note": "CC0 delta/fresh-head conformance vectors. Real crypto; expected accept/reason computed by ainra-core::status. Regenerate with `make vectors`."
    });
    std::fs::write(
        Path::new(dir).join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .expect("write delta manifest");
    println!(
        "wrote {} delta/fresh-head vectors to {}",
        vectors.len(),
        dir
    );
}

/// Replay the committed delta corpus through the CURRENT core and assert every baked expectation reproduces —
/// the delta-corpus twin of `--check` (review #9: without this, a core behavior change could leave the committed
/// corpus stale, degrading the sdk↔core delta differential into sdk-vs-yesterday's-core).
fn check_delta(dir: &str) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .expect("read delta dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().map(|x| x == "json").unwrap_or(false)
                && p.file_name().map(|f| f != "manifest.json").unwrap_or(false)
        })
        .collect();
    entries.sort();
    let mut total = 0usize;
    let mut fails = 0usize;
    for path in entries {
        let raw = std::fs::read_to_string(&path).expect("read delta vector");
        let v: WireDeltaVector = serde_json::from_str(&raw).expect("parse delta vector");
        let root_pub = b64::decode(&v.root_pub_slh).expect("root pk");
        let cert = checkpoint::DelegateCert {
            delegate_ed25519: b64::decode_array::<32>(&v.cert.delegate_ed25519)
                .expect("delegate pk"),
            scopes: v.cert.scopes.clone(),
            nbf: v.cert.nbf,
            exp: v.cert.exp,
            sig_slh: b64::decode(&v.cert.sig_slh).expect("cert sig"),
        };
        let res: Result<(), Reason> = if v.kind == "delta" {
            let reg = v.registrar_pub.as_ref().expect("registrar_pub");
            let reg_pub = crypto::HybridPublic {
                ed25519: b64::decode_array::<32>(&reg.ed25519).expect("reg ed"),
                mldsa65: b64::decode(&reg.mldsa65).expect("reg ml"),
            };
            let sig = v.sig_registrar.as_ref().expect("sig_registrar");
            let d = status::StatusDelta {
                uri: v.uri.clone().expect("uri"),
                from_seq: v.from_seq.expect("from_seq"),
                seq: v.seq.expect("seq"),
                ts: v.ts.expect("ts"),
                idx: v.idx.clone().expect("idx"),
                new_status: v.new_status.expect("new_status"),
                sig_registrar: crypto::HybridSig {
                    ed25519: b64::decode(&sig.ed25519).expect("sig ed"),
                    mldsa65: b64::decode(&sig.mldsa65).expect("sig ml"),
                },
                countersig_delegate: b64::decode(
                    v.countersig_delegate.as_deref().expect("countersig"),
                )
                .expect("countersig b64"),
            };
            d.verify(&reg_pub, &root_pub, &cert, v.now)
        } else {
            let h = status::FreshHead {
                uri: v.uri.clone().expect("uri"),
                seq: v.seq.expect("seq"),
                ts: v.ts.expect("ts"),
                status_hash: b64::decode_array::<32>(v.status_hash.as_deref().expect("hash"))
                    .expect("hash b64"),
                sig_delegate: b64::decode(v.sig_delegate.as_deref().expect("sig"))
                    .expect("sig b64"),
            };
            let f = match v.freshness.as_deref() {
                Some("F2") => status::Freshness::F2,
                Some("F3") => status::Freshness::F3,
                _ => status::Freshness::F1,
            };
            h.verify(&root_pub, &cert, v.now, f)
        };
        let got_accept = res.is_ok();
        let got_reason = res.err().map(reason_str);
        total += 1;
        if got_accept != v.expect.accept || got_reason != v.expect.reason {
            eprintln!(
                "DELTA CHECK MISMATCH {}: expected accept={} reason={:?}, got accept={} reason={:?}",
                v.name, v.expect.accept, v.expect.reason, got_accept, got_reason
            );
            fails += 1;
        }
    }
    if fails > 0 {
        eprintln!("{fails}/{total} delta vectors mismatched");
        std::process::exit(1);
    }
    println!("checked {total} delta vectors: all reproduce their recorded expectation");
}

// ── Directory conformance vectors (M4) ─────────────────────────────────────────────────────────────────────────
//
// A small corpus exercising the dual-root-signed registrar directory. Each vector is a real `Directory` signed by a
// stand-in Ed25519 root (a `TestDelegate` — the FROST group key emits the SAME standard signatures, proven in
// ainra-ceremony) + an SLH-DSA root; the expected accept/registrar-count is computed by the REAL core
// `Directory::accredit`. sdk-ts `runDirectoryVector` re-derives the same result (diff phase E).

fn dir_entry(id: &str, rng: &mut ChaCha20Rng) -> ainra_core::directory::DirectoryEntry {
    let issuer = crypto::HybridKeypair::generate(rng).public();
    let log = crypto::TestRootSlh::generate(rng).public();
    let status = crypto::HybridKeypair::generate(rng).public();
    ainra_core::directory::DirectoryEntry {
        registrar: id.to_string(),
        issuer_ed25519: b64::encode(&issuer.ed25519),
        issuer_mldsa65: b64::encode(&issuer.mldsa65),
        log_root_slh: b64::encode(&log),
        status_ed25519: b64::encode(&status.ed25519),
        status_mldsa65: b64::encode(&status.mldsa65),
        status_uri: format!("status://{id}/1"),
    }
}

fn dir_base(
    entries: Vec<ainra_core::directory::DirectoryEntry>,
    revoked: Vec<String>,
) -> ainra_core::directory::Directory {
    ainra_core::directory::Directory {
        epoch: 1,
        issued_at: 1_000_000,
        entries,
        revoked_delegates: revoked,
        sig_root_ed25519: String::new(),
        sig_root_slh: String::new(),
    }
}

/// Sign a directory with both roots over the same canonical bytes.
fn dir_sign(
    mut d: ainra_core::directory::Directory,
    ed: &crypto::TestDelegate,
    slh: &crypto::TestRootSlh,
) -> ainra_core::directory::Directory {
    d.sig_root_ed25519 = String::new();
    d.sig_root_slh = String::new();
    let msg = d.signing_bytes().expect("dir signing bytes");
    d.sig_root_ed25519 = b64::encode(&ed.sign(&msg));
    d.sig_root_slh = b64::encode(&slh.sign(&msg).expect("slh sign"));
    d
}

/// Wrap a directory as a conformance vector, computing the expectation via the REAL core `accredit`.
fn dir_vector(
    name: &str,
    d: &ainra_core::directory::Directory,
    root_ed_pk: &[u8; 32],
    root_slh_pk: &[u8],
) -> serde_json::Value {
    let expect = match d.accredit(root_ed_pk, root_slh_pk) {
        Ok(acc) => json!({ "accept": true, "registrars": acc.anchors.registrars.len() }),
        Err(_) => json!({ "accept": false }),
    };
    json!({
        "name": name,
        "expect": expect,
        "directory": serde_json::to_value(d).expect("ser dir"),
        "root_ed25519": b64::encode(root_ed_pk),
        "root_slh": b64::encode(root_slh_pk),
    })
}

fn generate_directory_vectors() -> Vec<serde_json::Value> {
    let mut rng = ChaCha20Rng::seed_from_u64(0x0D17_EC70);
    let root_ed = crypto::TestDelegate::generate(&mut rng); // stand-in for the FROST group key
    let root_ed_pk = root_ed.public();
    let root_slh = crypto::TestRootSlh::generate(&mut rng);
    let root_slh_pk = root_slh.public();
    let other_slh = crypto::TestRootSlh::generate(&mut rng);
    let other_ed = crypto::TestDelegate::generate(&mut rng);
    let mut out = Vec::new();

    // 1. valid, 2 registrars (sorted)
    let d = dir_sign(
        dir_base(
            vec![
                dir_entry("registrar-02", &mut rng),
                dir_entry("registrar-07", &mut rng),
            ],
            vec![],
        ),
        &root_ed,
        &root_slh,
    );
    out.push(dir_vector(
        "directory-valid-2",
        &d,
        &root_ed_pk,
        &root_slh_pk,
    ));

    // 2. valid, empty directory (0 registrars accredited — still a valid signed statement)
    let d = dir_sign(dir_base(vec![], vec![]), &root_ed, &root_slh);
    out.push(dir_vector(
        "directory-valid-empty",
        &d,
        &root_ed_pk,
        &root_slh_pk,
    ));

    // 3. valid, with a delegate revocation listed
    let d = dir_sign(
        dir_base(
            vec![dir_entry("registrar-07", &mut rng)],
            vec![b64::encode(&[9u8; 32])],
        ),
        &root_ed,
        &root_slh,
    );
    out.push(dir_vector(
        "directory-valid-with-revocation",
        &d,
        &root_ed_pk,
        &root_slh_pk,
    ));

    // 4. wrong SLH root signature (signed by other_slh) → reject
    let d = dir_sign(
        dir_base(vec![dir_entry("registrar-07", &mut rng)], vec![]),
        &root_ed,
        &other_slh,
    );
    out.push(dir_vector(
        "directory-wrong-slh-root",
        &d,
        &root_ed_pk,
        &root_slh_pk,
    ));

    // 5. wrong Ed25519 (FROST) root signature (signed by other_ed) → reject
    let d = dir_sign(
        dir_base(vec![dir_entry("registrar-07", &mut rng)], vec![]),
        &other_ed,
        &root_slh,
    );
    out.push(dir_vector(
        "directory-wrong-ed-root",
        &d,
        &root_ed_pk,
        &root_slh_pk,
    ));

    // 6. tampered entry after signing → reject (both sigs no longer cover the bytes)
    let mut d = dir_sign(
        dir_base(vec![dir_entry("registrar-07", &mut rng)], vec![]),
        &root_ed,
        &root_slh,
    );
    d.entries[0].registrar = "registrar-99".into();
    out.push(dir_vector(
        "directory-tampered-entry",
        &d,
        &root_ed_pk,
        &root_slh_pk,
    ));

    // 7. entries not strictly sorted → reject (canonical order enforced even though the sig covers this order)
    let d = dir_sign(
        dir_base(
            vec![
                dir_entry("registrar-07", &mut rng),
                dir_entry("registrar-02", &mut rng),
            ],
            vec![],
        ),
        &root_ed,
        &root_slh,
    );
    out.push(dir_vector(
        "directory-unsorted-entries",
        &d,
        &root_ed_pk,
        &root_slh_pk,
    ));

    // 8. duplicate registrar id → reject (not strictly increasing)
    let d = dir_sign(
        dir_base(
            vec![
                dir_entry("registrar-07", &mut rng),
                dir_entry("registrar-07", &mut rng),
            ],
            vec![],
        ),
        &root_ed,
        &root_slh,
    );
    out.push(dir_vector(
        "directory-duplicate-registrar",
        &d,
        &root_ed_pk,
        &root_slh_pk,
    ));

    // 9. malformed revoked-delegate fingerprint (not 32 bytes) → reject. Sigs + entries are valid; the bad
    // fingerprint decode fails closed (exercises the M4 revoked-fingerprint length check + sdk-ts parity fix).
    let d = dir_sign(
        dir_base(
            vec![dir_entry("registrar-07", &mut rng)],
            vec![b64::encode(b"too-short")],
        ),
        &root_ed,
        &root_slh,
    );
    out.push(dir_vector(
        "directory-malformed-fingerprint",
        &d,
        &root_ed_pk,
        &root_slh_pk,
    ));

    out
}

fn emit_directory(dir: &str) {
    let vectors = generate_directory_vectors();
    std::fs::create_dir_all(dir).expect("create dir");
    for v in &vectors {
        let name = v["name"].as_str().unwrap();
        std::fs::write(
            Path::new(dir).join(format!("{name}.json")),
            serde_json::to_string_pretty(v).expect("ser"),
        )
        .expect("write directory vector");
    }
    let accept = vectors
        .iter()
        .filter(|v| v["expect"]["accept"] == json!(true))
        .count();
    let manifest = json!({
        "version": "v1-directory", "count": vectors.len(), "accept": accept, "reject": vectors.len() - accept,
        "note": "CC0 directory conformance vectors. Real dual-root signing; expected computed by ainra-core::directory::Directory::accredit. Regenerate with `make vectors`."
    });
    std::fs::write(
        Path::new(dir).join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .expect("write manifest");
    println!("wrote {} directory vectors to {}", vectors.len(), dir);
}

fn check_directory(dir: &str) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .expect("read dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().map(|x| x == "json").unwrap_or(false)
                && p.file_name().map(|f| f != "manifest.json").unwrap_or(false)
        })
        .collect();
    entries.sort();
    let mut total = 0;
    let mut fails = 0;
    for path in entries {
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse");
        let d: ainra_core::directory::Directory =
            serde_json::from_value(v["directory"].clone()).expect("dir");
        let root_ed = b64::decode_array::<32>(v["root_ed25519"].as_str().unwrap()).expect("ed");
        let root_slh = b64::decode(v["root_slh"].as_str().unwrap()).expect("slh");
        let got = match d.accredit(&root_ed, &root_slh) {
            Ok(acc) => json!({ "accept": true, "registrars": acc.anchors.registrars.len() }),
            Err(_) => json!({ "accept": false }),
        };
        total += 1;
        if got != v["expect"] {
            eprintln!(
                "DIRECTORY CHECK MISMATCH {}: expected {} got {got}",
                v["name"], v["expect"]
            );
            fails += 1;
        }
    }
    if fails > 0 {
        eprintln!("{fails}/{total} directory vectors mismatched");
        std::process::exit(1);
    }
    println!("checked {total} directory vectors: all reproduce their recorded expectation");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut out_dir: Option<String> = None;
    let mut delta_out: Option<String> = None;
    let mut directory_out: Option<String> = None;
    let mut check_dir: Option<String> = None;
    let mut check_delta_dir: Option<String> = None;
    let mut check_directory_dir: Option<String> = None;
    let mut canon_file: Option<String> = None;
    let mut min: usize = 0;
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => out_dir = it.next().cloned(),
            "--delta-out" => delta_out = it.next().cloned(),
            "--directory-out" => directory_out = it.next().cloned(),
            "--check" => check_dir = it.next().cloned(),
            "--check-delta" => check_delta_dir = it.next().cloned(),
            "--check-directory" => check_directory_dir = it.next().cloned(),
            "--canon" => canon_file = it.next().cloned(),
            "--bench" => {} // handled after parsing
            "--min" => min = it.next().and_then(|s| s.parse().ok()).unwrap_or(0),
            other => {
                eprintln!("unknown arg: {other}");
                std::process::exit(2);
            }
        }
    }

    if args.iter().any(|a| a == "--bench") {
        bench_mode();
        return;
    }
    if let Some(file) = canon_file {
        canon_mode(&file);
        return;
    }
    if let Some(dir) = delta_out {
        emit_delta(&dir);
        return;
    }
    if let Some(dir) = directory_out {
        emit_directory(&dir);
        return;
    }
    if let Some(dir) = check_delta_dir {
        check_delta(&dir);
        return;
    }
    if let Some(dir) = check_directory_dir {
        check_directory(&dir);
        return;
    }
    if let Some(dir) = check_dir {
        check(&dir, min);
        return;
    }
    let dir = out_dir.unwrap_or_else(|| {
        eprintln!(
            "usage: ainra-vector-gen --out DIR [--min N] | --delta-out DIR | --check DIR [--min N]"
        );
        std::process::exit(2);
    });
    emit(&dir, min);
}

fn emit(dir: &str, min: usize) {
    let vectors = generate();
    if vectors.len() < min {
        eprintln!("generated {} vectors, below --min {}", vectors.len(), min);
        std::process::exit(1);
    }
    // Self-check before writing: the generator must never emit a vector whose recorded verdict it cannot reproduce.
    let mut mismatches = 0;
    for v in &vectors {
        if run(v) != expected(v) {
            eprintln!(
                "SELF-CHECK MISMATCH: {} expected {:?} got {:?}",
                v.name,
                expected(v),
                run(v)
            );
            mismatches += 1;
        }
    }
    if mismatches > 0 {
        eprintln!("{mismatches} vectors failed self-check; refusing to write a dishonest corpus");
        std::process::exit(1);
    }

    std::fs::create_dir_all(dir).expect("create out dir");
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for v in &vectors {
        let key = v
            .expect
            .reason
            .clone()
            .unwrap_or_else(|| "valid".to_string());
        *counts.entry(key).or_default() += 1;
        let path = Path::new(dir).join(format!("{}.json", v.name));
        let json = serde_json::to_string_pretty(v).expect("serialize vector");
        std::fs::write(&path, json).expect("write vector");
    }
    let manifest = json!({
        "version": "v1",
        "count": vectors.len(),
        "by_outcome": counts,
        "note": "CC0 conformance vectors. Each is a real signed credential + expected verdict. Regenerate with `make vectors`."
    });
    std::fs::write(
        Path::new(dir).join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .expect("write manifest");
    println!(
        "wrote {} vectors to {} (self-check: all reproduce)",
        vectors.len(),
        dir
    );
}

/// Canonicalize each JSON value (one per line) from `file`, printing the canonical string or `REJECT` per line.
/// The diff-harness feeds the SAME inputs to sdk-ts and the P0 cli-node `cjson` and asserts byte-identical output
/// (property P-5). `REJECT` marks an input ainra-core's canon refuses (float / non-ASCII key / out-of-range int).
fn canon_mode(file: &str) {
    let data = std::fs::read_to_string(file).expect("read canon input");
    for line in data.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line).expect("parse json line");
        match canon::canonicalize_value(&v) {
            Ok(s) => println!("{s}"),
            Err(_) => println!("REJECT"),
        }
    }
}

/// Print real, single-host timings as Markdown (→ BENCHMARKS.md via `make bench`). No fabricated numbers.
fn bench_mode() {
    use std::time::Instant;
    let mut vs: Vec<Vector> = Vec::new();
    for entry in
        std::fs::read_dir("vectors/v1").expect("read vectors/v1 (run `make vectors` first)")
    {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if path.file_name().and_then(|n| n.to_str()) == Some("manifest.json") {
            continue;
        }
        vs.push(serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap());
    }
    for v in &vs {
        let _ = run(v); // warm caches
    }
    let iters = 5u64;
    let start = Instant::now();
    let mut n = 0u64;
    for _ in 0..iters {
        for v in &vs {
            let _ = run(v);
            n += 1;
        }
    }
    let per_verify = start.elapsed().as_nanos() as f64 / n as f64;

    let sample = json!({
        "vct": "ainra/passport/v1", "iss": "did:ainra:registrar-01:acme:invoicing",
        "sub": "ainra:registrar-01:acme:invoicing@1.0.0", "nbf": 1000u64, "exp": 2000u64,
        "capabilities": ["read:x", "sign:y"], "nested": { "a": 1, "b": [1, 2, 3] }
    });
    let citers = 200_000u64;
    let cstart = Instant::now();
    for _ in 0..citers {
        let _ = canon::canonicalize_value(&sample).unwrap();
    }
    let per_canon = cstart.elapsed().as_nanos() as f64 / citers as f64;

    println!("<!-- Generated by `make bench` (ainra-vector-gen --bench). Real measurements, single host, release. -->");
    println!("# BENCHMARKS\n");
    println!("Indicative single-host numbers (release build). Reproduce with `make bench`. Not a controlled");
    println!("multi-region run — those are M2 (§21).\n");
    println!("| Operation | Per-op | Throughput |");
    println!("|---|---|---|");
    println!("| Full credential verify — 9 steps (hybrid Ed25519+ML-DSA-65, SLH-DSA checkpoint, RFC 6962 inclusion) | {:.1} µs | {:.0}/s |", per_verify / 1000.0, 1e9 / per_verify);
    println!(
        "| Canonical encode (representative claim body) | {:.0} ns | {:.0}/s |",
        per_canon,
        1e9 / per_canon
    );
    println!(
        "\n- verify: {} vectors × {} iterations = {} verifications.",
        vs.len(),
        iters,
        n
    );
    println!("- SLH-DSA-SHA2-128s *signing* is the slow primitive (~0.2 s/op); *verifying* is fast — which is why a");
    println!("  real log signs one checkpoint and serves many inclusion proofs.");
}

fn check(dir: &str, min: usize) {
    let mut total = 0usize;
    let mut fails = 0usize;
    for entry in std::fs::read_dir(dir).expect("read vectors dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if path.file_name().and_then(|n| n.to_str()) == Some("manifest.json") {
            continue;
        }
        let data = std::fs::read(&path).expect("read vector");
        let v: Vector = serde_json::from_slice(&data).expect("parse vector");
        total += 1;
        let (got, want) = (run(&v), expected(&v));
        if got != want {
            eprintln!("FAIL {}: expected {:?}, got {:?}", v.name, want, got);
            fails += 1;
        }
    }
    if total == 0 {
        eprintln!("no vectors found in {dir} — refusing to report success on an empty corpus");
        std::process::exit(1);
    }
    if total < min {
        eprintln!("checked {total} vectors, below --min {min}");
        std::process::exit(1);
    }
    if fails > 0 {
        eprintln!("{fails}/{total} vectors mismatched");
        std::process::exit(1);
    }
    println!("checked {total} vectors: all reproduce their recorded verdict");
}
