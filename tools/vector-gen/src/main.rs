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

// L5: every bytes → core-types conversion moved to ainra-adapter. This binary keeps only binary concerns
// (argv, file I/O, printing) and calls the ONE decode path for everything else.
use ainra_adapter::*;
use ainra_core::passport::ActLink;
use ainra_core::verdict::{Reason, Verdict};
use ainra_core::{b64, canon, chain, checkpoint, crypto, merkle, status, verify};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{json, Value};

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
    /// ADR-019: a REAL hybrid control key in `keys[0]`, baked into the body BEFORE it is canonicalised and
    /// logged. It cannot go through `build_mut`'s `mutate` hook — that runs after the leaf is computed (it exists
    /// for tamper tests), so a key planted there would not be the key that was logged, and every instance vector
    /// would fail at step 9 with `not_logged`. Which is exactly what happened on the first attempt.
    control_key: Option<crypto::HybridPublic>,
    chain: Vec<HopSpec>,
    /// Operative mandate path (id, parent) baked into the signed body. Empty = no mandate gate.
    mandates: Vec<(String, Option<String>)>,
    /// Sign the checkpoint via the ADR-002 delegate (root-certified Ed25519) instead of the root directly.
    delegate_checkpoint: bool,
    /// Override the delegate cert window `[0, exp]` (properly signed). Used to build a GENUINELY-expired cert so the
    /// expiry branch of `verify_sig_mode` actually fires (not a signature mismatch). `None` = the default long window.
    delegate_cert_exp: Option<u64>,
    /// ADR-017 renewal: the leaf of the generation this passport supersedes, baked into the signed body as
    /// `prev_leaf`. `None` = a first-generation passport, which is what every vector was until M31.
    prev_leaf: Option<[u8; 32]>,
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
    build_mut(p, |_| {})
}

const B64URL_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// A non-canonical-encoding transform (D-029 canonical-encoding sweep vectors).
type NcFn = fn(&str) -> String;

/// Turn a CANONICAL 32-byte (43-char) base64url string into a NON-canonical one with nonzero trailing bits: the
/// last char of a 43-char string has value ≡ 0 mod 4 (its 2 excess bits are zero), so `+1` keeps the same 4 data
/// bits but sets a trailing bit — still a valid alphabet char, but base64ct (and the SDK round-trip) reject it.
fn nc_trailing_bits(s: &str) -> String {
    let mut b = s.as_bytes().to_vec();
    let last = *b.last().expect("non-empty");
    let idx = B64URL_ALPHABET
        .iter()
        .position(|&c| c == last)
        .expect("alphabet char");
    assert_eq!(
        idx % 4,
        0,
        "expected a 32-byte canonical last char (value ≡ 0 mod 4)"
    );
    *b.last_mut().unwrap() = B64URL_ALPHABET[idx + 1];
    String::from_utf8(b).unwrap()
}
/// Embed whitespace (base64ct rejects it; Node's lenient decoder would strip it).
fn nc_whitespace(s: &str) -> String {
    format!("{} {}", &s[..4], &s[4..])
}
/// Add base64 padding (both implementations decode UNPADDED base64url; `=` is rejected).
fn nc_padding(s: &str) -> String {
    format!("{s}=")
}

/// D-029 non-canonical-encoding vectors: build a credential exactly like [`build`], but apply `mutate` to the full
/// claim body **before it is signed**, so a field carrying a non-canonical base64url encoding is genuinely part of
/// the issuer-signed credential (a mutate-after-sign would just fail the issuer signature at step 4, never reaching
/// the field's own decode). The issuer signature is valid; only the field's ENCODING is non-canonical, so core
/// rejects it at that field's decode (base64ct) and the SDK must reject identically via the one strict gateway.
fn build_mut(p: &CredParams, mutate: impl FnOnce(&mut Value)) -> Built {
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
        "keys": [ match &p.control_key {
            Some(k) => json!({ "ed25519": b64::encode(&k.ed25519), "mldsa65": b64::encode(&k.mldsa65) }),
            None => json!({ "ed25519": "AAAA", "mldsa65": "BBBB" }),
        } ],
        "cnf": { "jkt": "thumb" },
        "status": { "status_list": { "idx": p.status_idx, "uri": format!("status://{}/1", p.registrar) } },
        "act_chain": serde_json::to_value(&act_chain).expect("act_chain")
    });
    if let Some(pl) = &p.prev_leaf {
        // ADR-017 continuity. Emitted ONLY when set: adding a null here would change the canonical bytes of every
        // pre-existing vector and break `make repro` for no gain — the same discipline the wire `instance` field
        // follows.
        body["prev_leaf"] = json!(b64::encode(pl));
    }
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

    // Attach the log back-reference, apply any non-canonical-field mutation, then sign the full claims.
    let mut full = body;
    full["log"] =
        json!({ "leaf": b64::encode(&leaf), "root": b64::encode(&cp.root), "checkpoint": "cp-1" });
    mutate(&mut full);
    let claims = canon::canonicalize(&full).expect("canon full").into_bytes();
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

/// ADR-017: one lineage, two generations in ONE log — a first-issuance credential and its REISSUE (fresh
/// overlapping window, new status index, `prev_leaf` = the old body's RFC 6962 leaf). Both share the registrar,
/// the log, and one signed checkpoint, so each is independently verifiable and the continuity link in the new
/// body points at a leaf genuinely committed by the same log. Validity spans: old `[1000, 2000)`, new `[1600, 3200)` —
/// overlap `[1600, 2000)`.
fn build_renewal_pair(seed: u64) -> (Built, Built) {
    let mut rng = ChaCha20Rng::seed_from_u64(0x4149_4E52_4100_0000 ^ seed);
    let issuer = crypto::HybridKeypair::generate(&mut rng);
    let root = crypto::TestRootSlh::generate(&mut rng);
    let registrar = "registrar-01".to_string();

    let mk_body = |idx: u64, nbf: u64, exp: u64, prev: Option<String>| {
        let mut b = json!({
            "vct": ainra_core::PASSPORT_VCT,
            "iss": format!("did:ainra:{registrar}:acme:invoicing"),
            "sub": format!("ainra:{registrar}:acme:invoicing@1.0.0"),
            "nbf": nbf,
            "exp": exp,
            "authority": { "class": "A2", "principal_proof": "deadbeef" },
            "tier": "L1",
            "capabilities": ["read:invoices"],
            "scope_ceiling": ["read:invoices"],
            "keys": [ { "ed25519": "AAAA", "mldsa65": "BBBB" } ],
            "cnf": { "jkt": "thumb" },
            "status": { "status_list": { "idx": idx, "uri": format!("status://{registrar}/1") } },
            "act_chain": json!([])
        });
        if let Some(p) = prev {
            b["prev_leaf"] = json!(p);
        }
        b
    };

    let old_body = mk_body(3, 1_000, 2_000, None);
    let old_bytes = canon::canonicalize(&old_body)
        .expect("canon old")
        .into_bytes();
    let old_leaf = merkle::hash_leaf(&old_bytes);
    let new_body = mk_body(4, 1_600, 3_200, Some(b64::encode(&old_leaf)));
    let new_bytes = canon::canonicalize(&new_body)
        .expect("canon new")
        .into_bytes();
    let new_leaf = merkle::hash_leaf(&new_bytes);

    let mut log = merkle::TestLog::new();
    for k in 0..3u8 {
        log.append(&[k]);
    }
    let old_index = log.append(&old_bytes);
    let new_index = log.append(&new_bytes);
    let cp = checkpoint::Checkpoint {
        origin: format!("ainra-log/{registrar}"),
        tree_size: log.size(),
        root: log.root(),
    };
    let cp_sig = checkpoint_sig(&cp, &root, &mut rng, false, None);
    let status_list = status::StatusList::from_bits(vec![false; 16]);

    let finish = |body: Value, leaf: [u8; 32], index: u64| -> Built {
        let mut full = body;
        full["log"] = json!({ "leaf": b64::encode(&leaf), "root": b64::encode(&cp.root), "checkpoint": "cp-1" });
        let claims = canon::canonicalize(&full).expect("canon full").into_bytes();
        debug_assert_eq!(verify::prelog_leaf(&claims).expect("prelog"), leaf);
        let issuer_sig = issuer.sign(&claims).expect("sign claims");
        let (nbf, exp) = (
            full["nbf"].as_u64().expect("nbf"),
            full["exp"].as_u64().expect("exp"),
        );
        Built {
            claims,
            issuer_pub: issuer.public(),
            issuer_sig,
            root_pub: root.public(),
            registrar: registrar.clone(),
            cp: cp.clone(),
            cp_sig: cp_sig.clone(),
            proof: log.inclusion_proof(index).expect("proof"),
            leaf_index: index,
            status_list: status_list.clone(),
            status_len: 16,
            chain_keys: Vec::new(),
            hop_proofs: Vec::new(),
            nbf,
            exp,
        }
    };
    let old = finish(old_body, old_leaf, old_index);
    let new = finish(new_body, new_leaf, new_index);
    (old, new)
}

/// A fully valid credential whose signed body carries `"prev_leaf": null`. ADR-017 parity guard: Rust's
/// `Option<String>` maps a JSON null to `None` (= absent, a first issuance), so this credential must VERIFY;
/// the SDK must treat null identically to a missing field. Signed properly (not mutated post-sign) so the
/// expected verdict is VALID, not a signature error.
fn build_prevleaf_null(seed: u64) -> Built {
    let mut rng = ChaCha20Rng::seed_from_u64(0x4149_4E52_4143_0000 ^ seed);
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
        "act_chain": [],
        "prev_leaf": Value::Null
    });
    let body_bytes = canon::canonicalize(&body).expect("canon").into_bytes();
    let leaf = merkle::hash_leaf(&body_bytes);
    let mut log = merkle::TestLog::new();
    for k in 0..3u8 {
        log.append(&[k]);
    }
    let leaf_index = log.append(&body_bytes);
    let cp = checkpoint::Checkpoint {
        origin: format!("ainra-log/{}", p.registrar),
        tree_size: log.size(),
        root: log.root(),
    };
    let cp_sig = checkpoint_sig(&cp, &root, &mut rng, false, None);
    let proof = log.inclusion_proof(leaf_index).expect("proof");
    let mut full = body;
    full["log"] =
        json!({ "leaf": b64::encode(&leaf), "root": b64::encode(&cp.root), "checkpoint": "cp-1" });
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
        leaf_index,
        status_list: status::StatusList::from_bits(vec![false; p.status_len]),
        status_len: p.status_len,
        chain_keys: Vec::new(),
        hop_proofs: Vec::new(),
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
            distrust_from_leaf: None,
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
        instance: None,
        audience: String::new(),
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
        control_key: None,
        chain: Vec::new(),
        mandates: Vec::new(),
        // Every 4th credential exercises the ADR-002 delegate checkpoint-signing path (still VALID).
        delegate_checkpoint: i % 4 == 3,
        delegate_cert_exp: None,
        prev_leaf: None,
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

    // ── ADR-017 exact window boundaries: nbf INCLUSIVE, exp EXCLUSIVE. ADR-016's ±30 s skew tolerance applies
    //    to freshness-layer signed timestamps (heads/checkpoints), NEVER to the passport window — a skewed
    //    window would be a fail-open grace period, which ADR-017 forbids: expiry is expiry. ──
    let bper = 6usize;
    for i in 0..bper {
        let b = build(&valid_params(2_000 + i));
        let mut v = wire_valid(
            &format!("boundary-nbf-valid-{:04}", i),
            "now == nbf: the window is nbf-inclusive (ADR-017 exact comparison, no skew on the window)",
            &b,
        );
        v.presentation.now = b.nbf;
        v.presentation.status_issued_at = b.nbf.saturating_sub(10);
        out.push(v);
    }
    for i in 0..bper {
        let b = build(&valid_params(2_100 + i));
        let mut v = wire_valid(&format!("boundary-exp-expired-{:04}", i), "", &b);
        v.presentation.now = b.exp;
        v.presentation.status_issued_at = b.exp.saturating_sub(10);
        out.push(invalid(
            v,
            Reason::Expired,
            "now == exp: exp is exclusive — expiry is expiry, no grace period (ADR-017)",
        ));
    }
    for i in 0..bper {
        let b = build(&valid_params(2_200 + i));
        let mut v = wire_valid(
            &format!("boundary-exp-last-second-{:04}", i),
            "now == exp − 1: the last second inside the window still verifies",
            &b,
        );
        v.presentation.now = b.exp - 1;
        v.presentation.status_issued_at = b.exp.saturating_sub(11);
        out.push(v);
    }
    for i in 0..bper {
        let b = build(&valid_params(2_300 + i));
        let mut v = wire_valid(&format!("boundary-nbf-early-{:04}", i), "", &b);
        v.presentation.now = b.nbf - 1;
        v.presentation.status_issued_at = b.nbf.saturating_sub(11);
        out.push(invalid(
            v,
            Reason::NotYetValid,
            "now == nbf − 1: one second early is not yet valid (exact comparison, no skew)",
        ));
    }

    // ── ADR-017 renewal (REISSUE): one lineage, two generations in one log; the new body carries `prev_leaf`.
    //    Overlap [new.nbf, old.exp): BOTH verify. At old.exp the old fails closed; the new continues. ──
    for i in 0..bper {
        let (old_gen, new_gen) = build_renewal_pair(3_000 + i as u64);
        let inside = 1_800u64; // within the overlap [1600, 2000)
        let after = 2_000u64; // == old.exp — the overlap's hard edge
        let mut v = wire_valid(
            &format!("renewal-old-overlap-{:04}", i),
            "ADR-017 overlap: the renewed-away generation, still inside its own window, verifies",
            &old_gen,
        );
        v.presentation.now = inside;
        v.presentation.status_issued_at = inside - 10;
        out.push(v);
        let mut v = wire_valid(
            &format!("renewal-new-overlap-{:04}", i),
            "ADR-017 overlap: the REISSUE (with its prev_leaf continuity link) verifies alongside its predecessor",
            &new_gen,
        );
        v.presentation.now = inside;
        v.presentation.status_issued_at = inside - 10;
        out.push(v);
        let mut v = wire_valid(&format!("renewal-old-expired-{:04}", i), "", &old_gen);
        v.presentation.now = after;
        v.presentation.status_issued_at = after - 10;
        out.push(invalid(
            v,
            Reason::Expired,
            "after the overlap the old generation fails closed — expiry is expiry (ADR-017, no grace)",
        ));
        let mut v = wire_valid(
            &format!("renewal-new-survives-{:04}", i),
            "the reissued generation continues past its predecessor's exp",
            &new_gen,
        );
        v.presentation.now = after;
        v.presentation.status_issued_at = after - 10;
        out.push(v);
    }
    // A REISSUE whose continuity link is structurally malformed fails closed at the schema gate — a renewal that
    // LOOKS like a renewal but cannot be walked is refused, never ignored. The last case is the SUBTLE one that
    // guards cross-impl parity: a 43-char alphabet-valid but NON-CANONICAL base64url string (nonzero trailing
    // bits). Rust's base64ct decoder rejects it; Node's lenient Buffer.from would silently accept 32 bytes — so
    // the SDK must apply a canonical round-trip or it fails OPEN where Rust fails closed (M12 review finding).
    let noncanonical = "A".repeat(42) + "B"; // 43 base64url chars, last char carries nonzero trailing bits
    let nc_pad = "A".repeat(43) + "="; // padding on an otherwise-canonical 32-byte encoding
    let nc_ws = "A".repeat(21) + " " + &"A".repeat(21); // embedded whitespace
    let nc_alpha = "A".repeat(42) + "+"; // a standard-alphabet char ('+') — not valid unpadded base64url
    let bad_links: [&str; 7] = [
        "AAAA",                // wrong length (decodes to 3 bytes)
        "not!!b64",            // non-alphabet
        "",                    // empty
        noncanonical.as_str(), // nonzero trailing bits
        nc_pad.as_str(),       // padding
        nc_ws.as_str(),        // whitespace
        nc_alpha.as_str(),     // standard-alphabet swap
    ];
    for (i, bad) in bad_links.iter().enumerate() {
        let (_, new_gen) = build_renewal_pair(3_100 + i as u64);
        let mut v = wire_valid(&format!("renewal-invalid-prevleaf-{:04}", i), "", &new_gen);
        let mut claims: Value =
            serde_json::from_slice(&b64::decode(&v.presentation.claims).unwrap()).unwrap();
        claims["prev_leaf"] = json!(bad);
        v.presentation.claims = b64::encode(canon::canonicalize(&claims).unwrap().as_bytes());
        v.presentation.now = 1_800;
        v.presentation.status_issued_at = 1_790;
        out.push(invalid(
            v,
            Reason::SchemaViolation,
            "prev_leaf is not a canonical 32-byte base64url leaf hash — an unwalkable renewal link fails closed",
        ));
    }
    // A JSON `null` prev_leaf is NOT a renewal marker: Rust's `Option<String>` maps null → None (first issuance),
    // so it must VERIFY, and the SDK must treat null identically to a missing field (parity guard). Signed with
    // null in the body (not mutated post-sign), so the expected verdict is genuinely VALID.
    out.push(wire_valid(
        "renewal-null-prevleaf-0000",
        "prev_leaf: null is treated as absent (first issuance) by both implementations — verifies",
        &build_prevleaf_null(3_120),
    ));

    // ── D-029 canonical-encoding sweep: a non-canonical base64url encoding of a CLAIMS-INTERNAL decoded field
    //    (signed IN the body via build_mut, so the issuer signature is valid and the field's OWN decode is what
    //    fails). Core rejects at that field's decode (base64ct is strict); the SDK must reject IDENTICALLY via its
    //    one strict gateway (strictB64u round-trip). Presentation-level fields are the trusted boundary (the
    //    reference `run()` decodes them out-of-band), so the differential covers the claims-internal fields;
    //    per-variant exhaustiveness is locked by the b64/strictB64u unit tests. ──
    // log.leaf (decoded at step 9 → not_logged): the `log` object is stripped from the pre-log body, so mutating
    // its ENCODING isolates the decode cleanly. 32-byte field → all three variant shapes apply.
    let logleaf_variants: [(&str, NcFn); 3] = [
        ("trailingbits", nc_trailing_bits),
        ("whitespace", nc_whitespace),
        ("padding", nc_padding),
    ];
    for (i, (kind, tf)) in logleaf_variants.iter().enumerate() {
        let b = build_mut(&valid_params(4_000 + i), |full| {
            let s = full["log"]["leaf"].as_str().unwrap().to_string();
            full["log"]["leaf"] = json!(tf(&s));
        });
        let v = wire_valid(&format!("noncanon-logleaf-{kind}-{:04}", 0), "", &b);
        out.push(invalid(
            v,
            Reason::NotLogged,
            "non-canonical base64url log.leaf — core rejects at decode, the SDK rejects identically",
        ));
    }
    // hop sig (decoded at step 6 → alg_downgrade, BEFORE the log step): a chained credential with one hop
    // signature re-encoded non-canonically. 64/3309-byte fields → use the length-agnostic whitespace/padding.
    let hopsig_variants: [(&str, &str, NcFn); 2] = [
        ("sig_ed25519", "whitespace", nc_whitespace),
        ("sig_mldsa65", "padding", nc_padding),
    ];
    for (i, (field, kind, tf)) in hopsig_variants.iter().enumerate() {
        let b = build_mut(&valid_chain_params(50 + i), |full| {
            let s = full["act_chain"][0][field].as_str().unwrap().to_string();
            full["act_chain"][0][*field] = json!(tf(&s));
        });
        let v = wire_valid(&format!("noncanon-hopsig-{kind}-{:04}", 0), "", &b);
        out.push(invalid(
            v,
            Reason::AlgDowngrade,
            "non-canonical base64url hop signature — core rejects at decode, the SDK rejects identically",
        ));
    }

    // registrar
    for i in 0..per {
        let b = build(&valid_params(400 + i));
        let mut v = wire_valid(&format!("unknown-registrar-{:04}", i), "", &b);
        // replace the (correct) anchor with a stranger registrar id → issuer's registrar is not accredited
        let stranger = WireRegistrar {
            issuer_key: v.anchors.values().next().unwrap().issuer_key.clone(),
            log_root_key: v.anchors.values().next().unwrap().log_root_key.clone(),
            distrust_from_leaf: None,
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

    // The passport outliving its own delegation (D-052). Every hop here narrows correctly — hop 2 expires no later
    // than hop 1 — so `chain-expired` above cannot be the reason. What fails is the PASSPORT: it claims a window
    // that runs past the grant authorising it.
    //
    // This family exists because no vector could see the case. The generator sets every hop's `exp` EQUAL to the
    // passport's, and at equality the Python SDK's (inverted) rule and the Rust/TS rule agree — so a 1009-vector
    // four-way differential reported total agreement while the implementations disagreed about which direction
    // the inequality ran. Vectors prove agreement on the bytes they contain and nothing about the bytes nobody
    // generated; this is what closing that looks like.
    for i in 0..per {
        let mut p = valid_chain_params(1300 + i);
        let hop_exp = p.exp - 100;
        for hop in p.chain.iter_mut() {
            hop.exp = hop_exp;
        }
        let b = build(&p);
        let v = wire_valid(&format!("chain-hop-outlived-by-passport-{:04}", i), "", &b);
        out.push(invalid(
            v,
            Reason::ChainExpired,
            "the passport expires after the delegation hop that authorises it",
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
    // D-044 graduated distrust. TWO cases, and the second is what makes the first mean anything: a cutoff ABOVE
    // the credential's leaf must leave it VALID. Without that positive control, "graduated" would be indis-
    // tinguishable from "removed", which is the whole distinction the feature exists to draw.
    for i in 0..per {
        let b = build(&valid_params(2100 + i));
        let mut v = wire_valid(&format!("registrar-distrusted-{:04}", i), "", &b);
        let cut = v.presentation.leaf_index;
        for r in v.anchors.values_mut() {
            r.distrust_from_leaf = Some(cut);
        }
        out.push(invalid(
            v,
            Reason::RegistrarDistrusted,
            "credential logged at/after the registrar's distrust cutoff",
        ));
    }
    for i in 0..per {
        let b = build(&valid_params(2200 + i));
        let mut v = wire_valid(
            &format!("distrust-below-cutoff-{:04}", i),
            "cutoff sits above this credential's leaf — graduated distrust must not invalidate earlier work",
            &b,
        );
        let cut = v.presentation.leaf_index + 1;
        for r in v.anchors.values_mut() {
            r.distrust_from_leaf = Some(cut);
        }
        out.push(v);
    }

    // ── ADR-019 / D-047 — the instance rung ──────────────────────────────────────────────────────────────────────
    // EIGHT families. As with D-044's pair, the rejection families mean nothing without the acceptance family:
    // `instance-valid-*` proves the rung does not over-refuse, and every other family is that same fixture with
    // exactly one thing changed, so a failure names the field that caused it.
    //
    // WITNESS for this whole block: could these vectors have failed? Yes, and they did while being written — the
    // first `instance-valid` set came back `instance_pop_invalid` because the PoP was signed at the fixture's `nbf`
    // while the vector's `now` sits mid-window, which is a true answer to a question the vector was not asking.
    {
        const AUD: &str = "https://api.example";
        // A helper that plants a REAL control key in the passport (the existing corpus uses "AAAA"/"BBBB"
        // placeholders, which is fine only while nothing verifies against keys[0] — ADR-019 does).
        fn instance_fixture(
            seed: usize,
            caps: &[&str],
            revoked: bool,
        ) -> (Built, crypto::HybridKeypair, crypto::HybridKeypair, u64) {
            instance_fixture_with(seed, caps, revoked, |_| {})
        }

        /// The same fixture, with the passport's own parameters open to adjustment first.
        ///
        /// M30 recorded two coverage gaps by name: an instance credential under a DELEGATE-signed checkpoint, and
        /// one under a RENEWED passport. Both are combinations, not new features — the instance rung and each of
        /// those was covered alone, and nothing exercised them together. That is the shape of gap a corpus grown
        /// family-by-family tends to leave.
        fn instance_fixture_with(
            seed: usize,
            caps: &[&str],
            revoked: bool,
            adjust: impl FnOnce(&mut CredParams),
        ) -> (Built, crypto::HybridKeypair, crypto::HybridKeypair, u64) {
            let mut rng = ChaCha20Rng::seed_from_u64(0x494E_5354_0000_0000 ^ seed as u64);
            let ctrl = crypto::HybridKeypair::generate(&mut rng);
            let inst = crypto::HybridKeypair::generate(&mut rng);
            let mut p = valid_params(seed);
            p.status_revoked = revoked;
            p.capabilities = caps.iter().map(|s| s.to_string()).collect();
            p.control_key = Some(ctrl.public());
            adjust(&mut p);
            let b = build(&p);
            let now = b.nbf + (b.exp - b.nbf) / 2;
            (b, ctrl, inst, now)
        }

        /// Named rather than positional: eleven positional arguments is the same readability trap the repo
        /// already fixed once for `Decoded`, and one transposed keypair here would silently produce a vector
        /// that asserts the wrong thing while still looking plausible.
        struct Mint<'a> {
            b: &'a Built,
            inst: &'a crypto::HybridKeypair,
            caps: &'a [&'a str],
            nbf: u64,
            exp: u64,
            aud: &'a str,
            pop_aud: &'a str,
            pop_ts: u64,
            signer: &'a crypto::HybridKeypair,
            pop_signer: &'a crypto::HybridKeypair,
            /// D-053: overridden only by the bound-probing families below; None gives the derived default.
            iid: Option<String>,
        }
        fn mint(m: Mint<'_>) -> WireInstance {
            let Mint {
                b,
                inst,
                caps,
                nbf,
                exp,
                aud,
                pop_aud,
                pop_ts,
                signer,
                pop_signer,
                iid: m_iid,
            } = m;
            let leaf = ainra_core::verify::prelog_leaf(&b.claims).expect("prelog leaf");
            let ik = inst.public();
            let sub = serde_json::from_slice::<Value>(&b.claims).expect("claims")["sub"]
                .as_str()
                .expect("sub")
                .to_string();
            let ic = ainra_core::instance::InstanceCredential {
                sub: sub.clone(),
                iid: m_iid.unwrap_or_else(|| format!("i-{:04x}", nbf % 0xffff)),
                ikey: ik.clone(),
                nbf,
                exp,
                capabilities: caps.iter().map(|s| s.to_string()).collect(),
                aud: aud.to_string(),
                passport_leaf: leaf,
                sig: crypto::HybridSig {
                    ed25519: Vec::new(),
                    mldsa65: Vec::new(),
                },
            };
            let sig = signer
                .sign(&ic.signing_bytes().expect("ic bytes"))
                .expect("sign ic");
            let pop = ainra_core::instance::InstancePop {
                aud: pop_aud.to_string(),
                nonce: "n-0001".to_string(),
                ts: pop_ts,
                sig: crypto::HybridSig {
                    ed25519: Vec::new(),
                    mldsa65: Vec::new(),
                },
            };
            // D-049: the PoP is signed over the credential it accompanies. `ic` here carries exactly the field
            // values that go onto the wire below, so the digest the verifier recomputes matches.
            let psig = pop_signer
                .sign(&pop.signing_bytes(&ic).expect("pop bytes"))
                .expect("sign pop");
            WireInstance {
                sub,
                iid: ic.iid.clone(),
                ikey: wire_key(&ik),
                nbf,
                exp,
                capabilities: ic.capabilities.clone(),
                aud: aud.to_string(),
                passport_leaf: b64::encode(&leaf),
                sig: WireSig {
                    ed25519: b64::encode(&sig.ed25519),
                    mldsa65: b64::encode(&sig.mldsa65),
                },
                pop: WirePop {
                    aud: pop_aud.to_string(),
                    nonce: "n-0001".to_string(),
                    ts: pop_ts,
                    sig: WireSig {
                        ed25519: b64::encode(&psig.ed25519),
                        mldsa65: b64::encode(&psig.mldsa65),
                    },
                },
            }
        }

        // (1) ACCEPTANCE — the control that makes every rejection below meaningful.
        for i in 0..per {
            let caps = ["read:invoices"];
            let (b, ctrl, inst, now) = instance_fixture(4100 + i, &caps, false);
            let mut v = wire_valid(
            &format!("instance-valid-{:04}", i),
            "a running copy presenting a short, narrowed, holder-bound credential under its passport",
            &b,
        );
            v.presentation.instance = Some(mint(Mint {
                b: &b,
                inst: &inst,
                caps: &["read:invoices"],
                nbf: now - 60,
                exp: now + 600,
                aud: AUD,
                pop_aud: AUD,
                pop_ts: now,
                signer: &ctrl,
                pop_signer: &inst,
                iid: None,
            }));
            v.presentation.audience = AUD.to_string();
            out.push(v);
        }

        // (2) EXPIRED — window closed, and the boundary (exp is exclusive).
        for i in 0..per {
            let caps = ["read:invoices"];
            let (b, ctrl, inst, now) = instance_fixture(4200 + i, &caps, false);
            let mut v = wire_valid(&format!("instance-expired-{:04}", i), "", &b);
            v.presentation.instance = Some(mint(Mint {
                b: &b,
                inst: &inst,
                caps: &["read:invoices"],
                nbf: now - 600,
                exp: now,
                aud: AUD,
                pop_aud: AUD,
                pop_ts: now,
                signer: &ctrl,
                pop_signer: &inst,
                iid: None,
            }));
            v.presentation.audience = AUD.to_string();
            out.push(invalid(
                v,
                Reason::InstanceExpired,
                "instance window closed — exp is exclusive, so now == exp is expired",
            ));
        }

        // (3) LIFETIME CEILING — a validly signed credential whose window exceeds the ADR-019 hour.
        for i in 0..per {
            let caps = ["read:invoices"];
            let (b, ctrl, inst, now) = instance_fixture(4300 + i, &caps, false);
            let mut v = wire_valid(&format!("instance-too-long-{:04}", i), "", &b);
            v.presentation.instance = Some(mint(Mint {
                b: &b,
                inst: &inst,
                caps: &["read:invoices"],
                nbf: now - 60,
                exp: now + 3600,
                aud: AUD,
                pop_aud: AUD,
                pop_ts: now,
                signer: &ctrl,
                pop_signer: &inst,
                iid: None,
            }));
            v.presentation.audience = AUD.to_string();
            out.push(invalid(
                v,
                Reason::InstanceExpired,
                "lifetime exceeds the 1 h ceiling — enforced at verify, not only at issuance",
            ));
        }

        // (2b) THE TWO COMBINATIONS M30 RECORDED AS UNCOVERED.
        //
        // Both are ACCEPTANCE vectors, and that is deliberate: the risk in a combination is not that it is wrongly
        // refused but that one layer quietly stops applying in the presence of the other. A rejection family here
        // would pass even if the instance rung were skipped entirely.
        for i in 0..per {
            let caps = ["read:invoices"];
            let (b, ctrl, inst, now) =
                instance_fixture_with(5200 + i, &caps, false, |p| p.delegate_checkpoint = true);
            let mut v = wire_valid(&format!("instance-delegate-checkpoint-{:04}", i), "", &b);
            v.presentation.instance = Some(mint(Mint {
                b: &b,
                inst: &inst,
                caps: &["read:invoices"],
                nbf: now - 60,
                exp: now + 600,
                aud: AUD,
                pop_aud: AUD,
                pop_ts: now,
                signer: &ctrl,
                pop_signer: &inst,
                iid: None,
            }));
            v.presentation.audience = AUD.to_string();
            out.push(v);
        }
        for i in 0..per {
            let caps = ["read:invoices"];
            // A renewed passport: same lineage, new window, `prev_leaf` naming the generation it supersedes.
            let (b, ctrl, inst, now) =
                instance_fixture_with(5300 + i, &caps, false, |p| p.prev_leaf = Some([0x5Au8; 32]));
            let mut v = wire_valid(&format!("instance-under-renewal-{:04}", i), "", &b);
            v.presentation.instance = Some(mint(Mint {
                b: &b,
                inst: &inst,
                caps: &["read:invoices"],
                nbf: now - 60,
                exp: now + 600,
                aud: AUD,
                pop_aud: AUD,
                pop_ts: now,
                signer: &ctrl,
                pop_signer: &inst,
                iid: None,
            }));
            v.presentation.audience = AUD.to_string();
            out.push(v);
        }

        // (3a) POP BOUND TO ITS CREDENTIAL (D-049) — the substitution attack, as bytes.
        //
        // The operator mints TWO credentials to the SAME instance key at the SAME audience: a narrow one the
        // container presents honestly, and a wider one. Both are genuinely signed by the passport control key,
        // and both name the same lineage leaf. The vector presents the WIDE credential carrying the PoP that was
        // produced for the NARROW one.
        //
        // Everything the old `{aud, nonce, ts}` PoP body named is identical between the two, so that body could
        // not tell them apart: a PoP captured off an honest presentation verified against a credential it had
        // never seen. Nothing about the forwarded PoP is stale or replayed — it is fresh, its nonce is unused, and
        // its signature is genuine — so a nonce cache, which is the mitigation ADR-019 originally recommended,
        // does not fire. Only binding the credential's digest into the signed body refuses it.
        for i in 0..per {
            let caps = ["read:invoices", "sign:invoice"];
            let (b, ctrl, inst, now) = instance_fixture(4700 + i, &caps, false);
            let mut v = wire_valid(&format!("instance-pop-other-credential-{:04}", i), "", &b);
            // The honest, NARROW credential — and the PoP the container legitimately produced for it.
            let narrow = mint(Mint {
                b: &b,
                inst: &inst,
                caps: &["read:invoices"],
                nbf: now - 60,
                exp: now + 600,
                aud: AUD,
                pop_aud: AUD,
                pop_ts: now,
                signer: &ctrl,
                pop_signer: &inst,
                iid: None,
            });
            // The WIDER credential the attacker also holds: same instance key, same audience, same leaf.
            let mut wide = mint(Mint {
                b: &b,
                inst: &inst,
                caps: &["read:invoices", "sign:invoice"],
                nbf: now - 60,
                exp: now + 600,
                aud: AUD,
                pop_aud: AUD,
                pop_ts: now,
                signer: &ctrl,
                pop_signer: &inst,
                iid: None,
            });
            wide.pop = narrow.pop.clone(); // ← the forward
            v.presentation.instance = Some(wide);
            v.presentation.audience = AUD.to_string();
            out.push(invalid(
                v,
                Reason::InstancePopInvalid,
                "a PoP captured from one credential, forwarded with a wider one minted to the same instance key",
            ));
        }

        // (3b) SHAPE BOUNDS (D-053) — a VALIDLY SIGNED credential is still refused when a field is oversized.
        //
        // Both families sign correctly, so nothing here is a signature failure: what is being pinned is that the
        // verifier bounds attacker-chosen fields BEFORE it spends anything on them. The `iid` reaches the verdict
        // event (and therefore the operator's log) even for a bundle that is about to be refused; the capability
        // arrays reach an O(n×m) subset test on both sides.
        for i in 0..per {
            let caps = ["read:invoices"];
            let (b, ctrl, inst, now) = instance_fixture(5000 + i, &caps, false);
            let mut v = wire_valid(&format!("instance-iid-too-long-{:04}", i), "", &b);
            v.presentation.instance = Some(mint(Mint {
                b: &b,
                inst: &inst,
                caps: &["read:invoices"],
                nbf: now - 60,
                exp: now + 600,
                aud: AUD,
                pop_aud: AUD,
                pop_ts: now,
                signer: &ctrl,
                pop_signer: &inst,
                iid: Some("i-".to_string() + &"A".repeat(ainra_core::instance::MAX_IID_LEN)),
            }));
            v.presentation.audience = AUD.to_string();
            out.push(invalid(
                v,
                Reason::SchemaViolation,
                "iid past MAX_IID_LEN — refused before it can be read or logged",
            ));
        }
        for i in 0..per {
            let caps = ["read:invoices"];
            let (b, ctrl, inst, now) = instance_fixture(5100 + i, &caps, false);
            let mut v = wire_valid(&format!("instance-caps-too-many-{:04}", i), "", &b);
            let many: Vec<String> = (0..=ainra_core::instance::MAX_CAPABILITIES)
                .map(|n| format!("read:c{n}"))
                .collect();
            let many_refs: Vec<&str> = many.iter().map(String::as_str).collect();
            v.presentation.instance = Some(mint(Mint {
                b: &b,
                inst: &inst,
                caps: &many_refs,
                nbf: now - 60,
                exp: now + 600,
                aud: AUD,
                pop_aud: AUD,
                pop_ts: now,
                signer: &ctrl,
                pop_signer: &inst,
                iid: None,
            }));
            v.presentation.audience = AUD.to_string();
            out.push(invalid(
                v,
                Reason::SchemaViolation,
                "capability array past MAX_CAPABILITIES — bounded before the O(n×m) subset test",
            ));
        }

        // (4) SCOPE EXCEEDS — narrowing only; a properly signed widening is still refused.
        for i in 0..per {
            let caps = ["read:invoices"];
            let (b, ctrl, inst, now) = instance_fixture(4400 + i, &caps, false);
            let mut v = wire_valid(&format!("instance-scope-exceeds-{:04}", i), "", &b);
            v.presentation.instance = Some(mint(Mint {
                b: &b,
                inst: &inst,
                caps: &["read:invoices", "admin:all"],
                nbf: now - 60,
                exp: now + 600,
                aud: AUD,
                pop_aud: AUD,
                pop_ts: now,
                signer: &ctrl,
                pop_signer: &inst,
                iid: None,
            }));
            v.presentation.audience = AUD.to_string();
            out.push(invalid(
                v,
                Reason::InstanceScopeExceeds,
                "instance asks for a capability its passport does not hold",
            ));
        }

        // (5) WRONG SIGNER — a real signature by a key that is not the passport's control key.
        for i in 0..per {
            let caps = ["read:invoices"];
            let (b, _ctrl, inst, now) = instance_fixture(4500 + i, &caps, false);
            let mut rng = ChaCha20Rng::seed_from_u64(0xBAD5_1611_0000_0000 ^ i as u64);
            let impostor = crypto::HybridKeypair::generate(&mut rng);
            let mut v = wire_valid(&format!("instance-wrong-signer-{:04}", i), "", &b);
            v.presentation.instance = Some(mint(Mint {
                b: &b,
                inst: &inst,
                caps: &["read:invoices"],
                nbf: now - 60,
                exp: now + 600,
                aud: AUD,
                pop_aud: AUD,
                pop_ts: now,
                signer: &impostor,
                pop_signer: &inst,
                iid: None,
            }));
            v.presentation.audience = AUD.to_string();
            out.push(invalid(
                v,
                Reason::InstanceSigInvalid,
                "minted by a key that is not this passport's control key",
            ));
        }

        // (6) POP — the check that makes the credential holder-bound rather than bearer. Two shapes: a PoP signed by
        //     the wrong key, and a PoP for a different audience.
        for i in 0..per {
            let caps = ["read:invoices"];
            let (b, ctrl, inst, now) = instance_fixture(4600 + i, &caps, false);
            let mut rng = ChaCha20Rng::seed_from_u64(0x5701_1E00_0000_0000u64 ^ i as u64);
            let thief = crypto::HybridKeypair::generate(&mut rng);
            let mut v = wire_valid(&format!("instance-pop-wrong-key-{:04}", i), "", &b);
            v.presentation.instance = Some(mint(Mint {
                b: &b,
                inst: &inst,
                caps: &["read:invoices"],
                nbf: now - 60,
                exp: now + 600,
                aud: AUD,
                pop_aud: AUD,
                pop_ts: now,
                signer: &ctrl,
                pop_signer: &thief,
                iid: None,
            }));
            v.presentation.audience = AUD.to_string();
            out.push(invalid(
                v,
                Reason::InstancePopInvalid,
                "proof-of-possession signed by a key that is not the credential's instance key",
            ));
        }
        for i in 0..per {
            let caps = ["read:invoices"];
            let (b, ctrl, inst, now) = instance_fixture(4700 + i, &caps, false);
            let mut v = wire_valid(&format!("instance-replay-elsewhere-{:04}", i), "", &b);
            v.presentation.instance = Some(mint(Mint {
                b: &b,
                inst: &inst,
                caps: &["read:invoices"],
                nbf: now - 60,
                exp: now + 600,
                aud: "https://elsewhere.example",
                pop_aud: "https://elsewhere.example",
                pop_ts: now,
                signer: &ctrl,
                pop_signer: &inst,
                iid: None,
            }));
            v.presentation.audience = AUD.to_string();
            out.push(invalid(
                v,
                Reason::InstancePopInvalid,
                "a credential addressed to a different audience, replayed here",
            ));
        }

        // (7) THE R1 PAYOFF — revoke the passport, and every instance under it dies. The verdict is `revoked` from
        //     step 7, NOT an instance reason: the container is fine, the lineage is not, and the reason must say so.
        for i in 0..per {
            let caps = ["read:invoices"];
            let (b, ctrl, inst, now) = instance_fixture(4800 + i, &caps, true);
            let mut v = wire_valid(&format!("instance-passport-revoked-{:04}", i), "", &b);
            v.presentation.instance = Some(mint(Mint {
                b: &b,
                inst: &inst,
                caps: &["read:invoices"],
                nbf: now - 60,
                exp: now + 600,
                aud: AUD,
                pop_aud: AUD,
                pop_ts: now,
                signer: &ctrl,
                pop_signer: &inst,
                iid: None,
            }));
            v.presentation.audience = AUD.to_string();
            out.push(invalid(
                v,
                Reason::Revoked,
                "the passport under this instance is revoked — every live instance dies with it",
            ));
        }

        // (8) NON-CANONICAL — D-029 discipline reaches this rung too.
        for i in 0..per {
            let caps = ["read:invoices"];
            let (b, ctrl, inst, now) = instance_fixture(4900 + i, &caps, false);
            let mut v = wire_valid(&format!("instance-noncanon-{:04}", i), "", &b);
            let mut wi = mint(Mint {
                b: &b,
                inst: &inst,
                caps: &["read:invoices"],
                nbf: now - 60,
                exp: now + 600,
                aud: AUD,
                pop_aud: AUD,
                pop_ts: now,
                signer: &ctrl,
                pop_signer: &inst,
                iid: None,
            });
            // a non-canonical base64url tail on the bound leaf: the strict decoder must refuse it outright
            wi.passport_leaf = format!("{}=", &wi.passport_leaf);
            v.presentation.instance = Some(wi);
            v.presentation.audience = AUD.to_string();
            out.push(invalid(v, Reason::SchemaViolation, "non-canonical base64url in the instance layer — the strict gateway refuses it (D-029)"));
        }
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
        let res: Result<(), Reason> = delta_verify(&v);
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
        distrust_from_leaf: None,
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

/// Conformance runner adapter (M24 Task 2): read published vectors as JSON Lines on stdin — one vector per line —
/// and for each print `<name>\t<canonical-result-json>` computed by the REAL ainra-core verify path. This is the
/// Rust core's wrapper that fits the language-agnostic conformance CONTRACT (tools/conformance/CONTRACT.md); the
/// runner streams a corpus part here and compares each line to the vector's recorded `expect`. No files, no network.
fn emit_stdin(kind: &str) {
    use std::io::{BufRead, Write};
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for line in stdin.lock().lines() {
        let line = line.expect("read stdin line");
        if line.trim().is_empty() {
            continue;
        }
        let (name, result) = match kind {
            "passport" => {
                let v: Vector = serde_json::from_str(&line).expect("parse passport vector");
                let r = serde_json::to_value(run(&v)).expect("verdict json");
                (v.name, r)
            }
            "delta" => {
                let v: WireDeltaVector = serde_json::from_str(&line).expect("parse delta vector");
                let r = match delta_verify(&v) {
                    Ok(()) => json!({ "accept": true }),
                    Err(e) => json!({ "accept": false, "reason": reason_str(e) }),
                };
                (v.name, r)
            }
            "directory" => {
                let v: serde_json::Value =
                    serde_json::from_str(&line).expect("parse directory vector");
                let name = v["name"].as_str().expect("name").to_string();
                (name, directory_result(&v))
            }
            other => {
                eprintln!("unknown --emit kind: {other} (expected passport|delta|directory)");
                std::process::exit(2);
            }
        };
        writeln!(
            out,
            "{name}\t{}",
            serde_json::to_string(&result).expect("ser result")
        )
        .unwrap();
    }
    out.flush().unwrap();
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
        let got = directory_result(&v);
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

// ── v1-presentation — RFC 9421 request signatures (PLAN-M34 Task 3, D-062) ────────────────────────────────────
//
// The request exactly as a gate sees it, with the instance key that should have signed it. Every vector declares the
// answer it exists to test (`want`), and the generator refuses to write one whose core verdict disagrees — a vector
// named "moved path" that fails for some other reason tests nothing.

const PRES_NOW: u64 = 1_775_866_600;
const PRES_IID: &str = "i-5eed0001";

struct PresReq {
    method: String,
    authority: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

// One argument per thing a signed request is made of; bundling them into a struct would only rename the list.
#[allow(clippy::too_many_arguments)]
fn pres_sign(
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    pres: &str,
    created: u64,
    nonce: &str,
    keyid: &str,
    key: &crypto::HybridKeypair,
) -> PresReq {
    pres_sign_over(
        method,
        path,
        body,
        pres,
        created,
        nonce,
        keyid,
        key,
        Vec::new(),
    )
}

/// `pres_sign` on a request that already carries other headers — another signer's signature among them (D-070). The
/// signer's output REPLACES fields of the same name, which is how it appends its member to someone else's.
#[allow(clippy::too_many_arguments)]
fn pres_sign_over(
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    pres: &str,
    created: u64,
    nonce: &str,
    keyid: &str,
    key: &crypto::HybridKeypair,
    prior: Vec<(String, String)>,
) -> PresReq {
    use ainra_core::presentation::{sign_presentation, SignableRequest, PRESENTATION_HEADER};
    let mut headers = prior;
    headers.push((PRESENTATION_HEADER.to_string(), pres.to_string()));
    let req = SignableRequest {
        method,
        authority: "shop.example",
        path,
        headers: &headers,
        body,
    };
    let add = sign_presentation(&req, keyid, nonce, created, key).expect("sign");
    for (n, v) in add {
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case(&n));
        headers.push((n, v));
    }
    PresReq {
        method: method.into(),
        authority: "shop.example".into(),
        path: path.into(),
        headers,
        body: body.map(|b| b.to_vec()),
    }
}

fn pres_set(r: &mut PresReq, name: &str, value: &str) {
    for h in r.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case(name) {
            h.1 = value.into();
            return;
        }
    }
    r.headers.push((name.into(), value.into()));
}
fn pres_del(r: &mut PresReq, name: &str) {
    r.headers.retain(|h| !h.0.eq_ignore_ascii_case(name));
}
fn pres_get(r: &PresReq, name: &str) -> String {
    r.headers
        .iter()
        .find(|h| h.0.eq_ignore_ascii_case(name))
        .map(|h| h.1.clone())
        .expect("header")
}

// ── the other reader (D-070) ───────────────────────────────────────────────────────────────────────────────────
// A signature-agent's signature as the Web Bot Auth profile makes one: Ed25519, `tag="web-bot-auth"`, `created` and
// `expires`, `keyid` the RFC 8037 JWK thumbprint, covering `@authority` and its own `signature-agent` member. The
// generator builds it by hand; `make signature-agent-check` has an independent implementation of that profile verify
// it, so a mistake here cannot hide behind AINRA ignoring the member.
const AGENT_LABEL: &str = "sig1";
const AGENT_URI: &str = "https://signer.example";

fn agent_jwk(op: &crypto::HybridKeypair) -> (Value, String) {
    use sha2::{Digest, Sha256};
    let x = b64::encode(&op.public().ed25519);
    let thumb = b64::encode(&Sha256::digest(
        format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#).as_bytes(),
    ));
    (json!({ "kty": "OKP", "crv": "Ed25519", "x": x }), thumb)
}

/// Sign `r` as the signature agent, covering `@authority`, its `signature-agent` member, then `more` — each a
/// (serialized component identifier, value) pair. Returns the (signature-input, signature) members.
fn agent_member(
    r: &PresReq,
    more: &[(String, String)],
    created: u64,
    op: &crypto::HybridKeypair,
) -> (String, String) {
    use base64ct::{Base64, Encoding};
    let (_, kid) = agent_jwk(op);
    let mut lines = vec![
        ("\"@authority\"".to_string(), r.authority.clone()),
        (
            format!("\"signature-agent\";key=\"{AGENT_LABEL}\""),
            format!("\"{AGENT_URI}\""),
        ),
    ];
    lines.extend(more.iter().cloned());
    let ids: Vec<&str> = lines.iter().map(|(c, _)| c.as_str()).collect();
    let params = format!(
        "({});created={created};expires={};keyid=\"{kid}\";alg=\"ed25519\";tag=\"web-bot-auth\"",
        ids.join(" "),
        created + 3600
    );
    let mut base: Vec<String> = lines.iter().map(|(c, v)| format!("{c}: {v}")).collect();
    base.push(format!("\"@signature-params\": {params}"));
    let sig = op.sign(base.join("\n").as_bytes()).expect("sign").ed25519;
    (
        format!("{AGENT_LABEL}={params}"),
        format!("{AGENT_LABEL}=:{}:", Base64::encode_string(&sig)),
    )
}

fn presentation_vectors() -> Vec<Value> {
    use ainra_core::presentation::{content_digest, PRESENTATION_HEADER};
    let mut rng = ChaCha20Rng::seed_from_u64(0x4149_4E52_4100_9421); // "AINRA" ⊕ RFC 9421 — a public TEST seed
    let key = crypto::HybridKeypair::generate(&mut rng);
    let other = crypto::HybridKeypair::generate(&mut rng);
    let op = crypto::HybridKeypair::generate(&mut rng); // the signature agent's key (its Ed25519 half), D-070
    let pk = key.public();
    // What PRESENTATION_HEADER carries: since D-065 usually a digest reference; one vector carries a bundle-shaped
    // value, because the signature covers the header whatever it holds.
    let pres_ref = content_digest(b"ainra presentation vector: the stable part of a bundle");
    let pres_full = b64::encode(br#"{"claims":"eyJzdWIiOiJhaW5yYTpyZWdpc3RyYXItMDc6YWNtZTpib3RAMS4wLjAifQ","freshness":"F2"}"#);
    let body: &[u8] = br#"{"sku":"A-1","qty":2}"#;
    let sig = |r: &PresReq| pres_get(r, "signature");
    let zero_half = |field: &str, ed: bool| -> String {
        use base64ct::{Base64, Encoding};
        let inner = field
            .strip_prefix("ainra=:")
            .unwrap()
            .strip_suffix(':')
            .unwrap();
        let mut raw = Base64::decode_vec(inner).unwrap();
        let range = if ed { 0..64 } else { 64..raw.len() };
        for b in &mut raw[range] {
            *b = 0;
        }
        format!("ainra=:{}:", Base64::encode_string(&raw))
    };

    struct Case {
        name: &'static str,
        what: &'static str,
        req: PresReq,
        max_age: u64,
        seen: Vec<&'static str>,
        want: &'static str,
        /// D-070: what the signature agent's own verifier must conclude about its member, when the vector has one.
        other: Option<bool>,
    }
    let base = |m: &str, p: &str, b: Option<&[u8]>| {
        pres_sign(m, p, b, &pres_ref, PRES_NOW, "r-0001", PRES_IID, &key)
    };
    let mut cases: Vec<Case> = Vec::new();
    let mut add = |name, what, req, want| {
        cases.push(Case {
            name,
            what,
            req,
            max_age: 300,
            seen: vec![],
            want,
            other: None,
        })
    };

    add(
        "p01-valid-get",
        "a GET with no body, signed by the running copy",
        base("GET", "/orders", None),
        "ok",
    );
    add(
        "p02-valid-post-with-body",
        "a POST whose body is covered through content-digest",
        base("POST", "/orders", Some(body)),
        "ok",
    );
    add(
        "p03-valid-bundle-in-header",
        "the header carries a bundle rather than a digest reference",
        pres_sign(
            "GET", "/orders", None, &pres_full, PRES_NOW, "r-0003", PRES_IID, &key,
        ),
        "ok",
    );
    add(
        "p04-valid-at-max-age",
        "signed exactly 300 s ago: the window is inclusive",
        pres_sign(
            "GET",
            "/orders",
            None,
            &pres_ref,
            PRES_NOW - 300,
            "r-0004",
            PRES_IID,
            &key,
        ),
        "ok",
    );
    add(
        "p05-valid-at-max-future",
        "signed 30 s in the future: the clock-skew tolerance is inclusive",
        pres_sign(
            "GET",
            "/orders",
            None,
            &pres_ref,
            PRES_NOW + 30,
            "r-0005",
            PRES_IID,
            &key,
        ),
        "ok",
    );
    {
        let mut r = base("GET", "/orders", None);
        r.headers = r
            .headers
            .into_iter()
            .map(|(k, v)| (k.to_uppercase(), v))
            .collect();
        add(
            "p06-valid-header-names-any-case",
            "header names match case-insensitively",
            r,
            "ok",
        );
    }
    {
        let mut r = base("GET", "/orders", None);
        pres_del(&mut r, "signature");
        pres_del(&mut r, "signature-input");
        add(
            "p07-unsigned",
            "no signature at all, under a policy that requires one",
            r,
            "presentation_unsigned",
        );
    }
    {
        let mut r = base("GET", "/orders", None);
        pres_del(&mut r, "signature");
        add(
            "p08-input-without-signature",
            "signature-input present, signature missing",
            r,
            "presentation_unsigned",
        );
    }
    {
        let mut r = base("GET", "/orders", None);
        pres_del(&mut r, "signature-input");
        add(
            "p09-signature-without-input",
            "signature present, signature-input missing",
            r,
            "presentation_unsigned",
        );
    }
    {
        let mut r = base("POST", "/orders", Some(body));
        r.path = "/admin/refunds".into();
        add(
            "p10-moved-path",
            "the signed request replayed against another path",
            r,
            "presentation_sig_invalid",
        );
    }
    {
        let mut r = base("POST", "/orders", Some(body));
        r.authority = "evil.example".into();
        add(
            "p11-moved-authority",
            "the signed request replayed against another host",
            r,
            "presentation_sig_invalid",
        );
    }
    {
        let mut r = base("POST", "/orders", Some(body));
        r.method = "PUT".into();
        add(
            "p12-altered-method",
            "the method changed after signing",
            r,
            "presentation_sig_invalid",
        );
    }
    {
        let mut r = base("POST", "/orders", Some(body));
        r.body = Some(br#"{"sku":"A-1","qty":200}"#.to_vec());
        add(
            "p13-altered-body",
            "the body changed; the digest header still describes the old one",
            r,
            "presentation_sig_invalid",
        );
    }
    {
        let mut r = base("POST", "/orders", Some(body));
        let nb = br#"{"sku":"A-1","qty":200}"#.to_vec();
        pres_set(&mut r, "content-digest", &content_digest(&nb));
        r.body = Some(nb);
        add(
            "p14-altered-body-and-digest",
            "body and digest both changed consistently; the signature covered the old digest",
            r,
            "presentation_sig_invalid",
        );
    }
    {
        let mut r = base("GET", "/orders", None);
        pres_set(
            &mut r,
            PRESENTATION_HEADER,
            &content_digest(b"a different bundle"),
        );
        add(
            "p15-swapped-presentation",
            "another presentation under the same signature",
            r,
            "presentation_sig_invalid",
        );
    }
    add(
        "p16-wrong-key",
        "signed by a key that is not this instance credential's",
        pres_sign(
            "GET", "/orders", None, &pres_ref, PRES_NOW, "r-0016", PRES_IID, &other,
        ),
        "presentation_sig_invalid",
    );
    add(
        "p17-keyid-names-another-copy",
        "keyid names a different instance credential",
        pres_sign(
            "GET",
            "/orders",
            None,
            &pres_ref,
            PRES_NOW,
            "r-0017",
            "i-5eed0002",
            &key,
        ),
        "presentation_sig_invalid",
    );
    {
        let mut r = base("GET", "/orders", None);
        let i = pres_get(&r, "signature-input").replace("ainra-hybrid-v1", "ed25519");
        pres_set(&mut r, "signature-input", &i);
        add(
            "p18-alg-not-hybrid",
            "alg claims a single algorithm: hybrid or invalid",
            r,
            "presentation_sig_invalid",
        );
    }
    {
        let mut r = base("GET", "/orders", None);
        let i = pres_get(&r, "signature-input").replace("\"@path\" ", "");
        pres_set(&mut r, "signature-input", &i);
        add(
            "p19-path-not-covered",
            "the covered set leaves out @path",
            r,
            "presentation_sig_invalid",
        );
    }
    {
        let mut r = base("POST", "/orders", None);
        r.body = Some(body.to_vec());
        add(
            "p20-body-not-covered",
            "a body arrives that the signature never covered",
            r,
            "presentation_sig_invalid",
        );
    }
    {
        let r = pres_sign(
            "GET",
            "/orders",
            None,
            &pres_ref,
            PRES_NOW - 301,
            "r-0021",
            PRES_IID,
            &key,
        );
        add(
            "p21-stale",
            "signed 301 s ago: one second outside the window",
            r,
            "presentation_stale",
        );
    }
    {
        let r = pres_sign(
            "GET",
            "/orders",
            None,
            &pres_ref,
            PRES_NOW + 31,
            "r-0022",
            PRES_IID,
            &key,
        );
        add(
            "p22-from-the-future",
            "signed 31 s ahead: beyond the skew tolerance",
            r,
            "presentation_stale",
        );
    }
    {
        let mut r = pres_sign(
            "GET",
            "/orders",
            None,
            &pres_ref,
            PRES_NOW - 301,
            "r-0023",
            PRES_IID,
            &key,
        );
        r.path = "/admin".into();
        add(
            "p23-stale-and-moved",
            "both stale and moved: freshness is checked before the signature",
            r,
            "presentation_stale",
        );
    }
    {
        let mut r = base("GET", "/orders", None);
        let s = sig(&r);
        pres_set(&mut r, "signature", "ainra=:!!notbase64!!:");
        let _ = s;
        add(
            "p25-signature-not-base64",
            "the signature field is not a byte sequence",
            r,
            "presentation_sig_invalid",
        );
    }
    {
        let mut r = base("GET", "/orders", None);
        let s = sig(&r);
        let cut = format!("{}:", &s[..s.len() - 9]);
        pres_set(&mut r, "signature", &cut);
        add(
            "p26-signature-truncated",
            "the signature is shorter than both halves together",
            r,
            "presentation_sig_invalid",
        );
    }
    {
        let mut r = base("GET", "/orders", None);
        let z = zero_half(&sig(&r), true);
        pres_set(&mut r, "signature", &z);
        add(
            "p27-ed25519-half-zeroed",
            "only the ML-DSA-65 half is valid",
            r,
            "presentation_sig_invalid",
        );
    }
    {
        let mut r = base("GET", "/orders", None);
        let z = zero_half(&sig(&r), false);
        pres_set(&mut r, "signature", &z);
        add(
            "p28-mldsa-half-zeroed",
            "only the Ed25519 half is valid",
            r,
            "presentation_sig_invalid",
        );
    }
    {
        let mut r = base("GET", "/orders", None);
        let i = format!("{};expires=1775867000", pres_get(&r, "signature-input"));
        pres_set(&mut r, "signature-input", &i);
        add(
            "p29-extra-parameter",
            "a parameter outside the profile: the parser accepts exactly one shape",
            r,
            "presentation_sig_invalid",
        );
    }
    {
        let mut r = base("GET", "/orders", None);
        let i = pres_get(&r, "signature-input").replace("nonce=\"r-0001\"", "nonce=\"r 0001\"");
        pres_set(&mut r, "signature-input", &i);
        add(
            "p30-nonce-outside-charset",
            "a nonce with a space in it",
            r,
            "presentation_sig_invalid",
        );
    }
    // Same bytes, non-canonical text: the last base64 character before the padding carries two data bits and four
    // zero bits; flipping the lowest bit changes the text, not the bytes a lenient decoder returns. A trust root's
    // front door accepts exactly one encoding of a signature.
    {
        let mut r = base("GET", "/orders", None);
        let s0 = sig(&r);
        let inner = s0
            .strip_prefix("ainra=:")
            .unwrap()
            .strip_suffix(':')
            .unwrap();
        let body = inner.trim_end_matches('=');
        let alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let last = body.chars().last().unwrap();
        let idx = alpha.find(last).unwrap() ^ 1;
        let flipped = format!(
            "{}{}{}",
            &body[..body.len() - 1],
            &alpha[idx..idx + 1],
            &inner[body.len()..]
        );
        pres_set(&mut r, "signature", &format!("ainra=:{flipped}:"));
        add(
            "p33-signature-noncanonical-base64",
            "the same signature bytes in a non-canonical encoding",
            r,
            "presentation_sig_invalid",
        );
    }
    // ── D-070: one request, two readers ──────────────────────────────────────────────────────────────────────────
    // A signature agent signs first; the running copy appends its own member. Neither signature covers the other.
    let agent_signed = |m: &str, p: &str, b: Option<&[u8]>, nonce: &str| -> PresReq {
        let mut r = PresReq {
            method: m.into(),
            authority: "shop.example".into(),
            path: p.into(),
            headers: vec![(
                "signature-agent".into(),
                format!("{AGENT_LABEL}=\"{AGENT_URI}\""),
            )],
            body: None,
        };
        let (i, sg) = agent_member(&r, &[], PRES_NOW, &op);
        r.headers.push(("signature-input".into(), i));
        r.headers.push(("signature".into(), sg));
        pres_sign_over(
            m, p, b, &pres_ref, PRES_NOW, nonce, PRES_IID, &key, r.headers,
        )
    };
    let mut extra: Vec<Case> = Vec::new();
    let mut both = |name, what, req, want, other| {
        extra.push(Case {
            name,
            what,
            req,
            max_age: 300,
            seen: vec![],
            want,
            other: Some(other),
        })
    };
    both(
        "p34-beside-a-signature-agent",
        "a signature agent signed first and the running copy appended its member: each reader reads its own",
        agent_signed("GET", "/orders", None, "r-0034"),
        "ok",
        true,
    );
    {
        // The same two signatures, each signer's fields on lines of their own: one field, its lines joined.
        let r0 = agent_signed("POST", "/orders", Some(body), "r-0035");
        let mut r = PresReq {
            headers: Vec::new(),
            ..r0
        };
        for (k, v) in agent_signed("POST", "/orders", Some(body), "r-0035").headers {
            if k == "signature-input" || k == "signature" {
                let (agent, own) = v.split_once(", ").expect("two members");
                r.headers.push((k.clone(), agent.into()));
                r.headers.push((k, own.into()));
            } else {
                r.headers.push((k, v));
            }
        }
        both(
            "p35-beside-a-signature-agent-own-lines",
            "the same with a body, each signer's members on header lines of their own",
            r,
            "ok",
            true,
        );
    }
    {
        // The running copy signed first; the signature agent appended after it.
        let mut r = base("GET", "/orders", None);
        r.headers.insert(
            0,
            (
                "signature-agent".into(),
                format!("{AGENT_LABEL}=\"{AGENT_URI}\""),
            ),
        );
        let (i, sg) = agent_member(&r, &[], PRES_NOW, &op);
        let fi = format!("{}, {i}", pres_get(&r, "signature-input"));
        let fs = format!("{}, {sg}", pres_get(&r, "signature"));
        pres_set(&mut r, "signature-input", &fi);
        pres_set(&mut r, "signature", &fs);
        both(
            "p36-ainra-member-first",
            "AINRA's member first, the signature agent's after it",
            r,
            "ok",
            true,
        );
    }
    {
        // Each signature stands alone: one that fails its own verifier does not change the other's answer.
        let mut r = agent_signed("GET", "/orders", None, "r-0037");
        let s0 = pres_get(&r, "signature");
        let (agent, own) = s0.split_once(", ").unwrap();
        let flipped = {
            use base64ct::{Base64, Encoding};
            let inner = agent
                .strip_prefix("sig1=:")
                .unwrap()
                .strip_suffix(':')
                .unwrap();
            let mut raw = Base64::decode_vec(inner).unwrap();
            raw[0] ^= 1;
            format!("sig1=:{}:", Base64::encode_string(&raw))
        };
        pres_set(&mut r, "signature", &format!("{flipped}, {own}"));
        both(
            "p37-signature-agent-signature-broken",
            "the signature agent's signature is broken; AINRA's still holds, and each verifier says so of its own",
            r,
            "ok",
            false,
        );
    }
    {
        let mut r = agent_signed("GET", "/orders", None, "r-0038");
        let (i, _) = pres_get(&r, "signature-input")
            .split_once(", ")
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .unwrap();
        let (sg, _) = pres_get(&r, "signature")
            .split_once(", ")
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .unwrap();
        pres_set(&mut r, "signature-input", &i);
        pres_set(&mut r, "signature", &sg);
        both(
            "p38-signature-agent-only",
            "signed by the signature agent alone: unsigned as far as AINRA is concerned",
            r,
            "presentation_unsigned",
            true,
        );
    }
    {
        let mut r = agent_signed("GET", "/orders", None, "r-0039");
        let (sg, _) = pres_get(&r, "signature")
            .split_once(", ")
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .unwrap();
        pres_set(&mut r, "signature", &sg);
        add(
            "p39-ainra-input-without-ainra-signature",
            "signature-input names an ainra member; signature carries only the signature agent's",
            r,
            "presentation_unsigned",
        );
    }
    {
        let mut r = base("GET", "/orders", None);
        let i = pres_get(&r, "signature-input");
        pres_set(&mut r, "signature-input", &format!("{i}, {i}"));
        add(
            "p40-two-ainra-members",
            "two ainra members: which one is AINRA's is a guess, and a trust root does not guess",
            r,
            "presentation_sig_invalid",
        );
    }
    {
        let mut r = base("GET", "/orders", None);
        let i = pres_get(&r, "signature-input");
        pres_set(
            &mut r,
            "signature-input",
            &format!("other=(\"@authority\");note=\"open, {i}"),
        );
        add(
            "p41-unterminated-quote",
            "another member opens a quoted string that never closes",
            r,
            "presentation_sig_invalid",
        );
    }
    {
        let mut r = base("GET", "/orders", None);
        let i = pres_get(&r, "signature-input");
        pres_set(&mut r, "signature-input", &format!("{i},"));
        add(
            "p42-empty-member",
            "a trailing comma: an empty dictionary member",
            r,
            "presentation_sig_invalid",
        );
    }
    {
        let mut r = base("GET", "/orders", None);
        let (i, sg) = (pres_get(&r, "signature-input"), pres_get(&r, "signature"));
        pres_set(
            &mut r,
            "signature-input",
            &format!("other=(\"@authority\");note=\"a, ainra=(\\\"x\\\")\", {i}"),
        );
        pres_set(&mut r, "signature", &format!("other=:AAAA:, {sg}"));
        add(
            "p43-comma-inside-another-members-string",
            "a comma (and the text ainra=) inside another member's quoted string is not a member boundary",
            r,
            "ok",
        );
    }
    {
        // The signature agent signs LAST and covers AINRA's signature: its inputs, its value, and every component
        // AINRA's covered (the union the signature-agent profile requires of an outer signer).
        let mut r = base("GET", "/orders", None);
        r.headers.insert(
            0,
            (
                "signature-agent".into(),
                format!("{AGENT_LABEL}=\"{AGENT_URI}\""),
            ),
        );
        let ai = pres_get(&r, "signature-input");
        let asg = pres_get(&r, "signature");
        let more = vec![
            ("\"@method\"".to_string(), r.method.clone()),
            ("\"@path\"".to_string(), r.path.clone()),
            (
                format!("\"{PRESENTATION_HEADER}\""),
                pres_get(&r, PRESENTATION_HEADER),
            ),
            (
                "\"signature-input\";key=\"ainra\"".to_string(),
                ai.strip_prefix("ainra=").unwrap().to_string(),
            ),
            (
                "\"signature\";key=\"ainra\"".to_string(),
                asg.strip_prefix("ainra=").unwrap().to_string(),
            ),
        ];
        let (i, sg) = agent_member(&r, &more, PRES_NOW, &op);
        pres_set(&mut r, "signature-input", &format!("{ai}, {i}"));
        pres_set(&mut r, "signature", &format!("{asg}, {sg}"));
        both(
            "p44-signature-agent-covers-ainra",
            "the signature agent's outer signature covers AINRA's: evidence it was present, which AINRA neither needs nor reads",
            r,
            "ok",
            true,
        );
    }
    {
        let mut r = base("GET", "/orders", None);
        let (i, sg) = (pres_get(&r, "signature-input"), pres_get(&r, "signature"));
        pres_set(
            &mut r,
            "signature-input",
            &i.replacen("ainra=", "ainra2=", 1),
        );
        pres_set(&mut r, "signature", &sg.replacen("ainra=", "ainra2=", 1));
        add(
            "p45-label-ainra2",
            "the right signature under the label ainra2: the label is matched exactly, not by prefix",
            r,
            "presentation_unsigned",
        );
    }
    {
        let mut r = base("GET", "/orders", None);
        let (i, sg) = (pres_get(&r, "signature-input"), pres_get(&r, "signature"));
        pres_set(
            &mut r,
            "signature-input",
            &i.replacen("ainra=", "AINRA=", 1),
        );
        pres_set(&mut r, "signature", &sg.replacen("ainra=", "AINRA=", 1));
        add(
            "p46-label-uppercase",
            "dictionary keys are lowercase; AINRA= is not a key, so the field does not parse",
            r,
            "presentation_sig_invalid",
        );
    }
    cases.push(Case {
        name: "p24-replayed",
        what: "a correctly signed request whose nonce the cache has already seen",
        req: base("GET", "/orders", None),
        max_age: 300,
        seen: vec!["r-0001"],
        want: "presentation_replayed",
        other: None,
    });
    {
        let mut r = base("GET", "/orders", None);
        r.path = "/admin".into();
        cases.push(Case { name: "p31-replayed-but-moved", what: "a seen nonce on a moved request: the nonce is asked only after the signature holds",
        req: r, max_age: 300, seen: vec!["r-0001"], want: "presentation_sig_invalid", other: None });
    }
    cases.push(Case {
        name: "p32-verifier-policy-60s",
        what: "a verifier that accepts only 60 s refuses a 61 s-old signature",
        req: pres_sign(
            "GET",
            "/orders",
            None,
            &pres_ref,
            PRES_NOW - 61,
            "r-0032",
            PRES_IID,
            &key,
        ),
        max_age: 60,
        seen: vec![],
        want: "presentation_stale",
        other: None,
    });

    cases.extend(extra);
    cases.sort_by(|a, b| a.name.cmp(b.name));

    let mut out = Vec::new();
    for c in cases {
        let mut v = json!({
            "name": c.name,
            "description": c.what,
            "request": {
                "method": c.req.method, "authority": c.req.authority, "path": c.req.path,
                "headers": c.req.headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
                "body_b64u": c.req.body.as_ref().map(|b| b64::encode(b)),
            },
            "instance": { "iid": PRES_IID, "ikey": { "ed25519": b64::encode(&pk.ed25519), "mldsa65": b64::encode(&pk.mldsa65) } },
            "now": PRES_NOW,
            "max_age_secs": c.max_age,
            "seen_nonces": c.seen,
        });
        if let Some(valid) = c.other {
            v["other_signer"] = json!({
                "label": AGENT_LABEL, "signature_agent": AGENT_URI, "jwk": agent_jwk(&op).0, "valid": valid,
                "note": "the signature agent's own signature (Web Bot Auth profile); AINRA does not read it — `make signature-agent-check` has an independent implementation verify it",
            });
        }
        let got = presentation_result(&v);
        let ok = if c.want == "ok" {
            got["ok"] == json!(true)
        } else {
            got["reason"] == json!(c.want)
        };
        if !ok {
            eprintln!(
                "PRESENTATION VECTOR {} exists to test `{}` but the core says {got}",
                c.name, c.want
            );
            std::process::exit(1);
        }
        v["expect"] = got;
        out.push(v);
    }
    out
}

fn emit_presentation(dir: &str) {
    let vectors = presentation_vectors();
    std::fs::create_dir_all(dir).expect("create dir");
    for v in &vectors {
        std::fs::write(
            Path::new(dir).join(format!("{}.json", v["name"].as_str().unwrap())),
            serde_json::to_string_pretty(v).unwrap(),
        )
        .expect("write presentation vector");
    }
    let accept = vectors
        .iter()
        .filter(|v| v["expect"]["ok"] == json!(true))
        .count();
    let manifest = json!({
        "version": "v1-presentation",
        "count": vectors.len(),
        "accept": accept,
        "reject": vectors.len() - accept,
        "note": "CC0 presentation conformance vectors: RFC 9421 request signatures by a running copy's instance key (D-062). Real hybrid signing; expect computed by ainra-core::presentation::verify_presentation, each checked against the case it exists to test. Vectors with `other_signer` also carry a signature agent's signature (D-070), which AINRA does not read; `make signature-agent-check` has an independent implementation verify it. Regenerate with `make vectors`.",
    });
    std::fs::write(
        Path::new(dir).join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .expect("write manifest");
    println!(
        "wrote {} presentation vectors ({accept} accept) to {dir}",
        vectors.len()
    );
}

fn check_presentation(dir: &str) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .expect("read dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|x| x == "json")
                && p.file_name().is_some_and(|f| f != "manifest.json")
        })
        .collect();
    entries.sort();
    let (mut total, mut fails) = (0, 0);
    for path in entries {
        let v: Value = serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse");
        let got = presentation_result(&v);
        total += 1;
        if got != v["expect"] {
            eprintln!(
                "PRESENTATION CHECK MISMATCH {}: expected {} got {got}",
                v["name"], v["expect"]
            );
            fails += 1;
        }
    }
    if fails > 0 {
        eprintln!("{fails}/{total} presentation vectors mismatched");
        std::process::exit(1);
    }
    println!("checked {total} presentation vectors: all reproduce their recorded expectation");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut out_dir: Option<String> = None;
    let mut delta_out: Option<String> = None;
    let mut directory_out: Option<String> = None;
    let mut check_dir: Option<String> = None;
    let mut check_delta_dir: Option<String> = None;
    let mut check_directory_dir: Option<String> = None;
    let mut presentation_out: Option<String> = None;
    let mut check_presentation_dir: Option<String> = None;
    let mut canon_file: Option<String> = None;
    let mut emit_kind: Option<String> = None;
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
            "--presentation-out" => presentation_out = it.next().cloned(),
            "--check-presentation" => check_presentation_dir = it.next().cloned(),
            "--canon" => canon_file = it.next().cloned(),
            "--emit" => emit_kind = it.next().cloned(),
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
    if let Some(kind) = emit_kind {
        emit_stdin(&kind);
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
    if let Some(dir) = presentation_out {
        emit_presentation(&dir);
        return;
    }
    if let Some(dir) = check_presentation_dir {
        check_presentation(&dir);
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
