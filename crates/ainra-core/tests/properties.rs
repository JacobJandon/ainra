// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Property tests P-1..P-5 (MTS §28). Pure-logic properties run thousands of cases; the crypto property (P-1) is
//! bounded because SLH-DSA signing is deliberately expensive. All use only the public API.

use ainra_core::verdict::{Reason, Verdict};
use ainra_core::{b64, canon, chain, checkpoint, crypto, mandate, merkle, status, verify};
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{json, Value};

// ── P-1: verify ∘ sign = VALID ─────────────────────────────────────────────────────────────────────────────────
// Build a genuinely-signed credential for the given parameters and assert it verifies VALID. Bounded (SLH signing
// is seconds/op in debug); the 180 `valid-*` conformance vectors exercise this far more broadly.
struct ValidCred {
    claims: Vec<u8>,
    issuer_sig: crypto::HybridSig,
    anchors: verify::TrustAnchors,
    checkpoint: checkpoint::Checkpoint,
    checkpoint_sig: Vec<u8>,
    leaf_index: u64,
    proof: Vec<[u8; 32]>,
}

fn build_valid(seed: u64, nbf: u64, exp: u64, caps: &[&str]) -> ValidCred {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let issuer = crypto::HybridKeypair::generate(&mut rng);
    let root = crypto::TestRootSlh::generate(&mut rng);
    let caps_json: Vec<Value> = caps.iter().map(|c| json!(c)).collect();
    let body = json!({
        "vct": ainra_core::PASSPORT_VCT,
        "iss": "did:ainra:registrar-01:acme:invoicing",
        "sub": "ainra:registrar-01:acme:invoicing@1.0.0",
        "nbf": nbf, "exp": exp,
        "authority": { "class": "A2", "principal_proof": "deadbeef" },
        "tier": "L1",
        "capabilities": caps_json.clone(),
        "scope_ceiling": caps_json,
        "keys": [ { "ed25519": "AAAA", "mldsa65": "BBBB" } ],
        "cnf": { "jkt": "thumb" },
        "status": { "status_list": { "idx": 0u64, "uri": "status://registrar-01/1" } }
    });
    let body_bytes = canon::canonicalize(&body).unwrap().into_bytes();
    let leaf = merkle::hash_leaf(&body_bytes);
    let mut log = merkle::TestLog::new();
    for k in 0..3u8 {
        log.append(&[k]);
    }
    let leaf_index = log.append(&body_bytes);
    let cp = checkpoint::Checkpoint {
        origin: "ainra-log/registrar-01".into(),
        tree_size: log.size(),
        root: log.root(),
    };
    let cp_sig = cp.sign_test_root(&root).unwrap();
    let proof = log.inclusion_proof(leaf_index).unwrap();
    let mut full = body;
    full["log"] =
        json!({ "leaf": b64::encode(&leaf), "root": b64::encode(&cp.root), "checkpoint": "cp-1" });
    let claims = canon::canonicalize(&full).unwrap().into_bytes();
    let issuer_sig = issuer.sign(&claims).unwrap();
    let mut registrars = std::collections::BTreeMap::new();
    registrars.insert(
        "registrar-01".to_string(),
        verify::RegistrarInfo {
            issuer_key: issuer.public(),
            log_root_key: root.public(),
        },
    );
    ValidCred {
        claims,
        issuer_sig,
        anchors: verify::TrustAnchors { registrars },
        checkpoint: cp,
        checkpoint_sig: cp_sig,
        leaf_index,
        proof,
    }
}

#[test]
fn p1_sign_then_verify_is_valid() {
    let cases: &[(u64, u64, u64, &[&str])] = &[
        (1, 1_000, 2_000, &["read:x"]),
        (2, 500, 5_000, &["read:x", "sign:y"]),
        (3, 0, 100, &["a", "b", "c"]),
        (4, 42, 43, &["only"]),
        (
            5,
            10_000,
            20_000,
            &["read:invoices", "sign:invoice", "pay:invoice"],
        ),
        (6, 1, 2, &["x"]),
    ];
    for &(seed, nbf, exp, caps) in cases {
        let c = build_valid(seed, nbf, exp, caps);
        let now = nbf + (exp - nbf) / 2;
        let pres = verify::Presentation {
            claims: &c.claims,
            issuer_sig: c.issuer_sig.clone(),
            now,
            chain_keys: Vec::new(),
            hop_proofs: Vec::new(),
            status_list: status::StatusList::from_bits(vec![false; 4]),
            status_issued_at: now,
            freshness: status::Freshness::F2,
            checkpoint: c.checkpoint.clone(),
            checkpoint_sig: checkpoint::CheckpointSig::Root {
                slh: c.checkpoint_sig.clone(),
            },
            leaf_index: c.leaf_index,
            inclusion_proof: c.proof.clone(),
            mandate_path: Vec::new(),
            mandate_proofs: Vec::new(),
            mandate_revocations: mandate::RevocationSet::default(),
            revoked_delegates: Default::default(),
        };
        assert_eq!(
            verify::verify(&pres, &c.anchors),
            Verdict::Valid,
            "seed {seed} must verify VALID"
        );
    }
}

// A signature-less ActLink for testing `narrow`, which only reads `granted`/`exp`.
fn bare_link(granted: Vec<String>, exp: u64) -> ainra_core::passport::ActLink {
    ainra_core::passport::ActLink {
        from: "a".into(),
        to: "b".into(),
        granted,
        exp,
        sig_ed25519: String::new(),
        sig_mldsa65: String::new(),
        sig_child_ed25519: String::new(),
        sig_child_mldsa65: String::new(),
        log_leaf: String::new(),
    }
}

// ── P-2: a delegation chain never widens scope or extends expiry ────────────────────────────────────────────────
proptest! {
    #![proptest_config(ProptestConfig::with_cases(20_000))]

    #[test]
    fn p2_narrow_never_widens(
        // a strictly non-widening chain: each hop's granted ⊆ previous, exp ≤ previous
        root_caps in prop::collection::vec("[a-z]{1,4}", 1..6),
        shrink_seq in prop::collection::vec((0usize..6, 0u64..1000), 0..5),
        root_exp in 0u64..2000,
    ) {
        // build hops that only ever shrink caps (take a prefix) and never extend expiry
        let mut caps = root_caps.clone();
        let mut exp = root_exp;
        let mut hops = Vec::new();
        for (take, dec) in shrink_seq {
            let n = if caps.is_empty() { 0 } else { take % (caps.len() + 1) };
            caps = caps[..n].to_vec();
            exp = exp.saturating_sub(dec);
            hops.push(bare_link(caps.clone(), exp)); // narrow() ignores sig fields; leave them empty
        }
        let res = chain::narrow(&root_caps, root_exp, &hops);
        // a monotonically-narrowing chain must always be accepted, and the effective set must be ⊆ the root set
        let eff = res.expect("monotone chain must narrow");
        prop_assert!(eff.capabilities.iter().all(|c| root_caps.contains(c)));
        prop_assert!(eff.exp <= root_exp);
    }

    #[test]
    fn p2_widening_always_rejected(root_caps in prop::collection::vec("[a-z]{1,3}", 1..4), extra in "[A-Z]{1,3}") {
        // a hop that grants a capability the root never held must be rejected
        let mut granted = root_caps.clone();
        granted.push(extra); // `extra` is uppercase, disjoint from root_caps (lowercase)
        let hop = bare_link(granted, 0);
        prop_assert_eq!(chain::narrow(&root_caps, 1000, std::slice::from_ref(&hop)), Err(Reason::ChainWidening));
    }
}

// ── P-3: a revoked ancestor invalidates the whole mandate subtree ───────────────────────────────────────────────
proptest! {
    #![proptest_config(ProptestConfig::with_cases(20_000))]

    #[test]
    fn p3_revoked_ancestor_kills_subtree(depth in 1usize..8, revoke_at in 0usize..8) {
        // a linear mandate path m0 <- m1 <- ... ; revoking ANY node on the path must yield MandateRevoked
        let path: Vec<mandate::MandateNode> = (0..depth).map(|i| mandate::MandateNode {
            id: format!("m{i}"),
            parent: if i == 0 { None } else { Some(format!("m{}", i - 1)) },
        }).collect();
        let idx = revoke_at % depth;
        let rev = mandate::RevocationSet::from_ids([format!("m{idx}")]);
        prop_assert_eq!(mandate::check_path(&path, &rev), Err(Reason::MandateRevoked));
        // revoking a node NOT on the path leaves it valid
        let rev2 = mandate::RevocationSet::from_ids(["not-on-path".to_string()]);
        prop_assert_eq!(mandate::check_path(&path, &rev2), Ok(()));
    }
}

// ── P-4: TSL round-trip is bit-exact ────────────────────────────────────────────────────────────────────────────
proptest! {
    #![proptest_config(ProptestConfig::with_cases(5_000))]

    #[test]
    fn p4_tsl_roundtrip_bit_exact(bits in prop::collection::vec(any::<bool>(), 0..2048)) {
        let list = status::StatusList::from_bits(bits.clone());
        let back = status::StatusList::decode(&list.encode().unwrap(), bits.len()).unwrap();
        prop_assert_eq!(list, back);
        // and every index resolves to the original bit (set = revoked)
        let re = status::StatusList::from_bits(bits.clone());
        for (i, &b) in bits.iter().enumerate() {
            let want = if b { status::LineageStatus::Revoked } else { status::LineageStatus::Valid };
            prop_assert_eq!(re.status_of(i as u64), want);
        }
    }
}

// ── P-5: canonical encoding is total, deterministic, and idempotent ─────────────────────────────────────────────
fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-100000i64..100000).prop_map(|n| json!(n)),
        "[ -~]{0,12}".prop_map(Value::String), // printable ASCII string values
    ];
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
            prop::collection::hash_map("[a-z]{1,6}", inner, 0..5)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

// ── Fuzz-equivalent robustness: the parsers must never panic on arbitrary input (runs in `make test`, no nightly).
// The deeper cargo-fuzz soak lives in `fuzz/` (MTS §28); these give the same "no crash/UB" guarantee everywhere.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(8_000))]

    #[test]
    fn fuzz_passport_parse_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = ainra_core::passport::Passport::parse_checked(&bytes); // Result, never a panic
    }
    #[test]
    fn fuzz_status_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512), len in 0usize..4096) {
        let _ = status::StatusList::decode(&bytes, len);
    }
    // Exercise the DoS bounds (M5/D-020 + M6): a declared length across and ABOVE the MAX_STATUS_BITS cap must be
    // rejected without allocating, and a real zlib stream that would inflate past the declared need must be caught
    // (bomb bound) — never a panic, never an OOM. `len` spans below, at, and above 2^24.
    #[test]
    fn fuzz_status_decode_bounded_at_huge_lengths(
        seed in prop::collection::vec(any::<u8>(), 0..64),
        len in 0usize..((1usize << 25) + 3),
    ) {
        // arbitrary bytes (rarely valid zlib → Err) at a possibly-enormous declared length
        let _ = status::StatusList::decode(&seed, len);
        // a REAL small zlib stream declared at a huge length: must be Err (short/over-cap), never OOM
        let small = status::StatusList::from_bits(vec![false; 8]).encode().unwrap();
        prop_assert!(status::StatusList::decode(&small, len).is_err() || len <= 8);
    }
    #[test]
    fn fuzz_name_parse_never_panics(s in ".*") {
        let _ = ainra_core::AinraName::parse(&s);
        let _ = ainra_core::AinraName::parse_did(&s);
    }
    #[test]
    fn fuzz_canon_arbitrary_json_never_panics(s in ".{0,256}") {
        if let Ok(v) = serde_json::from_str::<Value>(&s) {
            let _ = canon::canonicalize_value(&v);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn p5_canon_total_and_idempotent(v in arb_json()) {
        // canonicalization of an ASCII-key, integer, no-float value never fails,
        let s1 = canon::canonicalize_value(&v).expect("canon must accept ASCII/int JSON");
        // is deterministic,
        let s2 = canon::canonicalize_value(&v).unwrap();
        prop_assert_eq!(&s1, &s2);
        // and is idempotent: re-parsing the canonical bytes and canonicalizing again yields identical bytes.
        let reparsed: Value = serde_json::from_str(&s1).unwrap();
        let s3 = canon::canonicalize_value(&reparsed).unwrap();
        prop_assert_eq!(&s1, &s3);
    }
}
