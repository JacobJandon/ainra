// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `witness-quorum-drill` — the NETWORKED fork drill (D-021 transport, closing the quorum to "deployable"). A
//! relying party talks over HTTP to N SEPARATELY-OPERATED `witnessd` processes: it submits the honest log's
//! checkpoints, collects each witness's cosignature over the wire, and assembles a `QuorumCertificate`. The
//! threshold **k is the relying party's own argument** — never read from anything fetched (the certificate carries
//! no threshold to lower). An injected fork is refused by every honest witness, so it cannot reach quorum. Boring
//! transport: fetch + verify, no gossip.
//!
//! Usage: `witness-quorum-drill <k> <witness-addr>...`  (e.g. `... 3 127.0.0.1:4891 127.0.0.1:4892 127.0.0.1:4893`)

use std::collections::BTreeSet;

use ainra_core::checkpoint::Checkpoint;
use ainra_core::{b64, crypto, merkle};
use ainra_services::http::{http_get, http_post};
use ainra_services::witness::QuorumCertificate;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const NOW: u64 = 1_775_865_600;
const ORIGIN: &str = "ainra-log/registrar-07";

fn witness_key(addr: &str) -> [u8; 32] {
    let body = http_get(addr, "/key").expect("GET /key");
    let v: serde_json::Value = serde_json::from_str(&body).expect("key json");
    b64::decode_array::<32>(v["ed25519"].as_str().expect("ed25519 field")).expect("32-byte key")
}

/// Submit one checkpoint to one witness over HTTP; return `(outcome, cosignature?)`.
fn submit(
    addr: &str,
    cp: &Checkpoint,
    sig_b64: &str,
    log_root_b64: &str,
    proof: &[[u8; 32]],
) -> (String, Option<Vec<u8>>) {
    let body = serde_json::json!({
        "origin": cp.origin, "size": cp.tree_size, "root_b64": b64::encode(&cp.root),
        "log_root_key_b64": log_root_b64, "checkpoint_sig_b64": sig_b64, "now": NOW,
        "consistency_proof_b64": proof.iter().map(|h| b64::encode(h)).collect::<Vec<_>>(),
    })
    .to_string();
    let resp = http_post(addr, "/consider", &body).expect("POST /consider");
    let v: serde_json::Value = serde_json::from_str(&resp).expect("consider json");
    let cosig = v["cosignature"].as_str().and_then(|s| b64::decode(s).ok());
    (v["outcome"].as_str().unwrap_or("").to_string(), cosig)
}

/// Submit to every witness; assemble the certificate from the cosignatures returned. Also returns the outcomes.
fn collect(
    witnesses: &[(String, [u8; 32])],
    cp: &Checkpoint,
    sig_b64: &str,
    log_root_b64: &str,
    proof: &[[u8; 32]],
) -> (QuorumCertificate, Vec<String>) {
    let mut cosigners = Vec::new();
    let mut outcomes = Vec::new();
    for (addr, key) in witnesses {
        let (outcome, cosig) = submit(addr, cp, sig_b64, log_root_b64, proof);
        if let Some(c) = cosig {
            cosigners.push((*key, c));
        }
        outcomes.push(outcome);
    }
    (
        QuorumCertificate {
            origin: cp.origin.clone(),
            tree_size: cp.tree_size,
            root: cp.root,
            cosigners,
        },
        outcomes,
    )
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let k: usize = args
        .first()
        .and_then(|s| s.parse().ok())
        .expect("usage: <k> <addr>...");
    let addrs: Vec<String> = args[1..].to_vec();
    assert!(
        addrs.len() >= 3,
        "the networked quorum needs >= 3 witnesses"
    );

    let mut rng = ChaCha20Rng::seed_from_u64(0x0D71_11ED);
    let root = crypto::TestRootSlh::generate(&mut rng);
    let log_root_b64 = b64::encode(&root.public());

    // The relying party fetches each witness's public key → its roster; k is ITS OWN choice, not fetched.
    let witnesses: Vec<(String, [u8; 32])> =
        addrs.iter().map(|a| (a.clone(), witness_key(a))).collect();
    let roster: BTreeSet<[u8; 32]> = witnesses.iter().map(|(_, k)| *k).collect();
    assert_eq!(
        roster.len(),
        witnesses.len(),
        "witnesses must have DISTINCT keys (independent operators)"
    );
    println!(
        "networked quorum: {} witnesses on separate ports, DISTINCT keys ✓ · threshold k={} (the relying party's)",
        witnesses.len(), k
    );

    // Honest log → C1 (first sight): every witness cosigns over the wire.
    let mut log = merkle::TestLog::new();
    for i in 0..6 {
        log.append(format!("e{i}").as_bytes());
    }
    let cp1 = Checkpoint {
        origin: ORIGIN.into(),
        tree_size: log.size(),
        root: log.root(),
    };
    let sig1 = b64::encode(&cp1.sign_test_root(&root).unwrap());
    let (cert1, _) = collect(&witnesses, &cp1, &sig1, &log_root_b64, &[]);
    println!(
        "  honest C1 → {} cosigns fetched → certified={}",
        cert1.valid_cosigns(&cp1, &roster),
        cert1.certified(&cp1, &roster, k)
    );

    // Honest growth C1 → C2 with a real consistency proof.
    for i in 6..11 {
        log.append(format!("e{i}").as_bytes());
    }
    let cp2 = Checkpoint {
        origin: ORIGIN.into(),
        tree_size: log.size(),
        root: log.root(),
    };
    let sig2 = b64::encode(&cp2.sign_test_root(&root).unwrap());
    let proof = log.consistency_proof(cp1.tree_size).unwrap();
    let (cert2, _) = collect(&witnesses, &cp2, &sig2, &log_root_b64, &proof);
    println!(
        "  honest C1→C2 → {} cosigns fetched → certified={}",
        cert2.valid_cosigns(&cp2, &roster),
        cert2.certified(&cp2, &roster, k)
    );

    // THE FORK: an equivocating log signs a divergent history at C2's size (valid log signature, different root).
    let mut evil = merkle::TestLog::new();
    for i in 0..cp2.tree_size {
        let s = if i == 2 {
            "REWRITTEN".to_string()
        } else {
            format!("e{i}")
        };
        evil.append(s.as_bytes());
    }
    let forked = Checkpoint {
        origin: ORIGIN.into(),
        tree_size: cp2.tree_size,
        root: evil.root(),
    };
    assert_ne!(forked.root, cp2.root);
    let sig_forked = b64::encode(&forked.sign_test_root(&root).unwrap());
    let bogus = evil.consistency_proof(cp1.tree_size).unwrap();
    let (fork_cert, fork_outcomes) =
        collect(&witnesses, &forked, &sig_forked, &log_root_b64, &bogus);
    let refused = fork_outcomes
        .iter()
        .filter(|o| o.as_str() == "refused_fork")
        .count();
    println!(
        "  INJECTED FORK → {refused}/{} witnesses refuse over the wire → {} cosigns → certified={}",
        witnesses.len(),
        fork_cert.valid_cosigns(&forked, &roster),
        fork_cert.certified(&forked, &roster, k)
    );

    assert!(
        cert1.certified(&cp1, &roster, k) && cert2.certified(&cp2, &roster, k),
        "honest heads must certify"
    );
    assert!(
        !fork_cert.certified(&forked, &roster, k),
        "a fork reached quorum over the network — BROKEN"
    );
    // Regression (M6/D-021 fix, preserved over the transport): k is the relying party's. The certificate carries no
    // threshold to lower, and `certified` refuses a nonsensical k=0 — so no fetched artifact can self-certify a fork.
    assert!(
        !fork_cert.certified(&forked, &roster, 0),
        "k=0 must never certify (no self-certification)"
    );

    println!("  ✔ the fork cannot gather a quorum over the network; k stayed the relying party's, not the wire's.");
    println!("networked-drill OK");
}
