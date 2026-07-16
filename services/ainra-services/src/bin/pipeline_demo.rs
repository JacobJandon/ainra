// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `pipeline-demo` — runs the whole M2 transparency pipeline end to end, in-process, printing a narrative. Nothing
//! is faked: real hybrid + SLH-DSA keys, a real fsync'd append-only log, real RFC 6962 inclusion + consistency
//! proofs, a real ADR-002 delegate-signed checkpoint, a real witness that cosigns honest growth and CATCHES an
//! injected fork. This is the "watch it work" artifact; the same behavior is asserted in `tests/fork_drill.rs`.

use ainra_core::{crypto, merkle};
use ainra_services::log::Logd;
use ainra_services::status::{self, Statusd};
use ainra_services::witness::{Witness, WitnessOutcome, WitnessQuorum};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn main() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xD311_0000_u64);
    let root = crypto::TestRootSlh::generate(&mut rng);
    let delegate = crypto::TestDelegate::generate(&mut rng);
    let now = 1_775_865_600u64;

    let dir = std::env::temp_dir().join(format!("ainra-pipeline-demo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut log = Logd::open(&dir, "ainra-log/registrar-07", &root, delegate, now, 86_400).unwrap();

    println!("== logd ==");
    for i in 0..5 {
        let idx = log
            .append(format!("credential-body-{i}").as_bytes())
            .unwrap();
        println!("  appended entry {i} at leaf #{idx} (fsync'd)");
    }
    let cp1 = log.signed_checkpoint();
    let _sc1 = log.sign_checkpoint(&cp1); // delegate-signed (ADR-002) — the artifact a real verifier would consume
    println!(
        "  checkpoint C1: size={} (delegate-signed, ADR-002)",
        cp1.tree_size
    );
    // prove one inclusion
    let leaf2 = merkle::hash_leaf(b"credential-body-2");
    let proof = log.inclusion_proof(2).unwrap();
    let included = merkle::verify_inclusion(&leaf2, 2, cp1.tree_size, &proof, &cp1.root);
    println!("  inclusion of leaf #2 under C1 verifies: {included}");
    assert!(included);

    println!("\n== witnessd ==");
    let mut witness = Witness::new(crypto::TestDelegate::generate(&mut rng));
    witness.register_log(&cp1.origin, log.root_public().to_vec()); // the witness knows the log's root key
    let o1 = witness.consider(&cp1, &log.sign_checkpoint(&cp1).sig, now, &[]);
    println!("  first sight of C1 (log-signed) → {o1:?}");
    assert_eq!(o1, WitnessOutcome::CosignedFirstSight);

    // honest growth: append more, checkpoint C2, prove C1→C2 consistency
    for i in 5..9 {
        log.append(format!("credential-body-{i}").as_bytes())
            .unwrap();
    }
    let cp2 = log.signed_checkpoint();
    let cproof = log.consistency_proof(cp1.tree_size).unwrap();
    let o2 = witness.consider(&cp2, &log.sign_checkpoint(&cp2).sig, now, &cproof);
    println!(
        "  honest growth C1→C2 (size {}→{}) → {o2:?}",
        cp1.tree_size, cp2.tree_size
    );
    assert_eq!(o2, WitnessOutcome::Cosigned);
    let _ = witness.cosign(&cp2);

    // THE FORK: an EQUIVOCATING log signs a second, divergent history at C2's size (a valid log signature over a
    // different root). The signature check passes; the consistency proof cannot — so the witness catches it.
    let mut evil = merkle::TestLog::new();
    for i in 0..cp2.tree_size {
        let s = if i == 1 {
            "TAMPERED".to_string()
        } else {
            format!("credential-body-{i}")
        };
        evil.append(s.as_bytes());
    }
    let forked_cp = ainra_core::checkpoint::Checkpoint {
        origin: cp2.origin.clone(),
        tree_size: cp2.tree_size,
        root: evil.root(),
    };
    let bogus_proof = evil.consistency_proof(cp1.tree_size).unwrap();
    let o3 = witness.consider(
        &forked_cp,
        &log.sign_checkpoint(&forked_cp).sig,
        now,
        &bogus_proof,
    );
    println!(
        "  INJECTED FORK at size {} (log-signed, root differs) → {o3:?}",
        forked_cp.tree_size
    );
    assert_eq!(o3, WitnessOutcome::RefusedFork);
    println!("  ✔ the witness caught the fork — not us.");

    println!("\n== witness quorum (k-of-N — the catch is THEIRS, not one operator's) ==");
    // Five INDEPENDENTLY-keyed witnesses, threshold 3. A checkpoint is certified only when ≥3 distinct witnesses
    // cosign it, verifiable by anyone holding the roster. An equivocating fork is refused by every honest witness
    // that already cosigned the head, so it cannot gather a quorum unless ≥3 witnesses are adversarial.
    let mut quorum = WitnessQuorum::new(
        (0..5)
            .map(|_| Witness::new(crypto::TestDelegate::generate(&mut rng)))
            .collect(),
        3,
    );
    let roster = quorum.roster();
    let k = quorum.threshold(); // the RELYING PARTY's required threshold — it decides k, never the certificate
    quorum.register_log(&cp1.origin, log.root_public().to_vec());
    let (qc1, _) = quorum.certify(&cp1, &log.sign_checkpoint(&cp1).sig, now, &[]);
    println!(
        "  5 witnesses, threshold 3 · honest C1 → {} cosigns → certified={}",
        qc1.valid_cosigns(&cp1, &roster),
        qc1.certified(&cp1, &roster, k)
    );
    let (qc2, _) = quorum.certify(&cp2, &log.sign_checkpoint(&cp2).sig, now, &cproof);
    println!(
        "  honest C1→C2 → {} cosigns → certified={}",
        qc2.valid_cosigns(&cp2, &roster),
        qc2.certified(&cp2, &roster, k)
    );
    let (qfork, ofork) = quorum.certify(
        &forked_cp,
        &log.sign_checkpoint(&forked_cp).sig,
        now,
        &bogus_proof,
    );
    let refused = ofork
        .iter()
        .filter(|o| matches!(o, WitnessOutcome::RefusedFork))
        .count();
    println!(
        "  INJECTED FORK → {refused}/5 witnesses refuse → {} cosigns → certified={}",
        qfork.valid_cosigns(&forked_cp, &roster),
        qfork.certified(&forked_cp, &roster, k)
    );
    assert!(qc1.certified(&cp1, &roster, k) && qc2.certified(&cp2, &roster, k));
    assert!(!qfork.certified(&forked_cp, &roster, k));
    println!("  ✔ the fork cannot gather a quorum — a ≥3-of-5 witness set caught it, not us.");

    println!("\n== statusd ==");
    let mut sd = Statusd::new(
        "status://registrar-07/1",
        16,
        crypto::HybridKeypair::generate(&mut rng),
    );
    let pubkey = sd.public();
    sd.revoke(2);
    let published = sd.publish(now);
    let s_ok = status::verify_publication(
        &pubkey,
        &published,
        now + 10,
        ainra_core::status::Freshness::F2,
        0,
    );
    let s_rev = status::verify_publication(
        &pubkey,
        &published,
        now + 10,
        ainra_core::status::Freshness::F2,
        2,
    );
    let s_stale = status::verify_publication(
        &pubkey,
        &published,
        now + 100_000,
        ainra_core::status::Freshness::F2,
        0,
    );
    println!("  idx 0 (fresh) → {s_ok:?}");
    println!("  idx 2 (fresh, revoked) → {s_rev:?}");
    println!("  idx 0 (day-old vs F2) → {s_stale:?} (Err = fail closed)");
    assert!(matches!(s_ok, Ok(ainra_core::status::LineageStatus::Valid)));
    assert!(matches!(
        s_rev,
        Ok(ainra_core::status::LineageStatus::Revoked)
    ));
    assert!(s_stale.is_err());

    let _ = std::fs::remove_dir_all(&dir);
    println!("\npipeline OK — logd + witnessd + statusd, all real, all over ainra-core.");
}
