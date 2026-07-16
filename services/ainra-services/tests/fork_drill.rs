// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The M2 fork drill (MTS §28 fault-injection / §29 DoD "injected fork caught by them, not by us"), asserted.
//! An honest log grows and the witness cosigns; an equivocating fork is presented and the witness REFUSES.

use std::collections::BTreeSet;

use ainra_core::{crypto, merkle};
use ainra_services::log::Logd;
use ainra_services::status::{verify_publication, Statusd};
use ainra_services::witness::{QuorumCertificate, Witness, WitnessOutcome, WitnessQuorum};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("ainra-drill-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[test]
fn honest_growth_cosigned_fork_refused() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xF0_4E_D8_11);
    let root = crypto::TestRootSlh::generate(&mut rng);
    let delegate = crypto::TestDelegate::generate(&mut rng);
    let now = 1_775_865_600u64;

    let dir = tmpdir("log");
    let mut log = Logd::open(&dir, "ainra-log/registrar-07", &root, delegate, now, 86_400).unwrap();
    for i in 0..6 {
        log.append(format!("entry-{i}").as_bytes()).unwrap();
    }
    let cp1 = log.signed_checkpoint();

    let mut witness = Witness::new(crypto::TestDelegate::generate(&mut rng));
    witness.register_log(&cp1.origin, log.root_public().to_vec());
    let sig_cp1 = log.sign_checkpoint(&cp1).sig;
    assert_eq!(
        witness.consider(&cp1, &sig_cp1, now, &[]),
        WitnessOutcome::CosignedFirstSight
    );

    // an UNSIGNED checkpoint (signed by a stranger root, not this log) is refused before anything else (#11)
    let mut stranger_rng = ChaCha20Rng::seed_from_u64(0xBAD_5157);
    let stranger = crypto::TestRootSlh::generate(&mut stranger_rng);
    let stranger_sig = ainra_core::checkpoint::CheckpointSig::Root {
        slh: cp1.sign_test_root(&stranger).unwrap(),
    };
    assert_eq!(
        witness.consider(&cp1, &stranger_sig, now, &[]),
        WitnessOutcome::RefusedUnsigned
    );

    // honest growth → cosigned with a real consistency proof
    for i in 6..11 {
        log.append(format!("entry-{i}").as_bytes()).unwrap();
    }
    let cp2 = log.signed_checkpoint();
    let sig_cp2 = log.sign_checkpoint(&cp2).sig;
    let proof = log.consistency_proof(cp1.tree_size).unwrap();
    assert_eq!(
        witness.consider(&cp2, &sig_cp2, now, &proof),
        WitnessOutcome::Cosigned
    );

    // a stale re-presentation of the SAME checkpoint is fine (idempotent)
    assert_eq!(
        witness.consider(&cp2, &sig_cp2, now, &[]),
        WitnessOutcome::Cosigned
    );

    // regression (older size) is refused
    assert_eq!(
        witness.consider(&cp1, &sig_cp1, now, &[]),
        WitnessOutcome::RefusedRegression
    );

    // THE FORK: an equivocating LOG signs a divergent history at cp2's size → valid sig, different root, bogus proof
    let mut evil = merkle::TestLog::new();
    for i in 0..cp2.tree_size {
        let e = if i == 2 {
            "REWRITTEN".to_string()
        } else {
            format!("entry-{i}")
        };
        evil.append(e.as_bytes());
    }
    let forked = ainra_core::checkpoint::Checkpoint {
        origin: cp2.origin.clone(),
        tree_size: cp2.tree_size,
        root: evil.root(),
    };
    assert_ne!(forked.root, cp2.root);
    let bogus = evil.consistency_proof(cp1.tree_size).unwrap();
    let sig_forked = log.sign_checkpoint(&forked).sig;
    assert_eq!(
        witness.consider(&forked, &sig_forked, now, &bogus),
        WitnessOutcome::RefusedFork
    );

    // even an HONEST-LOOKING larger fork (grown from the tampered prefix) can't fake consistency to the real cp1
    let mut evil2 = evil;
    for i in cp2.tree_size..cp2.tree_size + 3 {
        evil2.append(format!("entry-{i}").as_bytes());
    }
    let forked2 = ainra_core::checkpoint::Checkpoint {
        origin: cp2.origin.clone(),
        tree_size: evil2.size(),
        root: evil2.root(),
    };
    let bogus2 = evil2.consistency_proof(cp1.tree_size).unwrap();
    let sig_forked2 = log.sign_checkpoint(&forked2).sig;
    assert_eq!(
        witness.consider(&forked2, &sig_forked2, now, &bogus2),
        WitnessOutcome::RefusedFork
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// M6: a ≥3-of-N witness QUORUM certifies honest growth, and an equivocating fork cannot reach quorum — every
/// honest witness that already cosigned the head refuses the fork, so it gathers zero cosignatures. The catch is
/// the quorum's, verifiable against its public roster; we assert nothing.
#[test]
fn quorum_certifies_honest_head_but_a_fork_cannot_reach_quorum() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x9110_2117);
    let root = crypto::TestRootSlh::generate(&mut rng);
    let delegate = crypto::TestDelegate::generate(&mut rng);
    let now = 1_775_865_600u64;

    let dir = tmpdir("quorum");
    let mut log = Logd::open(&dir, "ainra-log/registrar-07", &root, delegate, now, 86_400).unwrap();
    for i in 0..6 {
        log.append(format!("e{i}").as_bytes()).unwrap();
    }
    let cp1 = log.signed_checkpoint();
    let sig1 = log.sign_checkpoint(&cp1).sig;

    // N = 5 independently-keyed witnesses, threshold k = 3.
    let witnesses: Vec<Witness> = (0..5)
        .map(|_| Witness::new(crypto::TestDelegate::generate(&mut rng)))
        .collect();
    let mut quorum = WitnessQuorum::new(witnesses, 3);
    let roster = quorum.roster();
    let k = quorum.threshold(); // the relying party's own required threshold
    quorum.register_log(&cp1.origin, log.root_public().to_vec());

    // honest first sight → all 5 cosign → certified (5 ≥ 3)
    let (c1, o1) = quorum.certify(&cp1, &sig1, now, &[]);
    assert!(o1.iter().all(|o| *o == WitnessOutcome::CosignedFirstSight));
    assert_eq!(c1.valid_cosigns(&cp1, &roster), 5);
    assert!(c1.certified(&cp1, &roster, k));

    // honest growth C1 → C2 → all cosign with a real consistency proof → certified
    for i in 6..11 {
        log.append(format!("e{i}").as_bytes()).unwrap();
    }
    let cp2 = log.signed_checkpoint();
    let sig2 = log.sign_checkpoint(&cp2).sig;
    let proof = log.consistency_proof(cp1.tree_size).unwrap();
    let (c2, o2) = quorum.certify(&cp2, &sig2, now, &proof);
    assert!(o2.iter().all(|o| *o == WitnessOutcome::Cosigned));
    assert!(c2.certified(&cp2, &roster, k));

    // THE FORK at C2's size: a valid LOG signature over a divergent root. Every honest witness already cosigned C2's
    // root at this size, so all REFUSE → 0 cosignatures → the fork cannot be certified.
    let mut evil = merkle::TestLog::new();
    for i in 0..cp2.tree_size {
        let e = if i == 2 {
            "REWRITTEN".to_string()
        } else {
            format!("e{i}")
        };
        evil.append(e.as_bytes());
    }
    let forked = ainra_core::checkpoint::Checkpoint {
        origin: cp2.origin.clone(),
        tree_size: cp2.tree_size,
        root: evil.root(),
    };
    assert_ne!(forked.root, cp2.root);
    let bogus = evil.consistency_proof(cp1.tree_size).unwrap();
    let sig_forked = log.sign_checkpoint(&forked).sig;
    let (fork_cert, ofork) = quorum.certify(&forked, &sig_forked, now, &bogus);
    assert!(ofork.iter().all(|o| *o == WitnessOutcome::RefusedFork));
    assert_eq!(fork_cert.valid_cosigns(&forked, &roster), 0);
    assert!(
        !fork_cert.certified(&forked, &roster, k),
        "an equivocating fork must not reach quorum"
    );
    // the honest head is still certified after the fork attempt
    assert!(c2.certified(&cp2, &roster, k));

    let _ = std::fs::remove_dir_all(&dir);
}

/// The quorum's trust assumption stated precisely: a fork certifies only if ≥ the RELYING PARTY's k witnesses are
/// adversarial — AND an attacker who AUTHORS the certificate cannot lower that k. The relying party supplies its own
/// threshold to `certified`; the certificate carries none. This pins the `f < k` boundary AND the fix for the M6
/// review's threshold-downgrade finding.
#[test]
fn a_fork_needs_threshold_traitors_to_certify_fewer_cannot() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xB772_A171);
    // 5 accredited witness keys — the roster a relying party trusts, with its OWN policy k = 3.
    let keys: Vec<crypto::TestDelegate> = (0..5)
        .map(|_| crypto::TestDelegate::generate(&mut rng))
        .collect();
    let roster: BTreeSet<[u8; 32]> = keys.iter().map(|k| k.public()).collect();
    let rp_k = 3usize;

    // A forged checkpoint an adversary wants certified.
    let forked = ainra_core::checkpoint::Checkpoint {
        origin: "ainra-log/registrar-07".into(),
        tree_size: 11,
        root: [0x77u8; 32],
    };
    let msg = forked.signing_bytes().unwrap();

    // `f` traitors cosign the fork (an adversary signs whatever it likes) → the best certificate they can assemble.
    let cert_with = |f: usize| QuorumCertificate {
        origin: forked.origin.clone(),
        tree_size: forked.tree_size,
        root: forked.root,
        cosigners: keys[..f]
            .iter()
            .map(|k| (k.public(), k.sign(&msg)))
            .collect(),
    };
    // f = 2 < k = 3 → NOT certified when the RELYING PARTY applies its own k (all an adversary short of k can muster).
    assert_eq!(cert_with(2).valid_cosigns(&forked, &roster), 2);
    assert!(!cert_with(2).certified(&forked, &roster, rp_k));
    // f = 3 == k → certified: the trust assumption is "FEWER than k adversarial witnesses" — the boundary, stated.
    assert!(cert_with(3).certified(&forked, &roster, rp_k));

    // THE FIX (M6 review, HIGH): the certificate carries no threshold of its own, so an attacker who authors a
    // certificate for a fork with ZERO or ONE cosign cannot make the relying party certify it — the RP always
    // applies ITS k, and `certified` also refuses a nonsensical k = 0.
    assert!(
        !cert_with(0).certified(&forked, &roster, rp_k),
        "zero-cosign fork must never certify"
    );
    assert!(
        !cert_with(1).certified(&forked, &roster, rp_k),
        "one traitor cannot downgrade k=3"
    );
    assert!(
        !cert_with(3).certified(&forked, &roster, 0),
        "a relying-party k of 0 is rejected, not trivially true"
    );
}

/// `QuorumCertificate::valid_cosigns` is fail-closed: it counts only cosignatures that are cryptographically valid,
/// from keys in the known roster, distinct, and over the exact checkpoint. A certificate cannot be padded to fake a
/// quorum with non-roster keys, duplicates, junk signatures, or a wrong-checkpoint cosign.
#[test]
fn quorum_certificate_counts_only_known_valid_distinct_cosigns() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xCE27_1F1E);
    let known: Vec<crypto::TestDelegate> = (0..3)
        .map(|_| crypto::TestDelegate::generate(&mut rng))
        .collect();
    let roster: BTreeSet<[u8; 32]> = known.iter().map(|k| k.public()).collect();
    let stranger = crypto::TestDelegate::generate(&mut rng); // NOT in the roster

    let cp = ainra_core::checkpoint::Checkpoint {
        origin: "ainra-log/registrar-07".into(),
        tree_size: 9,
        root: [0x11u8; 32],
    };
    let msg = cp.signing_bytes().unwrap();

    let cert = QuorumCertificate {
        origin: cp.origin.clone(),
        tree_size: cp.tree_size,
        root: cp.root,
        cosigners: vec![
            (known[0].public(), known[0].sign(&msg)), // ✓ counts once
            (known[0].public(), known[0].sign(&msg)), // duplicate key → not double-counted
            (stranger.public(), stranger.sign(&msg)), // valid sig but NOT in roster → ignored
            (known[1].public(), vec![0u8; 10]),       // malformed signature → ignored
            (known[1].public(), known[2].sign(&msg)), // key/signer mismatch → invalid → ignored
        ],
    };
    assert_eq!(
        cert.valid_cosigns(&cp, &roster),
        1,
        "only known[0], counted once"
    );
    assert!(!cert.certified(&cp, &roster, 2));

    // A certificate is bound to its exact checkpoint — it certifies nothing about a different root/size.
    let other = ainra_core::checkpoint::Checkpoint {
        root: [0x99u8; 32],
        ..cp.clone()
    };
    assert_eq!(cert.valid_cosigns(&other, &roster), 0);
}

#[test]
fn logd_persists_across_reopen() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x9E_09_E4_11);
    let root = crypto::TestRootSlh::generate(&mut rng);
    let now = 1_775_865_600u64;
    let dir = tmpdir("persist");

    let root_before;
    {
        let d1 = crypto::TestDelegate::generate(&mut rng);
        let mut log = Logd::open(&dir, "ainra-log/x", &root, d1, now, 86_400).unwrap();
        for i in 0..7 {
            log.append(format!("e{i}").as_bytes()).unwrap();
        }
        root_before = log.signed_checkpoint().root;
    }
    // reopen from disk → same size, same root (the tree rebuilt from the fsync'd entries)
    let d2 = crypto::TestDelegate::generate(&mut rng);
    let log = Logd::open(&dir, "ainra-log/x", &root, d2, now, 86_400).unwrap();
    assert_eq!(log.size(), 7);
    assert_eq!(log.signed_checkpoint().root, root_before);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn statusd_publish_verify_and_fail_closed() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x57A7_D811);
    let mut sd = Statusd::new(
        "status://registrar-07/1",
        32,
        crypto::HybridKeypair::generate(&mut rng),
    );
    let key = sd.public();
    sd.revoke(5);
    let now = 1_775_865_600u64;
    let pubd = sd.publish(now);

    use ainra_core::status::{Freshness, LineageStatus};
    assert!(matches!(
        verify_publication(&key, &pubd, now + 10, Freshness::F2, 0),
        Ok(LineageStatus::Valid)
    ));
    assert!(matches!(
        verify_publication(&key, &pubd, now + 10, Freshness::F2, 5),
        Ok(LineageStatus::Revoked)
    ));
    // past the end → fail closed → Revoked
    assert!(matches!(
        verify_publication(&key, &pubd, now + 10, Freshness::F2, 999),
        Ok(LineageStatus::Revoked)
    ));
    // stale under F2 → Err (fail closed)
    assert!(verify_publication(&key, &pubd, now + 100_000, Freshness::F2, 0).is_err());
    // tampered signature → Err
    let mut tampered = sd.publish(now);
    tampered.sig_ed25519 = "AAAA".to_string();
    assert!(verify_publication(&key, &tampered, now + 10, Freshness::F2, 0).is_err());
}
