// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ceremony` — the AINRA genesis rehearsal, end to end, with REAL crypto and a replayable transcript.
//!
//!   1. FROST 5-of-9 DKG (9 custodians) → the Ed25519 group root; SLH-DSA-128s ceremony root.
//!   2. Accredit registrars into a **dual-root-signed directory**; verify it the way a stranger would (`accredit`).
//!   3. Mint a REAL passport for one registrar, verify it VALID against the directory's trust anchors.
//!   4. REVOCATION drill: republish a new directory epoch revoking that registrar's checkpoint delegate; the SAME
//!      passport now verifies to `checkpoint_invalid` — the online key is dead network-wide.
//!   5. ROTATION drill: certify a fresh delegate, re-log the passport under a checkpoint it signs; VALID again
//!      (service restored; the revoked key stays dead).
//!   6. Write `directory.json` / `directory-epoch2.json` / `roots.json` / `transcript.json` + its SHA-256, and
//!      re-verify the written directory from disk (nothing trusted that a fresh verifier can't reproduce).
//!
//! Usage: `ceremony [out-dir]` (default `./ceremony-out`).  `make ceremony`.

use std::path::Path;

use ainra_ceremony::ceremony::Genesis;
use ainra_core::checkpoint::{Checkpoint, CheckpointSig};
use ainra_core::directory::Directory;
use ainra_core::verify::{HopLogProof, Presentation};
use ainra_core::{b64, canon, crypto, mandate, merkle, status, verify, Verdict};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use serde_json::json;
use sha2::{Digest, Sha256};

const NBF: u64 = 1_775_865_600; // 2026-04-11
const EXP: u64 = 1_807_401_600; // 2027-04-11
const NOW: u64 = NBF - 3600; // ceremony time
const VERIFY_AT: u64 = NBF + 10 * 24 * 3600; // within the 90-day delegate window

/// A minimal but fully real passport for a ceremony registrar, plus the pieces to present it under a given
/// delegate-signed checkpoint. Everything is genuine: hybrid issuer signature, RFC 6962 inclusion, delegate cert.
struct MintedPassport {
    claims: Vec<u8>,
    issuer_sig: crypto::HybridSig,
    checkpoint: Checkpoint,
    checkpoint_sig: CheckpointSig,
    leaf_index: u64,
    inclusion_proof: Vec<[u8; 32]>,
}

/// Mint + log a passport for registrar `reg` under a checkpoint signed by `delegate`/`cert`.
fn mint(
    reg: &ainra_ceremony::ceremony::RegistrarKeys,
    delegate: &crypto::TestDelegate,
    cert: &ainra_core::checkpoint::DelegateCert,
    rng: &mut impl CryptoRngCore,
) -> MintedPassport {
    let holder = crypto::HybridKeypair::generate(rng).public();
    let body = json!({
        "vct": ainra_core::PASSPORT_VCT,
        "iss": format!("did:ainra:{}:acme:invoicing", reg.id),
        "sub": format!("ainra:{}:acme:invoicing@1.0.0", reg.id),
        "nbf": NBF, "exp": EXP,
        "authority": { "class": "A2", "principal_proof": "deadbeef7f3a2c1d" },
        "tier": "L3",
        "capabilities": ["read:invoices"],
        "scope_ceiling": ["read:invoices"],
        "keys": [ { "ed25519": b64::encode(&holder.ed25519), "mldsa65": b64::encode(&holder.mldsa65) } ],
        "cnf": { "jkt": "sB3u9wKp" },
        "status": { "status_list": { "idx": 0, "uri": format!("status://{}/1", reg.id) } },
    });
    let body_bytes = canon::canonicalize(&body).expect("canon").into_bytes();
    let cred_leaf = merkle::hash_leaf(&body_bytes);
    let mut log = merkle::TestLog::new();
    for k in 0..4u8 {
        log.append(&[k]);
    }
    let leaf_index = log.append(&body_bytes);
    let cp = Checkpoint {
        origin: format!("ainra-log/{}", reg.id),
        tree_size: log.size(),
        root: log.root(),
    };
    let cp_sig = CheckpointSig::Delegate {
        cert: cert.clone(),
        sig_ed25519: cp.sign_delegate(delegate).expect("delegate sign"),
    };
    let proof = log.inclusion_proof(leaf_index).expect("proof");
    let mut full = body;
    full["log"] = json!({
        "leaf": b64::encode(&cred_leaf), "root": b64::encode(&cp.root),
        "checkpoint": format!("ainra-log/{}#{}", reg.id, log.size()),
    });
    let claims = canon::canonicalize(&full).expect("canon").into_bytes();
    let issuer_sig = reg.issuer.sign(&claims).expect("sign");
    MintedPassport {
        claims,
        issuer_sig,
        checkpoint: cp,
        checkpoint_sig: cp_sig,
        leaf_index,
        inclusion_proof: proof,
    }
}

/// Verify a minted passport against a specific directory epoch (its anchors + revoked-delegate set).
fn verify_against(
    dir: &Directory,
    root_ed: &[u8; 32],
    root_slh: &[u8],
    p: &MintedPassport,
) -> Verdict {
    let acc = match dir.accredit(root_ed, root_slh) {
        Ok(a) => a,
        Err(r) => return Verdict::invalid(r),
    };
    let pres = Presentation {
        claims: &p.claims,
        issuer_sig: p.issuer_sig.clone(),
        now: VERIFY_AT,
        chain_keys: vec![],
        hop_proofs: Vec::<HopLogProof>::new(),
        status_list: status::StatusList::from_bits(vec![false; 16]),
        status_issued_at: VERIFY_AT - 5,
        freshness: status::Freshness::F3,
        checkpoint: p.checkpoint.clone(),
        checkpoint_sig: p.checkpoint_sig.clone(),
        leaf_index: p.leaf_index,
        inclusion_proof: p.inclusion_proof.clone(),
        mandate_path: vec![],
        mandate_proofs: vec![],
        mandate_revocations: mandate::RevocationSet::default(),
        revoked_delegates: acc.revoked_delegates,
    };
    verify::verify(&pres, &acc.anchors)
}

fn vstr(v: &Verdict) -> String {
    match v {
        Verdict::Valid => "VALID".into(),
        Verdict::Invalid { reason } => format!("INVALID ({reason})"),
    }
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ceremony-out".to_string());
    let dir = Path::new(&out);
    std::fs::create_dir_all(dir).expect("mkdir");
    // Deterministic (seeded) so the transcript is reproducible; a real ceremony uses live custodian entropy. The
    // seed is public + labeled TEST — never a production key.
    let mut rng = ChaCha20Rng::seed_from_u64(0x0A11_BA9E_11E5_1500);

    println!("AINRA genesis ceremony (rehearsal) — real FROST 5-of-9 + SLH-DSA dual root\n");
    let ids = ["registrar-02", "registrar-07", "registrar-11"];
    let g = Genesis::run(&ids, NOW, vec![], &mut rng).expect("genesis");
    let root_ed = g.root_ed_public();
    let root_slh = g.root_slh.public();
    println!("1. DKG complete — 9 custodians, 5-of-9 threshold Ed25519 root");
    println!("   group root FP   {}", fp(&root_ed));
    println!("   SLH-DSA root FP {}", fp(&root_slh));
    println!(
        "2. Directory signed by BOTH roots — {} registrars accredited: {}",
        ids.len(),
        ids.join(", ")
    );
    match g.verify_output() {
        Ok(n) => println!("   dual-root accredit() -> {n} registrars trust-anchored (ok)"),
        Err(r) => {
            eprintln!("   accredit FAILED: {r}");
            std::process::exit(1);
        }
    }

    // Mint a real passport for registrar-07 and verify it under the genesis directory.
    let reg = g
        .registrars
        .iter()
        .find(|r| r.id == "registrar-07")
        .expect("reg-07");
    let passport = mint(reg, &reg.delegate, &reg.cert, &mut rng);
    let v1 = verify_against(&g.directory, &root_ed, &root_slh, &passport);
    println!(
        "3. Minted passport ainra:registrar-07:acme:invoicing@1.0.0 -> verify under genesis directory: {}",
        vstr(&v1)
    );

    // REVOCATION drill: republish epoch 2 revoking reg-07's checkpoint delegate.
    let fp_revoked = reg.cert.fingerprint();
    let dir2 = g
        .republish_with_revocations(&[fp_revoked], NOW + 3600, &mut rng)
        .expect("republish");
    let v2 = verify_against(&dir2, &root_ed, &root_slh, &passport);
    println!(
        "4. REVOKE delegate {} -> directory epoch {} -> SAME passport now: {}",
        fp(&fp_revoked),
        dir2.epoch,
        vstr(&v2)
    );

    // ROTATION drill: certify a fresh delegate, re-log the passport under a checkpoint it signs.
    let new_delegate = crypto::TestDelegate::generate(&mut rng);
    let new_cert = ainra_core::checkpoint::DelegateCert::issue_test_root(
        &reg.log_root,
        new_delegate.public(),
        vec![ainra_core::checkpoint::SCOPE_CHECKPOINT.to_string()],
        NOW + 3600,
        NOW + 3600 + 90 * 24 * 3600,
    )
    .expect("new cert");
    let rotated = mint(reg, &new_delegate, &new_cert, &mut rng);
    let v3 = verify_against(&dir2, &root_ed, &root_slh, &rotated);
    println!(
        "5. ROTATE to fresh delegate {} -> re-logged passport under epoch {}: {}",
        fp(&new_cert.fingerprint()),
        dir2.epoch,
        vstr(&v3)
    );

    // Artifacts + transcript + hash; then re-verify the WRITTEN directory from disk.
    write_json(dir.join("directory.json"), &g.directory);
    write_json(dir.join("directory-epoch2.json"), &dir2);
    let roots = json!({
        "root_ed25519_frost_5of9": b64::encode(&root_ed),
        "root_slh_dsa_128s": b64::encode(&root_slh),
        "note": "The Ed25519 root is a FROST 5-of-9 group key; its signatures are standard RFC 8032 (verify with any Ed25519 verifier). Both roots are required to accept a directory.",
    });
    write_json(dir.join("roots.json"), &roots);

    let transcript = json!({
        "ceremony": "AINRA genesis rehearsal",
        "roots": { "ed25519_frost": { "threshold": "5-of-9", "custodians": 9 }, "slh_dsa_128s": true },
        "accredited": ids,
        "genesis_epoch": g.directory.epoch,
        "drills": {
            "mint_verify": vstr(&v1),
            "revoke_delegate": { "fingerprint": b64::encode(&fp_revoked), "new_epoch": dir2.epoch, "verdict": vstr(&v2) },
            "rotate_delegate": { "fingerprint": b64::encode(&new_cert.fingerprint()), "verdict": vstr(&v3) },
        },
        "verified_at": VERIFY_AT,
    });
    let transcript_bytes = serde_json::to_vec_pretty(&transcript).unwrap();
    std::fs::write(dir.join("transcript.json"), &transcript_bytes).expect("write transcript");
    let thash: [u8; 32] = Sha256::digest(&transcript_bytes).into();
    std::fs::write(dir.join("transcript.sha256"), format!("{}\n", hex(&thash)))
        .expect("write hash");

    // Re-verify the directory AS WRITTEN (reload from disk) — the ceremony trusts nothing a stranger can't reproduce.
    let reloaded: Directory =
        serde_json::from_slice(&std::fs::read(dir.join("directory.json")).unwrap()).unwrap();
    let reloaded_ok = reloaded.accredit(&root_ed, &root_slh).is_ok();
    println!(
        "6. Wrote {out}/{{directory.json,directory-epoch2.json,roots.json,transcript.json,transcript.sha256}}"
    );
    println!("   transcript SHA-256 {}", hex(&thash));
    println!(
        "   reloaded directory re-verifies from disk: {}",
        if reloaded_ok { "ok" } else { "FAIL" }
    );

    // Fail the run if any invariant broke — nothing here is asserted-by-narration.
    let ok = v1.is_valid()
        && matches!(v2, Verdict::Invalid { reason } if reason == ainra_core::Reason::CheckpointInvalid)
        && v3.is_valid()
        && reloaded_ok;
    if ok {
        println!(
            "\nceremony OK — genesis trust-anchored; revocation kills the delegate; rotation restores service."
        );
    } else {
        eprintln!("\nCEREMONY FAILED — an invariant did not hold");
        std::process::exit(1);
    }
}

fn fp(bytes: &[u8]) -> String {
    let h: [u8; 32] = Sha256::digest(bytes).into();
    hex(&h[..4])
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn write_json<T: serde::Serialize>(path: std::path::PathBuf, v: &T) {
    std::fs::write(path, serde_json::to_string_pretty(v).unwrap()).expect("write json");
}
