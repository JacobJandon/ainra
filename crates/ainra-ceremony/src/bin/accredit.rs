// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `accredit` — build a dual-root-signed AINRA directory over LIVE registrars. Reads each registrar's published
//! `/accreditation` JSON (public keys only — no secrets leave the registrar), DKGs a FROST 5-of-9 + SLH-DSA dual
//! root, dual-signs the directory, and writes `directory.json` + `roots.json`. The M5 testbed uses this to compose
//! the real registrar-box daemon with the real ceremony so a stranger's `sdk-ts` Verifier trust-anchors the result.
//!
//! Usage: `accredit <out-dir> <accreditation.json>...`  (each accreditation is a registrar-box `/accreditation`).

use std::path::Path;

use ainra_ceremony::ceremony::Genesis;
use ainra_core::directory::DirectoryEntry;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const NOW: u64 = 1_775_865_600 - 3600; // ceremony time, just before the demo window opens

fn main() {
    let mut args = std::env::args().skip(1);
    let out = args.next().unwrap_or_else(|| {
        eprintln!("usage: accredit <out-dir> <accreditation.json>...");
        std::process::exit(2);
    });
    let dir = Path::new(&out);
    std::fs::create_dir_all(dir).expect("mkdir");

    // Read each registrar's published accreditation → a directory entry (public keys only).
    let mut entries = Vec::new();
    for path in args {
        let raw = std::fs::read(&path).unwrap_or_else(|e| {
            eprintln!("cannot read {path}: {e}");
            std::process::exit(1);
        });
        let acc: serde_json::Value = serde_json::from_slice(&raw).expect("parse accreditation");
        entries.push(DirectoryEntry {
            registrar: acc["registrar"].as_str().expect("registrar").to_string(),
            issuer_ed25519: acc["issuer_key"]["ed25519"]
                .as_str()
                .expect("issuer ed")
                .to_string(),
            issuer_mldsa65: acc["issuer_key"]["mldsa65"]
                .as_str()
                .expect("issuer ml")
                .to_string(),
            log_root_slh: acc["log_root_key"].as_str().expect("log root").to_string(),
            // Status-signing key (D-020) — published in the registrar's accreditation so a verifier authenticates
            // presented status lists against it. A registrar that omits it is trust-anchored but its passports fail
            // closed in the GA Verifier (no way to authenticate revocation).
            status_ed25519: acc["status_key"]["ed25519"]
                .as_str()
                .expect("status ed")
                .to_string(),
            status_mldsa65: acc["status_key"]["mldsa65"]
                .as_str()
                .expect("status ml")
                .to_string(),
            status_uri: acc["status_uri"].as_str().unwrap_or("").to_string(),
        });
    }
    if entries.is_empty() {
        eprintln!("no accreditations given");
        std::process::exit(2);
    }

    // Deterministic (seeded) so the testbed is reproducible; a real ceremony uses live custodian entropy.
    let mut rng = ChaCha20Rng::seed_from_u64(0x0ACC_ED17_E5ED);
    let n = entries.len();
    let (directory, root_ed, root_slh) =
        Genesis::accredit_external(entries, vec![], NOW, &mut rng).expect("accredit");

    // Self-verify the way a stranger would, before writing anything.
    match directory.accredit(&root_ed, &root_slh) {
        Ok(acc) => {
            assert_eq!(acc.anchors.registrars.len(), n);
        }
        Err(r) => {
            eprintln!("accredit produced an unverifiable directory: {r}");
            std::process::exit(1);
        }
    }

    std::fs::write(
        dir.join("directory.json"),
        serde_json::to_string_pretty(&directory).unwrap(),
    )
    .expect("write directory");
    std::fs::write(
        dir.join("roots.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "root_ed25519": ainra_core::b64::encode(&root_ed),
            "root_slh": ainra_core::b64::encode(&root_slh),
        }))
        .unwrap(),
    )
    .expect("write roots");
    println!(
        "accredited {n} registrar(s) → {out}/directory.json + roots.json (dual-root-signed, self-verified)"
    );
}
