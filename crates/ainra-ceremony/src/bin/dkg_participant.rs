// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `dkg-participant` — ONE custodian in a DISTRIBUTABLE FROST 5-of-9 ceremony (M23 Task 3).
//!
//! The M4 `ceremony` binary runs all nine custodians inside one process (a faithful simulation of the protocol).
//! This binary runs exactly ONE custodian, exchanging every round message through files in a shared "postbox"
//! directory — so the nine custodians can run as nine ISOLATED OS PROCESSES (or nine air-gapped machines that pass
//! USB sticks). No custodian ever sees another's secret; the group secret is never assembled anywhere. The group
//! key that emerges is a standard RFC 8032 Ed25519 key, so a verifier cannot tell the root is thresholdised.
//!
//! Rounds (each a separate invocation, so a custodian can power down between them):
//!   dkg1 <id> <n> <t> <box> <home> <seedhex>   part1 → broadcast r1 package; keep r1 secret private
//!   dkg2 <id> <n> <t> <box> <home>             part2 → per-recipient r2 packages; keep r2 secret private
//!   dkg3 <id> <n> <t> <box> <home>             part3 → private key share + the public group key
//!   commit <id> <box> <home> <seedhex>         signing round 1: broadcast a commitment, keep the nonce private
//!   sign   <id> <box> <home> <msghex>          signing round 2: emit this custodian's signature share
//!   aggregate <box> <msghex>                   coordinator: combine ≥t shares → one Ed25519 signature, verify it
//!
//! TEST-ROOT material only (seeds are passed in + labelled). The real recorded ceremony uses live custodian
//! entropy on air-gapped machines — see kits/ceremony/RUNBOOK.md.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use frost::keys::dkg;
use frost::{Identifier, Signature};
use frost_ed25519 as frost;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

type Pkg1 = dkg::round1::Package;
type Pkg2 = dkg::round2::Package;

fn die(m: &str) -> ! {
    eprintln!("✗ {m}");
    std::process::exit(1);
}
fn id_of(k: u16) -> Identifier {
    Identifier::try_from(k).unwrap_or_else(|_| die("identifier must be 1..=65535"))
}
fn rd(p: &Path) -> Vec<u8> {
    fs::read(p).unwrap_or_else(|_| die(&format!("missing file {}", p.display())))
}
fn wr(p: PathBuf, bytes: &[u8]) {
    if let Some(d) = p.parent() {
        fs::create_dir_all(d).ok();
    }
    fs::write(&p, bytes).unwrap_or_else(|_| die(&format!("cannot write {}", p.display())));
}
/// A per-custodian RNG seeded from (shared run seed ‖ id) — distinct per custodian, fresh per run.
fn seeded_rng(seedhex: &str, id: u16) -> ChaCha20Rng {
    let mut h = Sha256::new();
    h.update(hex_dec(seedhex));
    h.update(id.to_le_bytes());
    let seed: [u8; 32] = h.finalize().into();
    ChaCha20Rng::from_seed(seed)
}
fn hex_dec(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or_else(|_| die("bad hex")))
        .collect()
}
fn hex_enc(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
/// every custodian file in `dir` named `<k>.bin` (or `<k>-<id>.bin`) whose k ≠ me, deserialised.
fn others_r1(dir: &Path, me: u16) -> BTreeMap<Identifier, Pkg1> {
    let mut m = BTreeMap::new();
    for e in fs::read_dir(dir).unwrap_or_else(|_| die("no r1 packages in postbox")) {
        let p = e.unwrap().path();
        let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if let Ok(k) = stem.parse::<u16>() {
            if k != me {
                m.insert(
                    id_of(k),
                    Pkg1::deserialize(&rd(&p)).unwrap_or_else(|_| die("bad r1 pkg")),
                );
            }
        }
    }
    m
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 2 {
        die("usage: dkg-participant <dkg1|dkg2|dkg3|commit|sign|aggregate> …");
    }
    match a[1].as_str() {
        // ── DKG round 1 ────────────────────────────────────────────────────────────────────────────────────────
        "dkg1" => {
            let (id, n, t, bx, home, seed) = (
                u(&a, 2),
                u(&a, 3),
                u(&a, 4),
                pb(&a, 5),
                pb(&a, 6),
                a[7].clone(),
            );
            let mut rng = seeded_rng(&seed, id);
            let (secret, package) = dkg::part1(id_of(id), n, t, &mut rng)
                .unwrap_or_else(|e| die(&format!("part1: {e}")));
            wr(
                bx.join("r1").join(format!("{id}.bin")),
                &package.serialize().unwrap(),
            );
            wr(home.join("r1secret.bin"), &secret.serialize().unwrap());
            println!("custodian {id}: round 1 committed (r1 package broadcast; r1 secret kept)");
        }
        // ── DKG round 2 ────────────────────────────────────────────────────────────────────────────────────────
        "dkg2" => {
            let (id, n, _t, bx, home) = (u(&a, 2), u(&a, 3), u(&a, 4), pb(&a, 5), pb(&a, 6));
            let secret = dkg::round1::SecretPackage::deserialize(&rd(&home.join("r1secret.bin")))
                .unwrap_or_else(|_| die("bad r1 secret"));
            let r1 = others_r1(&bx.join("r1"), id);
            let (secret2, r2_to) =
                dkg::part2(secret, &r1).unwrap_or_else(|e| die(&format!("part2: {e}")));
            for k in 1..=n {
                if k == id {
                    continue;
                }
                if let Some(pkg) = r2_to.get(&id_of(k)) {
                    wr(
                        bx.join("r2").join(format!("{id}-{k}.bin")),
                        &pkg.serialize().unwrap(),
                    );
                }
            }
            wr(home.join("r2secret.bin"), &secret2.serialize().unwrap());
            println!("custodian {id}: round 2 dealt (per-recipient packages sent)");
        }
        // ── DKG round 3: derive the private share + the public group key ───────────────────────────────────────
        "dkg3" => {
            let (id, n, _t, bx, home) = (u(&a, 2), u(&a, 3), u(&a, 4), pb(&a, 5), pb(&a, 6));
            let secret2 = dkg::round2::SecretPackage::deserialize(&rd(&home.join("r2secret.bin")))
                .unwrap_or_else(|_| die("bad r2 secret"));
            let r1 = others_r1(&bx.join("r1"), id);
            let mut r2: BTreeMap<Identifier, Pkg2> = BTreeMap::new();
            for k in 1..=n {
                if k == id {
                    continue;
                }
                let p = bx.join("r2").join(format!("{k}-{id}.bin"));
                r2.insert(
                    id_of(k),
                    Pkg2::deserialize(&rd(&p)).unwrap_or_else(|_| die("bad r2 pkg to me")),
                );
            }
            let (key_pkg, pub_pkg) =
                dkg::part3(&secret2, &r1, &r2).unwrap_or_else(|e| die(&format!("part3: {e}")));
            wr(home.join("keypkg.bin"), &key_pkg.serialize().unwrap());
            wr(
                bx.join("group").join("pubkeys.bin"),
                &pub_pkg.serialize().unwrap(),
            );
            let gpk = pub_pkg.verifying_key().serialize().unwrap();
            wr(
                bx.join("group").join(format!("{id}.pub")),
                hex_enc(&gpk).as_bytes(),
            );
            println!(
                "custodian {id}: round 3 done — group key {}",
                &hex_enc(&gpk)[..16]
            );
        }
        // ── signing round 1: a quorum member broadcasts a commitment ──────────────────────────────────────────
        "commit" => {
            let (id, bx, home, seed) = (u(&a, 2), pb(&a, 3), pb(&a, 4), a[5].clone());
            let key_pkg = frost::keys::KeyPackage::deserialize(&rd(&home.join("keypkg.bin")))
                .unwrap_or_else(|_| die("bad key package — run dkg first"));
            let mut rng = seeded_rng(&seed, id.wrapping_add(9000));
            let (nonces, commitments) = frost::round1::commit(key_pkg.signing_share(), &mut rng);
            wr(
                bx.join("sign").join(format!("commit-{id}.bin")),
                &commitments.serialize().unwrap(),
            );
            wr(home.join("nonces.bin"), &nonces.serialize().unwrap());
            println!("custodian {id}: signing commitment broadcast");
        }
        // ── signing round 2: a quorum member emits its signature share ────────────────────────────────────────
        "sign" => {
            let (id, bx, home, msg) = (u(&a, 2), pb(&a, 3), pb(&a, 4), hex_dec(&a[5]));
            let commits = read_commits(&bx.join("sign"));
            let pkg = frost::SigningPackage::new(commits, &msg);
            let key_pkg = frost::keys::KeyPackage::deserialize(&rd(&home.join("keypkg.bin")))
                .unwrap_or_else(|_| die("bad key package"));
            let nonces = frost::round1::SigningNonces::deserialize(&rd(&home.join("nonces.bin")))
                .unwrap_or_else(|_| die("bad nonces — run commit first"));
            let share = frost::round2::sign(&pkg, &nonces, &key_pkg)
                .unwrap_or_else(|e| die(&format!("sign: {e}")));
            wr(
                bx.join("sign").join(format!("share-{id}.bin")),
                &share.serialize(),
            );
            wr(bx.join("sign").join("pkg.bin"), &pkg.serialize().unwrap());
            println!("custodian {id}: signature share emitted");
        }
        // ── coordinator: aggregate ≥t shares → one Ed25519 signature, verify against the group key ─────────────
        "aggregate" => {
            let (bx, msg) = (pb(&a, 2), hex_dec(&a[3]));
            let pkg = frost::SigningPackage::deserialize(&rd(&bx.join("sign").join("pkg.bin")))
                .unwrap_or_else(|_| die("no signing package"));
            let pub_pkg = frost::keys::PublicKeyPackage::deserialize(&rd(&bx
                .join("group")
                .join("pubkeys.bin")))
            .unwrap_or_else(|_| die("no public key package"));
            let shares = read_shares(&bx.join("sign"));
            let sig: Signature = match frost::aggregate(&pkg, &shares, &pub_pkg) {
                Ok(s) => s,
                Err(e) => die(&format!(
                    "aggregate refused with {} share(s): {e}",
                    shares.len()
                )),
            };
            let ok = pub_pkg.verifying_key().verify(&msg, &sig).is_ok();
            wr(bx.join("signature.bin"), &sig.serialize().unwrap());
            let gpk = pub_pkg.verifying_key().serialize().unwrap();
            println!(
                "coordinator: aggregated {} shares → RFC 8032 signature {} · verify against group key {} → {}",
                shares.len(),
                &hex_enc(&sig.serialize().unwrap())[..16],
                &hex_enc(&gpk)[..16],
                if ok { "VALID" } else { "INVALID" }
            );
            std::process::exit(if ok { 0 } else { 1 });
        }
        m => die(&format!("unknown mode {m}")),
    }
}

fn read_commits(dir: &Path) -> BTreeMap<Identifier, frost::round1::SigningCommitments> {
    let mut m = BTreeMap::new();
    for e in fs::read_dir(dir).unwrap_or_else(|_| die("no commitments")) {
        let p = e.unwrap().path();
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if let Some(k) = name
            .strip_prefix("commit-")
            .and_then(|s| s.strip_suffix(".bin"))
        {
            if let Ok(k) = k.parse::<u16>() {
                m.insert(
                    id_of(k),
                    frost::round1::SigningCommitments::deserialize(&rd(&p)).unwrap(),
                );
            }
        }
    }
    m
}
fn read_shares(dir: &Path) -> BTreeMap<Identifier, frost::round2::SignatureShare> {
    let mut m = BTreeMap::new();
    for e in fs::read_dir(dir).unwrap_or_else(|_| die("no shares")) {
        let p = e.unwrap().path();
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if let Some(k) = name
            .strip_prefix("share-")
            .and_then(|s| s.strip_suffix(".bin"))
        {
            if let Ok(k) = k.parse::<u16>() {
                m.insert(
                    id_of(k),
                    frost::round2::SignatureShare::deserialize(&rd(&p)).unwrap(),
                );
            }
        }
    }
    m
}
fn u(a: &[String], i: usize) -> u16 {
    a.get(i)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| die("expected a number argument"))
}
fn pb(a: &[String], i: usize) -> PathBuf {
    PathBuf::from(a.get(i).unwrap_or_else(|| die("expected a path argument")))
}
