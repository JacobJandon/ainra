// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `slh-root` — the offline SLH-DSA-SHA2-128s root signer for epoch-ceremony REHEARSALS (PLAN-M52 step 7).
//!
//! A directory needs two root signatures: the FROST 5-of-9 Ed25519 aggregate (`dkg-participant`) and one from the
//! SLH-DSA root. This is the second signer, on its own, so a rehearsal can sign an existing proposal the way the real
//! ceremony will: the signer derives the message from its own copy of the proposal (`ainra directory sign-request`)
//! and signs exactly that hex, nothing else.
//!
//!   slh-root keygen <keyfile>          a fresh TEST-ROOT key; the file is created 0600 and never overwritten
//!   slh-root pub    <keyfile>          the public key, base64url
//!   slh-root sign   <keyfile> <msghex> the signature over the message, base64url
//!
//! TEST-ROOT ONLY. The key file holds a 32-byte seed from /dev/urandom, and the key is derived from it with the same
//! `TestRootSlh::generate` the rest of the repository uses — no second SLH-DSA path. It is labelled in the file and
//! in every line printed. A key file that group or others can read is refused. The production SLH root, its recovery
//! split and its custody are PLAN-M52 step 9, not this.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use ainra_core::{b64, crypto};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const LABEL: &str =
    "TEST-ROOT — an SLH-DSA root for ceremony rehearsals only; never a production root key";

fn die(m: &str) -> ! {
    eprintln!("✗ slh-root: {m}");
    std::process::exit(1);
}

fn hex_enc(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_dec(s: &str) -> Vec<u8> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        die("the message is not hex");
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .unwrap_or_else(|_| die("the message is not hex"))
        })
        .collect()
}

fn load(path: &str) -> crypto::TestRootSlh {
    let attrs = fs::metadata(path).unwrap_or_else(|e| die(&format!("{path}: {e}")));
    if attrs.permissions().mode() & 0o077 != 0 {
        die(&format!(
            "{path} is readable by group or others (mode {:o}); a root key file is 0600",
            attrs.permissions().mode() & 0o777
        ));
    }
    let v: serde_json::Value =
        serde_json::from_slice(&fs::read(path).unwrap_or_else(|e| die(&format!("{path}: {e}"))))
            .unwrap_or_else(|_| die(&format!("{path}: not a slh-root key file")));
    if v["label"].as_str() != Some(LABEL) {
        die(&format!(
            "{path}: not labelled TEST-ROOT; this tool signs only with rehearsal keys"
        ));
    }
    let seed = hex_dec(v["seed"].as_str().unwrap_or(""));
    let seed: [u8; 32] = seed
        .try_into()
        .unwrap_or_else(|_| die("the seed is not 32 bytes"));
    crypto::TestRootSlh::generate(&mut ChaCha20Rng::from_seed(seed))
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match (a.first().map(String::as_str), a.get(1), a.get(2)) {
        (Some("keygen"), Some(path), None) => {
            if Path::new(path).exists() {
                die(&format!("{path} exists; a root key is never overwritten"));
            }
            let mut seed = [0u8; 32];
            fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut seed))
                .unwrap_or_else(|e| die(&format!("no entropy from /dev/urandom: {e}")));
            let body =
                serde_json::json!({ "label": LABEL, "seed": hex_enc(&seed) }).to_string() + "\n";
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap_or_else(|e| die(&format!("{path}: {e}")));
            f.write_all(body.as_bytes())
                .unwrap_or_else(|e| die(&format!("{path}: {e}")));
            let k = load(path);
            println!("{}", b64::encode(&k.public()));
            eprintln!("slh-root: TEST-ROOT key written to {path} (0600); the line above is its public key");
        }
        (Some("pub"), Some(path), None) => println!("{}", b64::encode(&load(path).public())),
        (Some("sign"), Some(path), Some(msghex)) => {
            let msg = hex_dec(msghex);
            let sig = load(path)
                .sign(&msg)
                .unwrap_or_else(|e| die(&format!("signing failed: {e}")));
            println!("{}", b64::encode(&sig));
            eprintln!("slh-root: TEST-ROOT signature over {} byte(s)", msg.len());
        }
        _ => {
            eprintln!("usage: slh-root keygen <keyfile> | pub <keyfile> | sign <keyfile> <msghex>   (TEST-ROOT only)");
            std::process::exit(2);
        }
    }
}
