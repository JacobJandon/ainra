// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The witnessed epoch log (PLAN-M52 step 10, D-097).
//!
//! The root's one act is a directory epoch. `ctl` remembers the epochs it has seen, so ONE observer notices a
//! rewritten epoch — but a host could show one history to some observers and another to the rest, and none of them
//! would know. The epoch log closes that: every archived epoch becomes a leaf of an RFC 6962 tree (origin
//! `ainra-directory`), and independent witnesses cosign its head. Two observers holding cosignatures from the same
//! witness hold the same history, or that witness signed two different histories — evidence anyone can check.
//!
//! The log needs no operator key. Each leaf is the digest of a directory that verifies under both roots, so anyone
//! recomputes the head from the epochs the contract already serves. A witness verifies every leaf itself and keeps a
//! memory (each epoch's digest, the last head), saved before it signs, under the same rules as `witnessd` (D-087).
//!
//!   ainra directory log     --net <url|dir> --roots <r> [--write <dir>] [--add-cosig <cosig.json>]…
//!   ainra directory witness --net <url|dir> --roots <pinned> --key <file> --state <file> [--out <cosig.json>]
//!
//! `ctl status` recomputes the head, alarms if the served `epoch-log.json` disagrees or a served cosignature does not
//! verify, and counts the cosignatures of the witnesses it pins (`--epoch-witness <key>`).
//!
//! WITNESS: `tools/epoch-log-drill.sh` — a witness cosigns growth; two different epoch-N digests shown to one witness
//! are refused (and `ctl`, with its memory, alarms); a leaf whose directory does not verify is refused; a shrunk log is
//! refused; a forged cosignature and a served head that lies each make `ctl` alarm; and with the witness's memory
//! deleted the equivocating history is cosigned — the memory is load-bearing.

use std::path::Path;

use ainra_core::{b64, crypto, merkle};
use serde_json::{json, Value};

pub const ORIGIN: &str = "ainra-directory";

/// The bytes of one leaf: the epoch and its signed-bytes digest. RFC 6962 hashes it with the 0x00 prefix.
pub fn leaf_data(epoch: u64, digest: &str) -> Vec<u8> {
    format!("ainra-directory/v1\n{epoch}\n{digest}\n").into_bytes()
}

/// RFC 6962 §2.1 Merkle Tree Hash over leaf hashes.
fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    match leaves.len() {
        0 => Sha256::digest(b"").into(),
        1 => leaves[0],
        n => {
            let mut k = 1; // the largest power of two strictly below n
            while k * 2 < n {
                k *= 2;
            }
            merkle::hash_node(&mth(&leaves[..k]), &mth(&leaves[k..]))
        }
    }
}

/// The head of the log over the first `size` entries of `history` (each (epoch, digest), epochs 1, 2, …).
pub fn root_at(history: &[(u64, String)], size: usize) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = history[..size]
        .iter()
        .map(|(n, d)| merkle::hash_leaf(&leaf_data(*n, d)))
        .collect();
    mth(&leaves)
}

/// The text a witness signs: origin, size, root — one per line.
pub fn checkpoint_text(size: u64, root: &[u8; 32]) -> String {
    format!("{ORIGIN}\n{size}\n{}\n", b64::encode(root))
}

/// Does this cosignature verify over the head of the first `size` epochs of `history`?
pub fn cosig_verifies(c: &Value, history: &[(u64, String)]) -> Result<u64, String> {
    let size = c["size"].as_u64().ok_or("no size")? as usize;
    if c["origin"].as_str() != Some(ORIGIN) {
        return Err("another origin".into());
    }
    if size == 0 || size > history.len() {
        return Err(format!(
            "size {size}, but the log has {} epoch(s)",
            history.len()
        ));
    }
    let root = root_at(history, size);
    if c["root"].as_str() != Some(&b64::encode(&root)) {
        return Err(format!(
            "its root for size {size} is not the root these epochs make — a different history"
        ));
    }
    let pk: [u8; crypto::ED25519_PK] = b64::decode_array(c["witness_key"].as_str().unwrap_or(""))
        .map_err(|_| "bad witness_key")?;
    let sig: [u8; crypto::ED25519_SIG] =
        b64::decode_array(c["sig"].as_str().unwrap_or("")).map_err(|_| "bad sig")?;
    if !crypto::ed25519_verify(&pk, checkpoint_text(size as u64, &root).as_bytes(), &sig) {
        return Err("the signature does not verify".into());
    }
    Ok(size as u64)
}

/// Read a contract's epochs and verify each one: listed in order from epoch 1, served, signed under both roots, and
/// carrying the digest the index lists. Any failure refuses the whole log, by name.
pub fn history(net: &str, roots: &[u8]) -> Result<Vec<(u64, String)>, String> {
    let index = crate::ctl::fetch_json(net, "epochs.json")?;
    let list = index["epochs"].as_array().cloned().unwrap_or_default();
    let mut out = Vec::new();
    for (i, e) in list.iter().enumerate() {
        let n = e["epoch"].as_u64().unwrap_or(0);
        if n != i as u64 + 1 {
            return Err(format!(
                "REFUSED: the epoch log runs 1, 2, 3, …; entry {} is epoch {n}",
                i + 1
            ));
        }
        let path = e["path"]
            .as_str()
            .map(String::from)
            .unwrap_or(format!("epochs/{n}.json"));
        let b = crate::ctl::fetch(net, &path)
            .map_err(|_| format!("REFUSED: epoch {n} is listed but {path} is not served"))?;
        if !crate::ctl::authentic(&b, roots) {
            return Err(format!("REFUSED: epoch {n} ({path}) does not verify under both roots — it cannot be a leaf"));
        }
        let id = crate::ctl::identity(&b).ok_or(format!("REFUSED: {path} is not a directory"))?;
        let digest = id["digest"].as_str().unwrap_or("").to_string();
        if id["epoch"].as_u64() != Some(n) || e["digest"].as_str() != Some(digest.as_str()) {
            return Err(format!("REFUSED: epochs.json says epoch {n} is {}, but {path} is epoch {} with digest {digest}", e["digest"], id["epoch"]));
        }
        out.push((n, digest));
    }
    if out.is_empty() {
        return Err("REFUSED: the contract lists no epochs".into());
    }
    Ok(out)
}

fn head_json(history: &[(u64, String)]) -> Value {
    let size = history.len() as u64;
    let root = root_at(history, history.len());
    json!({ "origin": ORIGIN, "size": size, "root": b64::encode(&root), "checkpoint": checkpoint_text(size, &root),
            "leaf": "SHA-256(0x00 || \"ainra-directory/v1\\n\" || epoch || \"\\n\" || digest || \"\\n\") (RFC 6962)",
            "leaves": history.iter().map(|(n, d)| json!({ "epoch": n, "digest": d })).collect::<Vec<_>>() })
}

fn write_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Recompute the head from an archive directory and write `<into>/epoch-log.json` (the archive calls this after every
/// append, and on a re-run, so a published record always carries the head its epochs make).
pub fn write_head(into: &Path, roots: &[u8]) -> Result<String, String> {
    let h = history(&into.to_string_lossy(), roots)?;
    let head = head_json(&h);
    write_atomic(
        &into.join("epoch-log.json"),
        &(serde_json::to_string_pretty(&head).unwrap() + "\n"),
    )
    .map_err(|e| {
        format!(
            "cannot write {}: {e}",
            into.join("epoch-log.json").display()
        )
    })?;
    Ok(format!(
        "epoch log head: size {} · root {}",
        head["size"],
        head["root"].as_str().unwrap_or("")
    ))
}

/// `ainra directory log`
pub fn log(args: &[String]) -> i32 {
    let (Some(net), Some(roots_p)) = (crate::ctl::opt(args, "net"), crate::ctl::opt(args, "roots"))
    else {
        eprintln!("usage: ainra directory log --net <url|dir> --roots <roots.json> [--write <dir>] [--add-cosig <cosig.json>]…");
        return 2;
    };
    let Ok(roots) = std::fs::read(roots_p) else {
        eprintln!("cannot read {roots_p}");
        return 2;
    };
    let h = match history(net, &roots) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let head = head_json(&h);
    println!(
        "epoch log {ORIGIN}: size {} · root {}",
        head["size"],
        head["root"].as_str().unwrap_or("")
    );
    let Some(dir) = crate::ctl::opt(args, "write") else {
        return 0;
    };
    let dir = Path::new(dir);
    let mut text = serde_json::to_string_pretty(&head).unwrap() + "\n";
    if let Err(e) = write_atomic(&dir.join("epoch-log.json"), &text) {
        eprintln!("cannot write {}: {e}", dir.join("epoch-log.json").display());
        return 2;
    }
    println!("wrote {}", dir.join("epoch-log.json").display());
    // cosignatures: kept only if they verify over this history; one per witness key and size
    let cpath = dir.join("epoch-log-cosignatures.json");
    let mut list: Vec<Value> = std::fs::read(&cpath)
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v["cosignatures"].as_array().cloned())
        .unwrap_or_default();
    let adds = crate::ctl::opt_all(args, "add-cosig");
    for f in &adds {
        let c: Value = match std::fs::read(f)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
        {
            Some(c) => c,
            None => {
                eprintln!("REFUSED: {f} is not a cosignature");
                return 1;
            }
        };
        if let Err(e) = cosig_verifies(&c, &h) {
            eprintln!("REFUSED: {f} — {e}");
            return 1;
        }
        let same = |x: &Value| x["witness_key"] == c["witness_key"] && x["size"] == c["size"];
        if !list.iter().any(same) {
            list.push(c);
        }
    }
    if !adds.is_empty() || cpath.exists() {
        list.sort_by_key(|c| {
            (
                c["size"].as_u64().unwrap_or(0),
                c["witness_key"].as_str().unwrap_or("").to_string(),
            )
        });
        text = serde_json::to_string_pretty(&json!({ "origin": ORIGIN, "cosignatures": list }))
            .unwrap()
            + "\n";
        if let Err(e) = write_atomic(&cpath, &text) {
            eprintln!("cannot write {}: {e}", cpath.display());
            return 2;
        }
        println!("wrote {} ({} cosignature(s))", cpath.display(), list.len());
    }
    0
}

/// `ainra directory witness`
pub fn witness(args: &[String]) -> i32 {
    let need = ["net", "roots", "key", "state"];
    if need.iter().any(|k| crate::ctl::opt(args, k).is_none()) {
        eprintln!("usage: ainra directory witness --net <url|dir> --roots <pinned roots.json> --key <file> --state <file> [--out <cosig.json>]");
        return 2;
    }
    let o = |k| crate::ctl::opt(args, k).unwrap();
    let Ok(roots) = std::fs::read(o("roots")) else {
        eprintln!("cannot read {}", o("roots"));
        return 2;
    };
    // the key: a random 32-byte seed, made only when the file is MISSING (any other read error is an identity this
    // process cannot see, and replacing it would be losing it — D-087)
    let key_path = Path::new(o("key"));
    let hex = match std::fs::read_to_string(key_path) {
        Ok(t) => t.trim().to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut seed = [0u8; 32];
            if let Err(e) = std::fs::File::open("/dev/urandom")
                .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed))
            {
                eprintln!("cannot read /dev/urandom for a new key: {e}");
                return 2;
            }
            let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
            let made = {
                use std::io::Write;
                #[cfg(unix)]
                use std::os::unix::fs::OpenOptionsExt;
                let mut oo = std::fs::OpenOptions::new();
                oo.write(true).create_new(true);
                #[cfg(unix)]
                oo.mode(0o600);
                oo.open(key_path)
                    .and_then(|mut f| f.write_all(hex.as_bytes()).and_then(|_| f.sync_all()))
            };
            if let Err(e) = made {
                eprintln!("cannot write the new key to {}: {e}", key_path.display());
                return 2;
            }
            eprintln!(
                "made a new random witness key in {} (keep it: it is this witness's identity)",
                key_path.display()
            );
            hex
        }
        Err(e) => {
            eprintln!(
                "cannot read the key in {}: {e} — refusing to act under a new identity",
                key_path.display()
            );
            return 2;
        }
    };
    let Some(seed) = (hex.len() == 64)
        .then(|| {
            (0..32)
                .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok())
                .collect::<Option<Vec<u8>>>()
        })
        .flatten()
    else {
        eprintln!("{} does not hold a 32-byte hex key", key_path.display());
        return 2;
    };
    let key = {
        use rand_chacha::rand_core::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed.try_into().unwrap());
        crypto::TestDelegate::generate(&mut rng)
    };
    // the memory: each epoch's digest and the last head; a state file that exists but cannot be read stops here
    let state_path = Path::new(o("state"));
    let state: Value = match std::fs::read(state_path) {
        Ok(b) => match serde_json::from_slice(&b) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("{} exists but is not readable state — refusing to forget what this witness has seen", state_path.display());
                return 2;
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            json!({ "origin": ORIGIN, "size": 0, "root": null, "epochs": {} })
        }
        Err(e) => {
            eprintln!("cannot read {}: {e}", state_path.display());
            return 2;
        }
    };
    let h = match history(o("net"), &roots) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let seen = state["epochs"].as_object().cloned().unwrap_or_default();
    for (n, d) in &h {
        if let Some(old) = seen.get(&n.to_string()).and_then(Value::as_str) {
            if old != d {
                eprintln!("REFUSED: split view — epoch {n} was shown to this witness as {old}, and is now {d}. Not cosigned.");
                return 1;
            }
        }
    }
    let old_size = state["size"].as_u64().unwrap_or(0);
    if (h.len() as u64) < old_size {
        eprintln!(
            "REFUSED: the log shrank from {old_size} to {} epoch(s). Not cosigned.",
            h.len()
        );
        return 1;
    }
    if old_size > 0 && state["root"].as_str() != Some(&b64::encode(&root_at(&h, old_size as usize)))
    {
        eprintln!("REFUSED: the first {old_size} epoch(s) no longer make the head this witness cosigned. Not cosigned.");
        return 1;
    }
    let size = h.len() as u64;
    let root = root_at(&h, h.len());
    let sig = key.sign(checkpoint_text(size, &root).as_bytes());
    let cosig = json!({ "origin": ORIGIN, "size": size, "root": b64::encode(&root),
        "witness_key": b64::encode(&key.public()), "sig": b64::encode(&sig) });
    // remember first, then answer: a cosignature this witness would not remember is never given
    let mut epochs = seen;
    for (n, d) in &h {
        epochs.insert(n.to_string(), json!(d));
    }
    let next =
        json!({ "origin": ORIGIN, "size": size, "root": b64::encode(&root), "epochs": epochs });
    if let Err(e) = write_atomic(
        state_path,
        &(serde_json::to_string_pretty(&next).unwrap() + "\n"),
    ) {
        eprintln!(
            "cannot save the witness state to {}: {e} — not cosigned",
            state_path.display()
        );
        return 2;
    }
    let text = serde_json::to_string_pretty(&cosig).unwrap() + "\n";
    match crate::ctl::opt(args, "out") {
        Some(f) => {
            if std::fs::write(f, &text).is_err() {
                eprintln!("cannot write {f}");
                return 2;
            }
            println!("cosigned {ORIGIN} at size {size} → {f}");
        }
        None => print!("{text}"),
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_head_is_rfc6962_over_the_epoch_leaves() {
        // the fixture log in ainra-core is the reference RFC 6962 implementation for every size up to 33
        for n in 1..=33u64 {
            let h: Vec<(u64, String)> = (1..=n).map(|i| (i, format!("{i:064x}"))).collect();
            let mut t = merkle::TestLog::new();
            for (e, d) in &h {
                t.append(&leaf_data(*e, d));
            }
            assert_eq!(root_at(&h, h.len()), t.root(), "size {n}");
        }
    }

    #[test]
    fn a_cosignature_binds_one_history() {
        let h: Vec<(u64, String)> = (1..=3).map(|i| (i, format!("{i:064x}"))).collect();
        let mut rng =
            <rand_chacha::ChaCha20Rng as rand_chacha::rand_core::SeedableRng>::from_seed([7; 32]);
        let k = crypto::TestDelegate::generate(&mut rng);
        let root = root_at(&h, 3);
        let c = json!({ "origin": ORIGIN, "size": 3, "root": b64::encode(&root), "witness_key": b64::encode(&k.public()),
                        "sig": b64::encode(&k.sign(checkpoint_text(3, &root).as_bytes())) });
        assert_eq!(cosig_verifies(&c, &h), Ok(3));
        let mut other = h.clone();
        other[1].1 = format!("{:064x}", 99);
        assert!(
            cosig_verifies(&c, &other).is_err(),
            "the same cosignature must not verify over another history"
        );
    }
}
