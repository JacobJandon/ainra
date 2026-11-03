// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `witnessd` daemon: POST /consider {origin,size,root_b64,consistency_proof_b64[], checkpoint_sig | checkpoint_sig_b64}
//! → the outcome (and a cosignature when it cosigns). Refuses forks + regressions. GET /key (alias /root) → the
//! witness public key. GET /seen → the last head it cosigned per log. GET /info → the operator's SELF-DECLARED
//! metadata (never verified by anyone). Local, zero telemetry.
//!
//! Usage:  witnessd <addr> [config.json]
//! The optional one-file config (all fields optional):
//!   { "key_file": "…", "state_file": "…", "directory": "…", "roots": "…",
//!     "seed": "<hex>", "operator": "…", "region": "…", "contact": "…", "note": "…" }
//!
//! What a witness a stranger runs needs (PLAN-M51 witness work), and why each is here:
//!   * `key_file` — a random key, made on first start (0600) and kept; only a MISSING file makes one, any other read
//!     error stops the daemon rather than replace an identity. Off loopback it is required: an address-derived key,
//!     or one from a `seed` phrase in a config, can be computed by anyone who sees the phrase or the address.
//!   * `state_file` — the last head cosigned per log, and the log key each is held to, kept across restarts and saved
//!     (and fsynced) before a cosignature is returned. A witness that forgets trusts the next checkpoint on first
//!     sight, a fork included, so a state file that exists but cannot be read stops the daemon too.
//!   * `directory` + `roots` — the root-signed directory (a copy is published at ainra.org/net/): every log key, and
//!     the revoked delegates, come from it, and a key a caller sends is ignored. Required off loopback. Only a
//!     loopback drill may run without one, holding each log to the first key that actually verified its checkpoint.
//!   * its own clock — the delegate cert a checkpoint is signed under is judged at the witness's time, never the
//!     caller's (`AINRA_CLOCK=pinned` lets a hermetic drill supply `now`, as for every other daemon here).
//!
//! Everything under operator/region/contact/note is SELF-DECLARED — `/info` serves it with `self_declared: true`.

use std::sync::Mutex;

use ainra_core::checkpoint::{Checkpoint, CheckpointSig};
use ainra_core::{b64, crypto};
use ainra_services::http::{serve, Request};
use ainra_services::registrar::WireCheckpointSig;
use ainra_services::witness::{Witness, WitnessOutcome, WitnessState};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

fn decode32(s: &str) -> Option<[u8; 32]> {
    b64::decode_array::<32>(s).ok()
}

fn die(msg: &str) -> ! {
    eprintln!("witnessd: {msg}");
    std::process::exit(2);
}

fn loopback(addr: &str) -> bool {
    addr.starts_with("127.") || addr.starts_with("[::1]") || addr.starts_with("localhost:")
}

fn wall_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A random 32-byte seed from the OS, hex — the content of a new `key_file`.
fn fresh_seed_hex() -> String {
    let mut buf = [0u8; 32];
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .unwrap_or_else(|e| die(&format!("cannot read /dev/urandom for a new key: {e}")));
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Write `text` to `path` atomically (temp file, then rename), owner-only when `secret`.
fn write_file(path: &str, text: &str, secret: bool) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = format!("{path}.tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    // The rename is durable only once the directory entry is: without this a crash could bring back the old state
    // after a cosignature over the new head had already gone out.
    let dir = std::path::Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    std::fs::File::open(dir)?.sync_all()
}

fn state_to_json(s: &WitnessState) -> String {
    let seen: serde_json::Map<String, serde_json::Value> = s
        .seen
        .iter()
        .map(|(o, (size, root))| {
            (
                o.clone(),
                serde_json::json!({ "size": size, "root": b64::encode(root) }),
            )
        })
        .collect();
    let keys: serde_json::Map<String, serde_json::Value> = s
        .log_keys
        .iter()
        .map(|(o, k)| (o.clone(), serde_json::json!(b64::encode(k))))
        .collect();
    serde_json::json!({ "seen": seen, "log_keys": keys }).to_string()
}

fn state_from_json(text: &str) -> Option<WitnessState> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let mut s = WitnessState::default();
    for (o, e) in v.get("seen")?.as_object()? {
        s.seen.insert(
            o.clone(),
            (
                e.get("size")?.as_u64()?,
                decode32(e.get("root")?.as_str()?)?,
            ),
        );
    }
    for (o, k) in v.get("log_keys")?.as_object()? {
        s.log_keys.insert(o.clone(), b64::decode(k.as_str()?).ok()?);
    }
    Some(s)
}

/// The log keys of every registrar in a root-signed directory, as `ainra-log/<registrar>` → SLH-DSA key, and the
/// delegate certs it revokes.
type DirectoryKeys = (Vec<(String, Vec<u8>)>, std::collections::BTreeSet<[u8; 32]>);
fn log_keys_from_directory(directory: &str, roots: &str) -> DirectoryKeys {
    let read = |p: &str| {
        std::fs::read_to_string(p).unwrap_or_else(|e| die(&format!("cannot read {p}: {e}")))
    };
    let d: ainra_core::directory::Directory = serde_json::from_str(&read(directory))
        .unwrap_or_else(|e| die(&format!("{directory} is not a directory: {e}")));
    let r: serde_json::Value =
        serde_json::from_str(&read(roots)).unwrap_or_else(|e| die(&format!("{roots}: {e}")));
    let (Some(ed), Some(slh)) = (
        r.get("root_ed25519")
            .and_then(|x| x.as_str())
            .and_then(decode32),
        r.get("root_slh")
            .and_then(|x| x.as_str())
            .and_then(|s| b64::decode(s).ok()),
    ) else {
        die(&format!("{roots} must carry root_ed25519 and root_slh"));
    };
    let acc = d.accredit(&ed, &slh).unwrap_or_else(|_| {
        die("the directory does not verify against the roots — refusing to witness on its word")
    });
    let keys = acc
        .anchors
        .registrars
        .iter()
        .map(|(id, info)| (format!("ainra-log/{id}"), info.log_root_key.clone()))
        .collect();
    (keys, acc.revoked_delegates)
}

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4883".to_string());
    // Optional one-file config (arg 2). Absent / unreadable / a non-JSON path (e.g. a legacy data-dir arg) → no
    // declared metadata. Witnessing needs no accreditation; only the key rules below can refuse a start.
    let cfg: serde_json::Value = std::env::args()
        .nth(2)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::Value::Null);
    let field = |k: &str| {
        cfg.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };

    // Key: `key_file` (random, kept), else `seed` (a phrase), else derived from the address — loopback only.
    let seed_rng = |hex: &str| ChaCha20Rng::from_seed(Sha256::digest(hex.as_bytes()).into());
    if !field("key_file").is_empty() && !field("seed").is_empty() {
        die("the config has both `key_file` and `seed` — choose one; they are two different identities");
    }
    if !loopback(&addr) && field("key_file").is_empty() {
        die(&format!(
            "listening on {addr} with no `key_file` in the config — an address-derived key, or one from a `seed` \
             phrase, can be computed by anyone who knows the address or the phrase, so its cosignatures would prove \
             nothing. Add \"key_file\": \"witness.key\" (see kits/witness)."
        ));
    }
    if !loopback(&addr) && (field("directory").is_empty() || field("roots").is_empty()) {
        die(&format!(
            "listening on {addr} with no `directory` + `roots` — a public witness takes every log's key from the \
             root-signed directory (a copy is at https://ainra.org/net/directory.json and roots.json), never from \
             whoever reaches it first."
        ));
    }
    let mut rng = if !field("key_file").is_empty() {
        let path = field("key_file");
        let hex = match std::fs::read_to_string(&path) {
            Ok(t) => t.trim().to_string(),
            // ONLY a missing file makes a new key. Anything else — unreadable, not text, a directory — is an identity
            // this process cannot see, and replacing it would be losing it.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let hex = fresh_seed_hex();
                write_file(&path, &hex, true)
                    .unwrap_or_else(|e| die(&format!("cannot write the new key to {path}: {e}")));
                eprintln!("witnessd: made a new random key in {path} (keep it; it is this witness's identity)");
                hex
            }
            Err(e) => die(&format!(
                "cannot read the key in {path}: {e} — refusing to start under a new identity"
            )),
        };
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            die(&format!("{path} does not hold a 32-byte hex key"));
        }
        seed_rng(&hex)
    } else if !field("seed").is_empty() {
        seed_rng(&field("seed"))
    } else {
        if !loopback(&addr) {
            die(&format!(
                "listening on {addr} with no `key_file` in the config — an address-derived key can be computed by \
                 anyone, so its cosignatures would prove nothing. Add \"key_file\": \"witness.key\" (see kits/witness)."
            ));
        }
        // Loopback drills: N processes on N ports get DISTINCT keys, never one key under many addresses.
        let mut seed = 0xcbf2_9ce4_8422_2325u64;
        for byte in addr.bytes() {
            seed ^= u64::from(byte);
            seed = seed.wrapping_mul(0x0000_0100_0000_01b3);
        }
        ChaCha20Rng::seed_from_u64(seed)
    };
    let mut witness = Witness::new(crypto::TestDelegate::generate(&mut rng));

    let pinned_keys = !field("directory").is_empty();
    if pinned_keys {
        if field("roots").is_empty() {
            die("`directory` needs `roots` beside it — a directory is trusted only through the root keys");
        }
        let (keys, revoked) = log_keys_from_directory(&field("directory"), &field("roots"));
        for (origin, key) in keys {
            witness.register_log(&origin, key);
        }
        witness.set_revoked_delegates(revoked);
    }
    let state_file = field("state_file");
    if !state_file.is_empty() {
        match std::fs::read_to_string(&state_file) {
            Ok(text) => {
                let mut s = state_from_json(&text).unwrap_or_else(|| {
                    die(&format!("{state_file} will not load — refusing to forget what it held"))
                });
                // With a directory, the directory is the only source of log keys: a key saved for a registrar it
                // no longer lists (withdrawn, say) must not come back through the state file.
                if pinned_keys {
                    s.log_keys.clear();
                }
                witness.restore(s);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // first start: nothing to remember yet
            Err(e) => die(&format!(
                "cannot read {state_file}: {e} — refusing to start with no memory of what it cosigned"
            )),
        }
    }
    let clock_pinned = std::env::var("AINRA_CLOCK").ok().as_deref() == Some("pinned");
    let witness = Mutex::new(witness);

    serve(&addr, move |req: &Request| {
        let mut w = witness.lock().unwrap();
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/key") | ("GET", "/root") => (
                200,
                serde_json::json!({ "ed25519": b64::encode(&w.public()) }).to_string(),
            ),
            ("GET", "/seen") => {
                let seen: serde_json::Map<String, serde_json::Value> = w
                    .last_cosigned()
                    .iter()
                    .map(|(o, (size, root))| {
                        (o.clone(), serde_json::json!({ "size": size, "root": b64::encode(root) }))
                    })
                    .collect();
                (200, serde_json::Value::Object(seen).to_string())
            }
            // SELF-DECLARED — the operator's own claim, verified by no one; the key is the only cryptographic fact.
            ("GET", "/info") => (
                200,
                serde_json::json!({
                    "self_declared": true,
                    "ed25519": b64::encode(&w.public()),
                    "operator": field("operator"),
                    "region": field("region"),
                    "contact": field("contact"),
                    "note": field("note"),
                    "log_keys_from_directory": pinned_keys,
                })
                .to_string(),
            ),
            ("POST", "/consider") => {
                let v: serde_json::Value = match serde_json::from_str(&req.body) {
                    Ok(v) => v,
                    Err(_) => return (400, r#"{"error":"bad json"}"#.to_string()),
                };
                let root = match v
                    .get("root_b64")
                    .and_then(|s| s.as_str())
                    .and_then(decode32)
                {
                    Some(r) => r,
                    None => return (400, r#"{"error":"root_b64 required"}"#.to_string()),
                };
                let cp = Checkpoint {
                    origin: v
                        .get("origin")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string(),
                    tree_size: v.get("size").and_then(|x| x.as_u64()).unwrap_or(0),
                    root,
                };
                let proof: Vec<[u8; 32]> = v
                    .get("consistency_proof_b64")
                    .and_then(|a| a.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|s| s.as_str())
                            .filter_map(decode32)
                            .collect()
                    })
                    .unwrap_or_default();
                // Either the registrar's own wire form (root or ADR-002 delegate mode, exactly as `/witness-feed`
                // and `/present` serve it) or the bare root-mode SLH signature of the original protocol.
                let sig: Option<CheckpointSig> = match (v.get("checkpoint_sig"), v.get("checkpoint_sig_b64")) {
                    (Some(wire), _) => serde_json::from_value::<WireCheckpointSig>(wire.clone())
                        .ok()
                        .and_then(|w| w.to_core()),
                    (None, Some(s)) => s
                        .as_str()
                        .and_then(|s| b64::decode(s).ok())
                        .map(|slh| CheckpointSig::Root { slh }),
                    _ => None,
                };
                let Some(sig) = sig else {
                    return (
                        400,
                        r#"{"error":"checkpoint_sig (or checkpoint_sig_b64) required"}"#.to_string(),
                    );
                };
                let now = if clock_pinned {
                    v.get("now").and_then(|x| x.as_u64()).unwrap_or(0)
                } else {
                    wall_now()
                };
                                // The witness cosigns only checkpoints validly signed by the LOG's own key (review #11). With a
                // directory, the key is the directory's and nothing a caller sends changes it. Without one (loopback
                // drills only), a caller's key is taken for a log this witness has no key for — and only if it
                // verifies the very checkpoint it came with, so a stray request cannot lock a log to a junk key.
                if !pinned_keys && !w.knows_log(&cp.origin) {
                    if let Some(k) = v
                        .get("log_root_key_b64")
                        .and_then(|s| s.as_str())
                        .and_then(|s| b64::decode(s).ok())
                    {
                        if cp.verify_sig_mode(&k, &sig, now).is_ok() {
                            w.register_log(&cp.origin, k);
                        }
                    }
                }
                let before = w.state();
                let outcome = w.consider(&cp, &sig, now, &proof);
                let cosigned = matches!(
                    outcome,
                    WitnessOutcome::Cosigned | WitnessOutcome::CosignedFirstSight
                );
                if cosigned && !state_file.is_empty() {
                    // Kept BEFORE the answer: a cosignature handed out and then forgotten is the fork hole itself.
                                        if let Err(e) = write_file(&state_file, &state_to_json(&w.state()), false) {
                        w.replace_state(before); // memory and disk must agree on what was cosigned: neither moved
                        return (
                            500,
                            serde_json::json!({ "error": format!("state not saved, cosignature withheld: {e}") })
                                .to_string(),
                        );
                    }
                }
                let cosig = cosigned.then(|| b64::encode(&w.cosign(&cp)));
                let name = match outcome {
                    WitnessOutcome::CosignedFirstSight => "cosigned_first_sight",
                    WitnessOutcome::Cosigned => "cosigned",
                    WitnessOutcome::RefusedRegression => "refused_regression",
                    WitnessOutcome::RefusedFork => "refused_fork",
                    WitnessOutcome::RefusedUnsigned => "refused_unsigned",
                };
                (
                    200,
                    serde_json::json!({ "outcome": name, "cosignature": cosig }).to_string(),
                )
            }
            _ => (404, r#"{"error":"not found"}"#.to_string()),
        }
    })
    .unwrap();
}
