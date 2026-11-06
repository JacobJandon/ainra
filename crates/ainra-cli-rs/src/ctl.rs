// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ainra ctl` and `ainra directory` — the control room that only reads, and the epoch archive (PLAN-M52 steps 1–2).
//!
//! The root's one act is a new directory epoch (D-088). These commands watch that act and everything that hangs off
//! it, from the public read contract alone, so anyone sees what the operator sees:
//!
//!   ainra directory digest  <directory.json>                       which directory is this (epoch, signed-bytes hash)
//!   ainra directory archive <directory.json> --roots <r> --into <d> keep it: epochs/<N>.json + epochs.json, append-only
//!   ainra ctl status --net <url|dir> [--roots <pinned.json>] [--mirror <url|dir>]… [--state <file>] [--max-age <s>] [--now <unix s>]
//!   (--max-age defaults to the published quarterly cadence, D-094)
//!   ainra ctl diff <N> <M> --net <url|dir>                         what changed between two epochs
//!   ainra ctl watch --net <url|dir> [--interval <s>] …             status, again and again
//!
//! The workbench commands that follow an epoch's life before it is archived — `request`, `check-request`, `propose`,
//! `check-proposal`, `sign-request`, `assemble` and `publish` (PLAN-M52 steps 5–8) — are in `workbench.rs`; `publish`
//! archives through the same `archive_into` as `archive`.
//!
//! `ctl` signs nothing, writes to no registrar, sends nothing anywhere, and exits 1 on any alarm (so it can be a cron
//! job or a CI step). It remembers what it last saw (`~/.ainra-ctl/seen.json`, or `--state`) and only moves that memory
//! forward on a run with no alarm, so a rollback is never learned as the new normal. Fetching uses `curl` for http(s)
//! — the bytes need no trust in the transport, because everything that matters is signed or hash-pinned and checked
//! here — or reads a local directory.
//!
//! WITNESS: `tools/ctl-drill.sh` builds contracts from the signed epoch vectors and requires an alarm, by name, for a
//! rollback, an equivocating epoch, an index that skips an epoch or lies about a digest, a shrinking log, a forked log,
//! a rewound status sequence, a mirror that disagrees, and a stale directory — and no alarm for an honest contract.
//! It also shows that deleting the memory file makes the rollback alarm disappear: the memory is load-bearing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

/// The core files every contract serves. Mirrors must agree on each of them byte for byte.
const CORE_FILES: [&str; 4] = [
    "directory.json",
    "roots.json",
    "registry.json",
    "epochs.json",
];

fn fetch(base: &str, path: &str) -> Result<Vec<u8>, String> {
    if base.starts_with("http://") || base.starts_with("https://") {
        let url = format!("{}/{}", base.trim_end_matches('/'), path);
        let out = Command::new("curl")
            .args(["-fsS", "--max-time", "20", &url])
            .output()
            .map_err(|e| format!("curl is needed to fetch {url}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "{url}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(out.stdout)
    } else {
        let p = Path::new(base).join(path);
        std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))
    }
}

fn fetch_json(base: &str, path: &str) -> Result<Value, String> {
    let b = fetch(base, path)?;
    serde_json::from_slice(&b).map_err(|e| format!("{path}: not JSON ({e})"))
}

pub(crate) fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// The identity of a directory (epoch, issue time, signed-bytes digest), through the one decode path.
fn identity(directory: &[u8]) -> Option<Value> {
    let v: Value = serde_json::from_str(&ainra_adapter::directory_identity_json(
        &String::from_utf8_lossy(directory),
    ))
    .ok()?;
    (v["ok"] == json!(true)).then_some(v)
}

/// Does this directory verify against these roots (both signatures)? Through the one decode path.
fn authentic(directory: &[u8], roots: &[u8]) -> bool {
    let out = ainra_adapter::accredit_json(
        &String::from_utf8_lossy(directory),
        &String::from_utf8_lossy(roots),
    );
    serde_json::from_str::<Value>(&out).is_ok_and(|v| v["ok"] == json!(true))
}

fn fingerprint(roots: &Value) -> String {
    let ed = roots["root_ed25519"].as_str().unwrap_or("");
    let slh = roots["root_slh"].as_str().unwrap_or("");
    sha256_hex(format!("{ed}.{slh}").as_bytes())[..16].to_string()
}

// ── ainra directory ─────────────────────────────────────────────────────────────────────────────────────────────

pub fn cmd_directory(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("digest") => {
            let Some(file) = args.get(1) else {
                eprintln!("usage: ainra directory digest <directory.json>");
                return 2;
            };
            match std::fs::read(file).ok().and_then(|b| identity(&b)) {
                Some(id) => {
                    println!("{id}");
                    0
                }
                None => {
                    eprintln!("{file}: not a directory");
                    1
                }
            }
        }
        Some("archive") => archive(&args[1..]),
        Some(
            cmd @ ("check-request" | "request" | "propose" | "check-proposal" | "sign-request"
            | "assemble" | "publish"),
        ) => crate::workbench::run(cmd, &args[1..]),
        _ => {
            eprintln!("{}", crate::workbench::USAGE);
            2
        }
    }
}

pub(crate) fn opt<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    let flag = format!("--{key}");
    args.iter()
        .position(|a| a == &flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

pub(crate) fn opt_all(args: &[String], key: &str) -> Vec<String> {
    let flag = format!("--{key}");
    args.windows(2)
        .filter(|w| w[0] == flag)
        .map(|w| w[1].clone())
        .collect()
}

/// Append a verified directory to `<into>/epochs/<N>.json` and `<into>/epochs.json`. Refuses anything that does not
/// verify, an epoch not newer than the last one archived, and a second, different directory at an archived epoch.
fn archive(args: &[String]) -> i32 {
    let (Some(file), Some(roots), Some(into)) =
        (args.first(), opt(args, "roots"), opt(args, "into"))
    else {
        eprintln!(
            "usage: ainra directory archive <directory.json> --roots <roots.json> --into <dir>"
        );
        return 2;
    };
    let (Ok(dir), Ok(roots)) = (std::fs::read(file), std::fs::read(roots)) else {
        eprintln!("cannot read {file} or the roots");
        return 2;
    };
    match archive_into(&dir, &roots, Path::new(into), Value::Null, Value::Null) {
        Ok(msg) => {
            println!("{msg}");
            0
        }
        Err((code, msg)) => {
            eprintln!("{msg}");
            code
        }
    }
}

/// The archive's last epoch and its digest, if it has one (what `ainra directory publish` extends).
pub(crate) fn archive_last(into: &Path) -> Option<(u64, String)> {
    let index: Value =
        serde_json::from_slice(&std::fs::read(into.join("epochs.json")).ok()?).ok()?;
    index["epochs"]
        .as_array()?
        .iter()
        .filter_map(|e| Some((e["epoch"].as_u64()?, e["digest"].as_str()?.to_string())))
        .max_by_key(|(n, _)| *n)
}

/// Append a verified directory to `<into>/epochs/<N>.json` and the index, recording the proposal and ceremony it came
/// from (`null` when it did not come through `publish`). `Ok` carries the line to print; `Err` the exit code and why.
pub(crate) fn archive_into(
    dir: &[u8],
    roots: &[u8],
    into: &Path,
    proposal: Value,
    ceremony: Value,
) -> Result<String, (i32, String)> {
    let file = "the directory";
    if !authentic(dir, roots) {
        return Err((1, format!("REFUSED: {file} does not verify under both roots — only a signed directory is archived")));
    }
    let id = identity(dir).expect("an authentic directory has an identity");
    let epoch = id["epoch"].as_u64().unwrap_or(0);
    let digest = id["digest"].as_str().unwrap_or("").to_string();
    let index_path = into.join("epochs.json");
    let mut index: Value = std::fs::read(&index_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| json!({ "version": 1, "epochs": [] }));
    let list = index["epochs"].as_array().cloned().unwrap_or_default();
    if let Some(same) = list.iter().find(|e| e["epoch"].as_u64() == Some(epoch)) {
        if same["digest"].as_str() == Some(&digest) {
            return Ok(format!(
                "epoch {epoch} is already archived with this digest — nothing to do"
            ));
        }
        return Err((1, format!("REFUSED: equivocation — epoch {epoch} is archived with digest {} and this directory's is {digest}", same["digest"].as_str().unwrap_or("?"))));
    }
    if let Some(last) = list.iter().filter_map(|e| e["epoch"].as_u64()).max() {
        if epoch <= last {
            return Err((1, format!("REFUSED: epoch {epoch} is not newer than the last archived epoch {last} (the archive only grows)")));
        }
    }
    let epochs_dir = into.join("epochs");
    std::fs::create_dir_all(&epochs_dir)
        .map_err(|e| (2, format!("{}: {e}", epochs_dir.display())))?;
    let path = epochs_dir.join(format!("{epoch}.json"));
    std::fs::write(&path, dir).map_err(|_| (2, format!("cannot write {}", path.display())))?;
    let mut list = list;
    list.push(json!({
        "epoch": epoch, "digest": digest, "issued_at": id["issued_at"], "sha256": sha256_hex(dir),
        "path": format!("epochs/{epoch}.json"), "proposal": proposal, "ceremony": ceremony,
    }));
    index["epochs"] = Value::Array(list);
    let text = serde_json::to_string_pretty(&index).unwrap() + "\n";
    std::fs::write(&index_path, text)
        .map_err(|_| (2, format!("cannot write {}", index_path.display())))?;
    Ok(format!(
        "archived epoch {epoch} → {} (digest {digest})",
        path.display()
    ))
}

// ── ainra ctl ───────────────────────────────────────────────────────────────────────────────────────────────────

struct Report {
    alarms: Vec<String>,
}

impl Report {
    fn ok(&self, what: &str) {
        println!("  ok     {what}");
    }
    fn info(&self, what: &str) {
        println!("  ·      {what}");
    }
    fn warn(&self, what: &str) {
        println!("  warn   {what}");
    }
    fn alarm(&mut self, what: String) {
        println!("  ALARM  {what}");
        self.alarms.push(what);
    }
}

fn state_path(args: &[String]) -> PathBuf {
    if let Some(p) = opt(args, "state") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    Path::new(&home).join(".ainra-ctl").join("seen.json")
}

/// The ceremony cadence AINRA publishes (D-094 item 3: quarterly). A directory older than this is a stale directory:
/// a host may be withholding a newer epoch (the freeze attack, D-094 item 7).
const PUBLISHED_CADENCE_SECS: u64 = 92 * 86_400;

fn now(args: &[String]) -> u64 {
    opt(args, "now")
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        })
}

pub fn cmd_ctl(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("status") => status(&args[1..]),
        Some("diff") => diff(&args[1..]),
        Some("watch") => {
            let secs: u64 = opt(&args[1..], "interval")
                .and_then(|s| s.parse().ok())
                .unwrap_or(300);
            loop {
                let code = status(&args[1..]);
                println!("(next check in {secs}s; exit {code} this round)\n");
                std::thread::sleep(std::time::Duration::from_secs(secs));
            }
        }
        _ => {
            eprintln!("usage: ainra ctl status --net <url|dir> [--roots <pinned roots.json>] [--mirror <url|dir>]… [--state <file>] [--max-age <secs>] [--fresh-max <secs>]\n       ainra ctl diff <N> <M> --net <url|dir>\n       ainra ctl watch --net <url|dir> [--interval <secs>] (and the status options)");
            2
        }
    }
}

fn status(args: &[String]) -> i32 {
    let Some(net) = opt(args, "net") else {
        eprintln!("ainra ctl status: --net <url|dir> is required");
        return 2;
    };
    let mut r = Report { alarms: Vec::new() };
    println!("ainra ctl status · {net}");
    println!("  (reads only: nothing here can sign, publish or write to any registrar; nothing is sent anywhere)");

    // 1 · roots: shown for out-of-band comparison, and held to a pinned copy if one is given.
    let (Ok(roots_b), Ok(dir_b)) = (fetch(net, "roots.json"), fetch(net, "directory.json")) else {
        eprintln!("cannot fetch roots.json and directory.json from {net}");
        return 2;
    };
    let roots: Value = serde_json::from_slice(&roots_b).unwrap_or(Value::Null);
    let fp = fingerprint(&roots);
    r.info(&format!(
        "root fingerprint {fp} (compare it out of band: site, release notes, another channel)"
    ));
    let roots_used = match opt(args, "roots") {
        Some(p) => match std::fs::read(p) {
            Ok(pinned) => {
                let pinned_v: Value = serde_json::from_slice(&pinned).unwrap_or(Value::Null);
                if fingerprint(&pinned_v) == fp {
                    r.ok(&format!("the contract's roots are the pinned roots ({p})"));
                } else {
                    r.alarm(format!("roots: the contract serves {fp}, the pinned roots are {} — verifying against the pinned ones", fingerprint(&pinned_v)));
                }
                pinned
            }
            Err(e) => {
                eprintln!("{p}: {e}");
                return 2;
            }
        },
        None => {
            r.warn("no --roots pinned: the directory is checked against the roots the same host serves, so a host that replaces both is caught only by the fingerprint above");
            roots_b.clone()
        }
    };

    // 2 · the directory: both signatures, then which one it is.
    let id = identity(&dir_b);
    if !authentic(&dir_b, &roots_used) {
        r.alarm("directory.json does not verify under both roots".into());
    } else {
        r.ok("directory.json verifies under both roots (FROST Ed25519 + SLH-DSA)");
    }
    let (epoch, digest, issued_at) = match &id {
        Some(v) => (
            v["epoch"].as_u64().unwrap_or(0),
            v["digest"].as_str().unwrap_or("").to_string(),
            v["issued_at"].as_u64().unwrap_or(0),
        ),
        None => {
            r.alarm("directory.json is not a directory".into());
            (0, String::new(), 0)
        }
    };
    let registrars: Vec<String> = id
        .as_ref()
        .and_then(|v| v["registrars"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|x| x.as_str().map(String::from))
        .collect();
    r.info(&format!(
        "epoch {epoch} · {} registrar(s) · digest {}",
        registrars.len(),
        &digest[..digest.len().min(16)]
    ));

    // 3 · freshness of the directory itself: the freeze attack (a host that keeps serving an old epoch).
    let t = now(args);
    let age = t.saturating_sub(issued_at);
    // The published cadence is quarterly (D-094 items 3 and 7), pinned here in the signed release so a host cannot
    // relax it; --max-age overrides it for a drill or a different policy.
    let (max, whose) = match opt(args, "max-age").and_then(|s| s.parse::<u64>().ok()) {
        Some(m) => (m, "the --max-age"),
        None => (PUBLISHED_CADENCE_SECS, "the published quarterly"),
    };
    if age > max {
        r.alarm(format!("stale directory: issued {} day(s) ago, {whose} cadence allows {} — a host may be withholding a newer epoch", age / 86_400, max / 86_400));
    } else {
        r.ok(&format!(
            "directory issued {} day(s) ago, within {whose} cadence of {} day(s)",
            age / 86_400,
            max / 86_400
        ));
    }

    // 4 · the epoch history.
    let mut history: Vec<(u64, String)> = Vec::new();
    match fetch(net, "epochs.json") {
        Err(_) => r.warn("no epochs.json: this contract publishes no epoch history, so an earlier epoch cannot be checked or diffed"),
        Ok(b) => match serde_json::from_slice::<Value>(&b) {
            Err(_) => r.alarm("epochs.json is not JSON".into()),
            Ok(index) => {
                let list = index["epochs"].as_array().cloned().unwrap_or_default();
                let mut prev: Option<u64> = None;
                let mut bad = false;
                for e in &list {
                    let n = e["epoch"].as_u64().unwrap_or(0);
                    let claimed = e["digest"].as_str().unwrap_or("");
                    if let Some(p) = prev {
                        if n <= p {
                            r.alarm(format!("epochs.json: epoch {n} listed after {p} (out of order)"));
                            bad = true;
                        } else if n != p + 1 {
                            r.alarm(format!("epochs.json: skips from epoch {p} to {n}"));
                            bad = true;
                        }
                    }
                    prev = Some(n);
                    let path = e["path"].as_str().map(String::from).unwrap_or(format!("epochs/{n}.json"));
                    match fetch(net, &path) {
                        Err(_) => {
                            r.alarm(format!("epochs.json lists epoch {n}, but {path} is not served"));
                            bad = true;
                        }
                        Ok(eb) => {
                            let got = identity(&eb);
                            let got_digest = got.as_ref().and_then(|g| g["digest"].as_str().map(String::from)).unwrap_or_default();
                            let got_epoch = got.as_ref().and_then(|g| g["epoch"].as_u64());
                            if !authentic(&eb, &roots_used) {
                                r.alarm(format!("{path} does not verify under both roots"));
                                bad = true;
                            } else if got_epoch != Some(n) || got_digest != claimed {
                                r.alarm(format!("epochs.json says epoch {n} has digest {}, but {path} is epoch {} with digest {}",
                                    &claimed[..claimed.len().min(16)], got_epoch.unwrap_or(0), &got_digest[..got_digest.len().min(16)]));
                                bad = true;
                            }
                            history.push((n, got_digest));
                        }
                    }
                }
                match list.last() {
                    Some(last) if last["epoch"].as_u64() == Some(epoch) && last["digest"].as_str() == Some(digest.as_str()) => {}
                    Some(last) => {
                        r.alarm(format!("the current directory (epoch {epoch}) is not the newest epoch the index lists (epoch {})", last["epoch"]));
                        bad = true;
                    }
                    None => r.warn("epochs.json lists no epochs"),
                }
                if !bad && !list.is_empty() {
                    r.ok(&format!("epoch history: {} epoch(s), contiguous, each signed, each digest as listed, ending at the current one", list.len()));
                }
            }
        },
    }

    // 5 · registrars: log heads and status sequence, as published.
    let mut heads: BTreeMap<String, Value> = BTreeMap::new();
    for id in &registrars {
        let Ok(export) = fetch_json(net, &format!("registrars/{id}/export.json")) else {
            r.warn(&format!("{id}: no export.json in this contract"));
            continue;
        };
        let (mut size, mut root) = (0u64, String::new());
        // An export lists `{record, verdict}`; the checkpoint a record was logged under is in `record`.
        for entry in export["records"].as_array().into_iter().flatten() {
            let rec = if entry["record"].is_object() {
                &entry["record"]
            } else {
                entry
            };
            let s = rec["checkpoint_size"].as_u64().unwrap_or(0);
            if s >= size {
                size = s;
                root = rec["checkpoint_root"].as_str().unwrap_or("").to_string();
            }
        }
        let seq = export["status_seq"].as_u64().unwrap_or(0);
        let fresh_ts = fetch_json(net, &format!("registrars/{id}/fresh-head.json"))
            .ok()
            .and_then(|h| h["ts"].as_u64());
        let note = match (
            fresh_ts,
            opt(args, "fresh-max").and_then(|s| s.parse::<u64>().ok()),
        ) {
            (Some(ts), Some(max)) if t.saturating_sub(ts) > max => {
                r.alarm(format!(
                    "{id}: fresh head is {}s old, over {max}s",
                    t.saturating_sub(ts)
                ));
                String::new()
            }
            (Some(ts), _) => format!(" · fresh head {}s old", t.saturating_sub(ts)),
            (None, _) => " · no fresh head published".into(),
        };
        r.info(&format!("{id}: log size {size} · status seq {seq}{note}"));
        heads.insert(
            id.clone(),
            json!({ "log_size": size, "log_root": root, "status_seq": seq }),
        );
    }

    // 6 · mirrors: the same bytes everywhere.
    for m in opt_all(args, "mirror") {
        let mut same = true;
        for f in CORE_FILES {
            match (fetch(net, f), fetch(&m, f)) {
                (Ok(a), Ok(b)) if a == b => {}
                (Err(_), Err(_)) => {}
                // The epoch history is newer than the read contract: one side may not publish it yet. That is a gap
                // to close, not two parties disagreeing about what is true.
                (Ok(_), Err(_)) | (Err(_), Ok(_)) if f == "epochs.json" => {
                    r.warn(&format!(
                        "only one of {net} and mirror {m} publishes epochs.json"
                    ));
                }
                _ => {
                    r.alarm(format!("mirror {m} disagrees with {net} on {f}"));
                    same = false;
                }
            }
        }
        if same {
            r.ok(&format!("mirror {m} serves the same bytes"));
        }
    }

    // 7 · memory: nothing goes backwards, and one epoch has one directory.
    let sp = state_path(args);
    let key = format!("{net}#{fp}");
    let mut state: Value = std::fs::read(&sp)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| json!({}));
    let seen = state[&key].clone();
    if seen.is_null() {
        r.info(&format!(
            "first look at this contract from here — remembering it in {}",
            sp.display()
        ));
    } else {
        let seen_epoch = seen["directory"]["epoch"].as_u64().unwrap_or(0);
        let seen_digest = seen["directory"]["digest"].as_str().unwrap_or("");
        if epoch < seen_epoch {
            r.alarm(format!(
                "rollback: serving epoch {epoch}, but epoch {seen_epoch} was seen here before"
            ));
        } else if epoch == seen_epoch && digest != seen_digest {
            r.alarm(format!(
                "equivocation: a second, different directory at epoch {epoch} (seen {}, now {})",
                &seen_digest[..seen_digest.len().min(16)],
                &digest[..digest.len().min(16)]
            ));
        }
        for (n, d) in &history {
            if let Some(old) = seen["epochs"][n.to_string()].as_str() {
                if old != d {
                    r.alarm(format!(
                        "equivocation: epoch {n} in the history changed since it was seen here"
                    ));
                }
            }
        }
        for (id, h) in &heads {
            let old = &seen["registrars"][id];
            if old.is_null() {
                continue;
            }
            let (os, ns) = (
                old["log_size"].as_u64().unwrap_or(0),
                h["log_size"].as_u64().unwrap_or(0),
            );
            if ns < os {
                r.alarm(format!("{id}: log shrank from {os} to {ns}"));
            } else if ns == os && old["log_root"] != h["log_root"] {
                r.alarm(format!(
                    "{id}: a different log root at size {ns} — a forked log"
                ));
            }
            if h["status_seq"].as_u64().unwrap_or(0) < old["status_seq"].as_u64().unwrap_or(0) {
                r.alarm(format!(
                    "{id}: status sequence went back from {} to {}",
                    old["status_seq"], h["status_seq"]
                ));
            }
        }
    }
    if r.alarms.is_empty() {
        let mut epochs = seen["epochs"].as_object().cloned().unwrap_or_default();
        for (n, d) in &history {
            epochs.insert(n.to_string(), json!(d));
        }
        state[&key] = json!({ "directory": { "epoch": epoch, "digest": digest }, "epochs": epochs, "registrars": heads, "at": t });
        if let Some(parent) = sp.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&sp, serde_json::to_string_pretty(&state).unwrap() + "\n");
        println!("CTL OK — no alarm. Memory moved forward.");
        0
    } else {
        println!(
            "CTL ALARM — {} alarm(s). Memory NOT moved forward, so the next run alarms again.",
            r.alarms.len()
        );
        1
    }
}

fn diff(args: &[String]) -> i32 {
    let nums: Vec<u64> = args.iter().filter_map(|a| a.parse().ok()).collect();
    let (Some(net), [a, b]) = (opt(args, "net"), nums.as_slice()) else {
        eprintln!("usage: ainra ctl diff <N> <M> --net <url|dir>");
        return 2;
    };
    let load = |n: u64| fetch_json(net, &format!("epochs/{n}.json"));
    let (Ok(da), Ok(db)) = (load(*a), load(*b)) else {
        eprintln!("epochs/{a}.json and epochs/{b}.json must both be served by {net}");
        return 2;
    };
    let entries = |d: &Value| -> BTreeMap<String, Value> {
        d["entries"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|e| {
                e["registrar"]
                    .as_str()
                    .map(|id| (id.to_string(), e.clone()))
            })
            .collect()
    };
    let (ea, eb) = (entries(&da), entries(&db));
    println!("ainra ctl diff · epoch {a} → epoch {b}");
    let mut changes = 0;
    for (id, e) in &eb {
        match ea.get(id) {
            None => {
                println!("  + accredited   {id}");
                changes += 1;
            }
            Some(old) if old != e => {
                let fields: Vec<&str> = [
                    "issuer_ed25519",
                    "issuer_mldsa65",
                    "log_root_slh",
                    "status_ed25519",
                    "status_mldsa65",
                    "status_uri",
                    "distrust_from_leaf",
                ]
                .into_iter()
                .filter(|f| old[*f] != e[*f])
                .collect();
                println!("  ~ changed      {id}: {}", fields.join(", "));
                changes += 1;
            }
            _ => {}
        }
    }
    for id in ea.keys().filter(|id| !eb.contains_key(*id)) {
        println!("  - withdrawn    {id}");
        changes += 1;
    }
    let rd = |d: &Value| -> Vec<String> {
        d["revoked_delegates"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|x| x.to_string())
            .collect()
    };
    let (ra, rb) = (rd(&da), rd(&db));
    for x in rb.iter().filter(|x| !ra.contains(x)) {
        println!("  + revoked delegate {x}");
        changes += 1;
    }
    for x in ra.iter().filter(|x| !rb.contains(x)) {
        println!("  - revoked delegate {x} (no longer listed)");
        changes += 1;
    }
    println!("{changes} change(s).");
    0
}
