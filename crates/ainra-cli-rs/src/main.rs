// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ainra` — the reference AINRA command line. Offline + persistent (no daemon): every command drives the REAL
//! [`RegistrarBox`] engine over `ainra-core` — real hybrid signing, real RFC 6962 log inclusion, real signed status
//! deltas — and prints what the real verifier decides. `ainra seed` builds the fictional registry the explorer
//! loads; `ainra reverify` re-checks an export with the pure core verifier (a third-party check).
//!
//! Run `ainra help` for the command list.

mod seed;

use std::path::Path;
use std::process::exit;

use ainra_core::Verdict;
use ainra_services::registrar::{IssueSpec, RegistrarBox};
use ainra_services::status::{WireDelta, WireFreshHead};
use rand_core::SeedableRng;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("help");
    let rest = &args[args.len().min(1)..];
    let code = match cmd {
        "init" => cmd_init(rest),
        "accredit" => cmd_accredit(rest),
        "issue" => cmd_issue(rest),
        "renew" => cmd_renew(rest),
        "list" => cmd_list(rest),
        "verify" => cmd_verify(rest),
        "revoke" => cmd_revoke(rest),
        "present" => cmd_present(rest),
        "log-verify" => cmd_log_verify(rest),
        "fresh-head" => cmd_fresh_head(rest),
        "status" => cmd_status(rest),
        "deltas" => cmd_deltas(rest),
        "export" => cmd_export(rest),
        "seed" => cmd_seed(rest),
        "reverify" => cmd_reverify(rest),
        "demo" => cmd_demo(),
        "help" | "-h" | "--help" => {
            print_help();
            0
        }
        other => {
            eprintln!("unknown command '{other}' — run `ainra help`");
            2
        }
    };
    exit(code);
}

// ── argument helpers ────────────────────────────────────────────────────────────────────────────────────────────

/// A positional arg at `i` (0-based, after the command).
fn pos(args: &[String], i: usize) -> Option<&str> {
    args.iter()
        .filter(|a| !a.starts_with("--"))
        .nth(i)
        .map(|s| s.as_str())
}
/// A `--key value` option.
fn opt<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    let flag = format!("--{key}");
    args.iter()
        .position(|a| a == &flag)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}
/// A repeated `--key value --key value` option, collected.
fn opt_multi(args: &[String], key: &str) -> Vec<String> {
    let flag = format!("--{key}");
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}
fn opt_u64(args: &[String], key: &str, default: u64) -> u64 {
    opt(args, key)
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}
fn now_or_default(args: &[String]) -> u64 {
    opt_u64(args, "now", seed::VERIFY_NOW)
}

/// Load a persisted registrar or print a friendly error.
fn load(dir: &str) -> Result<RegistrarBox, i32> {
    RegistrarBox::load(Path::new(dir)).map_err(|e| {
        eprintln!("cannot load registrar at '{dir}': {e}");
        1
    })
}

/// FNV-1a of a string → a stable default seed for `init` (reproducible without `--seed`).
fn default_seed(id: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in id.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h | 1 // never 0 (0 marks a non-reloadable snapshot)
}

// ── commands ────────────────────────────────────────────────────────────────────────────────────────────────────

fn cmd_init(a: &[String]) -> i32 {
    let (Some(dir), Some(id)) = (pos(a, 0), pos(a, 1)) else {
        eprintln!("usage: ainra init <dir> <registrar-id> [--seed N]");
        return 2;
    };
    let seed = opt_u64(a, "seed", default_seed(id));
    match RegistrarBox::create_seeded(
        Path::new(dir),
        id,
        opt_u64(a, "capacity", 256) as usize,
        seed,
        seed::CREATE_NOW,
        seed::NBF,
        seed::EXP,
    ) {
        Ok(rb) => {
            if let Err(e) = rb.save() {
                eprintln!("save failed: {e}");
                return 1;
            }
            println!("initialized registrar '{id}' at {dir} (seed {seed:#x})");
            print_json(&rb.accreditation());
            0
        }
        Err(e) => {
            eprintln!("init failed: {e}");
            1
        }
    }
}

fn cmd_accredit(a: &[String]) -> i32 {
    let Some(dir) = pos(a, 0) else {
        eprintln!("usage: ainra accredit <dir>");
        return 2;
    };
    match load(dir) {
        Ok(rb) => {
            print_json(&rb.accreditation());
            0
        }
        Err(c) => c,
    }
}

fn cmd_issue(a: &[String]) -> i32 {
    let Some(dir) = pos(a, 0) else {
        eprintln!("usage: ainra issue <dir> --operator O --lineage L --version V [--tier L2] [--auth A2] [--cap C]* [--ceiling C]*");
        return 2;
    };
    let (Some(operator), Some(lineage), Some(version)) =
        (opt(a, "operator"), opt(a, "lineage"), opt(a, "version"))
    else {
        eprintln!("issue requires --operator, --lineage, --version");
        return 2;
    };
    let caps = opt_multi(a, "cap");
    let mut ceiling = opt_multi(a, "ceiling");
    if ceiling.is_empty() {
        ceiling = caps.clone(); // ceiling defaults to the granted set
    }
    let spec = IssueSpec {
        operator: operator.into(),
        lineage: lineage.into(),
        version: version.into(),
        tier: opt(a, "tier").unwrap_or("L2").into(),
        auth_class: opt(a, "auth").unwrap_or("A2").into(),
        principal_proof: opt(a, "proof").unwrap_or("deadbeef00000000").into(),
        capabilities: if caps.is_empty() {
            vec!["read:data".into()]
        } else {
            caps
        },
        scope_ceiling: ceiling,
        hops: vec![],
        // ADR-017: L3+ requires current tier-audit evidence; the engine refuses without it (or past its expiry).
        audit: opt(a, "audit-expires")
            .and_then(|e| e.parse().ok())
            .map(|expires| ainra_services::registrar::AuditEvidence {
                reference: opt(a, "audit-ref").unwrap_or("audit-evidence").into(),
                expires,
            }),
    };
    let mut rb = match load(dir) {
        Ok(rb) => rb,
        Err(c) => return c,
    };
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(default_seed(lineage));
    match rb.issue(&spec, &[], &mut rng) {
        Ok(rec) => {
            if let Err(e) = rb.save() {
                eprintln!("save failed: {e}");
                return 1;
            }
            println!(
                "issued {}\n  tier {} · auth {} · status idx {} · leaf {} · checkpoint size {}",
                rec.sub,
                rec.tier,
                rec.auth_class,
                rec.status_idx,
                rec.leaf_index,
                rec.checkpoint_size
            );
            let v = rb.verify_record(&rec.sub, seed::VERIFY_NOW);
            println!("  verdict: {}", verdict_str(&v));
            0
        }
        Err(e) => {
            eprintln!("issue failed: {e}");
            1
        }
    }
}

fn cmd_renew(a: &[String]) -> i32 {
    let (Some(dir), Some(sub)) = (pos(a, 0), pos(a, 1)) else {
        eprintln!("usage: ainra renew <dir> <sub> [--version V] [--now T] [--audit-ref R --audit-expires T] [--dry-run]");
        return 2;
    };
    let mut rb = match load(dir) {
        Ok(rb) => rb,
        Err(c) => return c,
    };
    let now = now_or_default(a);
    let Some(old) = rb.get(sub).cloned() else {
        eprintln!("unknown subject: {sub}");
        return 1;
    };
    let new_exp = now.saturating_add(ainra_core::consts::PASSPORT_VALIDITY_DEFAULT_SECS);
    let audit = opt(a, "audit-expires")
        .and_then(|e| e.parse().ok())
        .map(|expires| ainra_services::registrar::AuditEvidence {
            reference: opt(a, "audit-ref").unwrap_or("audit-evidence").into(),
            expires,
        });
    if a.iter().any(|x| x == "--dry-run") {
        let head = rb
            .lineage_head(&old.operator, &old.lineage)
            .map(|(_, leaf)| leaf)
            .unwrap_or_default();
        // Honest dry-run: name the guards the REAL reissue would apply, so a dry-run never says "would reissue"
        // for a subject that the real command refuses (revoked / chained / expired / L3+ audit).
        let mut blockers: Vec<String> = Vec::new();
        if old.revoked {
            blockers.push("subject is REVOKED — a revoked lineage cannot renew (re-admission is a new accreditation)".into());
        }
        if now >= old.exp {
            blockers.push(format!("subject has EXPIRED (exp {}, now {now}) — renew before expiry; a lapsed credential needs fresh issuance", old.exp));
        }
        if !old.hops.is_empty() {
            blockers.push("subject carries a delegation chain — a chained passport cannot be auto-renewed (renewal is a re-delegation)".into());
        }
        if matches!(old.tier.as_str(), "L3" | "L4") {
            match &audit {
                None => blockers.push(format!("tier {} requires --audit-expires (current tier-audit evidence)", old.tier)),
                Some(a) if new_exp > a.expires => blockers.push(format!("tier {} audit expires {} — before the new window end {new_exp}; renew the audit first", old.tier, a.expires)),
                _ => {}
            }
        }
        if blockers.is_empty() {
            println!("DRY RUN — would reissue {sub} (ADR-017 renewal):");
            println!(
                "  window     [{}, {}] → [{now}, {new_exp}] (fresh 366-day window)",
                old.nbf, old.exp
            );
            println!("  prev_leaf  {head} (the lineage head this renewal chains from)");
            println!(
                "  version    {} → {}",
                old.version,
                opt(a, "version").unwrap_or(&old.version)
            );
            println!(
                "  overlap    both generations verify until the old exp {} — no grace after it",
                old.exp
            );
            return 0;
        }
        eprintln!("DRY RUN — reissue of {sub} WOULD BE REFUSED:");
        for b in &blockers {
            eprintln!("  ✗ {b}");
        }
        return 1;
    }
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(default_seed(sub) ^ now);
    match rb.reissue(sub, opt(a, "version"), now, audit.as_ref(), &mut rng) {
        Ok(rec) => {
            if let Err(e) = rb.save() {
                eprintln!("save failed: {e}");
                return 1;
            }
            println!("reissued {} (renewal of {sub})", rec.sub);
            println!(
                "  window [{}, {}] · status idx {} · prev_leaf {} · leaf {}",
                rec.nbf,
                rec.exp,
                rec.status_idx,
                serde_json::from_str::<serde_json::Value>(&rec.claims)
                    .ok()
                    .and_then(|v| v["prev_leaf"].as_str().map(String::from))
                    .unwrap_or_default(),
                rec.leaf_index
            );
            println!("  overlap: the old credential keeps verifying until its exp {} — then it fails closed (expired)", old.exp);
            println!(
                "  verdict(new): {}",
                verdict_str(&rb.verify_record(&rec.sub, now + 1))
            );
            0
        }
        Err(e) => {
            eprintln!("renew failed: {e}");
            1
        }
    }
}

fn cmd_list(a: &[String]) -> i32 {
    let Some(dir) = pos(a, 0) else {
        eprintln!("usage: ainra list <dir>");
        return 2;
    };
    let rb = match load(dir) {
        Ok(rb) => rb,
        Err(c) => return c,
    };
    let now = now_or_default(a);
    println!("registrar {} — {} credential(s)", rb.id(), rb.len());
    println!(
        "{:<44} {:<5} {:<5} {:<5} {:<8} verdict",
        "SUBJECT", "TIER", "AUTH", "HOPS", "STATUS"
    );
    for r in rb.records() {
        let v = rb.verify_record(&r.sub, now);
        println!(
            "{:<44} {:<5} {:<5} {:<5} {:<8} {}",
            truncate(&r.sub, 44),
            r.tier,
            r.auth_class,
            r.hops.len(),
            if r.revoked { "revoked" } else { "listed" },
            verdict_str(&v)
        );
    }
    0
}

fn cmd_verify(a: &[String]) -> i32 {
    let (Some(dir), Some(sub)) = (pos(a, 0), pos(a, 1)) else {
        eprintln!("usage: ainra verify <dir> <sub> [--now T]");
        return 2;
    };
    let rb = match load(dir) {
        Ok(rb) => rb,
        Err(c) => return c,
    };
    let v = rb.verify_record(sub, now_or_default(a));
    println!("{}", verdict_str(&v));
    i32::from(!v.is_valid())
}

fn cmd_revoke(a: &[String]) -> i32 {
    let (Some(dir), Some(sub)) = (pos(a, 0), pos(a, 1)) else {
        eprintln!("usage: ainra revoke <dir> <sub> [--now T]");
        return 2;
    };
    let mut rb = match load(dir) {
        Ok(rb) => rb,
        Err(c) => return c,
    };
    let now = now_or_default(a);
    match rb.revoke(sub, now) {
        Ok(delta) => {
            if let Err(e) = rb.save() {
                eprintln!("save failed: {e}");
                return 1;
            }
            println!(
                "revoked {sub} — signed delta seq {} → {}",
                delta.from_seq, delta.seq
            );
            print_json(&WireDelta::from_core(&delta));
            0
        }
        Err(e) => {
            eprintln!("revoke failed: {e}");
            1
        }
    }
}

fn cmd_present(a: &[String]) -> i32 {
    let (Some(dir), Some(sub)) = (pos(a, 0), pos(a, 1)) else {
        eprintln!("usage: ainra present <dir> <sub>");
        return 2;
    };
    let rb = match load(dir) {
        Ok(rb) => rb,
        Err(c) => return c,
    };
    match rb.get(sub) {
        Some(rec) => {
            print_json(rec);
            0
        }
        None => {
            eprintln!("unknown subject: {sub}");
            1
        }
    }
}

fn cmd_log_verify(a: &[String]) -> i32 {
    let (Some(dir), Some(sub)) = (pos(a, 0), pos(a, 1)) else {
        eprintln!("usage: ainra log-verify <dir> <sub> [--now T]");
        return 2;
    };
    let rb = match load(dir) {
        Ok(rb) => rb,
        Err(c) => return c,
    };
    let Some(rec) = rb.get(sub) else {
        eprintln!("unknown subject: {sub}");
        return 1;
    };
    match ainra_services::registrar::verify_log_inclusion(rec, &rb.root_public(), now_or_default(a))
    {
        Ok(()) => {
            println!(
                "logged-before-valid OK — leaf {} included under checkpoint {}#{} (RFC 6962), signature verified",
                rec.leaf_index, rec.log_origin, rec.checkpoint_size
            );
            0
        }
        Err(r) => {
            println!("log inclusion FAILED — {r}");
            1
        }
    }
}

fn cmd_fresh_head(a: &[String]) -> i32 {
    let Some(dir) = pos(a, 0) else {
        eprintln!("usage: ainra fresh-head <dir> [--now T]");
        return 2;
    };
    let rb = match load(dir) {
        Ok(rb) => rb,
        Err(c) => return c,
    };
    match rb.fresh_head(now_or_default(a)) {
        Some(h) => {
            print_json(&WireFreshHead::from_core(&h));
            0
        }
        None => {
            eprintln!("no delegate configured");
            1
        }
    }
}

fn cmd_status(a: &[String]) -> i32 {
    let Some(dir) = pos(a, 0) else {
        eprintln!("usage: ainra status <dir> [--now T]");
        return 2;
    };
    let rb = match load(dir) {
        Ok(rb) => rb,
        Err(c) => return c,
    };
    print_json(&rb.publish_status(now_or_default(a)));
    0
}

fn cmd_deltas(a: &[String]) -> i32 {
    let Some(dir) = pos(a, 0) else {
        eprintln!("usage: ainra deltas <dir> [--since S]");
        return 2;
    };
    let rb = match load(dir) {
        Ok(rb) => rb,
        Err(c) => return c,
    };
    let since = opt_u64(a, "since", 0);
    let deltas: Vec<_> = rb
        .deltas_since(since)
        .iter()
        .map(WireDelta::from_core)
        .collect();
    println!(
        "head_seq {} — {} delta(s) since {}",
        rb.status_seq(),
        deltas.len(),
        since
    );
    print_json(&deltas);
    0
}

fn cmd_export(a: &[String]) -> i32 {
    let Some(dir) = pos(a, 0) else {
        eprintln!("usage: ainra export <dir> [--now T]");
        return 2;
    };
    let rb = match load(dir) {
        Ok(rb) => rb,
        Err(c) => return c,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&seed::export(&rb, now_or_default(a))).unwrap()
    );
    0
}

fn cmd_seed(a: &[String]) -> i32 {
    let out = pos(a, 0).unwrap_or("seed-registry");
    match seed::build(Path::new(out)) {
        Ok(registry) => {
            let t = &registry["totals"];
            println!(
                "built {} registrar(s): {} issued, {} delegated, {} revoked → {}/registry.json",
                t["registrars"], t["issued"], t["delegated"], t["revoked"], out
            );
            // self-check: re-verify every record with the pure core verifier.
            let (checked, bad) = seed::reverify_registry(&registry);
            if bad.is_empty() {
                println!("self-check: {checked} record(s) re-verified with the core verifier — all match ✓");
                0
            } else {
                eprintln!("self-check FAILED ({} disagreement(s)):", bad.len());
                for b in &bad {
                    eprintln!("  {b}");
                }
                1
            }
        }
        Err(e) => {
            eprintln!("seed failed: {e}");
            1
        }
    }
}

fn cmd_reverify(a: &[String]) -> i32 {
    let Some(path) = pos(a, 0) else {
        eprintln!("usage: ainra reverify <registry.json>");
        return 2;
    };
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return 1;
        }
    };
    let registry: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("bad json: {e}");
            return 1;
        }
    };
    let (checked, bad) = seed::reverify_registry(&registry);
    if bad.is_empty() {
        println!("re-verified {checked} record(s) with the core verifier — every shipped verdict matches ✓");
        0
    } else {
        eprintln!("{} disagreement(s) of {checked}:", bad.len());
        for b in &bad {
            eprintln!("  {b}");
        }
        1
    }
}

fn cmd_demo() -> i32 {
    let dir = std::env::temp_dir().join("ainra-cli-demo");
    let _ = std::fs::remove_dir_all(&dir);
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xDE30);
    let mut rb = match RegistrarBox::create_seeded(
        &dir,
        "registrar-07",
        64,
        0xDEED,
        seed::CREATE_NOW,
        seed::NBF,
        seed::EXP,
    ) {
        Ok(rb) => rb,
        Err(e) => {
            eprintln!("demo create failed: {e}");
            return 1;
        }
    };
    let now = seed::VERIFY_NOW;
    println!("AINRA end-to-end demo (real crypto, one process)\n");
    println!(
        "1. registrar '{}' created — issuer + SLH-DSA root + status delegate",
        rb.id()
    );

    let spec = IssueSpec {
        operator: "acme".into(),
        lineage: "invoicing".into(),
        version: "4.2.1".into(),
        tier: "L3".into(),
        auth_class: "A2".into(),
        principal_proof: "deadbeef7f3a2c1d".into(),
        capabilities: vec!["read:invoices".into(), "sign:invoice".into()],
        scope_ceiling: vec![
            "read:invoices".into(),
            "sign:invoice".into(),
            "read:payments".into(),
        ],
        hops: vec![],
        // L3 demands current tier-audit evidence (ADR-017); the demo's placeholder audit outlives the window.
        audit: Some(ainra_services::registrar::AuditEvidence {
            reference: "audit-demo-invoicing".into(),
            expires: seed::EXP,
        }),
    };
    let rec = match rb.issue(&spec, &[], &mut rng) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("demo issue failed: {e}");
            return 1;
        }
    };
    println!("2. issued {}", rec.sub);
    println!(
        "   → hybrid-signed (Ed25519 + ML-DSA-65), logged at leaf {} under a signed checkpoint",
        rec.leaf_index
    );
    println!(
        "3. verify → {}",
        verdict_str(&rb.verify_record(&rec.sub, now))
    );
    println!(
        "4. logged-before-valid → {}",
        match ainra_services::registrar::verify_log_inclusion(&rec, &rb.root_public(), now) {
            Ok(()) => "leaf included (RFC 6962), checkpoint signature valid".to_string(),
            Err(r) => format!("FAILED: {r}"),
        }
    );
    match rb.revoke(&rec.sub, now) {
        Ok(d) => println!(
            "5. revoke → signed delta seq {} → {} (delegate-countersigned)",
            d.from_seq, d.seq
        ),
        Err(e) => {
            eprintln!("demo revoke failed: {e}");
            return 1;
        }
    }
    println!(
        "6. verify again → {}",
        verdict_str(&rb.verify_record(&rec.sub, now))
    );
    if let Some(h) = rb.fresh_head(now) {
        println!(
            "7. fresh head → seq {} @ ts {} (F1 30-second heartbeat, delegate-signed)",
            h.seq, h.ts
        );
    }
    println!("\nall verdicts above are the real verifier's output — nothing asserted.");
    0
}

// ── output helpers ──────────────────────────────────────────────────────────────────────────────────────────────

fn print_json<T: serde::Serialize>(v: &T) {
    println!("{}", serde_json::to_string_pretty(v).unwrap());
}
fn verdict_str(v: &Verdict) -> String {
    match v {
        Verdict::Valid => "VALID".into(),
        Verdict::Invalid { reason } => format!("INVALID ({reason})"),
    }
}
fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n - 1])
    }
}

fn print_help() {
    println!(
        r#"ainra — the reference AINRA command line (offline, persistent; no daemon required)

REGISTRAR LIFECYCLE (operate on a local data dir)
  init <dir> <id> [--seed N] [--capacity N]   create + persist a registrar
  accredit <dir>                              print the registrar's public keys (directory entry)
  issue <dir> --operator O --lineage L --version V [--tier L2] [--auth A2] [--cap C]* [--ceiling C]*
        [--audit-ref R --audit-expires T]     L3+ requires current tier-audit evidence (ADR-017)
  renew <dir> <sub> [--version V] [--now T] [--audit-ref R --audit-expires T] [--dry-run]
        ADR-017 reissue: fresh 366-day window, prev_leaf continuity, new status index; the old credential
        keeps verifying until its own exp (overlap), then fails closed. Run it at T−30 d before exp (the
        RENEWAL_LEAD default) — the lead is a deployment cadence, not a protocol rule; nothing here schedules.
  list <dir> [--now T]                        list credentials + live verdicts
  verify <dir> <sub> [--now T]                verify one credential (the REAL verifier)
  log-verify <dir> <sub> [--now T]            check ONLY logged-before-valid (RFC 6962 inclusion)
  revoke <dir> <sub> [--now T]                revoke → emit a signed, delegate-countersigned delta
  present <dir> <sub>                         print the full presentation record (JSON)
  status <dir> [--now T]                      the signed Token Status List
  fresh-head <dir> [--now T]                  the 30-second delegate-signed fresh head
  deltas <dir> [--since S]                    the signed delta stream since head S
  export <dir> [--now T]                      full export (records + live verdicts) for the explorer

REGISTRY
  seed [out-dir]                              build the fictional multi-registrar registry (+ self-check)
  reverify <registry.json>                    re-verify an export with the pure core verifier
  demo                                        one-process end-to-end lifecycle (zero setup)

Time is explicit (the core has no clock): pass --now <unix-seconds>; the default sits inside the demo window."#
    );
}
