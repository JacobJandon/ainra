// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ainra directory …` — the workbench that only proposes, and the two steps around a ceremony (PLAN-M52 steps 5–8).
//!
//!   ainra directory request <TYPE> --filed-at T --out F (--registrar <dir> | --subject <id> --filer <name>) …
//!                                                               a registrar files (and signs, with its own keys)
//!   ainra directory check-request <request.json> [--directory D --roots R] [--accreditation A]
//!   ainra directory check-request --list-checks                 the checks, as docs/ACCREDITATION-CHECKS.md
//!   ainra directory propose [--base D --roots R] --request r… --issued-at T --out P
//!   ainra directory check-proposal <P> [--base D --roots R]      re-derive N+1 from N and the requests alone
//!   ainra directory sign-request <P>                             the exact bytes custodians sign, and their SHA-256
//!   ainra directory assemble <P> --sig-ed25519 B --sig-slh B --roots R --out D
//!   ainra directory publish <D> --roots R --proposal P --transcript T [--transcript-sha256 F] --into <contract dir>
//!
//! What each decides lives in `ainra_adapter::workbench` (the one decode path); this file reads and writes files. No
//! command here holds a root key or touches the network: `propose` writes an UNSIGNED file, `assemble` only accepts
//! signatures the custodians and the SLH signer made offline, and `publish` writes into a local directory that another
//! host or mirror then copies. `request` signs with a REGISTRAR's own keys, on the registrar's own machine.
//!
//! WITNESS: `tools/sign-epoch-rehearsal.sh` (`make sign-epoch-rehearsal`) drives every command here across nine
//! custodian processes and requires each refusal by its check id; the adapter's tests refuse one input per check.

use std::path::Path;

use ainra_adapter::workbench as wb;
use ainra_core::b64;
use ainra_services::registrar::RegistrarBox;
use serde_json::{json, Value};

use crate::ctl::{archive_into, archive_last, opt, opt_all, sha256_hex};

pub const USAGE: &str = "usage: ainra directory digest <directory.json>
       ainra directory archive <directory.json> --roots <roots.json> --into <dir>
       ainra directory request <TYPE> --filed-at <T> --out <request.json> (--registrar <dir> | --subject <id> --filer <name>)
                               [--leaf <n>] [--cert <delegate-cert.json>] [--evidence <evidence.json>] [--test-root]
       ainra directory check-request <request.json> [--directory <current signed directory> --roots <roots.json>] [--accreditation <file>]
       ainra directory check-request --list-checks
       ainra directory propose [--base <epoch N signed directory> --roots <roots.json>] --request <r1> [--request <r2>]… --issued-at <T> --out <proposal.json>
       ainra directory check-proposal <proposal.json> [--base <epoch N signed directory> --roots <roots.json>]
       ainra directory sign-request <proposal.json>
       ainra directory assemble <proposal.json> --sig-ed25519 <b64> --sig-slh <b64> --roots <roots.json> --out <directory.json>
       ainra directory publish <directory.json> --roots <roots.json> --proposal <proposal.json> --transcript <transcript.json> [--transcript-sha256 <file>] --into <contract dir>";

/// The first argument that is not an option or an option's value.
fn positional(args: &[String]) -> Option<&str> {
    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            // flags without a value
            if matches!(args[i].as_str(), "--list-checks" | "--test-root") {
                i += 1;
            } else {
                i += 2;
            }
            continue;
        }
        return Some(args[i].as_str());
    }
    None
}

fn read(path: &str) -> Result<String, i32> {
    std::fs::read_to_string(path).map_err(|e| {
        eprintln!("{path}: {e}");
        2
    })
}

fn refused(e: &wb::Refusal) -> i32 {
    println!("REFUSED {e}");
    1
}

/// `--directory`/`--base` with `--roots`: both or neither.
fn base_pair(args: &[String], key: &str) -> Result<Option<(String, String)>, i32> {
    match (opt(args, key), opt(args, "roots")) {
        (Some(d), Some(r)) => Ok(Some((read(d)?, read(r)?))),
        (None, _) => Ok(None),
        (Some(_), None) => {
            eprintln!("--{key} needs --roots: the directory is checked against both roots before anything else");
            Err(2)
        }
    }
}

fn write(path: &str, text: &str) -> Result<(), i32> {
    std::fs::write(path, text).map_err(|e| {
        eprintln!("{path}: {e}");
        2
    })
}

pub fn run(cmd: &str, args: &[String]) -> i32 {
    let r = match cmd {
        "check-request" => check_request(args),
        "request" => request(args),
        "propose" => propose(args),
        "check-proposal" => check_proposal(args),
        "sign-request" => sign_request(args),
        "assemble" => assemble(args),
        "publish" => publish(args),
        _ => Err(2),
    };
    match r {
        Ok(()) => 0,
        Err(code) => {
            if code == 2 && !matches!(cmd, "check-request" | "check-proposal") {
                eprintln!("{USAGE}");
            }
            code
        }
    }
}

fn check_request(args: &[String]) -> Result<(), i32> {
    if args.iter().any(|a| a == "--list-checks") {
        print!("{}", wb::checks_markdown());
        return Ok(());
    }
    let Some(file) = positional(args) else {
        eprintln!("{USAGE}");
        return Err(2);
    };
    let req = read(file)?;
    let base = base_pair(args, "directory")?;
    let acc = match opt(args, "accreditation") {
        Some(p) => Some(read(p)?),
        None => None,
    };
    match wb::check_request_json(
        &req,
        base.as_ref().map(|(d, r)| (d.as_str(), r.as_str())),
        acc.as_deref(),
    ) {
        Ok(a) => {
            println!(
                "ACCEPTED {} for {} · digest {}",
                a.change_type, a.registrar, a.digest
            );
            println!("  checks passed: {}", a.passed.join(", "));
            if acc.is_none() && a.change_type == "ACCREDIT" {
                println!("  · accreditation-match not run: no copy of the registrar's /accreditation was given");
            }
            println!("  · live-endpoints is not built here (offline): run the compliance probe against the registrar");
            Ok(())
        }
        Err(e) => Err(refused(&e)),
    }
}

/// Draft a request and, with `--registrar`, sign it with that registrar's own keys (its offline home directory).
fn request(args: &[String]) -> Result<(), i32> {
    let (Some(t), Some(out), Some(filed_at)) = (
        positional(args),
        opt(args, "out"),
        opt(args, "filed-at").and_then(|s| s.parse::<u64>().ok()),
    ) else {
        return Err(2);
    };
    let rb = match opt(args, "registrar") {
        Some(dir) => Some(RegistrarBox::load(Path::new(dir)).map_err(|e| {
            eprintln!("cannot load the registrar at {dir}: {e}");
            2
        })?),
        None => None,
    };
    let (subject, filer) = match &rb {
        Some(rb) => (rb.id().to_string(), rb.id().to_string()),
        None => match (opt(args, "subject"), opt(args, "filer")) {
            (Some(s), Some(f)) => (s.to_string(), f.to_string()),
            _ => {
                eprintln!("a request is filed --registrar <its home> (signed with its keys), or --subject <id> --filer <name> (unsigned)");
                return Err(2);
            }
        },
    };
    let mut change = json!({});
    match t {
        "ACCREDIT" => {
            let Some(rb) = &rb else {
                eprintln!("ACCREDIT is filed by the registrar itself (--registrar): it must prove possession of every key");
                return Err(2);
            };
            let a = serde_json::to_value(rb.accreditation()).unwrap_or(Value::Null);
            change["entry"] = json!({
                "registrar": a["registrar"], "issuer_ed25519": a["issuer_key"]["ed25519"],
                "issuer_mldsa65": a["issuer_key"]["mldsa65"], "log_root_slh": a["log_root_key"],
                "status_ed25519": a["status_key"]["ed25519"], "status_mldsa65": a["status_key"]["mldsa65"],
                "status_uri": a["status_uri"],
            });
        }
        "DISTRUST_FROM_LEAF" => {
            let Some(leaf) = opt(args, "leaf").and_then(|s| s.parse::<u64>().ok()) else {
                eprintln!("DISTRUST_FROM_LEAF needs --leaf <n>");
                return Err(2);
            };
            change["leaf"] = json!(leaf);
        }
        "REVOKE_DELEGATE" => {
            change["cert"] = match opt(args, "cert") {
                Some(p) => serde_json::from_str(&read(p)?).map_err(|e| {
                    eprintln!("{p}: {e}");
                    2
                })?,
                None => {
                    let Some(c) = rb.as_ref().and_then(|rb| rb.status_delegate_cert()) else {
                        eprintln!("REVOKE_DELEGATE needs --cert <delegate-cert.json> (or a registrar with a status delegate)");
                        return Err(2);
                    };
                    serde_json::to_value(ainra_adapter::cert_wire(&c)).unwrap_or(Value::Null)
                }
            };
        }
        _ => {}
    }
    let evidence = match opt(args, "evidence") {
        Some(p) => serde_json::from_str::<Value>(&read(p)?).map_err(|e| {
            eprintln!("{p}: {e}");
            2
        })?,
        None => json!({}),
    };
    let mut req = json!({
        "version": 1, "kind": wb::REQUEST_KIND, "type": t, "registrar": subject, "filer": filer,
        "filed_at": filed_at, "test_root": args.iter().any(|a| a == "--test-root"),
        "change": change, "evidence": evidence,
    });
    let (digest, message) = match wb::request_digest_json(&req.to_string()) {
        Ok(x) => x,
        Err(e) => return Err(refused(&e)),
    };
    if let Some(rb) = &rb {
        let p = rb.sign_change_request(&message).map_err(|e| {
            eprintln!("cannot sign: {e}");
            1
        })?;
        let sig = |s: &ainra_core::crypto::HybridSig| json!({ "ed25519": b64::encode(&s.ed25519), "mldsa65": b64::encode(&s.mldsa65) });
        req["proofs"] = if t == "ACCREDIT" {
            json!({ "possession": { "issuer": sig(&p.issuer), "status": sig(&p.status), "log_root_slh": b64::encode(&p.log_root_slh) } })
        } else {
            json!({ "filer": sig(&p.issuer) })
        };
    }
    write(out, &(serde_json::to_string_pretty(&req).unwrap() + "\n"))?;
    println!(
        "wrote {t} for {subject} (filer {filer}) → {out} · digest {digest}{}",
        if rb.is_some() {
            " · signed with the registrar's own keys"
        } else {
            " · unsigned"
        }
    );
    Ok(())
}

fn propose(args: &[String]) -> Result<(), i32> {
    let (Some(out), Some(issued_at)) = (
        opt(args, "out"),
        opt(args, "issued-at").and_then(|s| s.parse::<u64>().ok()),
    ) else {
        return Err(2);
    };
    let base = base_pair(args, "base")?;
    let mut reqs = Vec::new();
    for p in opt_all(args, "request") {
        reqs.push(read(&p)?);
    }
    let mut accs = Vec::new();
    for p in opt_all(args, "accreditation") {
        accs.push(read(&p)?);
    }
    match wb::propose_json(
        base.as_ref().map(|(d, r)| (d.as_str(), r.as_str())),
        &reqs,
        issued_at,
        &accs,
    ) {
        Ok(p) => {
            let text = serde_json::to_string_pretty(&p).unwrap() + "\n";
            write(out, &text)?;
            let pd = wb::proposal_digest_json(&text).map_err(|e| refused(&e))?;
            println!(
                "PROPOSED epoch {} (UNSIGNED) on epoch {} · {} request(s) → {out}",
                p.epoch,
                p.base_epoch,
                p.requests.len()
            );
            for l in &p.diff {
                println!("  {}   [request {}…]", l.change, &l.request[..16]);
            }
            println!("  signing bytes SHA-256 {}", p.signing_bytes_sha256);
            println!("  proposal digest       {pd}");
            Ok(())
        }
        Err(e) => Err(refused(&e)),
    }
}

fn check_proposal(args: &[String]) -> Result<(), i32> {
    let Some(file) = positional(args) else {
        eprintln!("{USAGE}");
        return Err(2);
    };
    let text = read(file)?;
    let base = base_pair(args, "base")?;
    let mut accs = Vec::new();
    for p in opt_all(args, "accreditation") {
        accs.push(read(&p)?);
    }
    match wb::check_proposal_json(
        &text,
        base.as_ref().map(|(d, r)| (d.as_str(), r.as_str())),
        &accs,
    ) {
        Ok(ok) => {
            println!(
                "PROPOSAL OK — epoch {} re-derived from epoch {} and its {} request(s) alone",
                ok.epoch, ok.base_epoch, ok.requests
            );
            for l in &ok.diff {
                println!("  {}   [request {}…]", l.change, &l.request[..16]);
            }
            println!("  signing bytes SHA-256 {}", ok.signing_bytes_sha256);
            println!("  proposal digest       {}", ok.proposal_digest);
            Ok(())
        }
        Err(e) => Err(refused(&e)),
    }
}

fn sign_request(args: &[String]) -> Result<(), i32> {
    let Some(file) = positional(args) else {
        return Err(2);
    };
    match wb::sign_request_json(&read(file)?) {
        Ok((hex, sha, pd)) => {
            println!("{hex}");
            println!("sha256 {sha}");
            println!("proposal {pd}");
            Ok(())
        }
        Err(e) => Err(refused(&e)),
    }
}

fn assemble(args: &[String]) -> Result<(), i32> {
    let (Some(file), Some(roots), Some(out)) =
        (positional(args), opt(args, "roots"), opt(args, "out"))
    else {
        return Err(2);
    };
    let ed = opt(args, "sig-ed25519").unwrap_or("");
    let slh = opt(args, "sig-slh").unwrap_or("");
    match wb::assemble_json(&read(file)?, ed, slh, &read(roots)?) {
        Ok(d) => {
            write(out, &d)?;
            println!(
                "ASSEMBLED → {out}: both root signatures verify over the proposal's signing bytes"
            );
            Ok(())
        }
        Err(e) => Err(refused(&e)),
    }
}

fn publish(args: &[String]) -> Result<(), i32> {
    let (Some(file), Some(roots), Some(proposal), Some(transcript), Some(into)) = (
        positional(args),
        opt(args, "roots"),
        opt(args, "proposal"),
        opt(args, "transcript"),
        opt(args, "into"),
    ) else {
        return Err(2);
    };
    let (dir, roots_t, prop, tr) = (
        read(file)?,
        read(roots)?,
        read(proposal)?,
        read(transcript)?,
    );
    let published_sha = match opt(args, "transcript-sha256") {
        Some(p) => Some(read(p)?.split_whitespace().next().unwrap_or("").to_string()),
        None => None,
    };
    let into_p = Path::new(into);
    let last = archive_last(into_p);
    let ok = match wb::publish_check_json(
        &dir,
        &roots_t,
        &prop,
        &tr,
        last.as_ref().map(|(n, d)| (*n, d.as_str())),
        published_sha.as_deref(),
    ) {
        Ok(ok) => ok,
        Err(e) => return Err(refused(&e)),
    };
    let n = ok.epoch;
    for (sub, text) in [("proposals", &prop), ("ceremonies", &tr)] {
        let d = into_p.join(sub);
        std::fs::create_dir_all(&d).map_err(|e| {
            eprintln!("{}: {e}", d.display());
            2
        })?;
        write(&d.join(format!("{n}.json")).to_string_lossy(), text)?;
    }
    let archived = archive_into(
        dir.as_bytes(),
        roots_t.as_bytes(),
        into_p,
        json!({ "path": format!("proposals/{n}.json"), "digest": ok.proposal_digest }),
        json!({ "path": format!("ceremonies/{n}.json"), "sha256": sha256_hex(tr.as_bytes()) }),
    )
    .map_err(|(code, msg)| {
        eprintln!("{msg}");
        code
    })?;
    write(&into_p.join("directory.json").to_string_lossy(), &dir)?;
    println!("PUBLISHED epoch {n} into {into} (no network: another host or mirror copies this directory)");
    println!("  {archived}");
    println!(
        "  proposal {} · ceremony transcript {}",
        ok.proposal_digest,
        sha256_hex(tr.as_bytes())
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    /// The registrar signs only what the workbench asks it to: the two crates name the same message prefix.
    #[test]
    fn registrar_and_workbench_agree_on_the_request_message() {
        assert_eq!(
            ainra_services::registrar::CHANGE_REQUEST_PREFIX,
            ainra_adapter::workbench::REQUEST_MESSAGE_PREFIX
        );
    }
}
