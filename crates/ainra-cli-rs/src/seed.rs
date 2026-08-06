// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The fictional AINRA seed registry. Realistic in *shape* (multiple registrars, operators, lineages, tiers, auth
//! classes, delegation chains, revocations) but zero real-world identity — every operator is a neutral placeholder
//! (`acme`, `globex`, `operator-NN`; S7-clean) and every key is derived from a labeled TEST seed, never a prod key.
//!
//! Each registrar is built through the REAL [`RegistrarBox`] engine: real hybrid signing, real RFC 6962 log
//! inclusion, real signed status deltas. The verdicts in the export are produced by the real verifier — nothing is
//! asserted. The output is persisted (`entries.log` + `registrar.json` per registrar) AND combined into a single
//! `registry.json` the explorer loads.

use ainra_core::{b64, status};
use ainra_services::registrar::{HopSpec, IssueSpec, RegistrarBox};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::json;

// A coherent demo timeline: certs issued just before `NBF`; every credential's window is the ADR-017 366-day
// default; verification in the export happens 10 days in — comfortably inside the 90-day checkpoint-delegate
// window (ADR-002 cap).
pub const NBF: u64 = 1_775_865_600; // 2026-04-11 UTC
pub const EXP: u64 = NBF + ainra_core::consts::PASSPORT_VALIDITY_DEFAULT_SECS;
pub const CREATE_NOW: u64 = NBF - 3600;
pub const VERIFY_NOW: u64 = NBF + 10 * 24 * 60 * 60;

/// One lineage to issue, described declaratively. `revoke` flips its bit (through a signed delta) after issuance.
struct Lineage {
    operator: &'static str,
    lineage: &'static str,
    version: &'static str,
    tier: &'static str,
    auth: &'static str,
    caps: &'static [&'static str],
    ceiling: &'static [&'static str],
    hops: &'static [(&'static str, &'static str, &'static [&'static str])],
    revoke: bool,
    /// ADR-017: if `Some(new_version)`, this lineage is RENEWED (reissued) after issuance — a fresh 366-day window,
    /// a new status index, and a `prev_leaf` continuity link. Both generations verify during the overlap, so the
    /// export shows the renewal lifecycle state with real cryptography.
    renew: Option<&'static str>,
}

struct RegistrarPlan {
    id: &'static str,
    seed: u64,
    lineages: &'static [Lineage],
}

/// The whole fictional registry. Three registrars, a spread of operators/tiers/auth classes, two delegation chains,
/// and four revocations — enough for the explorer's search / filter / sort / detail flows to be meaningful.
const PLAN: &[RegistrarPlan] = &[
    RegistrarPlan {
        id: "registrar-07",
        seed: 0x075E_EDA1,
        lineages: &[
            Lineage {
                operator: "acme",
                lineage: "invoicing",
                version: "4.2.1",
                tier: "L3",
                auth: "A2",
                caps: &["read:invoices", "sign:invoice"],
                ceiling: &["read:invoices", "sign:invoice", "read:payments"],
                hops: &[],
                revoke: false,
                renew: None,
            },
            Lineage {
                operator: "acme",
                lineage: "data-export",
                version: "2.0.0",
                tier: "L2",
                auth: "A2",
                caps: &["export:data"],
                ceiling: &["export:data"],
                hops: &[],
                revoke: true,
                renew: None,
            },
            Lineage {
                operator: "acme",
                lineage: "support-bot",
                version: "1.0.0",
                tier: "L1",
                auth: "A2",
                caps: &["read:tickets"],
                ceiling: &["read:tickets", "reply:ticket"],
                // owner → support-desk → support-bot (each hop narrows: desk gets read+reply, bot gets read only)
                hops: &[
                    (
                        "ainra:registrar-07:acme:owner@1.0.0",
                        "ainra:registrar-07:acme:support-desk@1.0.0",
                        &["read:tickets", "reply:ticket"],
                    ),
                    (
                        "ainra:registrar-07:acme:support-desk@1.0.0",
                        "ainra:registrar-07:acme:support-bot@1.0.0",
                        &["read:tickets"],
                    ),
                ],
                revoke: false,
                renew: None,
            },
            Lineage {
                operator: "globex",
                lineage: "ledger-sync",
                version: "3.1.0",
                tier: "L4",
                auth: "A2",
                caps: &["read:ledger", "post:entry"],
                ceiling: &["read:ledger", "post:entry", "close:period"],
                hops: &[],
                revoke: false,
                renew: None,
            },
            Lineage {
                operator: "globex",
                lineage: "fraud-scan",
                version: "1.4.2",
                tier: "L3",
                auth: "A2",
                caps: &["read:transactions", "flag:transaction"],
                ceiling: &["read:transactions", "flag:transaction"],
                hops: &[],
                revoke: false,
                renew: None,
            },
        ],
    },
    RegistrarPlan {
        id: "registrar-11",
        seed: 0x115E_EDB2,
        lineages: &[
            Lineage {
                operator: "operator-03",
                lineage: "scheduler",
                version: "2.2.0",
                tier: "L2",
                auth: "A2",
                caps: &["read:calendar", "book:slot"],
                ceiling: &["read:calendar", "book:slot", "cancel:slot"],
                hops: &[],
                revoke: false,
                renew: Some("2.3.0"), // ADR-017: renewed → 2.3.0; both generations verify during the overlap
            },
            Lineage {
                operator: "operator-03",
                lineage: "crawler",
                version: "0.9.0",
                tier: "L0",
                auth: "A1",
                caps: &["fetch:public"],
                ceiling: &["fetch:public"],
                hops: &[],
                revoke: true,
                renew: None,
            },
            Lineage {
                operator: "operator-05",
                lineage: "procurement",
                version: "1.0.0",
                tier: "L2",
                auth: "A2",
                caps: &["read:catalog", "raise:po"],
                ceiling: &["read:catalog", "raise:po", "approve:po"],
                // buyer-owner → procurement (single narrowing hop)
                hops: &[(
                    "ainra:registrar-11:operator-05:buyer-owner@1.0.0",
                    "ainra:registrar-11:operator-05:procurement@1.0.0",
                    &["read:catalog", "raise:po"],
                )],
                revoke: false,
                renew: None,
            },
            Lineage {
                operator: "operator-05",
                lineage: "notifier",
                version: "3.0.1",
                tier: "L1",
                auth: "A2",
                caps: &["send:notification"],
                ceiling: &["send:notification"],
                hops: &[],
                revoke: false,
                renew: None,
            },
        ],
    },
    RegistrarPlan {
        id: "registrar-02",
        seed: 0x025E_EDC3,
        lineages: &[
            Lineage {
                operator: "operator-08",
                lineage: "translator",
                version: "5.0.0",
                tier: "L1",
                auth: "A2",
                caps: &["translate:text"],
                ceiling: &["translate:text"],
                hops: &[],
                revoke: false,
                renew: None,
            },
            Lineage {
                operator: "operator-08",
                lineage: "summarizer",
                version: "2.1.0",
                tier: "L1",
                auth: "A2",
                caps: &["summarize:document"],
                ceiling: &["summarize:document"],
                hops: &[],
                revoke: false,
                renew: None,
            },
            Lineage {
                operator: "acme",
                lineage: "legacy-batch",
                version: "0.1.0",
                tier: "L0",
                auth: "A1",
                caps: &["run:batch"],
                ceiling: &["run:batch"],
                hops: &[],
                revoke: true,
                renew: None,
            },
        ],
    },
];

/// Build the whole registry under `out_root`, persisting each registrar and writing `registry.json`. Returns the
/// combined registry JSON. Real crypto throughout; verdicts computed by the real verifier.
pub fn build(out_root: &std::path::Path) -> std::io::Result<serde_json::Value> {
    std::fs::create_dir_all(out_root)?;
    let mut registrars_json = Vec::new();
    let mut totals = (0u64, 0u64, 0u64); // issued, revoked, delegated

    for plan in PLAN {
        let dir = out_root.join(plan.id);
        let _ = std::fs::remove_dir_all(&dir);
        let mut rb =
            RegistrarBox::create_seeded(&dir, plan.id, 256, plan.seed, CREATE_NOW, NBF, EXP)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        // Each registrar's issuances use a deterministic rng derived from its seed (so chain party keys are stable).
        let mut rng = ChaCha20Rng::seed_from_u64(plan.seed ^ 0xA1);

        let mut to_revoke = Vec::new();
        for l in plan.lineages {
            let spec = IssueSpec {
                operator: l.operator.into(),
                lineage: l.lineage.into(),
                version: l.version.into(),
                tier: l.tier.into(),
                auth_class: l.auth.into(),
                principal_proof: principal_proof(plan.id, l.lineage),
                capabilities: l.caps.iter().map(|s| s.to_string()).collect(),
                scope_ceiling: l.ceiling.iter().map(|s| s.to_string()).collect(),
                hops: l
                    .hops
                    .iter()
                    .map(|(from, to, granted)| HopSpec {
                        from: from.to_string(),
                        to: to.to_string(),
                        granted: granted.iter().map(|s| s.to_string()).collect(),
                    })
                    .collect(),
                // ADR-017: every L3+ fixture lineage carries deterministic placeholder audit evidence whose
                // expiry equals the credential window's end (the cap binds exactly); below L3 none is needed.
                audit: matches!(l.tier, "L3" | "L4").then(|| {
                    ainra_services::registrar::AuditEvidence {
                        reference: format!("audit-{}-{}", plan.id, l.lineage),
                        expires: EXP,
                    }
                }),
            };
            let rec = rb
                .issue(&spec, &[], &mut rng)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            totals.0 += 1;
            if !rec.hops.is_empty() {
                totals.2 += 1;
            }
            // ADR-017 renewal (version-bumped reissue) at T = nbf + 5 days — inside the window, before the export's
            // verify time, so BOTH generations verify (the overlap). The new one carries the prev_leaf link.
            if let Some(new_version) = l.renew {
                let renew_at = NBF + 5 * 24 * 60 * 60;
                let audit = matches!(l.tier, "L3" | "L4").then(|| {
                    ainra_services::registrar::AuditEvidence {
                        reference: format!("audit-{}-{}-renew", plan.id, l.lineage),
                        expires: renew_at + ainra_core::consts::PASSPORT_VALIDITY_DEFAULT_SECS,
                    }
                });
                rb.reissue(
                    &rec.sub,
                    Some(new_version),
                    renew_at,
                    audit.as_ref(),
                    &mut rng,
                )
                .map_err(|e| std::io::Error::other(e.to_string()))?;
                totals.0 += 1;
            }
            if l.revoke {
                to_revoke.push(rec.sub.clone());
            }
        }
        for sub in &to_revoke {
            rb.revoke(sub, VERIFY_NOW)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            totals.1 += 1;
        }
        rb.save()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        registrars_json.push(export(&rb, VERIFY_NOW));
    }

    let registry = json!({
        "generated_window": { "nbf": NBF, "exp": EXP, "verified_at": VERIFY_NOW },
        "totals": { "issued": totals.0, "revoked": totals.1, "delegated": totals.2, "registrars": PLAN.len() },
        "registrars": registrars_json,
    });
    std::fs::write(
        out_root.join("registry.json"),
        serde_json::to_string_pretty(&registry)?,
    )?;
    Ok(registry)
}

/// A registrar's full export: accreditation, root key, the signed status list, and every record with a LIVE verdict.
pub fn export(rb: &RegistrarBox, now: u64) -> serde_json::Value {
    let published = rb.publish_status(now.saturating_sub(1));
    let records: Vec<_> = rb
        .records()
        .map(|r| {
            let v = rb.verify_record(&r.sub, now);
            json!({ "record": r, "verdict": serde_json::to_value(&v).unwrap() })
        })
        .collect();
    json!({
        "registrar": rb.id(),
        "accreditation": rb.accreditation(),
        "root_pub_slh": b64::encode(&rb.root_public()),
        "status_seq": rb.status_seq(),
        "status_list": serde_json::to_value(&published).unwrap(),
        "verified_at": now,
        "records": records,
    })
}

/// Re-verify every record in a registry export with the pure offline core verifier — a third-party check that the
/// shipped verdicts are real (not asserted). Returns `(checked, disagreements)`.
pub fn reverify_registry(registry: &serde_json::Value) -> (usize, Vec<String>) {
    let mut checked = 0usize;
    let mut bad = Vec::new();
    let empty = Vec::new();
    for reg in registry["registrars"].as_array().unwrap_or(&empty) {
        // Rebuild trust anchors from the accreditation.
        let anchors = ainra_adapter::anchors_from_export_json(reg);
        let now = reg["verified_at"].as_u64().unwrap_or(VERIFY_NOW);
        let published: ainra_services::status::SignedStatusList =
            match serde_json::from_value(reg["status_list"].clone()) {
                Ok(p) => p,
                Err(_) => {
                    bad.push(format!("{}: status_list decode", reg["registrar"]));
                    continue;
                }
            };
        let compressed = b64::decode(&published.status_list_b64).unwrap_or_default();
        let list = match status::StatusList::decode(&compressed, published.bit_len as usize) {
            Ok(l) => l,
            Err(_) => {
                bad.push(format!("{}: status list decode", reg["registrar"]));
                continue;
            }
        };
        for entry in reg["records"].as_array().unwrap_or(&empty) {
            let rec: ainra_services::registrar::IssuedRecord =
                match serde_json::from_value(entry["record"].clone()) {
                    Ok(r) => r,
                    Err(_) => {
                        bad.push("record decode".into());
                        continue;
                    }
                };
            let claimed = &entry["verdict"];
            let recomputed = ainra_services::registrar::verify_record_offline(
                &rec,
                &anchors,
                list.clone(),
                published.issued_at,
                now,
                status::Freshness::F3,
            );
            checked += 1;
            let recomputed_json = serde_json::to_value(&recomputed).unwrap();
            if &recomputed_json != claimed {
                bad.push(format!(
                    "{}: claimed {} but recomputed {}",
                    rec.sub, claimed, recomputed_json
                ));
            }
        }
    }
    (checked, bad)
}

/// A deterministic principal-proof reference (opaque hex; never PII) so each lineage's authority proof is stable.
/// FNV-1a over `registrar:lineage` → 16 hex chars — just an opaque, stable reference (never a real attestation).
fn principal_proof(registrar: &str, lineage: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in registrar
        .bytes()
        .chain(std::iter::once(b':'))
        .chain(lineage.bytes())
    {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}")
}
