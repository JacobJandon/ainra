// SPDX-License-Identifier: Apache-2.0 OR MIT
//! **The one place external bytes become core verify types.**
//!
//! L4 declined to hand-write a WASM adapter because a second implementation of "JSON → `Presentation` /
//! `TrustAnchors`" is precisely the divergence the four-way differential exists to catch. Mapping the boundary for
//! L5 found the second implementation *already existed* — a partial anchor decoder in the CLI's seed path that
//! **failed open**, substituting an all-zero issuer key for a malformed one. This crate exists so there is exactly
//! one answer to "what do these bytes mean", and so that answer is fail-closed everywhere.
//!
//! Discipline, matching `ainra-core`'s N7 purity: **no I/O, no clock, no argv, no network.** Callers read the
//! bytes and supply them; this crate only interprets. Every consumer — the vector generator, the conformance
//! runner, the WASM surface, and anything future — calls in here. If a change appears to need a second parse
//! implementation, that is a stop-and-report signal, not a thing to write.

use ainra_core::verdict::{Reason, Verdict};
use ainra_core::{b64, checkpoint, crypto, mandate, status, verify};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

// ── the wire shapes a conformance vector actually carries ──────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct WireKey {
    pub ed25519: String,
    pub mldsa65: String,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct WireSig {
    pub ed25519: String,
    pub mldsa65: String,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct WireRegistrar {
    pub issuer_key: WireKey,
    pub log_root_key: String,
    /// D-044 graduated-distrust cutoff. Absent = fully trusted, so every existing vector and directory decodes
    /// unchanged; present = refuse this registrar's credentials logged at leaf index >= n.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distrust_from_leaf: Option<u64>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct WireCheckpoint {
    pub origin: String,
    pub size: u64,
    pub root: String,
}
/// One hop's transparency-log inclusion evidence (M2 D-012).
#[derive(Serialize, Deserialize, Clone)]
pub struct WireHopProof {
    pub leaf_index: u64,
    pub proof: Vec<String>,
}
/// A checkpoint signature in one of the two ADR-002 modes.
#[derive(Serialize, Deserialize, Clone)]
pub struct WireCheckpointSig {
    pub mode: String, // "root" | "delegate"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slh: Option<String>, // root mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<WireDelegateCert>, // delegate mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig_ed25519: Option<String>, // delegate mode
}
#[derive(Serialize, Deserialize, Clone)]
pub struct WireDelegateCert {
    pub delegate_ed25519: String,
    pub scopes: Vec<String>,
    pub nbf: u64,
    pub exp: u64,
    pub sig_slh: String,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct WirePresentation {
    pub claims: String,
    pub issuer_sig: WireSig,
    pub now: u64,
    // One key per chain PARTY (hops + 1): [delegator_0, delegatee_0=delegator_1, …, subject] (M2 D-012).
    pub chain_keys: Vec<WireKey>,
    pub hop_proofs: Vec<WireHopProof>,
    pub status_list: String,
    pub status_len: u64,
    pub status_issued_at: u64,
    pub freshness: String,
    pub checkpoint: WireCheckpoint,
    pub checkpoint_sig: WireCheckpointSig,
    pub leaf_index: u64,
    pub inclusion_proof: Vec<String>,
    // The operative mandate path is inside the signed `claims` (authenticated); only the revocation set is here.
    pub mandate_revocations: Vec<String>,
    /// Revoked delegate-cert fingerprints (base64url SHA-256), M4. Omitted (default empty) for pre-M4 vectors so
    /// the existing corpus is byte-unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_delegates: Vec<String>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct WireExpect {
    pub verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Vector {
    pub name: String,
    pub description: String,
    pub expect: WireExpect,
    pub anchors: BTreeMap<String, WireRegistrar>,
    pub presentation: WirePresentation,
}

// ── decoding helpers ───────────────────────────────────────────────────────────────────────────────────────
//
// Fail-closed, and that is load-bearing rather than stylistic. These were `.expect(...)` back when this code only
// ever read fixtures the generator had just written. The WASM surface (L5 Task 2) hands the very same path bytes a
// stranger pasted into a browser, where an abort is a dead page rather than a refusal. The fix is **not** a second,
// lenient decoder for untrusted callers — that is exactly the divergence this crate exists to prevent. It is this
// one path learning to return a refusable `Reason`, so every caller fails closed identically. The corpus is
// unaffected: all 745 vectors are well-formed, so no arm below changes its answer, and the differential re-proves
// that byte-for-byte.

/// One decode step: the value, or the reason these bytes are unusable.
pub type D<T> = Result<T, Reason>;

/// Any decode error is a schema violation — we never guess at what malformed bytes meant.
fn bad<T, E>(r: Result<T, E>) -> D<T> {
    r.map_err(|_| Reason::SchemaViolation)
}

pub fn decode32(s: &str) -> D<[u8; 32]> {
    bad(b64::decode_array::<32>(s))
}

pub fn decode_cp_sig(w: &WireCheckpointSig) -> D<checkpoint::CheckpointSig> {
    Ok(match w.mode.as_str() {
        "root" => checkpoint::CheckpointSig::Root {
            slh: bad(b64::decode(w.slh.as_deref().unwrap_or("")))?,
        },
        "delegate" => {
            let c = w.cert.as_ref().ok_or(Reason::SchemaViolation)?;
            checkpoint::CheckpointSig::Delegate {
                cert: checkpoint::DelegateCert {
                    delegate_ed25519: decode32(&c.delegate_ed25519)?,
                    scopes: c.scopes.clone(),
                    nbf: c.nbf,
                    exp: c.exp,
                    sig_slh: bad(b64::decode(&c.sig_slh))?,
                },
                sig_ed25519: bad(b64::decode(w.sig_ed25519.as_deref().unwrap_or("")))?,
            }
        }
        // An unrecognised signature mode is REFUSED, never guessed. A verifier that treats a mode it does not know
        // as "probably the root one" is a verifier that can be talked past.
        _ => return Err(Reason::SchemaViolation),
    })
}

/// Trust anchors from either directory shape we actually publish, in **one** decoder.
///
/// Accepted: the conformance/directory form (`{"<registrar-id>": {issuer_key, log_root_key}}`, optionally nested
/// under `anchors`) and a registrar's own signed export (`{"accreditation": {...}}`). Anything else yields **no**
/// anchors, which makes every credential `unknown_registrar` — the fail-closed answer. This replaced a second
/// partial decoder that substituted an all-zero issuer key for a malformed one (see docs/PLAN-L5.md § finding #6).
pub fn anchors_from_json(v: &serde_json::Value) -> verify::TrustAnchors {
    let mut registrars = BTreeMap::new();
    if v.get("accreditation").is_some() {
        return anchors_from_export_json(v);
    }
    let map = match v.get("anchors").unwrap_or(v).as_object() {
        Some(m) => m,
        None => return verify::TrustAnchors { registrars },
    };
    for (id, r) in map {
        let Ok(w) = serde_json::from_value::<WireRegistrar>(r.clone()) else {
            continue; // an unreadable entry is simply not an anchor; it never becomes a lenient one
        };
        let (Ok(ed), Ok(ml), Ok(root)) = (
            decode32(&w.issuer_key.ed25519),
            bad(b64::decode(&w.issuer_key.mldsa65)),
            bad(b64::decode(&w.log_root_key)),
        ) else {
            continue;
        };
        registrars.insert(
            id.clone(),
            verify::RegistrarInfo {
                issuer_key: crypto::HybridPublic {
                    ed25519: ed,
                    mldsa65: ml,
                },
                log_root_key: root,
                distrust_from_leaf: w.distrust_from_leaf,
            },
        );
    }
    verify::TrustAnchors { registrars }
}

/// Decode a wire presentation into the core type. `now` is the **verifier's**, never the presenter's — freshness
/// and expiry are the receiving side's policy, so the caller supplies the clock and this overrides whatever the
/// bundle claims the time is.
/// Everything a [`verify::Presentation`] needs, owned, so the borrowed `claims` outlives the borrow.
///
/// A named struct rather than the tuple this started as: twelve positional fields are unreadable at the call site
/// and one transposed pair would compile silently into a wrong verdict. Clippy flagged it and clippy was right.
struct Decoded {
    claims: Vec<u8>,
    issuer_sig: crypto::HybridSig,
    chain_keys: Vec<crypto::HybridPublic>,
    hop_proofs: Vec<verify::HopLogProof>,
    checkpoint_sig: checkpoint::CheckpointSig,
    status_list: status::StatusList,
    checkpoint: checkpoint::Checkpoint,
    inclusion_proof: Vec<[u8; 32]>,
    freshness: status::Freshness,
    mandate_revocations: mandate::RevocationSet,
    revoked_delegates: std::collections::BTreeSet<[u8; 32]>,
}

fn presentation_parts(p: &WirePresentation) -> D<Decoded> {
    let claims = bad(b64::decode(&p.claims))?;
    let issuer_sig = crypto::HybridSig {
        ed25519: bad(b64::decode(&p.issuer_sig.ed25519))?,
        mldsa65: bad(b64::decode(&p.issuer_sig.mldsa65))?,
    };
    let mut chain_keys = Vec::with_capacity(p.chain_keys.len());
    for k in &p.chain_keys {
        chain_keys.push(crypto::HybridPublic {
            ed25519: decode32(&k.ed25519)?,
            mldsa65: bad(b64::decode(&k.mldsa65))?,
        });
    }
    let mut hop_proofs = Vec::with_capacity(p.hop_proofs.len());
    for hp in &p.hop_proofs {
        let mut proof = Vec::with_capacity(hp.proof.len());
        for s in &hp.proof {
            proof.push(decode32(s)?);
        }
        hop_proofs.push(verify::HopLogProof {
            leaf_index: hp.leaf_index,
            proof,
        });
    }
    let checkpoint_sig = decode_cp_sig(&p.checkpoint_sig)?;
    let status_list = bad(status::StatusList::decode(
        &bad(b64::decode(&p.status_list))?,
        p.status_len as usize,
    ))?;
    let checkpoint = checkpoint::Checkpoint {
        origin: p.checkpoint.origin.clone(),
        tree_size: p.checkpoint.size,
        root: decode32(&p.checkpoint.root)?,
    };
    let mut inclusion_proof = Vec::with_capacity(p.inclusion_proof.len());
    for s in &p.inclusion_proof {
        inclusion_proof.push(decode32(s)?);
    }
    let freshness = match p.freshness.as_str() {
        "F1" => status::Freshness::F1,
        "F2" => status::Freshness::F2,
        "F3" => status::Freshness::F3,
        _ => return Err(Reason::SchemaViolation),
    };
    let mandate_revocations = mandate::RevocationSet::from_ids(p.mandate_revocations.clone());
    let mut revoked_delegates = std::collections::BTreeSet::new();
    for fp in &p.revoked_delegates {
        revoked_delegates.insert(decode32(fp)?);
    }
    Ok(Decoded {
        claims,
        issuer_sig,
        chain_keys,
        hop_proofs,
        checkpoint_sig,
        status_list,
        checkpoint,
        inclusion_proof,
        freshness,
        mandate_revocations,
        revoked_delegates,
    })
}

// ── the single vector → Presentation/TrustAnchors → Verdict path ───────────────────────────────────────────

/// Verify one decoded wire presentation against decoded anchors at `now`.
///
/// This is **the** conversion: every surface — the generator, the conformance runner, the CLI, the browser —
/// reaches core verify types through this function and no other.
pub fn verify_wire(p: &WirePresentation, anchors: &verify::TrustAnchors, now: u64) -> Verdict {
    let d = match presentation_parts(p) {
        Ok(d) => d,
        Err(reason) => return Verdict::invalid(reason),
    };
    let pres = verify::Presentation {
        claims: &d.claims,
        issuer_sig: d.issuer_sig,
        // the CALLER's clock, not `p.now` — freshness and expiry are the verifier's policy, never the presenter's
        now,
        chain_keys: d.chain_keys,
        hop_proofs: d.hop_proofs,
        status_list: d.status_list,
        status_issued_at: p.status_issued_at,
        freshness: d.freshness,
        checkpoint: d.checkpoint,
        checkpoint_sig: d.checkpoint_sig,
        leaf_index: p.leaf_index,
        inclusion_proof: d.inclusion_proof,
        mandate_path: Vec::new(),
        mandate_proofs: Vec::new(),
        mandate_revocations: d.mandate_revocations,
        revoked_delegates: d.revoked_delegates,
    };
    verify::verify(&pres, anchors)
}

/// Run one conformance vector. A vector pins its own `now` on purpose — determinism is the point of the corpus.
pub fn run(v: &Vector) -> Verdict {
    let mut registrars = BTreeMap::new();
    for (id, r) in &v.anchors {
        let (Ok(ed), Ok(ml), Ok(root)) = (
            decode32(&r.issuer_key.ed25519),
            bad(b64::decode(&r.issuer_key.mldsa65)),
            bad(b64::decode(&r.log_root_key)),
        ) else {
            return Verdict::invalid(Reason::SchemaViolation);
        };
        registrars.insert(
            id.clone(),
            verify::RegistrarInfo {
                issuer_key: crypto::HybridPublic {
                    ed25519: ed,
                    mldsa65: ml,
                },
                log_root_key: root,
                distrust_from_leaf: r.distrust_from_leaf,
            },
        );
    }
    verify_wire(
        &v.presentation,
        &verify::TrustAnchors { registrars },
        v.presentation.now,
    )
}

// ── status-delta vectors ───────────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct WireDeltaCert {
    pub delegate_ed25519: String,
    pub scopes: Vec<String>,
    pub nbf: u64,
    pub exp: u64,
    pub sig_slh: String,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct WireDeltaExpect {
    pub accept: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct WireDeltaVector {
    pub name: String,
    pub kind: String, // "delta" | "fresh_head"
    pub expect: WireDeltaExpect,
    pub root_pub_slh: String,
    pub cert: WireDeltaCert,
    pub now: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrar_pub: Option<WireKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idx: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_status: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig_registrar: Option<WireKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub countersig_delegate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig_delegate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freshness: Option<String>,
}

pub fn cert_wire(c: &checkpoint::DelegateCert) -> WireDeltaCert {
    WireDeltaCert {
        delegate_ed25519: b64::encode(&c.delegate_ed25519),
        scopes: c.scopes.clone(),
        nbf: c.nbf,
        exp: c.exp,
        sig_slh: b64::encode(&c.sig_slh),
    }
}

pub fn reason_str(r: Reason) -> String {
    r.as_str().to_string()
}

pub fn delta_verify(v: &WireDeltaVector) -> Result<(), Reason> {
    let root_pub = b64::decode(&v.root_pub_slh).expect("root pk");
    let cert = checkpoint::DelegateCert {
        delegate_ed25519: b64::decode_array::<32>(&v.cert.delegate_ed25519).expect("delegate pk"),
        scopes: v.cert.scopes.clone(),
        nbf: v.cert.nbf,
        exp: v.cert.exp,
        sig_slh: b64::decode(&v.cert.sig_slh).expect("cert sig"),
    };
    if v.kind == "delta" {
        let reg = v.registrar_pub.as_ref().expect("registrar_pub");
        let reg_pub = crypto::HybridPublic {
            ed25519: b64::decode_array::<32>(&reg.ed25519).expect("reg ed"),
            mldsa65: b64::decode(&reg.mldsa65).expect("reg ml"),
        };
        let sig = v.sig_registrar.as_ref().expect("sig_registrar");
        let d = status::StatusDelta {
            uri: v.uri.clone().expect("uri"),
            from_seq: v.from_seq.expect("from_seq"),
            seq: v.seq.expect("seq"),
            ts: v.ts.expect("ts"),
            idx: v.idx.clone().expect("idx"),
            new_status: v.new_status.expect("new_status"),
            sig_registrar: crypto::HybridSig {
                ed25519: b64::decode(&sig.ed25519).expect("sig ed"),
                mldsa65: b64::decode(&sig.mldsa65).expect("sig ml"),
            },
            countersig_delegate: b64::decode(v.countersig_delegate.as_deref().expect("countersig"))
                .expect("countersig b64"),
        };
        d.verify(&reg_pub, &root_pub, &cert, v.now)
    } else {
        let h = status::FreshHead {
            uri: v.uri.clone().expect("uri"),
            seq: v.seq.expect("seq"),
            ts: v.ts.expect("ts"),
            status_hash: b64::decode_array::<32>(v.status_hash.as_deref().expect("hash"))
                .expect("hash b64"),
            sig_delegate: b64::decode(v.sig_delegate.as_deref().expect("sig")).expect("sig b64"),
        };
        let f = match v.freshness.as_deref() {
            Some("F2") => status::Freshness::F2,
            Some("F3") => status::Freshness::F3,
            _ => status::Freshness::F1,
        };
        h.verify(&root_pub, &cert, v.now, f)
    }
}

// ── directory vectors ──────────────────────────────────────────────────────────────────────────────────────

pub fn directory_result(v: &serde_json::Value) -> serde_json::Value {
    let d: ainra_core::directory::Directory =
        serde_json::from_value(v["directory"].clone()).expect("dir");
    let root_ed = b64::decode_array::<32>(v["root_ed25519"].as_str().unwrap()).expect("ed");
    let root_slh = b64::decode(v["root_slh"].as_str().unwrap()).expect("slh");
    match d.accredit(&root_ed, &root_slh) {
        Ok(acc) => json!({ "accept": true, "registrars": acc.anchors.registrars.len() }),
        Err(_) => json!({ "accept": false }),
    }
}

// ── registrar-export → trust anchors ───────────────────────────────────────────────────────────────────────────
/// Decode a registrar export's accreditation block into trust anchors.
///
/// L5 deleted a second implementation of this that **failed open**: a malformed issuer key became `[0u8; 32]`,
/// so a corrupt export produced a plausible-looking anchor and a verdict measured against a zero key. Here a
/// field that will not decode yields **no anchor at all**, which surfaces as `unknown_registrar` — the same
/// fail-closed posture every other decode in this crate has.
pub fn anchors_from_export_json(reg: &serde_json::Value) -> verify::TrustAnchors {
    let mut registrars = BTreeMap::new();
    let acc = &reg["accreditation"];
    let id = match acc["registrar"].as_str() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return verify::TrustAnchors { registrars },
    };
    let ed: [u8; 32] = match b64::decode(acc["issuer_key"]["ed25519"].as_str().unwrap_or(""))
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
    {
        Some(v) => v,
        None => return verify::TrustAnchors { registrars },
    };
    let (mldsa65, log_root_key) = match (
        b64::decode(acc["issuer_key"]["mldsa65"].as_str().unwrap_or("")),
        b64::decode(acc["log_root_key"].as_str().unwrap_or("")),
    ) {
        (Ok(m), Ok(l)) => (m, l),
        _ => return verify::TrustAnchors { registrars },
    };
    registrars.insert(
        id,
        verify::RegistrarInfo {
            issuer_key: crypto::HybridPublic {
                ed25519: ed,
                mldsa65,
            },
            log_root_key,
            distrust_from_leaf: acc["distrust_from_leaf"].as_u64(),
        },
    );
    verify::TrustAnchors { registrars }
}

// ── the canonical verdict EVENT (docs/PRESENTATION.md) ─────────────────────────────────────────────────────
//
// Fixed key order: status · reason · name · number · tier · freshness_age_s. This lived in the CLI binary while
// the CLI was its only Rust emitter; the browser surface would have made it a third copy alongside the SDK's, in
// the same drift class as a second decoder. It is wire vocabulary, so it belongs in the library — the same
// reasoning that moved `reason_str` here. A differential asserts the Rust and TS emitters are byte-identical.

/// The permanent AINRA Number: strip `@version` from a name → `did:ainra:reg:op:lineage`. `None` if it doesn't parse.
/// Mirrors the SDK's `numberFromName` exactly.
pub fn number_from_name(sub: &str) -> Option<String> {
    if !sub.contains('@') {
        return None;
    }
    let body = sub.strip_prefix("ainra:")?;
    let before_at = body.split('@').next()?;
    let parts: Vec<&str> = before_at.split(':').collect();
    let ok = parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    ok.then(|| format!("did:ainra:{}:{}:{}", parts[0], parts[1], parts[2]))
}

fn jstr(o: Option<&str>) -> String {
    o.map_or_else(
        || "null".to_string(),
        |v| serde_json::to_string(v).unwrap_or_else(|_| "null".into()),
    )
}

/// Canonical serialization — fixed key order, compact. MUST byte-match the SDK's `serializeVerdictEvent`.
pub fn event_json(
    status: &str,
    reason: Option<&str>,
    name: Option<&str>,
    number: Option<&str>,
    tier: Option<&str>,
    age: Option<i64>,
) -> String {
    format!(
        r#"{{"status":{},"reason":{},"name":{},"number":{},"tier":{},"freshness_age_s":{}}}"#,
        serde_json::to_string(status).unwrap_or_else(|_| "\"invalid\"".into()),
        jstr(reason),
        jstr(name),
        jstr(number),
        jstr(tier),
        age.map_or_else(|| "null".to_string(), |v| v.to_string()),
    )
}

/// Build the event from a verdict plus the presentation it was reached on. `name`/`number`/`tier` come out of the
/// **signed** claims; undecodable claims leave them null rather than inventing them — a well-formed event that
/// admits it knows less.
pub fn verdict_event(p: &WirePresentation, verdict: &Verdict, now: u64) -> String {
    let (mut name, mut number, mut tier) = (None, None, None);
    if let Ok(bytes) = b64::decode(&p.claims) {
        if let Ok(c) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if let Some(sub) = c.get("sub").and_then(|v| v.as_str()) {
                number = number_from_name(sub);
                name = Some(sub.to_string());
            }
            tier = c.get("tier").and_then(|v| v.as_str()).map(str::to_string);
        }
    }
    let age = (now as i64 - p.status_issued_at as i64).max(0);
    let reason = verdict.reason().map(reason_str);
    event_json(
        if verdict.is_valid() {
            "valid"
        } else {
            "invalid"
        },
        reason.as_deref(),
        name.as_deref(),
        number.as_deref(),
        tier.as_deref(),
        Some(age),
    )
}

// ── string entries: the only thing a non-Rust surface ever needs to call ───────────────────────────────────
//
// These take &str rather than a pre-parsed value on purpose. If the WASM binding parsed JSON itself it would own
// a decision — what counts as readable — and that decision is precisely what must have one home.

/// Unreadable input is a **verdict**, not an exception. Every surface refuses identically.
fn schema_violation_event() -> String {
    event_json("invalid", Some("schema_violation"), None, None, None, None)
}

/// Verify a presented bundle against a directory at the verifier's `now`. Returns the canonical verdict event.
///
/// `now_secs` is the **caller's** clock and overrides whatever the bundle claims the time is: freshness and expiry
/// are the receiving side's policy. This never panics and never allocates unboundedly on hostile input.
pub fn verify_bundle_json(bundle_json: &str, directory_json: &str, now_secs: u64) -> String {
    let Ok(p) = serde_json::from_str::<WirePresentation>(bundle_json) else {
        return schema_violation_event();
    };
    let Ok(dir) = serde_json::from_str::<serde_json::Value>(directory_json) else {
        return schema_violation_event();
    };
    let anchors = anchors_from_json(&dir);
    let verdict = verify_wire(&p, &anchors, now_secs);
    verdict_event(&p, &verdict, now_secs)
}

/// Run one conformance vector from its JSON text and return the verdict as JSON (`{"verdict":…}` / `…,"reason":…`).
/// This is the entry the cross-surface differential drives, so "it runs in your browser" is a claim the corpus can
/// defend rather than a description.
pub fn run_vector_json(vector_json: &str) -> String {
    let Ok(v) = serde_json::from_str::<Vector>(vector_json) else {
        return r#"{"verdict":"invalid","reason":"schema_violation"}"#.to_string();
    };
    serde_json::to_string(&run(&v))
        .unwrap_or_else(|_| r#"{"verdict":"invalid","reason":"schema_violation"}"#.to_string())
}
