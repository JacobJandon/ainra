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

// ── decoding helpers (fail-closed: a malformed field yields a refusable value, never a plausible one) ───────

pub fn decode32(s: &str) -> [u8; 32] {
    b64::decode_array::<32>(s).expect("32-byte field")
}


pub fn decode_cp_sig(w: &WireCheckpointSig) -> checkpoint::CheckpointSig {
    match w.mode.as_str() {
        "root" => checkpoint::CheckpointSig::Root {
            slh: b64::decode(w.slh.as_deref().unwrap_or("")).expect("slh"),
        },
        "delegate" => {
            let c = w.cert.as_ref().expect("delegate cert");
            checkpoint::CheckpointSig::Delegate {
                cert: checkpoint::DelegateCert {
                    delegate_ed25519: decode32(&c.delegate_ed25519),
                    scopes: c.scopes.clone(),
                    nbf: c.nbf,
                    exp: c.exp,
                    sig_slh: b64::decode(&c.sig_slh).expect("cert slh"),
                },
                sig_ed25519: b64::decode(w.sig_ed25519.as_deref().unwrap_or("")).expect("del sig"),
            }
        }
        other => panic!("unknown checkpoint sig mode {other}"),
    }
}

// ── the single vector → Presentation/TrustAnchors → Verdict path ───────────────────────────────────────────

pub fn run(v: &Vector) -> Verdict {
    let claims = b64::decode(&v.presentation.claims).expect("claims");
    let issuer_sig = crypto::HybridSig {
        ed25519: b64::decode(&v.presentation.issuer_sig.ed25519).expect("sig ed"),
        mldsa65: b64::decode(&v.presentation.issuer_sig.mldsa65).expect("sig ml"),
    };
    let chain_keys: Vec<crypto::HybridPublic> = v
        .presentation
        .chain_keys
        .iter()
        .map(|k| crypto::HybridPublic {
            ed25519: decode32(&k.ed25519),
            mldsa65: b64::decode(&k.mldsa65).expect("ml"),
        })
        .collect();
    let hop_proofs: Vec<verify::HopLogProof> = v
        .presentation
        .hop_proofs
        .iter()
        .map(|hp| verify::HopLogProof {
            leaf_index: hp.leaf_index,
            proof: hp.proof.iter().map(|s| decode32(s)).collect(),
        })
        .collect();
    let checkpoint_sig = decode_cp_sig(&v.presentation.checkpoint_sig);
    let status_list = status::StatusList::decode(
        &b64::decode(&v.presentation.status_list).expect("status bytes"),
        v.presentation.status_len as usize,
    )
    .expect("decode status list");
    let checkpoint = checkpoint::Checkpoint {
        origin: v.presentation.checkpoint.origin.clone(),
        tree_size: v.presentation.checkpoint.size,
        root: decode32(&v.presentation.checkpoint.root),
    };
    let inclusion_proof: Vec<[u8; 32]> = v
        .presentation
        .inclusion_proof
        .iter()
        .map(|s| decode32(s))
        .collect();
    let freshness = match v.presentation.freshness.as_str() {
        "F1" => status::Freshness::F1,
        "F2" => status::Freshness::F2,
        "F3" => status::Freshness::F3,
        other => panic!("unknown freshness {other}"),
    };
    let mandate_revocations =
        mandate::RevocationSet::from_ids(v.presentation.mandate_revocations.clone());

    let mut registrars = BTreeMap::new();
    for (id, r) in &v.anchors {
        registrars.insert(
            id.clone(),
            verify::RegistrarInfo {
                issuer_key: crypto::HybridPublic {
                    ed25519: decode32(&r.issuer_key.ed25519),
                    mldsa65: b64::decode(&r.issuer_key.mldsa65).expect("issuer ml"),
                },
                log_root_key: b64::decode(&r.log_root_key).expect("log root"),
            },
        );
    }
    let anchors = verify::TrustAnchors { registrars };

    let revoked_delegates: std::collections::BTreeSet<[u8; 32]> = v
        .presentation
        .revoked_delegates
        .iter()
        .map(|fp| decode32(fp))
        .collect();
    let pres = verify::Presentation {
        claims: &claims,
        issuer_sig,
        now: v.presentation.now,
        chain_keys,
        hop_proofs,
        status_list,
        status_issued_at: v.presentation.status_issued_at,
        freshness,
        checkpoint,
        checkpoint_sig,
        leaf_index: v.presentation.leaf_index,
        inclusion_proof,
        mandate_path: Vec::new(),
        mandate_proofs: Vec::new(),
        mandate_revocations,
        revoked_delegates,
    };
    verify::verify(&pres, &anchors)
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
            issuer_key: crypto::HybridPublic { ed25519: ed, mldsa65 },
            log_root_key,
        },
    );
    verify::TrustAnchors { registrars }
}
