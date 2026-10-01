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
use ainra_core::{b64, checkpoint, crypto, instance, mandate, status, verify};
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
    /// ADR-019 / D-047 — the instance rung. Omitted on every pre-M28 vector (same `skip_serializing_if`
    /// discipline as `revoked_delegates`, and for the same reason: a `null` here would change the canonical bytes
    /// of every existing vector and break `make repro` for no gain).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<WireInstance>,
    /// FIXTURE DATA ONLY — the audience a *conformance vector* says its verifier has, so the corpus can pin
    /// audience-mismatch cases deterministically.
    ///
    /// This field is on the wire struct because vectors are serialised with it, and a real presenter therefore
    /// CAN set it. Nothing in the verify path reads it: [`verify_wire`] takes the audience as a parameter, and
    /// only [`run`] — the vector runner, where the fixture is the whole point — passes this value in. Do not
    /// reintroduce a read of it from any other path.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub audience: String,
    /// The registrar's signature over this status publication (D-020), and the URI it was published under. A
    /// conformance vector has none — its status is a fixture input — so they are optional and omitted there. A GATE
    /// requires them: [`verify_gate`] authenticates the list against the directory's status key before it believes
    /// a bit of it (D-072). Until then this struct did not declare them, serde dropped them, and the Rust path
    /// trusted whatever status a presenter supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_sig_ed25519: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_sig_mldsa65: Option<String>,
}

/// The instance credential + its proof-of-possession, as they travel.
#[derive(Serialize, Deserialize, Clone)]
pub struct WireInstance {
    pub sub: String,
    pub iid: String,
    pub ikey: WireKey,
    pub nbf: u64,
    pub exp: u64,
    pub capabilities: Vec<String>,
    pub aud: String,
    pub passport_leaf: String,
    pub sig: WireSig,
    pub pop: WirePop,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct WirePop {
    pub aud: String,
    pub nonce: String,
    pub ts: u64,
    pub sig: WireSig,
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
// unaffected: every vector is well-formed, so no arm below changes its answer, and the differential re-proves
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
    instance: Option<(instance::InstanceCredential, instance::InstancePop)>,
}

fn presentation_parts(p: &WirePresentation) -> D<Decoded> {
    let claims = bad(b64::decode(&p.claims))?;
    // ADR-019 — decoded HERE and nowhere else. Strict canonical base64url throughout (D-029): a non-canonical
    // instance field is a decode failure, not a lenient parse, exactly like every other field on this path.
    let instance = match &p.instance {
        None => None,
        Some(w) => {
            let ic = instance::InstanceCredential {
                sub: w.sub.clone(),
                iid: w.iid.clone(),
                ikey: crypto::HybridPublic {
                    ed25519: decode32(&w.ikey.ed25519)?,
                    mldsa65: bad(b64::decode(&w.ikey.mldsa65))?,
                },
                nbf: w.nbf,
                exp: w.exp,
                capabilities: w.capabilities.clone(),
                aud: w.aud.clone(),
                passport_leaf: decode32(&w.passport_leaf)?,
                sig: crypto::HybridSig {
                    ed25519: bad(b64::decode(&w.sig.ed25519))?,
                    mldsa65: bad(b64::decode(&w.sig.mldsa65))?,
                },
            };
            let pop = instance::InstancePop {
                aud: w.pop.aud.clone(),
                nonce: w.pop.nonce.clone(),
                ts: w.pop.ts,
                sig: crypto::HybridSig {
                    ed25519: bad(b64::decode(&w.pop.sig.ed25519))?,
                    mldsa65: bad(b64::decode(&w.pop.sig.mldsa65))?,
                },
            };
            Some((ic, pop))
        }
    };
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
        instance,
    })
}

// ── the single vector → Presentation/TrustAnchors → Verdict path ───────────────────────────────────────────

/// FIXTURE semantics: the freshness class and the revoked-delegate set come from the WIRE, because a conformance
/// vector is self-contained (the TS SDK's `runVector` does the same). A GATE must not use this — a presenter would
/// choose its own freshness (up to F3, 24 h) and bring an empty revocation list. Gates call [`verify_wire_policy`]
/// with the verifier's class and the trusted directory's revocations (D-068).
pub fn verify_wire(
    p: &WirePresentation,
    anchors: &verify::TrustAnchors,
    now: u64,
    audience: &str,
) -> Verdict {
    verify_wire_policy(p, anchors, now, audience, None, None)
}

/// Verify with the CALLER's policy: its clock, its audience, its freshness class, and the revoked delegates of the
/// directory it trusts. `None` falls back to the wire's value — which only a self-contained fixture should ever do.
///
/// NOT A GATE. The status list and its issue time are taken from the wire as given; this function does not
/// authenticate them. A gate calls [`verify_gate`], which does, and then calls this (D-072).
/// Verify one decoded wire presentation against decoded anchors at `now`, **for the audience the caller names**.
///
/// This is **the** conversion: every surface — the generator, the conformance runner, the CLI, the browser —
/// reaches core verify types through this function and no other.
///
/// `audience` is a parameter rather than a field read off `p` (D-051). It used to be the latter, and the M30 fix
/// corrected the two entry points above this one while leaving this layer reading the wire — so a third party
/// calling the public function directly still got presenter-chosen audience binding, under a field comment that
/// said a presenter could not set it. A parameter cannot be forgotten; a field can.
pub fn verify_wire_policy(
    p: &WirePresentation,
    anchors: &verify::TrustAnchors,
    now: u64,
    audience: &str,
    freshness: Option<status::Freshness>,
    revoked_delegates: Option<&std::collections::BTreeSet<[u8; 32]>>,
) -> Verdict {
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
        // The VERIFIER's freshness class when it has one; the wire's only for a self-contained fixture.
        freshness: freshness.unwrap_or(d.freshness),
        checkpoint: d.checkpoint,
        checkpoint_sig: d.checkpoint_sig,
        leaf_index: p.leaf_index,
        inclusion_proof: d.inclusion_proof,
        mandate_path: Vec::new(),
        mandate_proofs: Vec::new(),
        mandate_revocations: d.mandate_revocations,
        // The trusted DIRECTORY's revocations when the caller holds one; the wire's only for a fixture.
        revoked_delegates: revoked_delegates.cloned().unwrap_or(d.revoked_delegates),
        instance: d.instance,
        audience: audience.to_string(),
    };
    verify::verify(&pres, anchors)
}

/// What a gate trusts, taken from a directory that verified against both ceremony roots ([`accredit_json`]).
pub struct GateTrust {
    pub anchors: verify::TrustAnchors,
    pub revoked_delegates: std::collections::BTreeSet<[u8; 32]>,
    /// registrar → the key that signs its status publications and the URI they are published under. A registrar
    /// with no entry cannot have its revocations authenticated, so its passports fail closed (`stale_status`).
    pub status: BTreeMap<String, StatusAuthority>,
}

/// One registrar's status-signing key and status URI, from the signed directory.
pub struct StatusAuthority {
    pub key: crypto::HybridPublic,
    pub uri: String,
}

/// Authenticate the presented status list against the registrar's directory-published status key (D-020) — the
/// Rust statement of what `@ainra/sdk`'s `Verifier` and the Python `Verifier` do, in the same order and with the
/// same reasons. The presenter supplies the compressed list and `status_issued_at`; they mean nothing until this
/// proves the registrar signed exactly those values. Everything fails closed to `stale_status`: status that cannot
/// be authenticated is status that is not available.
///
///   (a) the bundle carries a hybrid status signature and a `status_uri`;
///   (b) the passport's claimed status URI, the bundle's, and the directory's all agree — so another registrar's
///       all-clear list cannot be spliced in;
///   (c) the signature verifies over [`status::publication_signing_bytes`] under the registrar's status key.
///
/// It reads the claims and the status TEXT only: nothing is decompressed before the signature holds.
fn authenticate_status(p: &WirePresentation, trust: &GateTrust) -> Result<(), Reason> {
    let claims = bad(b64::decode(&p.claims))?;
    let passport = ainra_core::passport::Passport::parse_checked(&claims)?;
    let (registrar, _, _) =
        ainra_core::name::AinraName::parse_did(&passport.iss).map_err(|_| Reason::NameMalformed)?;
    if !trust.anchors.registrars.contains_key(&registrar) {
        return Err(Reason::UnknownRegistrar);
    }
    let authority = trust.status.get(&registrar).ok_or(Reason::StaleStatus)?;
    let (Some(uri), Some(ed), Some(ml)) =
        (&p.status_uri, &p.status_sig_ed25519, &p.status_sig_mldsa65)
    else {
        return Err(Reason::StaleStatus);
    };
    if *uri != authority.uri || passport.status.status_list.uri != authority.uri {
        return Err(Reason::StaleStatus);
    }
    let (Ok(ed25519), Ok(mldsa65)) = (b64::decode(ed), b64::decode(ml)) else {
        return Err(Reason::StaleStatus);
    };
    let signing =
        status::publication_signing_bytes(uri, p.status_len, p.status_issued_at, &p.status_list)
            .map_err(|_| Reason::StaleStatus)?;
    crypto::verify_hybrid(
        &authority.key,
        signing.as_bytes(),
        &crypto::HybridSig { ed25519, mldsa65 },
    )
    .map_err(|_| Reason::StaleStatus)
}

/// Verify a presentation AS A GATE (D-072): everything a presenter could otherwise choose is the verifier's.
///
///   * the status list is authenticated against the directory's status key before it is decompressed or read;
///   * the freshness class is the gate's (D-068);
///   * the revoked delegates are the directory's (D-068);
///   * the mandate-revocation set is empty — there is no dynamic mandate feed, so nothing a presenter sends can be
///     one (static mandates inside the signed passport are still enforced);
///   * the clock and the audience are the caller's.
///
/// This is the function `@ainra/edge` and `ainra verify-request` reach. [`verify_wire_policy`] is NOT a gate: it
/// applies the caller's freshness and revocations to status it has not authenticated, which is right for a fixture
/// and for nothing else.
pub fn verify_gate(
    p: &WirePresentation,
    trust: &GateTrust,
    now: u64,
    audience: &str,
    freshness: status::Freshness,
) -> Verdict {
    if let Err(reason) = authenticate_status(p, trust) {
        return Verdict::invalid(reason);
    }
    let mut q = p.clone();
    q.mandate_revocations.clear();
    verify_wire_policy(
        &q,
        &trust.anchors,
        now,
        audience,
        Some(freshness),
        Some(&trust.revoked_delegates),
    )
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
    // The vector IS the fixture, so its declared audience is the verifier's audience here — said explicitly
    // rather than absorbed silently from the wire struct.
    verify_wire(
        &v.presentation,
        &verify::TrustAnchors { registrars },
        v.presentation.now,
        &v.presentation.audience,
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

/// Evaluate one `vectors/v1-presentation` vector through the core's RFC 9421 profile (PLAN-M34 Task 3–4).
///
/// The vector is the request exactly as a gate would see it — method, authority, path, the header list IN ORDER,
/// the body — plus the instance credential's id and key, the verifier's clock and the nonces its cache has already
/// seen. The result is `{"ok":true,"nonce","created"}` or `{"ok":false,"reason"}`, the shape every implementation's
/// runner must reproduce.
pub fn presentation_result(v: &serde_json::Value) -> serde_json::Value {
    presentation_eval(v).expect("a well-formed presentation vector")
}

/// The same evaluation from JSON text, for hosts that must never panic (the WASM boundary): anything malformed is
/// `{"ok":false,"reason":"schema_violation"}`.
pub fn run_presentation_vector_json(vector_json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(vector_json)
        .ok()
        .and_then(|v| presentation_eval(&v))
        .unwrap_or_else(|| json!({ "ok": false, "reason": "schema_violation" }))
        .to_string()
}

fn presentation_eval(v: &serde_json::Value) -> Option<serde_json::Value> {
    use ainra_core::presentation::{verify_presentation, SignableRequest};
    let r = &v["request"];
    let headers: Vec<(String, String)> = r["headers"]
        .as_array()?
        .iter()
        .map(|p| {
            Some((
                p.get(0)?.as_str()?.to_string(),
                p.get(1)?.as_str()?.to_string(),
            ))
        })
        .collect::<Option<_>>()?;
    let body = match r["body_b64u"].as_str() {
        Some(b) => Some(b64::decode(b).ok()?),
        None => None,
    };
    let req = SignableRequest {
        method: r["method"].as_str()?,
        authority: r["authority"].as_str()?,
        path: r["path"].as_str()?,
        headers: &headers,
        body: body.as_deref(),
    };
    let ik = &v["instance"]["ikey"];
    let ikey = crypto::HybridPublic {
        ed25519: b64::decode_array::<32>(ik["ed25519"].as_str()?).ok()?,
        mldsa65: b64::decode(ik["mldsa65"].as_str()?).ok()?,
    };
    let seen: Vec<&str> = v["seen_nonces"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    Some(
        match verify_presentation(
            &req,
            v["instance"]["iid"].as_str()?,
            &ikey,
            v["now"].as_u64()?,
            v["max_age_secs"].as_u64()?,
            |n| seen.contains(&n),
        ) {
            Ok((nonce, created)) => json!({ "ok": true, "nonce": nonce, "created": created }),
            Err(reason) => json!({ "ok": false, "reason": reason.as_str() }),
        },
    )
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
    event_json_instance(status, reason, name, number, tier, age, None, None)
}

/// The full event, including the ADR-019 instance fields.
///
/// The two instance keys are ALWAYS present — `null` when a passport was presented directly. A variable-shape
/// event would mean every consumer has to branch, and the whole point of this shape (M16, D-033) is that one
/// serializer's bytes are every surface's bytes.
///
/// `instance_iid` is emitted only when it is within [`instance::MAX_IID_LEN`], and null otherwise (D-053). The
/// comment that used to sit here said the field was "safe to emit: opaque and random by construction" — which is
/// what ADR-019 asks a HONEST minter to do, and therefore a promise made by the party the verifier is in the middle
/// of deciding whether to trust. The event is built for refused bundles too, so an unbounded read here is the
/// presenter writing arbitrary text into the operator's logging pipeline.
#[allow(clippy::too_many_arguments)]
pub fn event_json_instance(
    status: &str,
    reason: Option<&str>,
    name: Option<&str>,
    number: Option<&str>,
    tier: Option<&str>,
    age: Option<i64>,
    instance_iid: Option<&str>,
    instance_exp: Option<u64>,
) -> String {
    format!(
        r#"{{"status":{},"reason":{},"name":{},"number":{},"tier":{},"freshness_age_s":{},"instance_iid":{},"instance_exp":{}}}"#,
        serde_json::to_string(status).unwrap_or_else(|_| "\"invalid\"".into()),
        jstr(reason),
        jstr(name),
        jstr(number),
        jstr(tier),
        age.map_or_else(|| "null".to_string(), |v| v.to_string()),
        jstr(instance_iid),
        instance_exp.map_or_else(|| "null".to_string(), |v| v.to_string()),
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
    let (iid, iexp) = match &p.instance {
        // D-053: an `iid` past the bound is not an `iid`. Emit null rather than the presenter's payload — this
        // event is built for REFUSED bundles too, so the write happens whether or not the bundle was trusted.
        Some(i) if i.iid.len() <= ainra_core::instance::MAX_IID_LEN => {
            (Some(i.iid.as_str()), Some(i.exp))
        }
        Some(i) => (None, Some(i.exp)),
        None => (None, None),
    };
    event_json_instance(
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
        iid,
        iexp,
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
    // Audience defaults to the fail-closed empty string: a caller that has not said who it is accepts no
    // instance credential. Callers that CAN name themselves should use `verify_bundle_json_aud`.
    verify_bundle_json_aud(bundle_json, directory_json, now_secs, "")
}

/// Verify a presented bundle at the caller's clock AND the caller's audience (ADR-019).
///
/// NOT A GATE (D-068, D-072). The directory is taken as given, not checked against the roots, and the freshness
/// class and the status list are the bundle's own: this is the fixture-semantics path the browser demonstration
/// uses on specimen records. Anything deciding access calls [`accredit_json`] once and [`gate_json`] /
/// [`credential_json`] per request, which authenticate all three.
///
/// The audience is a PARAMETER, never read from the bundle. It was read from the bundle until the M30 adversarial
/// review: `WirePresentation.audience` exists so the conformance corpus can pin audience cases deterministically —
/// exactly as it pins `now` — and `verify_bundle_json` had no audience parameter at all, so the presenter's value
/// was the only one available. Every embedded Rust verifier and every browser using `ainra-wasm` therefore let a
/// presenter name its own audience, defeating ADR-019 audience binding. The doc comment on that field even said
/// "a presenter cannot set this", which was true of the corpus runner and false of this entry point.
pub fn verify_bundle_json_aud(
    bundle_json: &str,
    directory_json: &str,
    now_secs: u64,
    audience: &str,
) -> String {
    let Ok(p) = serde_json::from_str::<WirePresentation>(bundle_json) else {
        return schema_violation_event();
    };
    let Ok(dir) = serde_json::from_str::<serde_json::Value>(directory_json) else {
        return schema_violation_event();
    };
    let anchors = anchors_from_json(&dir);
    // The CALLER's audience is passed, never absorbed from the bundle — exactly as `now` is.
    let verdict = verify_wire(&p, &anchors, now_secs, audience);
    verdict_event(&p, &verdict, now_secs)
}

// ── the edge gate (PLAN-M34 Task 5) ─────────────────────────────────────────────────────────────────────────────

/// The digest that names a bundle's stable part (D-065): the bundle with `instance.pop` removed, in the core's
/// canonical JSON, under SHA-256 — `sha-256=:…:`. The same value `@ainra/sdk`'s `presentationRef` computes, because
/// the two canonical encoders are held byte-identical by `make diff` (B). `None` for anything that is not JSON or
/// cannot be canonicalised.
pub fn presentation_ref_json(bundle_json: &str) -> Option<String> {
    let mut v: serde_json::Value = serde_json::from_str(bundle_json).ok()?;
    if let Some(inst) = v.get_mut("instance").and_then(|i| i.as_object_mut()) {
        inst.remove("pop");
    }
    let c = ainra_core::canon::canonicalize_value(&v).ok()?;
    Some(ainra_core::presentation::content_digest(c.as_bytes()))
}

/// A gate's trust, established ONCE: the directory must verify against BOTH ceremony roots (FROST Ed25519 and
/// SLH-DSA), and what comes back is its anchors AND its revoked delegates — the verifier's, never the presenter's.
/// Returns `{"ok":true,"trust":{"anchors":{…},"revoked_delegates":[…]},"epoch":n}` or `{"ok":false}`; a host
/// that gets `ok:false` must not start. The trust object is what every [`gate_json`] call then receives.
pub fn accredit_json(directory_json: &str, roots_json: &str) -> String {
    let fail = || json!({ "ok": false }).to_string();
    let (Ok(d), Ok(roots)) = (
        serde_json::from_str::<ainra_core::directory::Directory>(directory_json),
        serde_json::from_str::<serde_json::Value>(roots_json),
    ) else {
        return fail();
    };
    let (Some(ed), Some(slh)) = (roots["root_ed25519"].as_str(), roots["root_slh"].as_str()) else {
        return fail();
    };
    let (Ok(ed), Ok(slh)) = (b64::decode_array::<32>(ed), b64::decode(slh)) else {
        return fail();
    };
    let Ok(acc) = d.accredit(&ed, &slh) else {
        return fail();
    };
    let anchors: serde_json::Map<String, serde_json::Value> = acc
        .anchors
        .registrars
        .iter()
        .map(|(id, r)| {
            let w = WireRegistrar {
                issuer_key: WireKey {
                    ed25519: b64::encode(&r.issuer_key.ed25519),
                    mldsa65: b64::encode(&r.issuer_key.mldsa65),
                },
                log_root_key: b64::encode(&r.log_root_key),
                distrust_from_leaf: r.distrust_from_leaf,
            };
            (
                id.clone(),
                serde_json::to_value(w).unwrap_or(serde_json::Value::Null),
            )
        })
        .collect();
    let revoked: Vec<String> = acc
        .revoked_delegates
        .iter()
        .map(|fp| b64::encode(fp))
        .collect();
    // Each accredited registrar's status key and URI, from the directory that just verified (D-072). An entry with
    // no status key gets no authority here, and its passports then fail closed at the gate.
    let status: serde_json::Map<String, serde_json::Value> = d
        .entries
        .iter()
        .filter(|e| !e.status_ed25519.is_empty() && !e.status_mldsa65.is_empty())
        .map(|e| {
            (
                e.registrar.clone(),
                json!({ "key": { "ed25519": e.status_ed25519, "mldsa65": e.status_mldsa65 }, "uri": e.status_uri }),
            )
        })
        .collect();
    json!({ "ok": true, "trust": { "anchors": anchors, "revoked_delegates": revoked, "status": status }, "epoch": acc.epoch })
        .to_string()
}

/// Decode the trust object [`accredit_json`] produced. `None` — fail closed — for anything malformed.
fn gate_trust(trust_json: &str) -> Option<GateTrust> {
    let t: serde_json::Value = serde_json::from_str(trust_json).ok()?;
    t.get("anchors")?.as_object()?;
    let mut revoked_delegates = std::collections::BTreeSet::new();
    for fp in t.get("revoked_delegates")?.as_array()? {
        revoked_delegates.insert(b64::decode_array::<32>(fp.as_str()?).ok()?);
    }
    // `status` is REQUIRED: a trust object without it predates D-072, and a gate built from one would have nothing
    // to authenticate status with. Fail closed rather than fall back to believing the presenter.
    let mut status = BTreeMap::new();
    for (id, a) in t.get("status")?.as_object()? {
        status.insert(
            id.clone(),
            StatusAuthority {
                key: crypto::HybridPublic {
                    ed25519: b64::decode_array::<32>(a["key"]["ed25519"].as_str()?).ok()?,
                    mldsa65: b64::decode(a["key"]["mldsa65"].as_str()?).ok()?,
                },
                uri: a["uri"].as_str()?.to_string(),
            },
        );
    }
    Some(GateTrust {
        anchors: anchors_from_json(&t),
        revoked_delegates,
        status,
    })
}

fn freshness_of(s: &str) -> Option<status::Freshness> {
    match s {
        "F1" => Some(status::Freshness::F1),
        "F2" => Some(status::Freshness::F2),
        "F3" => Some(status::Freshness::F3),
        _ => None,
    }
}

/// The credential alone, under the gate's policy — what a send-once endpoint checks before it stores anything.
/// Returns the canonical verdict event.
pub fn credential_json(
    bundle_json: &str,
    trust_json: &str,
    now_secs: u64,
    audience: &str,
    freshness: &str,
) -> String {
    let (Ok(p), Some(trust), Some(f)) = (
        serde_json::from_str::<WirePresentation>(bundle_json),
        gate_trust(trust_json),
        freshness_of(freshness),
    ) else {
        return schema_violation_event();
    };
    let verdict = verify_gate(&p, &trust, now_secs, audience, f);
    verdict_event(&p, &verdict, now_secs)
}

/// The edge gate's one call: verify the CREDENTIAL under the gate's policy, then the REQUEST it arrived on (D-062).
/// `trust_json` is the object [`accredit_json`] returned; `freshness` is the gate's class ("F1"/"F2"/"F3"), never
/// the presenter's. `request_json` is `{method, authority, path, headers: [[name, value], …], body_b64u}`.
///
/// Returns `{"allow", "reason", "event", "nonce"}`. `nonce` is set only when everything verified: single use is the
/// caller's to enforce (N7), and only now, after the signature held.
pub fn gate_json(
    bundle_json: &str,
    trust_json: &str,
    request_json: &str,
    now_secs: u64,
    audience: &str,
    freshness: &str,
) -> String {
    use ainra_core::presentation::{verify_presentation, SignableRequest, MAX_AGE_SECS};
    let out =
        |allow: bool, reason: Option<&str>, event: serde_json::Value, nonce: Option<String>| {
            json!({ "allow": allow, "reason": reason, "event": event, "nonce": nonce }).to_string()
        };
    let schema =
        || serde_json::from_str(&schema_violation_event()).unwrap_or(serde_json::Value::Null);
    let (Ok(p), Some(trust), Some(f)) = (
        serde_json::from_str::<WirePresentation>(bundle_json),
        gate_trust(trust_json),
        freshness_of(freshness),
    ) else {
        return out(false, Some("schema_violation"), schema(), None);
    };
    let verdict = verify_gate(&p, &trust, now_secs, audience, f);
    let event: serde_json::Value = serde_json::from_str(&verdict_event(&p, &verdict, now_secs))
        .unwrap_or(serde_json::Value::Null);
    if let Verdict::Invalid { reason } = &verdict {
        let r = serde_json::to_value(reason)
            .ok()
            .and_then(|x| x.as_str().map(String::from));
        return out(
            false,
            Some(r.as_deref().unwrap_or("schema_violation")),
            event,
            None,
        );
    }
    let Some(inst) = &p.instance else {
        return out(false, Some("presentation_unsigned"), event, None);
    };
    let (Ok(ed), Ok(ml)) = (
        b64::decode_array::<32>(&inst.ikey.ed25519),
        b64::decode(&inst.ikey.mldsa65),
    ) else {
        return out(false, Some("schema_violation"), event, None);
    };
    let ikey = crypto::HybridPublic {
        ed25519: ed,
        mldsa65: ml,
    };
    let Ok(r) = serde_json::from_str::<serde_json::Value>(request_json) else {
        return out(false, Some("schema_violation"), event, None);
    };
    let headers: Option<Vec<(String, String)>> = r["headers"].as_array().map(|a| {
        a.iter()
            .filter_map(|h| {
                Some((
                    h.get(0)?.as_str()?.to_string(),
                    h.get(1)?.as_str()?.to_string(),
                ))
            })
            .collect()
    });
    let body = match r["body_b64u"].as_str() {
        None => None,
        Some(b) => match b64::decode(b) {
            Ok(v) => Some(v),
            Err(_) => return out(false, Some("schema_violation"), event, None),
        },
    };
    let (Some(method), Some(authority), Some(path), Some(headers)) = (
        r["method"].as_str(),
        r["authority"].as_str(),
        r["path"].as_str(),
        headers,
    ) else {
        return out(false, Some("schema_violation"), event, None);
    };
    let req = SignableRequest {
        method,
        authority,
        path,
        headers: &headers,
        body: body.as_deref(),
    };
    match verify_presentation(&req, &inst.iid, &ikey, now_secs, MAX_AGE_SECS, |_| false) {
        Ok((nonce, _)) => out(true, None, event, Some(nonce)),
        Err(reason) => out(false, Some(reason.as_str()), event, None),
    }
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

#[cfg(test)]
mod audience_tests {
    //! ADR-019: the audience is the CALLER's, never the bundle's.
    //!
    //! WITNESS — could this fail? It did, against the code as it stood. `verify_bundle_json` had no audience
    //! parameter, so `WirePresentation.audience` (which exists so the corpus can pin audience cases) was the only
    //! value available and the presenter supplied it. Every embedded Rust verifier and every browser using
    //! `ainra-wasm` accepted an instance credential addressed to somebody else. Restore
    //! `audience: p.audience.clone()` and the second assertion below returns "valid".
    use super::*;

    fn instance_vector() -> serde_json::Value {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/v1");
        let mut names: Vec<_> = std::fs::read_dir(&dir)
            .expect("vectors/v1")
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .filter(|n| n.starts_with("instance-valid-"))
            .collect();
        names.sort();
        let raw = std::fs::read_to_string(dir.join(&names[0])).expect("vector");
        serde_json::from_str(&raw).expect("json")
    }

    #[test]
    fn the_caller_supplies_the_audience_not_the_presenter() {
        let v = instance_vector();
        let bundle = serde_json::to_string(&v["presentation"]).expect("bundle");
        // REAL anchors, so verification actually reaches step 10 and the audience is what decides the verdict.
        // The first version of this test passed empty anchors: every case came back `unknown_registrar`, the
        // instance rung was never reached, and restoring the defect left the test green. A test that cannot
        // reach the code it names is not a test.
        let dir = serde_json::json!({ "anchors": v["anchors"] }).to_string();
        let claimed = v["presentation"]["audience"]
            .as_str()
            .expect("aud")
            .to_string();
        let now = v["presentation"]["now"].as_u64().expect("now");

        // (a) the caller declares the audience the credential names → accepted.
        let ok = verify_bundle_json_aud(&bundle, &dir, now, &claimed);
        assert!(
            ok.contains("\"status\":\"valid\""),
            "the honest case must verify, else the rest proves nothing: {ok}"
        );

        // (b) the caller declares a DIFFERENT audience → refused, even though the bundle still claims its own.
        let elsewhere =
            verify_bundle_json_aud(&bundle, &dir, now, "https://not-this-service.example");
        assert!(
            elsewhere.contains("instance_pop_invalid"),
            "a foreign audience was accepted: {elsewhere}"
        );

        // (c) no audience declared → the fail-closed default, never "whatever the bundle said".
        let defaulted = verify_bundle_json(&bundle, &dir, now);
        assert!(
            defaulted.contains("instance_pop_invalid"),
            "the default accepted an instance credential: {defaulted}"
        );
    }
}
