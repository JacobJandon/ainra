// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `registrar-box` — a REAL AINRA registrar (spec C5: issuer API + datastore + key mgmt + TSL segment). It composes
//! the audited primitives and the M2 daemons; it invents no security logic of its own:
//!
//!   * **key management** — one hybrid issuer key (Ed25519 + ML-DSA-65) that signs every passport, and one SLH-DSA
//!     ceremony-root stand-in that certifies the log's checkpoint delegate AND the status segment's delta delegate;
//!   * **issuance** — build the SD-JWT-VC claim-set, (dual-)sign any delegation hops, append the credential body
//!     (and each hop's bytes) to its own [`Logd`] shard, snapshot + delegate-sign a checkpoint, and keep the RFC 6962
//!     inclusion proof — i.e. *logged-before-valid* at issue time;
//!   * **revocation** — flip the lineage's bit through the [`Statusd`] TSL segment, emitting a signed, delegate-
//!     countersigned [`ainra_core::status::StatusDelta`] that advances the head sequence;
//!   * **datastore** — every issued credential is kept as a fully self-describing [`IssuedRecord`] (all binary as
//!     base64url) that round-trips to disk and reconstructs a verifiable [`Presentation`] on demand.
//!
//! The verdict for any record is produced by actually calling [`ainra_core::verify::verify`] — never asserted.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ainra_core::checkpoint::{Checkpoint, CheckpointSig};
use ainra_core::passport::ActLink;
use ainra_core::verify::{self, HopLogProof, Presentation, RegistrarInfo, TrustAnchors};
use ainra_core::{b64, canon, chain, crypto, mandate, merkle, status, Verdict};
use rand_core::{CryptoRngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::log::Logd;
use crate::status::Statusd;

/// Operational delegate-cert lifetime: 90 days, inside the ADR-002 ≤ 92-day cap. The cap itself lives in
/// [`ainra_core::consts`]; the compile-time assert keeps this operational choice from ever drifting past it.
const CERT_VALIDITY: u64 = 90 * 24 * 60 * 60;
const _: () = assert!(CERT_VALIDITY <= ainra_core::consts::DELEGATE_CERT_MAX_SECS);

/// A single delegation hop to author (pre-signing). `granted` MUST be ⊆ the delegator's effective set — the engine
/// does not widen for you; a widening chain will simply verify to `chain_widening`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopSpec {
    pub from: String,
    pub to: String,
    pub granted: Vec<String>,
}

/// ADR-017 tier-audit evidence, held REGISTRAR-SIDE (Standard §4: evidence lives at the registrar, never at the
/// root and never on the wire — the passport format is unchanged). L3+ issuance/renewal is refused unless this
/// is present and the requested passport `exp` does not exceed `expires`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvidence {
    /// Opaque reference to the audit artifact in the registrar's evidence store (e.g. a digest). Never PII.
    pub reference: String,
    /// Unix seconds the audit attestation itself expires.
    pub expires: u64,
}

/// Everything needed to issue one credential. `operator`/`lineage`/`version` compose the `ainra:` subject under the
/// engine's registrar id. `status_idx` is auto-allocated if `None`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssueSpec {
    pub operator: String,
    pub lineage: String,
    pub version: String,
    pub tier: String,
    pub auth_class: String,
    pub principal_proof: String,
    pub capabilities: Vec<String>,
    pub scope_ceiling: Vec<String>,
    #[serde(default)]
    pub hops: Vec<HopSpec>,
    /// ADR-017: current tier-audit evidence — REQUIRED for L3/L4 (see [`AuditEvidence`]); ignored below L3.
    #[serde(default)]
    pub audit: Option<AuditEvidence>,
}

/// The tier and authority-class vocabularies are CLOSED (MTS §15: L0..L4, A1..A4). Issuance refuses anything
/// else — a free-string tier like `"l3"` or `"L5"` would dodge the ADR-017 audit cap while minting a credential
/// the verifier rejects anyway; the engine surfaces the error honestly at issue time instead.
fn validate_tier_auth(tier: &str, auth: &str) -> Result<(), IssueError> {
    if !matches!(tier, "L0" | "L1" | "L2" | "L3" | "L4") {
        return Err(IssueError::Malformed(format!(
            "unknown tier '{tier}' — the tier vocabulary is closed: L0..L4 (MTS §15)"
        )));
    }
    if !matches!(auth, "A1" | "A2" | "A3" | "A4") {
        return Err(IssueError::Malformed(format!(
            "unknown authority class '{auth}' — the class vocabulary is closed: A1..A4 (MTS §15)"
        )));
    }
    Ok(())
}

/// ADR-017's audit cap: an L3+ passport may never outlive the audit behind its tier. Below L3 no audit is
/// required (that's what keeps L2 issuance permission-light); at L3+ a missing audit refuses issuance and a
/// window past the audit's own expiry refuses with the reason spelled out.
fn check_audit_cap(tier: &str, exp: u64, audit: Option<&AuditEvidence>) -> Result<(), IssueError> {
    if !matches!(tier, "L3" | "L4") {
        return Ok(());
    }
    let Some(a) = audit else {
        return Err(IssueError::AuditRequired(format!(
            "tier {tier} issuance/renewal requires current tier-audit evidence — ADR-017: an L3+ passport may \
             never outlive its audit"
        )));
    };
    if exp > a.expires {
        return Err(IssueError::AuditStale(format!(
            "requested passport exp {exp} exceeds the tier audit's expiry {} — ADR-017: \"audited\" must mean \
             audited recently, so the credential may not outlive the evidence behind its tier; renew the audit \
             first or request a shorter window",
            a.expires
        )));
    }
    Ok(())
}

/// Read one field out of a stored record's signed claim JSON (e.g. `/authority/principal_proof`). `None` if the
/// claims fail to parse or the pointer is absent — callers treat that as "unknown", never as a default identity.
fn passport_field(rec: &IssuedRecord, pointer: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(&rec.claims).ok()?;
    v.pointer(pointer)?.as_str().map(|s| s.to_string())
}

/// A stored record's own credential leaf (base64url) — the `log.leaf` its claims commit to.
fn record_leaf(rec: &IssuedRecord) -> Option<String> {
    passport_field(rec, "/log/leaf")
}

/// A fully self-describing issued credential: the signed claims, the issuer signature, the transparency-log anchor
/// (leaf + snapshot checkpoint + inclusion proof), the delegation parties + hop proofs, and issuance metadata. All
/// binary is base64url; this struct persists to disk and reconstructs a [`Presentation`] verbatim.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuedRecord {
    pub sub: String,
    pub iss: String,
    pub registrar: String,
    pub operator: String,
    pub lineage: String,
    pub version: String,
    pub tier: String,
    pub auth_class: String,
    pub capabilities: Vec<String>,
    pub scope_ceiling: Vec<String>,
    pub status_idx: u64,
    pub status_uri: String,
    pub nbf: u64,
    pub exp: u64,
    pub issued_at: u64,
    /// Canonical claim bytes (exactly what the issuer signed), as a UTF-8 string.
    pub claims: String,
    pub issuer_sig_ed25519: String,
    pub issuer_sig_mldsa65: String,
    // transparency-log anchor (issuance-time snapshot)
    pub log_origin: String,
    pub leaf_index: u64,
    pub checkpoint_size: u64,
    pub checkpoint_root: String,
    /// Base64url SLH-DSA/delegate checkpoint signature material — see [`WireCheckpointSig`].
    pub checkpoint_sig: WireCheckpointSig,
    pub inclusion_proof: Vec<String>,
    // delegation evidence (empty for a root-issued lineage)
    pub chain_keys: Vec<WireHybridPublic>,
    pub hops: Vec<ActLink>,
    pub hop_proofs: Vec<WireHopProof>,
    /// Engine-tracked convenience mirror of the status bit (authoritative status is the signed list).
    pub revoked: bool,
}

/// Wire form of a hybrid public key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireHybridPublic {
    pub ed25519: String,
    pub mldsa65: String,
}
impl WireHybridPublic {
    fn from_core(p: &crypto::HybridPublic) -> Self {
        Self {
            ed25519: b64::encode(&p.ed25519),
            mldsa65: b64::encode(&p.mldsa65),
        }
    }
    fn to_core(&self) -> Option<crypto::HybridPublic> {
        Some(crypto::HybridPublic {
            ed25519: b64::decode(&self.ed25519).ok()?.try_into().ok()?,
            mldsa65: b64::decode(&self.mldsa65).ok()?,
        })
    }
}

/// Wire form of a per-hop inclusion proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireHopProof {
    pub leaf_index: u64,
    pub proof: Vec<String>,
}

/// Wire form of a checkpoint signature. The engine snapshots checkpoints in delegate mode (ADR-002); `root` mode is
/// carried for completeness so a record can also hold a ceremony-root snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum WireCheckpointSig {
    Root {
        slh: String,
    },
    Delegate {
        cert: crate::status::WireDelegateCert,
        sig_ed25519: String,
    },
}
impl WireCheckpointSig {
    fn from_core(sig: &CheckpointSig) -> Self {
        match sig {
            CheckpointSig::Root { slh } => WireCheckpointSig::Root {
                slh: b64::encode(slh),
            },
            CheckpointSig::Delegate { cert, sig_ed25519 } => WireCheckpointSig::Delegate {
                cert: crate::status::WireDelegateCert::from_core(cert),
                sig_ed25519: b64::encode(sig_ed25519),
            },
        }
    }
    fn to_core(&self) -> Option<CheckpointSig> {
        Some(match self {
            WireCheckpointSig::Root { slh } => CheckpointSig::Root {
                slh: b64::decode(slh).ok()?,
            },
            WireCheckpointSig::Delegate { cert, sig_ed25519 } => CheckpointSig::Delegate {
                cert: cert.to_core()?,
                sig_ed25519: b64::decode(sig_ed25519).ok()?,
            },
        })
    }
}

/// The registrar's published accreditation: the id + the two public keys a verifier chains to. This is what a
/// signed directory entry would carry (the directory itself is M4). No secrets.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Accreditation {
    pub registrar: String,
    pub issuer_key: WireHybridPublic,
    pub log_root_key: String,
    /// The registrar's Token Status List signing public key (D-020). A verifier authenticates a presented status
    /// list against this before trusting a revocation bit, so a presenter cannot forge an all-clear status.
    pub status_key: WireHybridPublic,
    pub log_origin: String,
    pub status_uri: String,
}

/// A running registrar-in-a-box.
pub struct RegistrarBox {
    id: String,
    issuer: crypto::HybridKeypair,
    root: crypto::TestRootSlh,
    log: Logd,
    status: Statusd,
    records: BTreeMap<String, IssuedRecord>,
    /// ADR-017 overlap: generations displaced by a same-sub REISSUE. They stay fully verifiable until their own
    /// `exp` (that IS the overlap window — nothing is deleted, no grace period exists) and stay revocable (a
    /// lineage revocation flips EVERY unexpired generation, or renewal would be a 30-day revocation bypass).
    superseded: Vec<IssuedRecord>,
    /// ADR-017 continuity heads: `operator:lineage` → (current sub, current credential leaf b64). A REISSUE must
    /// chain from exactly this leaf — renewing a superseded generation is a fork and is refused, fail closed.
    lineage_heads: BTreeMap<String, (String, String)>,
    next_status_idx: usize,
    status_capacity: usize,
    dir: PathBuf,
    nbf: u64,
    exp: u64,
    /// The master seed the registrar's keys derive from — persisted so [`RegistrarBox::load`] regenerates byte-
    /// identical issuer/root/delegate keys and the stored records still verify. `0` marks a non-reloadable
    /// (externally-seeded) instance (e.g. the HTTP daemon, which is a single long-lived process).
    seed: u64,
    /// The unix time the certs were issued at — persisted for deterministic reload.
    create_now: u64,
}

/// An issuance error the engine surfaces honestly (never a faked success).
#[derive(Debug)]
pub enum IssueError {
    /// The subject name is already issued under this registrar.
    Duplicate(String),
    /// The TSL segment is full (all status indices allocated).
    StatusFull,
    /// A structural problem building the credential (bad name, canon failure, …).
    Malformed(String),
    /// An I/O failure in the log/datastore.
    Io(String),
    /// ADR-017: a REISSUE whose claimed `prev_leaf` is not the lineage's current head leaf (wrong, missing, or
    /// pointing at a superseded generation — a renewal fork). Rejected before anything is logged; fail closed.
    ReissueContinuity(String),
    /// ADR-017: a revoked lineage attempted to renew — revocation is the kill switch; renewal is for lineages
    /// in good standing, so a reissue can never launder a revoked lineage into a fresh status index.
    LineageRevoked(String),
    /// ADR-017: L3+ issuance/renewal requires current tier-audit evidence, and none was supplied.
    AuditRequired(String),
    /// ADR-017: the requested passport `exp` exceeds the tier audit's own expiry — "audited" must mean audited
    /// recently, so the credential may never outlive the evidence behind its tier.
    AuditStale(String),
}

impl core::fmt::Display for IssueError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IssueError::Duplicate(s) => write!(f, "duplicate subject: {s}"),
            IssueError::StatusFull => write!(f, "status segment full"),
            IssueError::Malformed(s) => write!(f, "malformed issuance: {s}"),
            IssueError::Io(s) => write!(f, "io: {s}"),
            IssueError::ReissueContinuity(s) => write!(f, "reissue continuity: {s}"),
            IssueError::LineageRevoked(s) => write!(f, "lineage revoked: {s}"),
            IssueError::AuditRequired(s) => write!(f, "audit required: {s}"),
            IssueError::AuditStale(s) => write!(f, "audit stale: {s}"),
        }
    }
}

impl RegistrarBox {
    /// Open (or create) a registrar at `dir` with id `registrar-NN`. Generates a fresh issuer + root, opens the log
    /// shard, and enables the status segment's delta delegate. `now` stamps the certs; `[nbf, exp]` is the issuance
    /// validity window applied to every credential. `rng` MUST be a CSPRNG (seeded in fixtures/seed only).
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        dir: &Path,
        id: &str,
        status_capacity: usize,
        now: u64,
        nbf: u64,
        exp: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, IssueError> {
        let issuer = crypto::HybridKeypair::generate(rng);
        let root = crypto::TestRootSlh::generate(rng);
        let log_delegate = crypto::TestDelegate::generate(rng);
        let status_delegate = crypto::TestDelegate::generate(rng);
        let origin = format!("ainra-log/{id}");
        let log = Logd::open(dir, &origin, &root, log_delegate, now, CERT_VALIDITY)
            .map_err(|e| IssueError::Io(e.to_string()))?;
        let status_uri = format!("status://{id}/1");
        let status = Statusd::new(
            &status_uri,
            status_capacity,
            crypto::HybridKeypair::generate(rng),
        )
        .with_delegate(&root, status_delegate, now, CERT_VALIDITY)
        .map_err(|e| IssueError::Malformed(format!("{e:?}")))?;
        Ok(Self {
            id: id.to_string(),
            issuer,
            root,
            log,
            status,
            records: BTreeMap::new(),
            superseded: Vec::new(),
            lineage_heads: BTreeMap::new(),
            next_status_idx: 0,
            status_capacity,
            dir: dir.to_path_buf(),
            nbf,
            exp,
            seed: 0,
            create_now: now,
        })
    }

    /// Deterministic constructor: the same `seed` regenerates byte-identical keys, so a registrar can be persisted
    /// (its `entries.log` + `registrar.json`) and reloaded offline with [`RegistrarBox::load`]. This is the CLI's
    /// path (no daemon required); [`RegistrarBox::create`] with an external rng is the daemon's.
    #[allow(clippy::too_many_arguments)]
    pub fn create_seeded(
        dir: &Path,
        id: &str,
        status_capacity: usize,
        seed: u64,
        now: u64,
        nbf: u64,
        exp: u64,
    ) -> Result<Self, IssueError> {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        let mut me = Self::create(dir, id, status_capacity, now, nbf, exp, &mut rng)?;
        me.seed = seed;
        Ok(me)
    }

    /// Reload a persisted registrar from `dir` (offline, no daemon). Regenerates the keys from the stored seed,
    /// rebuilds the log tree from `entries.log`, restores the issued records, and replays the stored status deltas so
    /// revocations survive a restart. Fails if the snapshot is missing or was created with a non-reloadable seed (0).
    pub fn load(dir: &Path) -> Result<Self, IssueError> {
        let path = dir.join("registrar.json");
        let raw = std::fs::read_to_string(&path).map_err(|e| IssueError::Io(e.to_string()))?;
        let snap: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| IssueError::Malformed(e.to_string()))?;
        let id = snap["id"]
            .as_str()
            .ok_or_else(|| IssueError::Malformed("id".into()))?;
        // The reload seed lives in `registrar.secret` (0600), NEVER in the shareable snapshot (review #3).
        let secret_raw = std::fs::read_to_string(dir.join("registrar.secret")).map_err(|e| {
            IssueError::Io(format!(
                "registrar.secret missing/unreadable ({e}) — the snapshot alone is not reloadable by design"
            ))
        })?;
        let secret: serde_json::Value =
            serde_json::from_str(&secret_raw).map_err(|e| IssueError::Malformed(e.to_string()))?;
        let seed = secret["seed"].as_u64().unwrap_or(0);
        if seed == 0 {
            return Err(IssueError::Malformed(
                "snapshot is not reloadable (seed 0 — created by the daemon, not the CLI)".into(),
            ));
        }
        let capacity = snap["status_capacity"].as_u64().unwrap_or(4096) as usize;
        let create_now = snap["create_now"].as_u64().unwrap_or(0);
        let nbf = snap["nbf"].as_u64().unwrap_or(0);
        let exp = snap["exp"].as_u64().unwrap_or(0);
        let mut me = Self::create_seeded(dir, id, capacity, seed, create_now, nbf, exp)?;
        // Restore records + the status-index cursor.
        if let Some(records) = snap["records"].as_array() {
            for r in records {
                let rec: IssuedRecord = serde_json::from_value(r.clone())
                    .map_err(|e| IssueError::Malformed(format!("record: {e}")))?;
                me.records.insert(rec.sub.clone(), rec);
            }
        }
        // ADR-017: restore superseded generations + the lineage continuity heads. Absent in pre-M12 snapshots —
        // then every lineage's sole record is its head (derived below, latest leaf_index wins deterministically).
        if let Some(sup) = snap["superseded"].as_array() {
            for r in sup {
                let rec: IssuedRecord = serde_json::from_value(r.clone())
                    .map_err(|e| IssueError::Malformed(format!("superseded record: {e}")))?;
                me.superseded.push(rec);
            }
        }
        if let Some(heads) = snap["lineage_heads"].as_object() {
            for (k, v) in heads {
                let (Some(sub), Some(leaf)) = (v["sub"].as_str(), v["leaf"].as_str()) else {
                    return Err(IssueError::Malformed(format!("lineage head {k}")));
                };
                me.lineage_heads
                    .insert(k.clone(), (sub.to_string(), leaf.to_string()));
            }
        } else {
            let derived: Vec<(String, String, String, u64)> = me
                .records
                .values()
                .filter_map(|r| {
                    Some((
                        format!("{}:{}", r.operator, r.lineage),
                        r.sub.clone(),
                        record_leaf(r)?,
                        r.leaf_index,
                    ))
                })
                .collect();
            for (key, sub, leaf, idx) in derived {
                let newer = me
                    .lineage_heads
                    .get(&key)
                    .and_then(|(s, _)| me.records.get(s))
                    .is_some_and(|cur| cur.leaf_index >= idx);
                if !newer {
                    me.lineage_heads.insert(key, (sub, leaf));
                }
            }
        }
        me.next_status_idx = snap["next_status_idx"].as_u64().unwrap_or(0) as usize;
        // Replay stored deltas so the status bits + head sequence match the persisted state. `replay_delta`
        // re-verifies BOTH signatures + the delegate cert (fail closed on a forged/edited delta — review #1).
        if let Some(deltas) = snap["deltas"].as_array() {
            for d in deltas {
                let wire: crate::status::WireDelta = serde_json::from_value(d.clone())
                    .map_err(|e| IssueError::Malformed(format!("delta: {e}")))?;
                let core = wire
                    .to_core()
                    .ok_or_else(|| IssueError::Malformed("delta decode".into()))?;
                me.status
                    .replay_delta(core)
                    .map_err(|r| IssueError::Malformed(format!("delta replay: {r}")))?;
            }
        }
        // Head-sequence integrity (review #2): the replayed head MUST equal the persisted `status_seq`. A truncated
        // or extended delta log (dropping revocations to roll them back, or adding some) changes the head — refuse
        // to load rather than silently restore a rolled-back status. Fail closed on any tampered snapshot.
        let claimed_seq = snap["status_seq"].as_u64().unwrap_or(0);
        if me.status.current_seq() != claimed_seq {
            return Err(IssueError::Malformed(format!(
                "delta log inconsistent with persisted status_seq (replayed {}, claimed {}) — refusing tampered snapshot",
                me.status.current_seq(),
                claimed_seq
            )));
        }
        Ok(me)
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn log_origin(&self) -> String {
        format!("ainra-log/{}", self.id)
    }
    pub fn status_uri(&self) -> String {
        format!("status://{}/1", self.id)
    }

    /// The registrar's SLH-DSA ceremony-root public key. It certifies BOTH the log's checkpoint delegate and the
    /// status segment's delta/fresh-head delegate, so a verifier chains deltas, fresh heads, AND checkpoints to it.
    pub fn root_public(&self) -> Vec<u8> {
        self.root.public()
    }

    /// The delegate cert authorizing this registrar's status deltas + fresh heads (for a delta-stream verifier).
    pub fn status_delegate_cert(&self) -> Option<ainra_core::checkpoint::DelegateCert> {
        self.status.delegate_cert().cloned()
    }

    /// The registrar's accreditation (public keys a verifier trusts). Feed this to [`RegistrarBox::trust_anchors`]
    /// or a peer verifier — it is exactly a signed-directory entry minus the root's signature over it (M4).
    pub fn accreditation(&self) -> Accreditation {
        Accreditation {
            registrar: self.id.clone(),
            issuer_key: WireHybridPublic::from_core(&self.issuer.public()),
            log_root_key: b64::encode(self.log.root_public()),
            status_key: WireHybridPublic::from_core(&self.status.public()),
            log_origin: self.log_origin(),
            status_uri: self.status_uri(),
        }
    }

    /// Trust anchors covering just this registrar (what a verifier needs to check its credentials).
    pub fn trust_anchors(&self) -> TrustAnchors {
        let mut registrars = BTreeMap::new();
        registrars.insert(
            self.id.clone(),
            RegistrarInfo {
                issuer_key: self.issuer.public(),
                log_root_key: self.log.root_public().to_vec(),
                // A registrar never distrusts itself; a cutoff is set by the ROOT, in the signed directory.
                distrust_from_leaf: None,
            },
        );
        TrustAnchors { registrars }
    }

    pub fn records(&self) -> impl Iterator<Item = &IssuedRecord> {
        self.records.values()
    }
    pub fn get(&self, sub: &str) -> Option<&IssuedRecord> {
        self.records.get(sub)
    }
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Issue one credential. Performs REAL work: build claims → (dual-)sign hops → append to the log → snapshot +
    /// delegate-sign a checkpoint → compute inclusion proofs → sign claims → store. Returns the new record.
    /// The validity window is the registrar's configured `[nbf, exp]`; for L3+ tiers the ADR-017 audit cap
    /// applies (`spec.audit` must be present and outlive `exp`).
    pub fn issue(
        &mut self,
        spec: &IssueSpec,
        chain_party_keys: &[crypto::HybridKeypair],
        rng: &mut impl CryptoRngCore,
    ) -> Result<IssuedRecord, IssueError> {
        let sub = format!(
            "ainra:{}:{}:{}@{}",
            self.id, spec.operator, spec.lineage, spec.version
        );
        if self.records.contains_key(&sub) {
            return Err(IssueError::Duplicate(sub));
        }
        check_audit_cap(&spec.tier, self.exp, spec.audit.as_ref())?;
        let (nbf, exp) = (self.nbf, self.exp);
        self.issue_with(spec, sub, (nbf, exp), None, chain_party_keys, rng)
    }

    /// The shared issuance engine behind [`Self::issue`] and [`Self::reissue`]: `window` is this credential's own
    /// `[nbf, exp]` (per-credential — ADR-017 renewal mints fresh windows), and `prev_leaf` (base64url, 32 B) marks
    /// a REISSUE by committing the predecessor's leaf into the SIGNED AND LOGGED claim body. On success the new
    /// credential becomes its lineage's continuity head. Callers do the policy checks (duplicate/continuity/audit).
    fn issue_with(
        &mut self,
        spec: &IssueSpec,
        sub: String,
        window: (u64, u64),
        prev_leaf: Option<&str>,
        chain_party_keys: &[crypto::HybridKeypair],
        rng: &mut impl CryptoRngCore,
    ) -> Result<IssuedRecord, IssueError> {
        validate_tier_auth(&spec.tier, &spec.auth_class)?;
        // The constructed subject MUST be a well-formed ainra name — this rejects an operator/lineage/version
        // carrying a `:` or `@` that would otherwise (a) desync the `operator:lineage` continuity/revocation
        // composite key (colliding two different lineages onto one head/bit) and (b) mint a credential the
        // verifier rejects at its own name gate anyway. Catch it honestly at issue time. (ainra-core AinraName.)
        ainra_core::AinraName::parse(&sub).map_err(|e| {
            IssueError::Malformed(format!("subject is not a well-formed ainra name: {e:?}"))
        })?;
        if self.next_status_idx >= self.status_capacity {
            return Err(IssueError::StatusFull);
        }
        let status_idx = self.next_status_idx as u64;

        // Party keys for the delegation chain: `hops + 1` parties. Caller may supply them (so it can present the
        // matching secret keys elsewhere); otherwise we generate them here. With NO hops there are NO chain
        // parties — caller-supplied keys are ignored rather than baked into a chainless record, which would make
        // it permanently unverifiable (`chain_keys` non-empty + `act_chain` empty ⇒ schema_violation; review #11).
        let n_parties = if spec.hops.is_empty() {
            0
        } else {
            spec.hops.len() + 1
        };
        let owned_keys: Vec<crypto::HybridKeypair> =
            if n_parties > 0 && chain_party_keys.len() == n_parties {
                Vec::new()
            } else {
                (0..n_parties)
                    .map(|_| crypto::HybridKeypair::generate(rng))
                    .collect()
            };
        let party_keys: &[crypto::HybridKeypair] = if n_parties == 0 {
            &[]
        } else if owned_keys.is_empty() {
            chain_party_keys
        } else {
            &owned_keys
        };

        // Build + dual-sign each hop; compute its log_leaf.
        let mut act_chain: Vec<ActLink> = Vec::new();
        for (i, h) in spec.hops.iter().enumerate() {
            let mut link = ActLink {
                from: h.from.clone(),
                to: h.to.clone(),
                granted: h.granted.clone(),
                exp: window.1,
                sig_ed25519: String::new(),
                sig_mldsa65: String::new(),
                sig_child_ed25519: String::new(),
                sig_child_mldsa65: String::new(),
                log_leaf: String::new(),
            };
            let msg = chain::hop_signing_bytes(&link)
                .map_err(|e| IssueError::Malformed(format!("hop bytes: {e:?}")))?;
            let ds = party_keys[i]
                .sign(&msg)
                .map_err(|e| IssueError::Malformed(format!("delegator sign: {e:?}")))?;
            link.sig_ed25519 = b64::encode(&ds.ed25519);
            link.sig_mldsa65 = b64::encode(&ds.mldsa65);
            let cs = party_keys[i + 1]
                .sign(&msg)
                .map_err(|e| IssueError::Malformed(format!("delegatee sign: {e:?}")))?;
            link.sig_child_ed25519 = b64::encode(&cs.ed25519);
            link.sig_child_mldsa65 = b64::encode(&cs.mldsa65);
            link.log_leaf = b64::encode(
                &chain::hop_leaf(&link)
                    .map_err(|e| IssueError::Malformed(format!("hop leaf: {e:?}")))?,
            );
            act_chain.push(link);
        }

        // The HOLDER's hybrid keypair — a REAL Ed25519 + ML-DSA-65 pair, not placeholder bytes (review #10: a
        // credential must never advertise fabricated key material). In a production flow the agent generates this
        // and submits the public half (CSR-style); the reference engine generates it in-process. `cnf.jkt` is a
        // real thumbprint: SHA-256 over the canonical JSON of the two public keys (JWK-thumbprint-style binding).
        let holder = crypto::HybridKeypair::generate(rng);
        let holder_pub = holder.public();
        let holder_ed = b64::encode(&holder_pub.ed25519);
        let holder_ml = b64::encode(&holder_pub.mldsa65);
        let jkt = {
            use sha2::{Digest, Sha256};
            let canon_key =
                canon::canonicalize(&json!({ "ed25519": holder_ed, "mldsa65": holder_ml }))
                    .map_err(|e| IssueError::Malformed(format!("canon holder key: {e:?}")))?;
            let digest: [u8; 32] = Sha256::digest(canon_key.as_bytes()).into();
            b64::encode(&digest)
        };

        // Claim body (without the `log` back-reference yet).
        let mut body = json!({
            "vct": ainra_core::PASSPORT_VCT,
            "iss": format!("did:ainra:{}:{}:{}", self.id, spec.operator, spec.lineage),
            "sub": sub,
            "nbf": window.0, "exp": window.1,
            "authority": { "class": spec.auth_class, "principal_proof": spec.principal_proof },
            "tier": spec.tier,
            "capabilities": spec.capabilities,
            "scope_ceiling": spec.scope_ceiling,
            "keys": [ { "ed25519": holder_ed, "mldsa65": holder_ml } ],
            "cnf": { "jkt": jkt },
            "status": { "status_list": { "idx": status_idx, "uri": self.status_uri() } },
        });
        if !act_chain.is_empty() {
            body["act_chain"] = serde_json::to_value(&act_chain)
                .map_err(|e| IssueError::Malformed(format!("act_chain: {e}")))?;
        }
        // ADR-017: a REISSUE commits its predecessor's leaf into the signed AND logged body (it must be part of
        // what the log commits, so renewals walk back through the log as one unbroken chain).
        if let Some(pl) = prev_leaf {
            body["prev_leaf"] = json!(pl);
        }
        let body_bytes = canon::canonicalize(&body)
            .map_err(|e| IssueError::Malformed(format!("canon body: {e:?}")))?
            .into_bytes();
        let cred_leaf = merkle::hash_leaf(&body_bytes);

        // Append the credential body + every hop's bytes to the log shard (durable).
        let cred_index = self
            .log
            .append(&body_bytes)
            .map_err(|e| IssueError::Io(e.to_string()))?;
        let mut hop_indices = Vec::with_capacity(act_chain.len());
        for h in &act_chain {
            let hb = chain::hop_signing_bytes(h)
                .map_err(|e| IssueError::Malformed(format!("hop bytes: {e:?}")))?;
            hop_indices.push(
                self.log
                    .append(&hb)
                    .map_err(|e| IssueError::Io(e.to_string()))?,
            );
        }

        // Snapshot + delegate-sign the checkpoint at the current size (issuance-time anchor, permanent).
        let size = self.log.size();
        let root_at = self
            .log
            .root_at(size)
            .ok_or_else(|| IssueError::Io("root_at snapshot".into()))?;
        let cp = Checkpoint {
            origin: self.log_origin(),
            tree_size: size,
            root: root_at,
        };
        let signed = self.log.sign_checkpoint(&cp);
        let cred_proof = self
            .log
            .inclusion_proof(cred_index)
            .ok_or_else(|| IssueError::Io("cred inclusion proof".into()))?;
        let mut hop_proofs = Vec::with_capacity(hop_indices.len());
        for &i in &hop_indices {
            let p = self
                .log
                .inclusion_proof(i)
                .ok_or_else(|| IssueError::Io("hop inclusion proof".into()))?;
            hop_proofs.push(WireHopProof {
                leaf_index: i,
                proof: p.iter().map(|h| b64::encode(h)).collect(),
            });
        }

        // Attach the log back-reference + sign the full claims.
        let mut full = body;
        full["log"] = json!({
            "leaf": b64::encode(&cred_leaf),
            "root": b64::encode(&cp.root),
            "checkpoint": format!("{}#{}", self.log_origin(), size),
        });
        let claims = canon::canonicalize(&full)
            .map_err(|e| IssueError::Malformed(format!("canon full: {e:?}")))?
            .into_bytes();
        let issuer_sig = self
            .issuer
            .sign(&claims)
            .map_err(|e| IssueError::Malformed(format!("issuer sign: {e:?}")))?;

        self.next_status_idx += 1;
        let record = IssuedRecord {
            sub: sub.clone(),
            iss: format!("did:ainra:{}:{}:{}", self.id, spec.operator, spec.lineage),
            registrar: self.id.clone(),
            operator: spec.operator.clone(),
            lineage: spec.lineage.clone(),
            version: spec.version.clone(),
            tier: spec.tier.clone(),
            auth_class: spec.auth_class.clone(),
            capabilities: spec.capabilities.clone(),
            scope_ceiling: spec.scope_ceiling.clone(),
            status_idx,
            status_uri: self.status_uri(),
            nbf: window.0,
            exp: window.1,
            issued_at: now_from_cert(&signed),
            claims: String::from_utf8(claims.clone())
                .map_err(|e| IssueError::Malformed(format!("claims utf8: {e}")))?,
            issuer_sig_ed25519: b64::encode(&issuer_sig.ed25519),
            issuer_sig_mldsa65: b64::encode(&issuer_sig.mldsa65),
            log_origin: self.log_origin(),
            leaf_index: cred_index,
            checkpoint_size: size,
            checkpoint_root: b64::encode(&cp.root),
            checkpoint_sig: WireCheckpointSig::from_core(&signed.sig),
            inclusion_proof: cred_proof.iter().map(|h| b64::encode(h)).collect(),
            chain_keys: party_keys
                .iter()
                .map(|k| WireHybridPublic::from_core(&k.public()))
                .collect(),
            hops: act_chain,
            hop_proofs,
            revoked: false,
        };
        // The new credential is now its lineage's continuity head (ADR-017): future reissues chain from THIS leaf.
        self.lineage_heads.insert(
            format!("{}:{}", spec.operator, spec.lineage),
            (sub.clone(), b64::encode(&cred_leaf)),
        );
        self.records.insert(sub, record.clone());
        Ok(record)
    }

    /// ADR-017 renewal: reissue `sub` with a FRESH `[now, now + 366 d]` window, a NEW status index, and a
    /// `prev_leaf` continuity link to the credential it renews. The old credential is kept and keeps verifying
    /// until its own `exp` — that IS the overlap window; after it, the old one fails closed `expired` while the
    /// new one continues. `new_version` optionally bumps the version (policy allows same or bumped). For L3+
    /// tiers, `audit` must be present and outlive the new window (ADR-017's audit cap). Delegated (chained)
    /// passports are NOT auto-renewable: the delegation parties' consent signatures are theirs to give, not the
    /// registrar's to re-mint — renewal of a delegation is a re-delegation.
    pub fn reissue(
        &mut self,
        sub: &str,
        new_version: Option<&str>,
        now: u64,
        audit: Option<&AuditEvidence>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<IssuedRecord, IssueError> {
        let head_leaf = self
            .records
            .get(sub)
            .ok_or_else(|| IssueError::Malformed(format!("unknown subject: {sub}")))
            .map(|r| format!("{}:{}", r.operator, r.lineage))
            .map(|key| self.lineage_heads.get(&key).map(|(_, l)| l.clone()))?
            .unwrap_or_default();
        self.reissue_with_prev(sub, &head_leaf, new_version, now, audit, rng)
    }

    /// The ACME-style reissue: the caller CLAIMS which credential it renews (`claimed_prev_leaf`), and the
    /// registrar validates that claim against the lineage's recorded continuity head **before anything is
    /// logged** — a wrong, missing, or superseded-generation link is [`IssueError::ReissueContinuity`], fail
    /// closed. [`Self::reissue`] is the convenience wrapper that claims the recorded head.
    pub fn reissue_with_prev(
        &mut self,
        sub: &str,
        claimed_prev_leaf: &str,
        new_version: Option<&str>,
        now: u64,
        audit: Option<&AuditEvidence>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<IssuedRecord, IssueError> {
        let old = self
            .records
            .get(sub)
            .cloned()
            .ok_or_else(|| IssueError::Malformed(format!("unknown subject: {sub}")))?;
        // A REVOKED lineage must never renew itself into a fresh, clean status index — revocation is the kill
        // switch, and renewal is for lineages in good standing (ADR-017). Re-admitting a revoked lineage is a
        // fresh accreditation DECISION, not a mechanical reissue. Fail closed.
        if old.revoked {
            return Err(IssueError::LineageRevoked(format!(
                "{sub} is revoked — a revoked lineage cannot renew; re-admission is a new accreditation \
                 decision, not a reissue"
            )));
        }
        // Renewal is for a credential in GOOD STANDING — ADR-017's rhythm is reissue at T−30 d, BEFORE expiry,
        // with an overlap. An already-expired credential is not renewed, it is re-issued (a fresh accreditation
        // decision). Refusing it also closes the durability gap where revoking one generation while every
        // generation is expired would otherwise leave a lapsed sibling reissue-able into a clean status index.
        if now >= old.exp {
            return Err(IssueError::Malformed(format!(
                "{sub} has expired (exp {}, now {now}) — renewal happens before expiry (ADR-017 T−30 d overlap); \
                 a lapsed credential requires fresh issuance, not a reissue",
                old.exp
            )));
        }
        if !old.hops.is_empty() {
            return Err(IssueError::Malformed(format!(
                "{sub} carries a delegation chain — a chained passport cannot be auto-renewed; renewal of a \
                 delegation is a re-delegation (the parties must dual-sign a fresh chain, ADR-017)"
            )));
        }
        let key = format!("{}:{}", old.operator, old.lineage);
        let Some((head_sub, head_leaf)) = self.lineage_heads.get(&key).cloned() else {
            return Err(IssueError::ReissueContinuity(format!(
                "lineage {key} has no continuity head recorded"
            )));
        };
        if claimed_prev_leaf.is_empty() {
            return Err(IssueError::ReissueContinuity(
                "missing prev_leaf — a reissue must name the credential it renews".into(),
            ));
        }
        if head_sub != sub || claimed_prev_leaf != head_leaf {
            return Err(IssueError::ReissueContinuity(format!(
                "claimed prev_leaf {claimed_prev_leaf} does not match the lineage head {head_leaf} (head \
                 generation {head_sub}) — renewing a superseded or foreign generation would fork the renewal \
                 chain; refused"
            )));
        }
        // checked_add: a hostile/absurd `now` near u64::MAX must never wrap into an exp < nbf window (which would
        // vacuously pass the audit cap and mint a structurally-broken credential). Fail closed instead.
        let exp = now
            .checked_add(ainra_core::consts::PASSPORT_VALIDITY_DEFAULT_SECS)
            .ok_or_else(|| IssueError::Malformed("reissue window overflows u64".into()))?;
        let window = (now, exp);
        check_audit_cap(&old.tier, window.1, audit)?;
        let version = new_version.unwrap_or(&old.version);
        let new_sub = format!(
            "ainra:{}:{}:{}@{}",
            self.id, old.operator, old.lineage, version
        );
        if new_sub != sub && self.records.contains_key(&new_sub) {
            return Err(IssueError::Duplicate(new_sub));
        }
        let spec = IssueSpec {
            operator: old.operator.clone(),
            lineage: old.lineage.clone(),
            version: version.to_string(),
            tier: old.tier.clone(),
            auth_class: old.auth_class.clone(),
            principal_proof: passport_field(&old, "/authority/principal_proof")
                .unwrap_or_else(|| "reissued".into()),
            capabilities: old.capabilities.clone(),
            scope_ceiling: old.scope_ceiling.clone(),
            hops: vec![],
            audit: audit.cloned(),
        };
        let new_rec =
            self.issue_with(&spec, new_sub.clone(), window, Some(&head_leaf), &[], rng)?;
        // Same-sub renewal displaced the old record from the map (`issue_with` inserted the new one under the
        // same key); keep the old generation verifiable + revocable until its own exp. A bumped version leaves
        // the old record in place under its own sub — same overlap, different key.
        if new_sub == sub {
            self.superseded.push(old);
        }
        Ok(new_rec)
    }

    /// The superseded (renewed-away) generations still inside their validity windows or expired-but-retained.
    pub fn superseded_records(&self) -> impl Iterator<Item = &IssuedRecord> {
        self.superseded.iter()
    }

    /// The lineage continuity head (current sub + credential leaf) for `operator:lineage`, if issued.
    pub fn lineage_head(&self, operator: &str, lineage: &str) -> Option<(String, String)> {
        self.lineage_heads
            .get(&format!("{operator}:{lineage}"))
            .cloned()
    }

    /// Revoke a lineage: flip its status bit through the signed-delta path and mark the record. Returns the emitted
    /// [`status::StatusDelta`]. `now` stamps the delta. Fails closed if the subject is unknown or the delta is
    /// rejected by the core codec.
    ///
    /// ADR-017 + MTS §16 (the status list is one bit **per lineage**): revocation is lineage-wide — it flips the
    /// named record's bit AND every other unexpired generation of the same lineage (superseded by renewal or
    /// version-bumped), so a freshly-renewed lineage cannot dodge revocation by presenting its still-valid
    /// predecessor during the overlap window.
    pub fn revoke(&mut self, sub: &str, now: u64) -> Result<status::StatusDelta, IssueError> {
        let rec = self
            .records
            .get(sub)
            .ok_or_else(|| IssueError::Malformed(format!("unknown subject: {sub}")))?;
        let key = format!("{}:{}", rec.operator, rec.lineage);
        let mut idxs = vec![rec.status_idx as usize];
        let mut marked: Vec<String> = vec![rec.sub.clone()];
        for r in self.records.values() {
            if r.sub != sub && format!("{}:{}", r.operator, r.lineage) == key && now < r.exp {
                idxs.push(r.status_idx as usize);
                marked.push(r.sub.clone());
            }
        }
        let mut superseded_hit = Vec::new();
        for (i, r) in self.superseded.iter().enumerate() {
            if format!("{}:{}", r.operator, r.lineage) == key && now < r.exp && !r.revoked {
                idxs.push(r.status_idx as usize);
                superseded_hit.push(i);
            }
        }
        let delta = self
            .status
            .revoke_delta(&idxs, now)
            .ok_or_else(|| IssueError::Malformed("status delegate not configured".into()))?
            .map_err(|r| IssueError::Malformed(format!("delta rejected: {r}")))?;
        for s in marked {
            if let Some(r) = self.records.get_mut(&s) {
                r.revoked = true;
            }
        }
        for i in superseded_hit {
            self.superseded[i].revoked = true;
        }
        Ok(delta)
    }

    /// The current signed status publication (full list) stamped `now`.
    pub fn publish_status(&self, now: u64) -> crate::status::SignedStatusList {
        self.status.publish(now)
    }

    /// A self-contained **presentation bundle** for one credential — exactly the JSON the `sdk-ts` GA `Verifier`
    /// (`Verifier.verify(bundle, now)`) consumes: the signed claims + issuer signature, the delegation chain keys +
    /// per-hop proofs, the current signed status list, and the log anchor (checkpoint + inclusion proof). The
    /// verifier supplies its OWN `now` + revocation set (from the directory), so those fields here are informational.
    /// `None` if the subject is unknown. `freshness` selects the status class the bundle advertises (default F3).
    pub fn present(&self, sub: &str, now: u64, freshness: &str) -> Option<serde_json::Value> {
        let rec = self.records.get(sub)?;
        let published = self.status.publish(now.saturating_sub(1));
        let mut bundle = json!({
            "claims": b64::encode(rec.claims.as_bytes()),
            "issuer_sig": { "ed25519": rec.issuer_sig_ed25519, "mldsa65": rec.issuer_sig_mldsa65 },
            "now": now,
            "chain_keys": rec.chain_keys,
            "hop_proofs": rec.hop_proofs,
            "status_list": published.status_list_b64,
            "status_len": published.bit_len,
            "status_issued_at": published.issued_at,
            "freshness": freshness,
            // The registrar's SIGNED status publication (D-020): the GA Verifier authenticates the bits above against
            // this hybrid signature (over the canonical `{bit_len, issued_at, status_list, uri}`) using the status
            // key from the directory — so a presenter cannot swap in a forged all-clear list.
            "status_uri": published.uri,
            "status_sig_ed25519": published.sig_ed25519,
            "status_sig_mldsa65": published.sig_mldsa65,
            "checkpoint": { "origin": rec.log_origin, "size": rec.checkpoint_size, "root": rec.checkpoint_root },
            "checkpoint_sig": rec.checkpoint_sig,
            "leaf_index": rec.leaf_index,
            "inclusion_proof": rec.inclusion_proof,
            "mandate_revocations": [],
        });
        // M6 (D-021): the delegate-signed FRESH HEAD + its delegate cert. A currency-mode verifier verifies the head
        // (cert → the registrar's log root, delegate sig, F1 recency), binds it to the presented list by `head_hash`,
        // and tracks its monotonic `seq` — so a genuine but SUPERSEDED status snapshot cannot be replayed to
        // re-validate a revoked lineage. Stamped at `now` (its own ≤30 s heartbeat); the default verifier ignores it.
        if let (Some(head), Some(cert)) = (self.fresh_head(now), self.status_delegate_cert()) {
            bundle["fresh_head"] =
                serde_json::to_value(crate::status::WireFreshHead::from_core(&head)).unwrap();
            bundle["status_delegate_cert"] =
                serde_json::to_value(crate::status::WireDelegateCert::from_core(&cert)).unwrap();
        }
        Some(bundle)
    }

    /// The current delegate-signed fresh head, stamped `now` (`None` should never happen — the delegate is always
    /// configured by [`RegistrarBox::create`]).
    pub fn fresh_head(&self, now: u64) -> Option<status::FreshHead> {
        self.status.fresh_head(now)
    }

    pub fn deltas_since(&self, seq: u64) -> Vec<status::StatusDelta> {
        self.status.deltas_since(seq)
    }
    pub fn status_seq(&self) -> u64 {
        self.status.current_seq()
    }

    /// Verify one stored record at time `now` by reconstructing its [`Presentation`] and calling the REAL verifier.
    /// The status list used is the registrar's current signed segment, so a post-issuance revocation is reflected.
    pub fn verify_record(&self, sub: &str, now: u64) -> Verdict {
        let Some(rec) = self.records.get(sub) else {
            return Verdict::invalid(ainra_core::Reason::UnknownRegistrar);
        };
        self.verify_reconstructed(rec, now, status::Freshness::F3)
    }

    /// Verify an [`IssuedRecord`] (possibly loaded from disk) against this registrar's anchors + live status.
    pub fn verify_reconstructed(
        &self,
        rec: &IssuedRecord,
        now: u64,
        freshness: status::Freshness,
    ) -> Verdict {
        reconstruct_and_verify(rec, &self.trust_anchors(), &self.status, now, freshness)
    }

    /// Persist the datastore (records + accreditation) to `dir/registrar.json`. The log itself is already durable on
    /// disk (`entries.log`); this snapshot is the issuer's index + published keys.
    pub fn save(&self) -> Result<(), IssueError> {
        let deltas: Vec<_> = self
            .status
            .deltas_since(0)
            .iter()
            .map(crate::status::WireDelta::from_core)
            .collect();
        // NO key material here (review #3): `registrar.json` doubles as the exportable index/accreditation
        // snapshot, so it must be safe to copy around. The reload seed — which IS the registrar's entire private
        // key material (every key derives from it) — lives in a separate `registrar.secret`, written 0600.
        let snapshot = json!({
            "id": self.id,
            "accreditation": self.accreditation(),
            "create_now": self.create_now,
            "nbf": self.nbf,
            "exp": self.exp,
            "next_status_idx": self.next_status_idx,
            "status_capacity": self.status_capacity,
            "status_seq": self.status.current_seq(),
            "deltas": deltas,
            "records": self.records.values().collect::<Vec<_>>(),
            // ADR-017: renewed-away generations (still verifiable/revocable until their own exp) + the lineage
            // continuity heads the next reissue must chain from.
            "superseded": self.superseded,
            "lineage_heads": self.lineage_heads.iter().map(|(k, (sub, leaf))| {
                (k.clone(), json!({ "sub": sub, "leaf": leaf }))
            }).collect::<serde_json::Map<_, _>>(),
        });
        let path = self.dir.join("registrar.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&snapshot).map_err(|e| IssueError::Io(e.to_string()))?,
        )
        .map_err(|e| IssueError::Io(e.to_string()))?;

        // The secret: owner-read-only. A TEST-labeled dev keystore, not production key management (that's M4+ HSM/
        // ceremony work) — but at minimum the secret never travels with the shareable snapshot.
        let secret_path = self.dir.join("registrar.secret");
        std::fs::write(
            &secret_path,
            serde_json::to_string(&json!({
                "comment": "TEST reload seed — this derives ALL of this registrar's private keys. Never share; never a production keystore.",
                "seed": self.seed,
            }))
            .map_err(|e| IssueError::Io(e.to_string()))?,
        )
        .map_err(|e| IssueError::Io(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| IssueError::Io(e.to_string()))?;
        }
        Ok(())
    }
}

/// Deterministically read a placeholder issue time for a record: the checkpoint delegate cert's `nbf` (issuance
/// clock proxy) — the engine has no wall clock. Falls back to 0 for a root-mode snapshot.
fn now_from_cert(signed: &crate::log::SignedCheckpoint) -> u64 {
    match &signed.sig {
        CheckpointSig::Delegate { cert, .. } => cert.nbf,
        CheckpointSig::Root { .. } => 0,
    }
}

/// Offline verification: reconstruct a [`Presentation`] from a stored record + an explicit decoded status list and
/// verify with the REAL core verifier. This is what a THIRD PARTY does with an export file — no live registrar, no
/// network. `status_issued_at` + `freshness` gate status recency exactly as in the hot path.
pub fn verify_record_offline(
    rec: &IssuedRecord,
    anchors: &TrustAnchors,
    status_list: status::StatusList,
    status_issued_at: u64,
    now: u64,
    freshness: status::Freshness,
) -> Verdict {
    match reconstruct_presentation(rec) {
        Ok(parts) => {
            let pres = Presentation {
                claims: &parts.claims,
                issuer_sig: parts.issuer_sig,
                now,
                chain_keys: parts.chain_keys,
                hop_proofs: parts.hop_proofs,
                status_list,
                status_issued_at,
                freshness,
                checkpoint: parts.checkpoint,
                checkpoint_sig: parts.checkpoint_sig,
                leaf_index: rec.leaf_index,
                inclusion_proof: parts.inclusion,
                mandate_path: Vec::new(),
                mandate_proofs: Vec::new(),
                mandate_revocations: mandate::RevocationSet::default(),
                revoked_delegates: Default::default(),
            };
            verify::verify(&pres, anchors)
        }
        Err(r) => Verdict::invalid(r),
    }
}

/// The reconstructed, non-status parts of a presentation (everything the record itself carries).
struct PresentationParts {
    claims: Vec<u8>,
    issuer_sig: crypto::HybridSig,
    chain_keys: Vec<crypto::HybridPublic>,
    hop_proofs: Vec<HopLogProof>,
    checkpoint: Checkpoint,
    checkpoint_sig: CheckpointSig,
    inclusion: Vec<[u8; 32]>,
}

/// Rebuild the record's own material (claims, sigs, log anchor, chain) — everything except the live status list.
fn reconstruct_presentation(rec: &IssuedRecord) -> Result<PresentationParts, ainra_core::Reason> {
    let root_arr: [u8; 32] = b64::decode(&rec.checkpoint_root)
        .map_err(|_| ainra_core::Reason::CheckpointInvalid)?
        .try_into()
        .map_err(|_| ainra_core::Reason::CheckpointInvalid)?;
    let checkpoint = Checkpoint {
        origin: rec.log_origin.clone(),
        tree_size: rec.checkpoint_size,
        root: root_arr,
    };
    let checkpoint_sig = rec
        .checkpoint_sig
        .to_core()
        .ok_or(ainra_core::Reason::CheckpointInvalid)?;
    let inclusion = decode_proof(&rec.inclusion_proof).ok_or(ainra_core::Reason::NotLogged)?;
    let chain_keys = rec
        .chain_keys
        .iter()
        .map(|k| k.to_core())
        .collect::<Option<Vec<_>>>()
        .ok_or(ainra_core::Reason::SchemaViolation)?;
    let hop_proofs = rec
        .hop_proofs
        .iter()
        .map(|hp| {
            Some(HopLogProof {
                leaf_index: hp.leaf_index,
                proof: decode_proof(&hp.proof)?,
            })
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(ainra_core::Reason::NotLogged)?;
    let issuer_sig = crypto::HybridSig {
        ed25519: b64::decode(&rec.issuer_sig_ed25519).unwrap_or_default(),
        mldsa65: b64::decode(&rec.issuer_sig_mldsa65).unwrap_or_default(),
    };
    Ok(PresentationParts {
        claims: rec.claims.clone().into_bytes(),
        issuer_sig,
        chain_keys,
        hop_proofs,
        checkpoint,
        checkpoint_sig,
        inclusion,
    })
}

/// Verify ONLY the logged-before-valid step: is the record's leaf included under its signed checkpoint? Isolates the
/// RFC 6962 inclusion + checkpoint-signature check from the rest of the pipeline (CLI `log-verify`).
pub fn verify_log_inclusion(
    rec: &IssuedRecord,
    root_pk_slh: &[u8],
    now: u64,
) -> core::result::Result<(), ainra_core::Reason> {
    let parts = reconstruct_presentation(rec)?;
    let leaf = ainra_core::verify::prelog_leaf(&parts.claims)?;
    parts
        .checkpoint
        .verify_sig_mode(root_pk_slh, &parts.checkpoint_sig, now)?;
    ainra_core::checkpoint::verify_logged(
        &leaf,
        rec.leaf_index,
        &parts.checkpoint,
        &parts.inclusion,
    )
}

/// Reconstruct a [`Presentation`] from a stored record + verify it against `anchors`, reading the live status
/// segment `status` so revocations after issuance are honored. All-in-one so the CLI, explorer export, and tests
/// share exactly one verification path.
pub fn reconstruct_and_verify(
    rec: &IssuedRecord,
    anchors: &TrustAnchors,
    status: &Statusd,
    now: u64,
    freshness: status::Freshness,
) -> Verdict {
    // Read the live status list from the segment's current publication (reflects post-issuance revocations), then
    // verify offline through the one shared path.
    let published = status.publish(now.saturating_sub(1));
    let compressed = b64::decode(&published.status_list_b64).unwrap_or_default();
    let status_list = match status::StatusList::decode(&compressed, published.bit_len as usize) {
        Ok(l) => l,
        Err(_) => return Verdict::invalid(ainra_core::Reason::StaleStatus),
    };
    verify_record_offline(
        rec,
        anchors,
        status_list,
        published.issued_at,
        now,
        freshness,
    )
}

fn decode_proof(hashes: &[String]) -> Option<Vec<[u8; 32]>> {
    hashes
        .iter()
        .map(|h| b64::decode(h).ok()?.try_into().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const NBF: u64 = 1_775_865_600;
    // ADR-017 366 d default window. Verification happens WITHIN the checkpoint delegate cert's 90-day window
    // (ADR-002 cap); the credential's own window is independent — cert rotation across 90-day boundaries is M4.
    const EXP: u64 = NBF + ainra_core::consts::PASSPORT_VALIDITY_DEFAULT_SECS;
    const VERIFY_NOW: u64 = NBF + 10 * 24 * 60 * 60; // 10 days after issuance

    fn spec(op: &str, lineage: &str, ver: &str) -> IssueSpec {
        IssueSpec {
            operator: op.into(),
            lineage: lineage.into(),
            version: ver.into(),
            tier: "L2".into(),
            auth_class: "A2".into(),
            principal_proof: "deadbeef".into(),
            capabilities: vec!["read:invoices".into()],
            scope_ceiling: vec!["read:invoices".into(), "sign:invoice".into()],
            hops: vec![],
            audit: None,
        }
    }

    fn engine(dir: &Path) -> RegistrarBox {
        let mut rng = ChaCha20Rng::seed_from_u64(0x9E_11_A2_02);
        let now = NBF - 1000;
        RegistrarBox::create(dir, "registrar-07", 64, now, NBF, EXP, &mut rng).unwrap()
    }

    #[test]
    fn issue_then_verify_valid() {
        let tmp = std::env::temp_dir().join("ainra-rb-valid");
        let _ = std::fs::remove_dir_all(&tmp);
        let mut rb = engine(&tmp);
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let rec = rb
            .issue(&spec("acme", "invoicing", "1.0.0"), &[], &mut rng)
            .unwrap();
        let now = VERIFY_NOW;
        assert_eq!(rb.verify_record(&rec.sub, now), Verdict::Valid);
    }

    #[test]
    fn revoke_makes_it_invalid() {
        let tmp = std::env::temp_dir().join("ainra-rb-revoke");
        let _ = std::fs::remove_dir_all(&tmp);
        let mut rb = engine(&tmp);
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let rec = rb
            .issue(&spec("acme", "data-export", "2.0.0"), &[], &mut rng)
            .unwrap();
        let now = VERIFY_NOW;
        assert_eq!(rb.verify_record(&rec.sub, now), Verdict::Valid);
        let delta = rb.revoke(&rec.sub, now).unwrap();
        assert_eq!(delta.seq, 1);
        assert_eq!(delta.idx, vec![rec.status_idx]);
        assert_eq!(
            rb.verify_record(&rec.sub, now),
            Verdict::invalid(ainra_core::Reason::Revoked)
        );
    }

    #[test]
    fn delegated_chain_verifies() {
        let tmp = std::env::temp_dir().join("ainra-rb-deleg");
        let _ = std::fs::remove_dir_all(&tmp);
        let mut rb = engine(&tmp);
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let reg = "registrar-07";
        let mut s = spec("acme", "support-bot", "1.0.0");
        s.capabilities = vec!["read:tickets".into()];
        s.scope_ceiling = vec!["read:tickets".into(), "reply:ticket".into()];
        s.hops = vec![
            HopSpec {
                from: format!("ainra:{reg}:acme:owner@1.0.0"),
                to: format!("ainra:{reg}:acme:support-desk@1.0.0"),
                granted: vec!["read:tickets".into(), "reply:ticket".into()],
            },
            HopSpec {
                from: format!("ainra:{reg}:acme:support-desk@1.0.0"),
                to: format!("ainra:{reg}:acme:support-bot@1.0.0"),
                granted: vec!["read:tickets".into()],
            },
        ];
        let rec = rb.issue(&s, &[], &mut rng).unwrap();
        assert_eq!(rec.hops.len(), 2);
        assert_eq!(rec.chain_keys.len(), 3);
        let now = VERIFY_NOW;
        assert_eq!(rb.verify_record(&rec.sub, now), Verdict::Valid);
    }

    #[test]
    fn duplicate_subject_rejected() {
        let tmp = std::env::temp_dir().join("ainra-rb-dup");
        let _ = std::fs::remove_dir_all(&tmp);
        let mut rb = engine(&tmp);
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        rb.issue(&spec("acme", "invoicing", "1.0.0"), &[], &mut rng)
            .unwrap();
        let again = rb.issue(&spec("acme", "invoicing", "1.0.0"), &[], &mut rng);
        assert!(matches!(again, Err(IssueError::Duplicate(_))));
    }

    // ── ADR-017: renewal (REISSUE), overlap, continuity, and the L3+ audit cap ─────────────────────────────────

    /// A renewal window that begins inside the checkpoint-delegate cert's 90-day window, so the reissued
    /// credential verifies without M4 cert-rotation machinery (which is out of ADR-017's scope).
    const RENEW_AT: u64 = NBF + 20 * 24 * 60 * 60;

    #[test]
    fn reissue_overlap_then_old_expires() {
        let tmp = std::env::temp_dir().join("ainra-rb-reissue-overlap");
        let _ = std::fs::remove_dir_all(&tmp);
        // A SHORT first window (40 d) so `old.exp` sits inside the checkpoint delegate cert's 90-day window —
        // the post-expiry verdicts below then exercise the PASSPORT window, not M4 cert rotation.
        let mut rng = ChaCha20Rng::seed_from_u64(20);
        let mut rb = RegistrarBox::create(
            &tmp,
            "registrar-07",
            64,
            NBF - 1000,
            NBF,
            NBF + 40 * 24 * 60 * 60,
            &mut rng,
        )
        .unwrap();
        let old = rb
            .issue(&spec("acme", "invoicing", "1.0.0"), &[], &mut rng)
            .unwrap();
        let new = rb
            .reissue(&old.sub, None, RENEW_AT, None, &mut rng)
            .unwrap();
        // Fresh 366-day window + a new status index + the continuity link.
        assert_eq!(new.nbf, RENEW_AT);
        assert_eq!(
            new.exp,
            RENEW_AT + ainra_core::consts::PASSPORT_VALIDITY_DEFAULT_SECS
        );
        assert_ne!(new.status_idx, old.status_idx, "renewal burns a NEW index");
        assert_eq!(
            passport_field(&new, "/prev_leaf").as_deref(),
            record_leaf(&old).as_deref(),
            "the reissue commits its predecessor's leaf"
        );
        // OVERLAP: inside [new.nbf, old.exp] BOTH generations verify as the same lineage in good standing.
        let inside = RENEW_AT + 1;
        assert_eq!(rb.verify_record(&new.sub, inside), Verdict::Valid);
        let old_stored = rb.superseded_records().next().unwrap().clone();
        assert_eq!(old_stored.sub, old.sub);
        assert_eq!(
            rb.verify_reconstructed(&old_stored, inside, status::Freshness::F3),
            Verdict::Valid,
            "the superseded generation stays valid during the overlap"
        );
        // AFTER old.exp: the old one fails closed `expired` (no grace), the new one continues.
        let after = old.exp;
        assert_eq!(
            rb.verify_reconstructed(&old_stored, after, status::Freshness::F3),
            Verdict::invalid(ainra_core::Reason::Expired)
        );
        assert_eq!(rb.verify_record(&new.sub, after), Verdict::Valid);
    }

    #[test]
    fn reissue_chain_walks_back_unbroken() {
        let tmp = std::env::temp_dir().join("ainra-rb-reissue-chain");
        let _ = std::fs::remove_dir_all(&tmp);
        let mut rb = engine(&tmp);
        let mut rng = ChaCha20Rng::seed_from_u64(21);
        let g1 = rb
            .issue(&spec("acme", "dispatch", "1.0.0"), &[], &mut rng)
            .unwrap();
        let g2 = rb.reissue(&g1.sub, None, RENEW_AT, None, &mut rng).unwrap();
        let g3 = rb
            .reissue(&g2.sub, Some("1.1.0"), RENEW_AT + 60, None, &mut rng)
            .unwrap();
        // The continuity chain: g3 → g2 → g1 → (first issuance, no link). Each link is the predecessor's leaf,
        // and every generation's body is IN the log — a verifier walks renewals back as one unbroken chain.
        assert_eq!(
            passport_field(&g3, "/prev_leaf").as_deref(),
            record_leaf(&g2).as_deref()
        );
        assert_eq!(
            passport_field(&g2, "/prev_leaf").as_deref(),
            record_leaf(&g1).as_deref()
        );
        assert_eq!(passport_field(&g1, "/prev_leaf"), None);
        // The head moved with each renewal (version bump included).
        assert_eq!(
            rb.lineage_head("acme", "dispatch").unwrap().0,
            g3.sub,
            "the newest generation is the lineage head"
        );
    }

    #[test]
    fn reissue_wrong_missing_or_forked_prev_leaf_rejected() {
        let tmp = std::env::temp_dir().join("ainra-rb-reissue-continuity");
        let _ = std::fs::remove_dir_all(&tmp);
        let mut rb = engine(&tmp);
        let mut rng = ChaCha20Rng::seed_from_u64(22);
        let g1 = rb
            .issue(&spec("acme", "payroll", "1.0.0"), &[], &mut rng)
            .unwrap();
        // Wrong prev_leaf: rejected before anything is logged.
        let wrong = b64::encode(&[9u8; 32]);
        let log_size_before = rb.log.size();
        assert!(matches!(
            rb.reissue_with_prev(&g1.sub, &wrong, None, RENEW_AT, None, &mut rng),
            Err(IssueError::ReissueContinuity(_))
        ));
        // Missing prev_leaf: same, fail closed.
        assert!(matches!(
            rb.reissue_with_prev(&g1.sub, "", None, RENEW_AT, None, &mut rng),
            Err(IssueError::ReissueContinuity(_))
        ));
        assert_eq!(rb.log.size(), log_size_before, "nothing was logged");
        // Fork refusal: after a genuine renewal (version bump), renewing the SUPERSEDED generation again — even
        // with its once-correct leaf — is a fork of the renewal chain and is refused.
        let g1_leaf = record_leaf(&g1).unwrap();
        rb.reissue(&g1.sub, Some("2.0.0"), RENEW_AT, None, &mut rng)
            .unwrap();
        assert!(matches!(
            rb.reissue_with_prev(
                &g1.sub,
                &g1_leaf,
                Some("3.0.0"),
                RENEW_AT + 60,
                None,
                &mut rng
            ),
            Err(IssueError::ReissueContinuity(_))
        ));
    }

    #[test]
    fn revoke_kills_every_unexpired_generation() {
        let tmp = std::env::temp_dir().join("ainra-rb-reissue-revoke");
        let _ = std::fs::remove_dir_all(&tmp);
        let mut rb = engine(&tmp);
        let mut rng = ChaCha20Rng::seed_from_u64(23);
        let old = rb
            .issue(&spec("acme", "collector", "1.0.0"), &[], &mut rng)
            .unwrap();
        let new = rb
            .reissue(&old.sub, None, RENEW_AT, None, &mut rng)
            .unwrap();
        let inside = RENEW_AT + 1;
        // Revoke the lineage: the status list is one bit per LINEAGE (MTS §16), so the delta must flip the new
        // AND the still-unexpired superseded generation — otherwise renewal would be a 30-day revocation bypass.
        let delta = rb.revoke(&new.sub, inside).unwrap();
        let mut idx = delta.idx.clone();
        idx.sort_unstable();
        assert_eq!(
            idx,
            vec![
                old.status_idx.min(new.status_idx),
                old.status_idx.max(new.status_idx)
            ]
        );
        assert_eq!(
            rb.verify_record(&new.sub, inside),
            Verdict::invalid(ainra_core::Reason::Revoked)
        );
        let old_stored = rb.superseded_records().next().unwrap().clone();
        assert_eq!(
            rb.verify_reconstructed(&old_stored, inside, status::Freshness::F3),
            Verdict::invalid(ainra_core::Reason::Revoked),
            "the superseded generation is revoked too — no bypass through the overlap"
        );
    }

    #[test]
    fn tier_vocabulary_is_closed_no_case_dodge() {
        let tmp = std::env::temp_dir().join("ainra-rb-tier-vocab");
        let _ = std::fs::remove_dir_all(&tmp);
        let mut rb = engine(&tmp);
        let mut rng = ChaCha20Rng::seed_from_u64(29);
        // "l3"/"L5"/garbage tiers could otherwise dodge the ADR-017 audit cap while minting an unverifiable
        // credential — issuance refuses the closed vocabulary honestly instead.
        for bad in ["l3", "L5", "gold"] {
            let mut s = spec("acme", "vocab", "1.0.0");
            s.tier = bad.into();
            assert!(
                matches!(rb.issue(&s, &[], &mut rng), Err(IssueError::Malformed(ref m)) if m.contains("closed")),
                "tier {bad:?} must be refused"
            );
        }
        let mut s = spec("acme", "vocab", "1.0.0");
        s.auth_class = "A9".into();
        assert!(matches!(
            rb.issue(&s, &[], &mut rng),
            Err(IssueError::Malformed(_))
        ));
    }

    #[test]
    fn expired_credential_cannot_be_renewed() {
        let tmp = std::env::temp_dir().join("ainra-rb-reissue-expired");
        let _ = std::fs::remove_dir_all(&tmp);
        // 40-day window so the credential can lapse well inside the checkpoint delegate cert's 90-day window.
        let mut rng = ChaCha20Rng::seed_from_u64(30);
        let mut rb = RegistrarBox::create(
            &tmp,
            "registrar-07",
            64,
            NBF - 1000,
            NBF,
            NBF + 40 * 24 * 60 * 60,
            &mut rng,
        )
        .unwrap();
        let rec = rb
            .issue(&spec("acme", "lapsed", "1.0.0"), &[], &mut rng)
            .unwrap();
        // ADR-017: renewal is at T−30 d, BEFORE expiry (the overlap). A credential renewed AFTER it has expired
        // is not a renewal — that is fresh issuance / re-accreditation. Refused, fail closed. (This also closes
        // the durability gap: a lapsed generation can never be reissued into a clean status index.)
        let after_expiry = rec.exp + 1;
        assert!(matches!(
            rb.reissue(&rec.sub, None, after_expiry, None, &mut rng),
            Err(IssueError::Malformed(ref m)) if m.contains("expired")
        ));
    }

    #[test]
    fn revoked_lineage_cannot_renew_itself_clean() {
        let tmp = std::env::temp_dir().join("ainra-rb-reissue-revoked");
        let _ = std::fs::remove_dir_all(&tmp);
        let mut rb = engine(&tmp);
        let mut rng = ChaCha20Rng::seed_from_u64(28);
        let rec = rb
            .issue(&spec("acme", "escapist", "1.0.0"), &[], &mut rng)
            .unwrap();
        rb.revoke(&rec.sub, RENEW_AT - 60).unwrap();
        // The kill switch stays killed: a revoked lineage cannot launder itself into a fresh status index via
        // renewal (with or without a version bump).
        assert!(matches!(
            rb.reissue(&rec.sub, None, RENEW_AT, None, &mut rng),
            Err(IssueError::LineageRevoked(_))
        ));
        assert!(matches!(
            rb.reissue(&rec.sub, Some("2.0.0"), RENEW_AT, None, &mut rng),
            Err(IssueError::LineageRevoked(_))
        ));
    }

    #[test]
    fn chained_passport_cannot_auto_renew() {
        let tmp = std::env::temp_dir().join("ainra-rb-reissue-chained");
        let _ = std::fs::remove_dir_all(&tmp);
        let mut rb = engine(&tmp);
        let mut rng = ChaCha20Rng::seed_from_u64(24);
        let reg = "registrar-07";
        let mut s = spec("acme", "helper-bot", "1.0.0");
        s.hops = vec![HopSpec {
            from: format!("ainra:{reg}:acme:owner@1.0.0"),
            to: format!("ainra:{reg}:acme:helper-bot@1.0.0"),
            granted: vec!["read:invoices".into()],
        }];
        let rec = rb.issue(&s, &[], &mut rng).unwrap();
        // The delegation parties' consent signatures are theirs to give — renewal of a delegation is a
        // re-delegation, so the registrar refuses to auto-renew a chained passport.
        let err = rb.reissue(&rec.sub, None, RENEW_AT, None, &mut rng);
        assert!(matches!(err, Err(IssueError::Malformed(ref m)) if m.contains("re-delegation")));
    }

    #[test]
    fn audit_cap_l3_requires_current_audit() {
        let tmp = std::env::temp_dir().join("ainra-rb-audit-cap");
        let _ = std::fs::remove_dir_all(&tmp);
        let mut rb = engine(&tmp);
        let mut rng = ChaCha20Rng::seed_from_u64(25);
        // L3 with NO audit: refused, and the error says why.
        let mut l3 = spec("acme", "treasury", "1.0.0");
        l3.tier = "L3".into();
        assert!(matches!(
            rb.issue(&l3, &[], &mut rng),
            Err(IssueError::AuditRequired(ref m)) if m.contains("ADR-017")
        ));
        // L3 with a STALE audit (expires before the passport would): refused, error names both times.
        l3.audit = Some(AuditEvidence {
            reference: "audit-acme-treasury".into(),
            expires: EXP - 1,
        });
        assert!(matches!(
            rb.issue(&l3, &[], &mut rng),
            Err(IssueError::AuditStale(ref m)) if m.contains("exceeds the tier audit")
        ));
        // The SAME request at L2 (no audit required) succeeds.
        let mut l2 = spec("acme", "treasury", "1.0.0");
        l2.tier = "L2".into();
        let rec = rb.issue(&l2, &[], &mut rng).unwrap();
        assert_eq!(rb.verify_record(&rec.sub, VERIFY_NOW), Verdict::Valid);
        // L3 with a CURRENT audit (outlives the window) succeeds.
        let mut l3ok = spec("acme", "settlement", "1.0.0");
        l3ok.tier = "L3".into();
        l3ok.audit = Some(AuditEvidence {
            reference: "audit-acme-settlement".into(),
            expires: EXP,
        });
        let rec = rb.issue(&l3ok, &[], &mut rng).unwrap();
        assert_eq!(rb.verify_record(&rec.sub, VERIFY_NOW), Verdict::Valid);
        // RENEWAL of that L3: the fresh 366-day window now exceeds the old audit's expiry → refused until the
        // audit itself is renewed. With a renewed audit it succeeds — "audited" means audited recently.
        assert!(matches!(
            rb.reissue(
                &rec.sub,
                None,
                RENEW_AT,
                Some(&AuditEvidence {
                    reference: "audit-acme-settlement".into(),
                    expires: EXP,
                }),
                &mut rng
            ),
            Err(IssueError::AuditStale(_))
        ));
        let renewed_audit = AuditEvidence {
            reference: "audit-acme-settlement-2".into(),
            expires: RENEW_AT + ainra_core::consts::PASSPORT_VALIDITY_DEFAULT_SECS,
        };
        let new = rb
            .reissue(&rec.sub, None, RENEW_AT, Some(&renewed_audit), &mut rng)
            .unwrap();
        assert_eq!(rb.verify_record(&new.sub, RENEW_AT + 1), Verdict::Valid);
    }

    #[test]
    fn reissue_survives_persist_reload() {
        let tmp = std::env::temp_dir().join("ainra-rb-reissue-reload");
        let _ = std::fs::remove_dir_all(&tmp);
        let old_sub;
        let new_sub;
        {
            let mut rb = RegistrarBox::create_seeded(
                &tmp,
                "registrar-07",
                64,
                0xC0FFEE,
                NBF - 1000,
                NBF,
                EXP,
            )
            .unwrap();
            let mut rng = ChaCha20Rng::seed_from_u64(26);
            let old = rb
                .issue(&spec("acme", "archivist", "1.0.0"), &[], &mut rng)
                .unwrap();
            old_sub = old.sub.clone();
            let new = rb
                .reissue(&old.sub, None, RENEW_AT, None, &mut rng)
                .unwrap();
            new_sub = new.sub.clone();
            rb.save().unwrap();
        }
        let mut rb = RegistrarBox::load(&tmp).unwrap();
        let inside = RENEW_AT + 1;
        assert_eq!(rb.verify_record(&new_sub, inside), Verdict::Valid);
        let old_stored = rb.superseded_records().next().unwrap().clone();
        assert_eq!(old_stored.sub, old_sub);
        assert_eq!(
            rb.verify_reconstructed(&old_stored, inside, status::Freshness::F3),
            Verdict::Valid,
            "overlap survives a reload"
        );
        // The continuity head survived too: a further renewal chains cleanly from the reloaded head. (The bump
        // leaves the head generation in `records` under its own sub — compare against that record's leaf.)
        let head_leaf = rb.get(&new_sub).and_then(record_leaf);
        let mut rng = ChaCha20Rng::seed_from_u64(27);
        let g3 = rb
            .reissue(&new_sub, Some("1.1.0"), RENEW_AT + 120, None, &mut rng)
            .unwrap();
        assert_eq!(
            passport_field(&g3, "/prev_leaf"),
            head_leaf,
            "the reloaded head is what the next renewal chained from"
        );
    }

    #[test]
    fn persist_reload_preserves_keys_records_and_revocations() {
        let tmp = std::env::temp_dir().join("ainra-rb-reload");
        let _ = std::fs::remove_dir_all(&tmp);
        // Build, issue two, revoke one, persist.
        let created_root;
        let revoked_sub;
        let valid_sub;
        {
            let mut rb = RegistrarBox::create_seeded(
                &tmp,
                "registrar-07",
                64,
                0xABCDEF,
                NBF - 1000,
                NBF,
                EXP,
            )
            .unwrap();
            created_root = rb.root_public();
            let mut rng = ChaCha20Rng::seed_from_u64(11);
            let a = rb
                .issue(&spec("acme", "invoicing", "1.0.0"), &[], &mut rng)
                .unwrap();
            let b = rb
                .issue(&spec("globex", "ledger", "2.0.0"), &[], &mut rng)
                .unwrap();
            valid_sub = a.sub.clone();
            revoked_sub = b.sub.clone();
            rb.revoke(&revoked_sub, VERIFY_NOW).unwrap();
            rb.save().unwrap();
        }
        // Reload from disk (no daemon, deterministic keys) and re-verify.
        let rb = RegistrarBox::load(&tmp).unwrap();
        assert_eq!(
            rb.root_public(),
            created_root,
            "keys regenerate identically"
        );
        assert_eq!(rb.len(), 2);
        assert_eq!(rb.status_seq(), 1, "the one revocation delta replayed");
        assert_eq!(rb.verify_record(&valid_sub, VERIFY_NOW), Verdict::Valid);
        assert_eq!(
            rb.verify_record(&revoked_sub, VERIFY_NOW),
            Verdict::invalid(ainra_core::Reason::Revoked)
        );
    }

    #[test]
    fn tampered_snapshot_is_refused_fail_closed() {
        // Review #1/#2: the on-disk snapshot is untrusted. A forged delta (bad signatures) OR a truncated delta log
        // (rolling back a revocation) MUST be refused at load — never applied + laundered into a signed status list.
        let tmp = std::env::temp_dir().join("ainra-rb-tamper");
        let _ = std::fs::remove_dir_all(&tmp);
        let sub;
        {
            let mut rb = RegistrarBox::create_seeded(
                &tmp,
                "registrar-07",
                64,
                0xABCDEF,
                NBF - 1000,
                NBF,
                EXP,
            )
            .unwrap();
            let mut rng = ChaCha20Rng::seed_from_u64(12);
            let r = rb
                .issue(&spec("acme", "invoicing", "1.0.0"), &[], &mut rng)
                .unwrap();
            sub = r.sub.clone();
            rb.revoke(&sub, VERIFY_NOW).unwrap();
            rb.save().unwrap();
        }
        let path = tmp.join("registrar.json");
        let raw = std::fs::read_to_string(&path).unwrap();

        // (a) forge the delta's countersignature → load must fail closed (not apply it).
        let mut snap: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let cs = snap["deltas"][0]["countersig_delegate"]
            .as_str()
            .unwrap()
            .to_string();
        let mut bytes = ainra_core::b64::decode(&cs).unwrap();
        bytes[0] ^= 0xff;
        snap["deltas"][0]["countersig_delegate"] = json!(ainra_core::b64::encode(&bytes));
        std::fs::write(&path, serde_json::to_string(&snap).unwrap()).unwrap();
        assert!(
            RegistrarBox::load(&tmp).is_err(),
            "a forged delta signature must be refused at load"
        );

        // (b) truncate the delta log to roll back the revocation, but keep status_seq=1 → mismatch → refused.
        let mut snap2: serde_json::Value = serde_json::from_str(&raw).unwrap();
        snap2["deltas"] = json!([]);
        std::fs::write(&path, serde_json::to_string(&snap2).unwrap()).unwrap();
        assert!(
            RegistrarBox::load(&tmp).is_err(),
            "a truncated delta log (status_seq rollback) must be refused at load"
        );

        // (c) the untampered snapshot still loads and the revocation survives.
        std::fs::write(&path, &raw).unwrap();
        let rb = RegistrarBox::load(&tmp).unwrap();
        assert_eq!(
            rb.verify_record(&sub, VERIFY_NOW),
            Verdict::invalid(ainra_core::Reason::Revoked)
        );
    }

    #[test]
    fn offline_verify_from_export_matches_live() {
        let tmp = std::env::temp_dir().join("ainra-rb-offline");
        let _ = std::fs::remove_dir_all(&tmp);
        let mut rb = engine(&tmp);
        let mut rng = ChaCha20Rng::seed_from_u64(21);
        let rec = rb
            .issue(&spec("acme", "invoicing", "1.0.0"), &[], &mut rng)
            .unwrap();
        // Export the signed status list + record, then verify with the pure offline path (no live Statusd).
        let published = rb.publish_status(VERIFY_NOW - 1);
        let compressed = b64::decode(&published.status_list_b64).unwrap();
        let list = status::StatusList::decode(&compressed, published.bit_len as usize).unwrap();
        let v = verify_record_offline(
            &rec,
            &rb.trust_anchors(),
            list,
            published.issued_at,
            VERIFY_NOW,
            status::Freshness::F3,
        );
        assert_eq!(v, Verdict::Valid);
        // The log-only inclusion check also passes in isolation.
        assert_eq!(
            verify_log_inclusion(&rec, &rb.root_public(), VERIFY_NOW),
            Ok(())
        );
    }

    #[test]
    fn record_roundtrips_through_json_and_still_verifies() {
        let tmp = std::env::temp_dir().join("ainra-rb-json");
        let _ = std::fs::remove_dir_all(&tmp);
        let mut rb = engine(&tmp);
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let rec = rb
            .issue(&spec("globex", "ledger", "3.1.0"), &[], &mut rng)
            .unwrap();
        let json = serde_json::to_string(&rec).unwrap();
        let back: IssuedRecord = serde_json::from_str(&json).unwrap();
        let now = VERIFY_NOW;
        assert_eq!(
            rb.verify_reconstructed(&back, now, status::Freshness::F3),
            Verdict::Valid
        );
    }
}
