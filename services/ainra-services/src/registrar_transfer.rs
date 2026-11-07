// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Holder-driven portability: the transfer door (PLAN-M53 step 7, D-102; Standard 0.5(iii); MTS F6, C5
//! `POST /transfer-out|in`). A child module of `registrar`, like `link` and `heads`: it shares the registrar's log,
//! status segment and issuer key, and issues through the same engine.
//!
//! A lineage moves between registrars with its history intact. The move starts at the GAINING registrar, so a
//! registrar cannot keep its customers by refusing to let them go, and a dead or distrusted registrar cannot strand
//! them. The root takes no part and never chooses the gaining registrar (P6). The rules, deliberately few:
//!
//! 1. **The operator moves a lineage, not the agent.** A request carries the passport key's signature (whoever holds
//!    the passport asks) and must gain the operator's signature before it completes. The operator's key is the one
//!    the losing registrar logged beside the lineage ([`OperatorKeyReceipt`]); the gaining registrar checks that
//!    receipt against the losing registrar's log, offline. An agent key alone never moves a lineage.
//! 2. **Every move is public for [`CONTEST_WINDOW_SECS`].** It is logged when it opens. The operator may stop it at
//!    any time in the window. The losing registrar may stop it too, with a reason from a closed list, but only while
//!    it is in good standing: a registrar the root has distrusted cannot keep its customers. Every contest is
//!    recorded, counted or not.
//! 3. **The gaining registrar issues under its own name.** The new passport's signed `transfer_history` names the old
//!    passport, its log and its leaf, so the trail runs unbroken through both logs. The gaining registrar applies its
//!    own policy: an L3+ tier needs its own audit evidence, an A1 class its own principal check.
//! 4. **A lineage that moved is locked for [`TRANSFER_LOCK_SECS`].** The lock is read from the passport itself, so
//!    any registrar can enforce it without asking another.
//! 5. **The losing registrar revokes the old passport when shown the new one** (`transfer_out`). Until it does, the
//!    old passport keeps verifying; that overlap is stated, not hidden.
use ainra_core::checkpoint::Checkpoint;
use ainra_core::verify::TrustAnchors;
use ainra_core::{b64, canon, crypto, merkle, status, AinraName, Verdict};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{
    check_audit_cap, principal, verify_holder, verify_record_offline_with, HybridB64, IssueError,
    IssueSpec, IssuedRecord, RegistrarBox, WireCheckpointSig,
};
use crate::status::SignedStatusList;

/// How long a move, or a change of owner, stays open to contest before it can complete (five days, as for
/// domain-name transfers).
pub const CONTEST_WINDOW_SECS: u64 = 5 * 86_400;
/// How long a lineage that has just moved cannot move again.
pub const TRANSFER_LOCK_SECS: u64 = 60 * 86_400;
/// How old a request may be when the gaining registrar receives it, so a captured request cannot be replayed later.
pub const REQUEST_MAX_AGE_SECS: u64 = 86_400;
/// How far ahead of the gaining registrar's clock a request may be dated.
const CLOCK_SKEW_SECS: u64 = 300;
/// The reasons a losing registrar may give for stopping a move. Closed: anything else is refused as a contest.
pub const REGISTRAR_CONTEST_REASONS: &[&str] =
    &["operator_key_compromised", "fraud_evidence", "legal_order"];

/// What the holder sends the gaining registrar.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransferRequest {
    /// The passport being moved, by its full name at the losing registrar.
    pub from_sub: String,
    /// The gaining registrar's id. A request names exactly one gaining registrar.
    pub to_registrar: String,
    pub requested_at: u64,
    /// The key the gaining registrar is asked to certify, and its proof of possession for THAT registrar (D-063).
    /// It may be the key the old passport already carries.
    pub new_holder_key: HybridB64,
    pub new_holder_pop: HybridB64,
    /// The old passport's key (`keys[0]`) over [`request_message`].
    pub holder_sig: HybridB64,
    /// The operator's key over the same message. It may come later, during the window ([`RegistrarBox::transfer_consent`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_sig: Option<HybridB64>,
}

/// An operator's key as the losing registrar logged it, with the proof that it is in that registrar's log. The
/// gaining registrar needs nothing from the losing registrar but this and the directory, so a registrar that has
/// stopped answering cannot hold a lineage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorKeyReceipt {
    pub registrar: String,
    pub operator: String,
    pub lineage: String,
    pub key: HybridB64,
    /// The proof of possession the operator gave, over [`operator_key_message`].
    pub pop: HybridB64,
    pub leaf_index: u64,
    pub inclusion_proof: Vec<String>,
    pub checkpoint_origin: String,
    pub checkpoint_size: u64,
    pub checkpoint_root: String,
    pub checkpoint_sig: WireCheckpointSig,
}

/// One operator key, as the registrar keeps it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorKeyEntry {
    pub operator: String,
    pub lineage: String,
    pub key: HybridB64,
    pub pop: HybridB64,
    pub leaf_index: u64,
}

/// Where a move stands.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TransferState {
    Open,
    Refused { reason: String },
    Completed { sub: String },
}

/// One contest, as the public record shows it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContestRecord {
    /// `operator` or `registrar`.
    pub by: String,
    pub reason: String,
    pub at: u64,
    pub counted: bool,
    pub note: String,
}

/// The public record of one move, as the gaining registrar publishes it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingTransfer {
    pub id: String,
    pub request: TransferRequest,
    pub from_registrar: String,
    pub operator: String,
    pub lineage: String,
    pub version: String,
    /// The old passport's log position, carried into the new passport's `transfer_history`.
    pub from_log_origin: String,
    pub from_leaf_index: u64,
    pub from_checkpoint_size: u64,
    pub from_checkpoint_root: String,
    /// The old passport's assurance as issued. The gaining registrar re-applies its own policy at completion.
    pub tier: String,
    pub auth_class: String,
    pub principal_proof: String,
    pub capabilities: Vec<String>,
    pub scope_ceiling: Vec<String>,
    pub prior_history: Vec<Value>,
    pub operator_key: HybridB64,
    pub operator_signed: bool,
    /// Where the opening statement sits in the gaining registrar's log.
    pub opened_leaf: u64,
    pub opened_at: u64,
    pub closes_at: u64,
    pub contests: Vec<ContestRecord>,
    #[serde(flatten)]
    pub state: TransferState,
}

/// What one registrar needs to know about the other, all of it public and all of it from one signed directory: the
/// anchors (with any distrust cutoff), the revoked delegate certificates, the other registrar's status key, and its
/// current signed status list.
pub struct PeerRegistrar<'a> {
    pub anchors: &'a TrustAnchors,
    pub revoked_delegates: &'a std::collections::BTreeSet<[u8; 32]>,
    pub status_key: &'a crypto::HybridPublic,
    pub status: &'a SignedStatusList,
}

/// The bytes the old passport's key (and the operator's) sign.
pub fn request_message(
    from_sub: &str,
    to_registrar: &str,
    requested_at: u64,
    new_holder_key: &HybridB64,
) -> Result<String, IssueError> {
    canonical(&json!({
        "purpose": "ainra-transfer-v1",
        "from": from_sub,
        "to": to_registrar,
        "at": requested_at,
        "new_holder": { "ed25519": new_holder_key.ed25519, "mldsa65": new_holder_key.mldsa65 },
    }))
}

/// The bytes a contest is signed over.
pub fn contest_message(id: &str, by: &str, reason: &str) -> Result<String, IssueError> {
    canonical(
        &json!({ "purpose": "ainra-transfer-contest-v1", "transfer": id, "by": by, "reason": reason }),
    )
}

/// The bytes an operator signs to have its key logged beside a lineage. Bound to one registrar and one lineage.
pub fn operator_key_message(
    registrar: &str,
    operator: &str,
    lineage: &str,
    key: &HybridB64,
) -> Result<String, IssueError> {
    canonical(&json!({
        "purpose": "ainra-operator-key-v1", "registrar": registrar, "operator": operator, "lineage": lineage,
        "key": { "ed25519": key.ed25519, "mldsa65": key.mldsa65 },
    }))
}

/// What the registrar logs for an operator key: the message and the operator's proof, so the log entry alone shows
/// the operator held the key.
fn operator_key_statement(msg: &str, pop: &HybridB64) -> Result<String, IssueError> {
    let m: Value = serde_json::from_str(msg).map_err(|e| IssueError::Malformed(e.to_string()))?;
    canonical(
        &json!({ "operator_key": m, "pop": { "ed25519": pop.ed25519, "mldsa65": pop.mldsa65 } }),
    )
}

/// A move's id: the first 32 hex of SHA-256 over its request message.
pub fn transfer_id(message: &str) -> String {
    Sha256::digest(message.as_bytes())
        .iter()
        .take(16)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Sign `msg` with a hybrid keypair, as wire base64url (holders, operators and registrars alike).
pub fn sign_b64(k: &crypto::HybridKeypair, msg: &str) -> Result<HybridB64, IssueError> {
    let s = k
        .sign(msg.as_bytes())
        .map_err(|e| IssueError::Malformed(format!("sign: {e:?}")))?;
    Ok(HybridB64 {
        ed25519: b64::encode(&s.ed25519),
        mldsa65: b64::encode(&s.mldsa65),
    })
}

/// A hybrid public key as wire base64url.
pub fn wire_of(k: &crypto::HybridPublic) -> HybridB64 {
    HybridB64 {
        ed25519: b64::encode(&k.ed25519),
        mldsa65: b64::encode(&k.mldsa65),
    }
}

fn canonical(v: &Value) -> Result<String, IssueError> {
    canon::canonicalize(v).map_err(|e| IssueError::Malformed(format!("canon: {e:?}")))
}

fn refuse<T>(why: impl Into<String>) -> Result<T, IssueError> {
    Err(IssueError::Transfer(why.into()))
}

fn public_of(k: &HybridB64) -> Option<crypto::HybridPublic> {
    let ed: [u8; crypto::ED25519_PK] = b64::decode(&k.ed25519).ok()?.as_slice().try_into().ok()?;
    let ml = b64::decode(&k.mldsa65).ok()?;
    (ml.len() == crypto::MLDSA65_PK).then_some(crypto::HybridPublic {
        ed25519: ed,
        mldsa65: ml,
    })
}

/// Does `sig` verify over `msg` under `pk`? Both halves, or not at all.
fn verifies(pk: &crypto::HybridPublic, msg: &str, sig: &HybridB64) -> bool {
    let (Ok(ed), Ok(ml)) = (b64::decode(&sig.ed25519), b64::decode(&sig.mldsa65)) else {
        return false;
    };
    crypto::verify_hybrid(
        pk,
        msg.as_bytes(),
        &crypto::HybridSig {
            ed25519: ed,
            mldsa65: ml,
        },
    )
    .is_ok()
}

/// Is the passport `old` valid now, with its registrar's status list authenticated under that registrar's status key
/// first (D-072: an unauthenticated status list is a revocation bypass)?
fn old_passport_valid(
    old: &IssuedRecord,
    losing: &PeerRegistrar,
    now: u64,
) -> Result<(), IssueError> {
    let fresh = status::Freshness::F2;
    // The index comes from the SIGNED claims: the record's own `status_idx` is an unsigned copy a presenter can edit.
    let claims: Value = serde_json::from_str(&old.claims)
        .map_err(|e| IssueError::Malformed(format!("claims: {e}")))?;
    let Some(idx) = claims["status"]["status_list"]["idx"].as_u64() else {
        return refuse("the passport names no status index");
    };
    // A registrar the root has DISTRUSTED gets no say through its status list, either way: not by revoking a customer
    // who asked to leave, and not by going dark so that no fresh list exists. Otherwise a distrusted or defunct
    // registrar could strand every customer at no cost (2026-11-07 review), which is exactly what the distrust cutoff
    // must not allow. What still protects a stolen passport is what the registrar cannot fake: the operator's
    // signature, under a key logged before the cutoff, and the public window in which the operator can stop a move.
    // The passport itself must still verify: issued before the cutoff, signed, logged.
    let registrar = AinraName::parse(claims["sub"].as_str().unwrap_or(""))
        .map(|n| n.registrar().to_string())
        .unwrap_or_default();
    if losing
        .anchors
        .registrars
        .get(&registrar)
        .is_some_and(|i| i.distrust_from_leaf.is_some())
    {
        const MAX_IDX: u64 = 1 << 24;
        if idx >= MAX_IDX {
            return refuse("the passport names a status index beyond any status list");
        }
        let clear = status::StatusList::from_bits(vec![false; idx as usize + 1]);
        return match verify_record_offline_with(
            old,
            losing.anchors,
            losing.revoked_delegates,
            clear,
            now,
            now,
            fresh,
        ) {
            Verdict::Valid => Ok(()),
            v => refuse(format!(
                "the passport does not verify ({}); only a valid passport can move",
                v.reason().map(|r| r.as_str()).unwrap_or("invalid")
            )),
        };
    }
    // The list must be the one the passport's SIGNED claims name. Otherwise any accredited registrar's genuine, fresh
    // list (where this index happens to be clear) could stand in for the real one and hide a revocation: the status
    // key is chosen by the caller's side of the door (2026-11-07 review).
    if claims["status"]["status_list"]["uri"].as_str() != Some(losing.status.uri.as_str()) {
        return refuse("the status list is not the one the passport names");
    }
    match crate::status::verify_publication(losing.status_key, losing.status, now, fresh, idx) {
        Ok(status::LineageStatus::Valid) => {}
        Ok(_) => return refuse("the passport is revoked at its registrar"),
        Err(_) => {
            return refuse("the losing registrar's status list is not authentic or not fresh (F2)")
        }
    }
    let compressed = b64::decode(&losing.status.status_list_b64).unwrap_or_default();
    let list = status::StatusList::decode(&compressed, losing.status.bit_len as usize)
        .map_err(|_| IssueError::Transfer("the status list does not decode".into()))?;
    match verify_record_offline_with(
        old,
        losing.anchors,
        losing.revoked_delegates,
        list,
        losing.status.issued_at,
        now,
        fresh,
    ) {
        Verdict::Valid => Ok(()),
        v => refuse(format!(
            "the passport does not verify ({}); only a valid passport can move",
            v.reason().map(|r| r.as_str()).unwrap_or("invalid")
        )),
    }
}

/// Check an operator-key receipt against the losing registrar's log, offline: the statement is the one for this
/// operator and lineage, it is included under a checkpoint the losing registrar's log root signed, and it sits before
/// any distrust cutoff the directory sets for that registrar.
fn check_operator_receipt(
    r: &OperatorKeyReceipt,
    losing_id: &str,
    operator: &str,
    lineage: &str,
    anchors: &TrustAnchors,
    revoked_delegates: &std::collections::BTreeSet<[u8; 32]>,
    now: u64,
) -> Result<crypto::HybridPublic, IssueError> {
    if r.registrar != losing_id || r.operator != operator || r.lineage != lineage {
        return refuse("the operator-key receipt is for another registrar, operator or lineage");
    }
    let Some(info) = anchors.registrars.get(losing_id) else {
        return refuse(format!("{losing_id} is not in the directory"));
    };
    let pk = public_of(&r.key)
        .ok_or_else(|| IssueError::Transfer("the operator key does not decode".into()))?;
    let msg = operator_key_message(losing_id, operator, lineage, &r.key)?;
    if !verifies(&pk, &msg, &r.pop) {
        return refuse("the operator never proved it holds the logged key");
    }
    let statement = operator_key_statement(&msg, &r.pop)?;
    let root: [u8; 32] = b64::decode(&r.checkpoint_root)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| {
            IssueError::Transfer("the receipt's checkpoint root does not decode".into())
        })?;
    let cp = Checkpoint {
        origin: r.checkpoint_origin.clone(),
        tree_size: r.checkpoint_size,
        root,
    };
    if cp.origin != format!("ainra-log/{losing_id}") {
        return refuse("the receipt names another log");
    }
    let sig = r.checkpoint_sig.to_core().ok_or_else(|| {
        IssueError::Transfer("the receipt's checkpoint signature does not decode".into())
    })?;
    if let ainra_core::checkpoint::CheckpointSig::Delegate { cert, .. } = &sig {
        if revoked_delegates.contains(&cert.fingerprint()) {
            return refuse(
                "the receipt's checkpoint is signed by a delegate the directory revoked",
            );
        }
    }
    cp.verify_sig_mode(&info.log_root_key, &sig, now)
        .map_err(|_| {
            IssueError::Transfer(
                "the receipt's checkpoint is not signed by that registrar's log".into(),
            )
        })?;
    let proof: Vec<[u8; 32]> = r
        .inclusion_proof
        .iter()
        .map(|h| b64::decode(h).ok()?.try_into().ok())
        .collect::<Option<_>>()
        .ok_or_else(|| {
            IssueError::Transfer("the receipt's inclusion proof does not decode".into())
        })?;
    ainra_core::checkpoint::verify_logged(
        &merkle::hash_leaf(statement.as_bytes()),
        r.leaf_index,
        &cp,
        &proof,
    )
    .map_err(|_| IssueError::Transfer("the operator key is not in that registrar's log".into()))?;
    if info
        .distrust_from_leaf
        .is_some_and(|cut| r.leaf_index >= cut)
    {
        return refuse("the operator key was logged after the registrar's distrust cutoff");
    }
    Ok(pk)
}

/// The last `transfer_history` entry's time, read from signed claims.
fn last_transfer_at(history: &[Value]) -> Option<u64> {
    history.last()?.get("at")?.as_u64()
}

impl RegistrarBox {
    /// Log an operator's key beside one of this registrar's lineages, and return its receipt. This is the registrar's
    /// act, done as it authenticates its own customer (at issuance or later), so the HTTP door keeps it behind the
    /// issuance token. The operator proves it holds the key; the statement goes into the log, where the operator,
    /// or anyone monitoring, sees a key registered without them. One key per lineage: changing it is not built.
    pub fn register_operator_key(
        &mut self,
        operator: &str,
        lineage: &str,
        key: &HybridB64,
        pop: &HybridB64,
    ) -> Result<OperatorKeyReceipt, IssueError> {
        let k = format!("{operator}:{lineage}");
        if !self.lineage_heads.contains_key(&k) {
            return Err(IssueError::Malformed(format!(
                "no lineage {k} at {}",
                self.id
            )));
        }
        let pk = public_of(key)
            .ok_or_else(|| IssueError::HolderProof("the operator key does not decode".into()))?;
        let msg = operator_key_message(&self.id, operator, lineage, key)?;
        if !verifies(&pk, &msg, pop) {
            return Err(IssueError::HolderProof(
                "the operator's proof does not verify under the key".into(),
            ));
        }
        if let Some(e) = self.operator_keys.get(&k) {
            if &e.key == key {
                return self
                    .operator_key_receipt(operator, lineage)
                    .ok_or_else(|| IssueError::Io("proof".into()));
            }
            return refuse("this lineage already has an operator key; changing it is not built");
        }
        let statement = operator_key_statement(&msg, pop)?;
        let leaf_index = self
            .log
            .append(statement.as_bytes())
            .map_err(|e| IssueError::Io(e.to_string()))?;
        self.operator_keys.insert(
            k,
            OperatorKeyEntry {
                operator: operator.into(),
                lineage: lineage.into(),
                key: key.clone(),
                pop: pop.clone(),
                leaf_index,
            },
        );
        self.operator_key_receipt(operator, lineage)
            .ok_or_else(|| IssueError::Io("inclusion proof".into()))
    }

    /// The receipt for a logged operator key, proven under the current checkpoint.
    pub fn operator_key_receipt(
        &self,
        operator: &str,
        lineage: &str,
    ) -> Option<OperatorKeyReceipt> {
        let e = self.operator_keys.get(&format!("{operator}:{lineage}"))?;
        let cp = self.log.signed_checkpoint();
        let signed = self.log.sign_checkpoint(&cp);
        let proof = self.log.inclusion_proof(e.leaf_index)?;
        Some(OperatorKeyReceipt {
            registrar: self.id.clone(),
            operator: e.operator.clone(),
            lineage: e.lineage.clone(),
            key: e.key.clone(),
            pop: e.pop.clone(),
            leaf_index: e.leaf_index,
            inclusion_proof: proof.iter().map(|h| b64::encode(h)).collect(),
            checkpoint_origin: self.log_origin(),
            checkpoint_size: cp.tree_size,
            checkpoint_root: b64::encode(&cp.root),
            checkpoint_sig: WireCheckpointSig::from_core(&signed.sig),
        })
    }

    /// This registrar, as the LOSING side, signs a contest of move `id` with its issuer key. The message names its
    /// purpose, so the signature cannot pass for a passport or a change request.
    pub fn sign_transfer_contest(&self, id: &str, reason: &str) -> Result<HybridB64, IssueError> {
        sign_b64(&self.issuer, &contest_message(id, "registrar", reason)?)
    }

    /// The key this registrar's status lists are signed with, as its directory entry publishes it.
    pub fn status_public(&self) -> crypto::HybridPublic {
        self.status.public()
    }

    /// Every move this registrar has opened, in order: the public pending-transfer record.
    pub fn transfers(&self) -> &[PendingTransfer] {
        &self.transfers
    }

    /// Open a move INTO this registrar. Everything is checked before anything is logged: the request is for this
    /// registrar and recent, the old passport verifies now (status authenticated), the passport's key signed the
    /// request, the new key is held, the lineage is not locked by a recent move, the operator's key is in the losing
    /// registrar's log, and no other move of this lineage is open here. The opening is then logged and public.
    pub fn transfer_in(
        &mut self,
        req: TransferRequest,
        old: &IssuedRecord,
        operator_key: &OperatorKeyReceipt,
        losing: &PeerRegistrar,
        now: u64,
    ) -> Result<PendingTransfer, IssueError> {
        if req.to_registrar != self.id {
            return refuse(format!(
                "the request names {}, not this registrar",
                req.to_registrar
            ));
        }
        if req.requested_at + REQUEST_MAX_AGE_SECS < now || req.requested_at > now + CLOCK_SKEW_SECS
        {
            return refuse("the request is too old or dated in the future");
        }
        let claims: Value = serde_json::from_str(&old.claims)
            .map_err(|e| IssueError::Malformed(format!("claims: {e}")))?;
        let signed_sub = claims["sub"].as_str().unwrap_or("");
        if signed_sub != req.from_sub {
            return refuse("the passport presented is not the one the request names");
        }
        let name = AinraName::parse(signed_sub)
            .map_err(|e| IssueError::Malformed(format!("subject: {e:?}")))?;
        let from_registrar = name.registrar().to_string();
        if from_registrar == self.id {
            return refuse("the lineage is already at this registrar");
        }
        old_passport_valid(old, losing, now)?;
        let holder: HybridB64 = serde_json::from_value(claims["keys"][0].clone())
            .map_err(|_| IssueError::Transfer("the passport carries no key".into()))?;
        let holder_pk = public_of(&holder)
            .ok_or_else(|| IssueError::Transfer("the passport key does not decode".into()))?;
        let msg = request_message(
            &req.from_sub,
            &req.to_registrar,
            req.requested_at,
            &req.new_holder_key,
        )?;
        if !verifies(&holder_pk, &msg, &req.holder_sig) {
            return refuse("the passport's own key did not sign this request");
        }
        verify_holder(&self.id, &req.new_holder_key, Some(&req.new_holder_pop))?;
        let prior_history: Vec<Value> = claims["transfer_history"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if let Some(at) = last_transfer_at(&prior_history) {
            if now < at + TRANSFER_LOCK_SECS {
                return refuse(format!(
                    "the lineage moved at {at} and is locked until {}",
                    at + TRANSFER_LOCK_SECS
                ));
            }
        }
        let (operator, lineage) = (name.operator().to_string(), name.lineage().to_string());
        let op_pk = check_operator_receipt(
            operator_key,
            &from_registrar,
            &operator,
            &lineage,
            losing.anchors,
            losing.revoked_delegates,
            now,
        )?;
        let operator_signed = match &req.operator_sig {
            Some(s) if verifies(&op_pk, &msg, s) => true,
            Some(_) => {
                return refuse(
                    "the operator signature does not verify under the logged operator key",
                )
            }
            None => false,
        };
        if self.transfers.iter().any(|t| {
            t.operator == operator && t.lineage == lineage && t.state == TransferState::Open
        }) {
            return refuse("a move of this lineage is already open here");
        }
        self.refuse_name_taken(&operator, &lineage)?;
        let id = transfer_id(&msg);
        if self.transfers.iter().any(|t| t.id == id) {
            return refuse("this request was already received");
        }
        let opened = canonical(&json!({
            "purpose": "ainra-transfer-opened-v1", "transfer": id, "request": msg,
            "holder_sig": req.holder_sig, "at": now, "closes_at": now + CONTEST_WINDOW_SECS,
        }))?;
        let opened_leaf = self
            .log
            .append(opened.as_bytes())
            .map_err(|e| IssueError::Io(e.to_string()))?;
        let auth = &claims["authority"];
        let strings = |v: &Value| -> Vec<String> {
            v.as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        };
        let pending = PendingTransfer {
            id,
            request: req,
            from_registrar,
            operator,
            lineage,
            version: name.version().to_string(),
            from_log_origin: old.log_origin.clone(),
            from_leaf_index: old.leaf_index,
            from_checkpoint_size: old.checkpoint_size,
            from_checkpoint_root: old.checkpoint_root.clone(),
            tier: claims["tier"].as_str().unwrap_or("").into(),
            auth_class: auth["class"].as_str().unwrap_or("").into(),
            principal_proof: auth["principal_proof"].as_str().unwrap_or("").into(),
            capabilities: strings(&claims["capabilities"]),
            scope_ceiling: strings(&claims["scope_ceiling"]),
            prior_history,
            operator_key: operator_key.key.clone(),
            operator_signed,
            opened_leaf,
            opened_at: now,
            closes_at: now + CONTEST_WINDOW_SECS,
            contests: Vec::new(),
            state: TransferState::Open,
        };
        self.transfers.push(pending.clone());
        Ok(pending)
    }

    fn open_transfer(&mut self, id: &str, now: u64) -> Result<usize, IssueError> {
        let Some(i) = self.transfers.iter().position(|t| t.id == id) else {
            return refuse(format!("no move {id} here"));
        };
        if self.transfers[i].state != TransferState::Open {
            return refuse(format!("move {id} is no longer open"));
        }
        if now >= self.transfers[i].closes_at {
            return refuse(format!("the window for move {id} has closed"));
        }
        Ok(i)
    }

    /// A move may not merge two lineages: if this registrar already has `operator:lineage`, that name is someone's here.
    fn refuse_name_taken(&self, operator: &str, lineage: &str) -> Result<(), IssueError> {
        if self
            .lineage_heads
            .contains_key(&format!("{operator}:{lineage}"))
        {
            return refuse(format!(
                "this registrar already has a lineage {operator}:{lineage}; a move cannot merge two lineages"
            ));
        }
        Ok(())
    }

    /// The operator signs a move the agent asked for, during the window.
    pub fn transfer_consent(
        &mut self,
        id: &str,
        operator_sig: &HybridB64,
        now: u64,
    ) -> Result<(), IssueError> {
        let i = self.open_transfer(id, now)?;
        let t = &self.transfers[i];
        let pk = public_of(&t.operator_key)
            .ok_or_else(|| IssueError::Transfer("operator key".into()))?;
        let r = &t.request;
        let msg = request_message(
            &r.from_sub,
            &r.to_registrar,
            r.requested_at,
            &r.new_holder_key,
        )?;
        if !verifies(&pk, &msg, operator_sig) {
            return refuse("the operator signature does not verify under the logged operator key");
        }
        let t = &mut self.transfers[i];
        t.request.operator_sig = Some(operator_sig.clone());
        t.operator_signed = true;
        Ok(())
    }

    /// Contest a move during its window. `by` is `operator` (signed with the logged operator key; always stops the
    /// move) or `registrar` (signed with the losing registrar's issuer key from the directory; stops the move only
    /// while that registrar has no distrust cutoff, and only with a reason from [`REGISTRAR_CONTEST_REASONS`]). A
    /// contest whose signature does not verify is refused and not recorded: nobody can fill the record with noise.
    pub fn transfer_contest(
        &mut self,
        id: &str,
        by: &str,
        reason: &str,
        sig: &HybridB64,
        anchors: &TrustAnchors,
        now: u64,
    ) -> Result<PendingTransfer, IssueError> {
        let i = self.open_transfer(id, now)?;
        let msg = contest_message(id, by, reason)?;
        let t = &self.transfers[i];
        let (counted, note) = match by {
            "operator" => {
                let pk = public_of(&t.operator_key)
                    .ok_or_else(|| IssueError::Transfer("operator key".into()))?;
                if !verifies(&pk, &msg, sig) {
                    return refuse("the contest is not signed by the logged operator key");
                }
                (true, "the operator stopped the move".to_string())
            }
            "registrar" => {
                if !REGISTRAR_CONTEST_REASONS.contains(&reason) {
                    return refuse(format!(
                        "a registrar contest needs one of {REGISTRAR_CONTEST_REASONS:?}"
                    ));
                }
                let Some(info) = anchors.registrars.get(&t.from_registrar) else {
                    return refuse("the losing registrar is not in the directory");
                };
                if !verifies(&info.issuer_key, &msg, sig) {
                    return refuse(
                        "the contest is not signed by the losing registrar's issuer key",
                    );
                }
                match info.distrust_from_leaf {
                    None => (true, "the losing registrar stopped the move".to_string()),
                    Some(cut) => (
                        false,
                        format!(
                            "not counted: the root distrusts {} from leaf {cut}",
                            t.from_registrar
                        ),
                    ),
                }
            }
            _ => return refuse("a contest is by `operator` or `registrar`"),
        };
        let line = canonical(&json!({
            "purpose": "ainra-transfer-contested-v1", "contest": msg, "sig": sig, "at": now, "counted": counted,
        }))?;
        self.log
            .append(line.as_bytes())
            .map_err(|e| IssueError::Io(e.to_string()))?;
        let t = &mut self.transfers[i];
        t.contests.push(ContestRecord {
            by: by.into(),
            reason: reason.into(),
            at: now,
            counted,
            note: note.clone(),
        });
        if counted {
            t.state = TransferState::Refused { reason: note };
        }
        Ok(t.clone())
    }

    /// Complete a move once its window has closed. A move the operator never signed is refused here, and the record
    /// says so. The old passport must still verify now (a revocation during the window stops the move). The gaining
    /// registrar issues under its own name, with its own policy, and the new passport's `transfer_history` names the
    /// old passport's log position.
    #[allow(clippy::too_many_arguments)]
    pub fn transfer_complete(
        &mut self,
        id: &str,
        old: &IssuedRecord,
        losing: &PeerRegistrar,
        audit: Option<&super::AuditEvidence>,
        principal_evidence: Option<Value>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<IssuedRecord, IssueError> {
        self.refuse_outside_delegate_window(now)?;
        let Some(i) = self.transfers.iter().position(|t| t.id == id) else {
            return refuse(format!("no move {id} here"));
        };
        let t = self.transfers[i].clone();
        if t.state != TransferState::Open {
            return refuse(format!("move {id} is no longer open"));
        }
        if now < t.closes_at {
            return refuse(format!(
                "move {id} is open to contest until {}",
                t.closes_at
            ));
        }
        if !t.operator_signed {
            let reason =
                "the operator never signed the move; an agent key alone does not move a lineage"
                    .to_string();
            self.transfers[i].state = TransferState::Refused {
                reason: reason.clone(),
            };
            return refuse(reason);
        }
        let claims: Value = serde_json::from_str(&old.claims)
            .map_err(|e| IssueError::Malformed(format!("claims: {e}")))?;
        if claims["sub"].as_str() != Some(t.request.from_sub.as_str())
            || old.leaf_index != t.from_leaf_index
        {
            return refuse("the passport presented is not the one this move opened with");
        }
        if let Err(e) = old_passport_valid(old, losing, now) {
            self.transfers[i].state = TransferState::Refused {
                reason: e.to_string(),
            };
            return Err(e);
        }
        if let Err(e) = self.refuse_name_taken(&t.operator, &t.lineage) {
            self.transfers[i].state = TransferState::Refused {
                reason: e.to_string(),
            };
            return Err(e);
        }
        let sub = format!(
            "ainra:{}:{}:{}@{}",
            self.id, t.operator, t.lineage, t.version
        );
        if self.records.contains_key(&sub) {
            return Err(IssueError::Duplicate(sub));
        }
        let spec = IssueSpec {
            operator: t.operator.clone(),
            lineage: t.lineage.clone(),
            version: t.version.clone(),
            tier: t.tier.clone(),
            auth_class: t.auth_class.clone(),
            principal_proof: t.principal_proof.clone(),
            capabilities: t.capabilities.clone(),
            scope_ceiling: t.scope_ceiling.clone(),
            hops: vec![],
            audit: audit.cloned(),
            holder_key: Some(t.request.new_holder_key.clone()),
            holder_pop: Some(t.request.new_holder_pop.clone()),
            principal_evidence,
        };
        check_audit_cap(&spec.tier, self.exp, spec.audit.as_ref())?;
        let proof = principal::principal_for(&self.principal_policy, &self.id, &spec)?;
        let spec = IssueSpec {
            principal_proof: proof,
            ..spec
        };
        let mut history = t.prior_history.clone();
        history.push(json!({
            "kind": "registrar",
            "from": t.request.from_sub,
            "log_origin": t.from_log_origin,
            "leaf_index": t.from_leaf_index,
            "checkpoint_size": t.from_checkpoint_size,
            "checkpoint_root": t.from_checkpoint_root,
            "transfer": t.id,
            "at": now,
        }));
        let (nbf, exp) = (self.nbf, self.exp);
        let rec = self.issue_with(&spec, sub.clone(), (nbf, exp), None, &history, &[], rng)?;
        self.transfers[i].state = TransferState::Completed { sub };
        Ok(rec)
    }

    /// The losing registrar, shown the passport the gaining registrar issued AND the signed request behind it,
    /// revokes the old one. A valid passport from another registrar is not enough: an accredited registrar that
    /// turned hostile could issue one naming a competitor's customer. So the losing registrar checks, against its own
    /// records, that its customer asked: the request is signed by the old passport's key and by the operator key this
    /// registrar logged, it names the gaining registrar and the key the new passport carries, and its id is the one
    /// the new passport's history records.
    pub fn transfer_out(
        &mut self,
        new: &IssuedRecord,
        request: &TransferRequest,
        gaining: &PeerRegistrar,
        now: u64,
    ) -> Result<status::StatusDelta, IssueError> {
        old_passport_valid(new, gaining, now)
            .map_err(|e| IssueError::Transfer(format!("the new passport: {e}")))?;
        let claims: Value = serde_json::from_str(&new.claims)
            .map_err(|e| IssueError::Malformed(format!("claims: {e}")))?;
        let last = claims["transfer_history"]
            .as_array()
            .and_then(|h| h.last().cloned())
            .ok_or_else(|| IssueError::Transfer("the new passport records no transfer".into()))?;
        let from = last["from"].as_str().unwrap_or("");
        let Some(rec) = self.records.get(from) else {
            return refuse(format!("{from} is not a passport of this registrar"));
        };
        if last["log_origin"].as_str() != Some(self.log_origin().as_str())
            || last["leaf_index"].as_u64() != Some(rec.leaf_index)
        {
            return refuse("the transfer record does not match this registrar's log");
        }
        let (new_sub, old_sub) = (claims["sub"].as_str().unwrap_or(""), rec.sub.clone());
        let (n, o) = (
            AinraName::parse(new_sub).map_err(|e| IssueError::Malformed(format!("{e:?}")))?,
            AinraName::parse(&old_sub).map_err(|e| IssueError::Malformed(format!("{e:?}")))?,
        );
        if n.operator() != o.operator() || n.lineage() != o.lineage() {
            return refuse("the new passport is for another lineage");
        }
        let msg = request_message(
            &request.from_sub,
            &request.to_registrar,
            request.requested_at,
            &request.new_holder_key,
        )?;
        if request.from_sub != old_sub
            || request.to_registrar != n.registrar()
            || last["transfer"].as_str() != Some(transfer_id(&msg).as_str())
        {
            return refuse("the request is not the one the new passport's history records");
        }
        let new_key: Option<HybridB64> = serde_json::from_value(claims["keys"][0].clone()).ok();
        if new_key.as_ref() != Some(&request.new_holder_key) {
            return refuse("the new passport does not carry the key the request asked for");
        }
        let old_claims: Value = serde_json::from_str(&rec.claims)
            .map_err(|e| IssueError::Malformed(format!("claims: {e}")))?;
        let old_key = serde_json::from_value::<HybridB64>(old_claims["keys"][0].clone())
            .ok()
            .and_then(|k| public_of(&k))
            .ok_or_else(|| IssueError::Transfer("the old passport carries no key".into()))?;
        if !verifies(&old_key, &msg, &request.holder_sig) {
            return refuse("the request is not signed by the old passport's key");
        }
        let op_key = self
            .operator_keys
            .get(&format!("{}:{}", o.operator(), o.lineage()))
            .and_then(|e| public_of(&e.key))
            .ok_or_else(|| {
                IssueError::Transfer("no operator key is logged here for this lineage".into())
            })?;
        match &request.operator_sig {
            Some(s) if verifies(&op_key, &msg, s) => {}
            _ => return refuse("the request is not signed by the operator key logged here"),
        }
        self.revoke(&old_sub, now)
    }
}

// ── A change of owner (PLAN-M53 step 8, D-103) ──────────────────────────────────────────────────────────────────
//
// The Standard §1: "a genuine ownership transfer is a logged event that resets assurance evidence while preserving the
// historical record", and the version is re-certified on every change of operator. The rules, at one registrar:
//
// 1. **The old owner gives the lineage away, with the operator key its registrar logged.** An agent key cannot.
// 2. **The new owner proves it holds its own operator key**, which is logged beside the lineage under its name when the
//    change completes, so the new owner can later move the lineage or give it away in turn.
// 3. **The change is public for [`CONTEST_WINDOW_SECS`], logged when it opens.** The old operator key may stop it: a
//    thief holding that key and the real owner hold the same key, and stopping is the safe outcome.
// 4. **Assurance starts again.** The registrar completes the change with the tier, class, principal proof,
//    capabilities and scope it establishes for the NEW owner now; nothing is copied from the old passport. Completing
//    is the registrar's own act (it authenticates its new customer), behind its write authorization.
// 5. **The history is kept and the old passport ends.** The new passport (`ainra:{registrar}:{new operator}:{lineage}`)
//    carries the old one in its signed `transfer_history` with `kind: "ownership"` and `assurance_reset: true`; the old
//    lineage is revoked in the same step; the sixty-day lock applies to any kind of change.

/// What the old owner signs to give a lineage to a new owner.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnershipRequest {
    /// The passport whose lineage changes hands, by its full name at this registrar.
    pub from_sub: String,
    pub new_operator: String,
    pub requested_at: u64,
    /// The new owner's operator key, and its proof over [`operator_key_message`] for the new name.
    pub new_operator_key: HybridB64,
    pub new_operator_pop: HybridB64,
    /// The key the new passport certifies, and its proof of possession for this registrar (D-063).
    pub new_holder_key: HybridB64,
    pub new_holder_pop: HybridB64,
    /// The OLD operator key (as logged here) over [`ownership_message`].
    pub old_operator_sig: HybridB64,
}

/// The public record of one change of owner.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingOwnership {
    pub id: String,
    pub request: OwnershipRequest,
    pub operator: String,
    pub lineage: String,
    pub version: String,
    pub from_leaf_index: u64,
    pub from_checkpoint_size: u64,
    pub from_checkpoint_root: String,
    pub prior_history: Vec<Value>,
    pub old_operator_key: HybridB64,
    pub opened_leaf: u64,
    pub opened_at: u64,
    pub closes_at: u64,
    pub contests: Vec<ContestRecord>,
    #[serde(flatten)]
    pub state: TransferState,
}

/// The assurance the registrar establishes for the NEW owner, at completion. Nothing here comes from the old passport.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewOwnerAssurance {
    pub tier: String,
    pub auth_class: String,
    pub principal_proof: String,
    pub capabilities: Vec<String>,
    pub scope_ceiling: Vec<String>,
    #[serde(default)]
    pub audit: Option<super::AuditEvidence>,
    #[serde(default)]
    pub principal_evidence: Option<Value>,
}

/// The bytes the old operator key signs to give a lineage away.
pub fn ownership_message(
    from_sub: &str,
    new_operator: &str,
    requested_at: u64,
    new_operator_key: &HybridB64,
    new_holder_key: &HybridB64,
) -> Result<String, IssueError> {
    canonical(&json!({
        "purpose": "ainra-ownership-v1",
        "from": from_sub,
        "new_operator": new_operator,
        "at": requested_at,
        "new_operator_key": { "ed25519": new_operator_key.ed25519, "mldsa65": new_operator_key.mldsa65 },
        "new_holder": { "ed25519": new_holder_key.ed25519, "mldsa65": new_holder_key.mldsa65 },
    }))
}

impl RegistrarBox {
    /// Every change of owner this registrar has opened, in order: the public record.
    pub fn ownerships(&self) -> &[PendingOwnership] {
        &self.ownerships
    }

    /// Open a change of owner. Checked before anything is logged: the passport is this registrar's current head of its
    /// lineage and not revoked; the old operator key logged here signed the request; the new owner holds its operator
    /// key and the new holder key; the lineage is not locked by a recent change; the new name is free here; no other
    /// change of this lineage is open.
    pub fn ownership_open(
        &mut self,
        req: OwnershipRequest,
        now: u64,
    ) -> Result<PendingOwnership, IssueError> {
        if req.requested_at + REQUEST_MAX_AGE_SECS < now || req.requested_at > now + CLOCK_SKEW_SECS
        {
            return refuse("the request is too old or dated in the future");
        }
        let Some(rec) = self.records.get(&req.from_sub).cloned() else {
            return refuse(format!(
                "{} is not a passport of this registrar",
                req.from_sub
            ));
        };
        if rec.revoked {
            return refuse("the passport is revoked; a revoked lineage does not change hands");
        }
        let (operator, lineage) = (rec.operator.clone(), rec.lineage.clone());
        let key = format!("{operator}:{lineage}");
        if self.lineage_heads.get(&key).map(|(s, _)| s.as_str()) != Some(req.from_sub.as_str()) {
            return refuse("only the lineage's current passport can change hands");
        }
        let Some(old_op) = self.operator_keys.get(&key).map(|e| e.key.clone()) else {
            return refuse("no operator key is logged here for this lineage");
        };
        let msg = ownership_message(
            &req.from_sub,
            &req.new_operator,
            req.requested_at,
            &req.new_operator_key,
            &req.new_holder_key,
        )?;
        let old_pk =
            public_of(&old_op).ok_or_else(|| IssueError::Transfer("operator key".into()))?;
        if !verifies(&old_pk, &msg, &req.old_operator_sig) {
            return refuse("the request is not signed by the operator key logged for this lineage");
        }
        if req.new_operator == operator {
            return refuse("the new owner is the current owner");
        }
        let new_name = format!(
            "ainra:{}:{}:{}@{}",
            self.id, req.new_operator, lineage, rec.version
        );
        AinraName::parse(&new_name).map_err(|e| {
            IssueError::Malformed(format!("the new name is not well-formed: {e:?}"))
        })?;
        let new_op_pk = public_of(&req.new_operator_key).ok_or_else(|| {
            IssueError::HolderProof("the new operator key does not decode".into())
        })?;
        let pop_msg =
            operator_key_message(&self.id, &req.new_operator, &lineage, &req.new_operator_key)?;
        if !verifies(&new_op_pk, &pop_msg, &req.new_operator_pop) {
            return refuse("the new owner did not prove it holds its operator key");
        }
        verify_holder(&self.id, &req.new_holder_key, Some(&req.new_holder_pop))?;
        let claims: Value = serde_json::from_str(&rec.claims)
            .map_err(|e| IssueError::Malformed(format!("claims: {e}")))?;
        let prior_history: Vec<Value> = claims["transfer_history"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if let Some(at) = last_transfer_at(&prior_history) {
            if now < at + TRANSFER_LOCK_SECS {
                return refuse(format!(
                    "the lineage changed at {at} and is locked until {}",
                    at + TRANSFER_LOCK_SECS
                ));
            }
        }
        self.refuse_name_taken(&req.new_operator, &lineage)?;
        let busy = self.ownerships.iter().any(|o| {
            o.operator == operator && o.lineage == lineage && o.state == TransferState::Open
        }) || self.transfers.iter().any(|t| {
            t.operator == operator && t.lineage == lineage && t.state == TransferState::Open
        });
        if busy {
            return refuse("a change of this lineage is already open here");
        }
        let id = transfer_id(&msg);
        if self.ownerships.iter().any(|o| o.id == id) {
            return refuse("this request was already received");
        }
        let opened = canonical(&json!({
            "purpose": "ainra-ownership-opened-v1", "change": id, "request": msg,
            "old_operator_sig": req.old_operator_sig, "at": now, "closes_at": now + CONTEST_WINDOW_SECS,
        }))?;
        let opened_leaf = self
            .log
            .append(opened.as_bytes())
            .map_err(|e| IssueError::Io(e.to_string()))?;
        let pending = PendingOwnership {
            id,
            request: req,
            operator,
            lineage,
            version: rec.version.clone(),
            from_leaf_index: rec.leaf_index,
            from_checkpoint_size: rec.checkpoint_size,
            from_checkpoint_root: rec.checkpoint_root.clone(),
            prior_history,
            old_operator_key: old_op,
            opened_leaf,
            opened_at: now,
            closes_at: now + CONTEST_WINDOW_SECS,
            contests: Vec::new(),
            state: TransferState::Open,
        };
        self.ownerships.push(pending.clone());
        Ok(pending)
    }

    /// The old operator key stops a change of owner during its window. A contest that does not verify is refused and
    /// leaves no record.
    pub fn ownership_contest(
        &mut self,
        id: &str,
        reason: &str,
        sig: &HybridB64,
        now: u64,
    ) -> Result<PendingOwnership, IssueError> {
        let Some(i) = self.ownerships.iter().position(|o| o.id == id) else {
            return refuse(format!("no change {id} here"));
        };
        let o = &self.ownerships[i];
        if o.state != TransferState::Open {
            return refuse(format!("change {id} is no longer open"));
        }
        if now >= o.closes_at {
            return refuse(format!("the window for change {id} has closed"));
        }
        let msg = contest_message(id, "operator", reason)?;
        let pk = public_of(&o.old_operator_key)
            .ok_or_else(|| IssueError::Transfer("operator key".into()))?;
        if !verifies(&pk, &msg, sig) {
            return refuse("the contest is not signed by the logged operator key");
        }
        let line = canonical(&json!({
            "purpose": "ainra-ownership-contested-v1", "contest": msg, "sig": sig, "at": now,
        }))?;
        self.log
            .append(line.as_bytes())
            .map_err(|e| IssueError::Io(e.to_string()))?;
        let note = "the operator stopped the change of owner".to_string();
        let o = &mut self.ownerships[i];
        o.contests.push(ContestRecord {
            by: "operator".into(),
            reason: reason.into(),
            at: now,
            counted: true,
            note: note.clone(),
        });
        o.state = TransferState::Refused { reason: note };
        Ok(o.clone())
    }

    /// Complete a change of owner after its window, with the assurance this registrar establishes for the new owner.
    /// Issues the new passport, logs the new owner's operator key, and revokes the old lineage, in that order; a
    /// failure before issuance changes nothing.
    pub fn ownership_complete(
        &mut self,
        id: &str,
        assurance: &NewOwnerAssurance,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<IssuedRecord, IssueError> {
        self.refuse_outside_delegate_window(now)?;
        let Some(i) = self.ownerships.iter().position(|o| o.id == id) else {
            return refuse(format!("no change {id} here"));
        };
        let o = self.ownerships[i].clone();
        if o.state != TransferState::Open {
            return refuse(format!("change {id} is no longer open"));
        }
        if now < o.closes_at {
            return refuse(format!(
                "change {id} is open to contest until {}",
                o.closes_at
            ));
        }
        let old_sub = o.request.from_sub.clone();
        let still_head = self
            .lineage_heads
            .get(&format!("{}:{}", o.operator, o.lineage))
            .map(|(s, _)| s.clone());
        let revoked = self
            .records
            .get(&old_sub)
            .map(|r| r.revoked)
            .unwrap_or(true);
        if revoked || still_head.as_deref() != Some(old_sub.as_str()) {
            let reason = "the passport was revoked or renewed during the window".to_string();
            self.ownerships[i].state = TransferState::Refused {
                reason: reason.clone(),
            };
            return refuse(reason);
        }
        if let Err(e) = self.refuse_name_taken(&o.request.new_operator, &o.lineage) {
            self.ownerships[i].state = TransferState::Refused {
                reason: e.to_string(),
            };
            return Err(e);
        }
        let spec = IssueSpec {
            operator: o.request.new_operator.clone(),
            lineage: o.lineage.clone(),
            version: o.version.clone(),
            tier: assurance.tier.clone(),
            auth_class: assurance.auth_class.clone(),
            principal_proof: assurance.principal_proof.clone(),
            capabilities: assurance.capabilities.clone(),
            scope_ceiling: assurance.scope_ceiling.clone(),
            hops: vec![],
            audit: assurance.audit.clone(),
            holder_key: Some(o.request.new_holder_key.clone()),
            holder_pop: Some(o.request.new_holder_pop.clone()),
            principal_evidence: assurance.principal_evidence.clone(),
        };
        check_audit_cap(&spec.tier, self.exp, spec.audit.as_ref())?;
        let proof = principal::principal_for(&self.principal_policy, &self.id, &spec)?;
        let spec = IssueSpec {
            principal_proof: proof,
            ..spec
        };
        let mut history = o.prior_history.clone();
        history.push(json!({
            "kind": "ownership",
            "from": old_sub,
            "log_origin": self.log_origin(),
            "leaf_index": o.from_leaf_index,
            "checkpoint_size": o.from_checkpoint_size,
            "checkpoint_root": o.from_checkpoint_root,
            "transfer": o.id,
            "at": now,
            "assurance_reset": true,
        }));
        let sub = format!(
            "ainra:{}:{}:{}@{}",
            self.id, spec.operator, spec.lineage, spec.version
        );
        let (nbf, exp) = (self.nbf, self.exp);
        let rec = self.issue_with(&spec, sub.clone(), (nbf, exp), None, &history, &[], rng)?;
        // The new owner's key, logged beside the lineage under its new name, exactly as `register_operator_key` would.
        let pop_msg = operator_key_message(
            &self.id,
            &spec.operator,
            &spec.lineage,
            &o.request.new_operator_key,
        )?;
        let statement = operator_key_statement(&pop_msg, &o.request.new_operator_pop)?;
        let leaf_index = self
            .log
            .append(statement.as_bytes())
            .map_err(|e| IssueError::Io(e.to_string()))?;
        self.operator_keys.insert(
            format!("{}:{}", spec.operator, spec.lineage),
            OperatorKeyEntry {
                operator: spec.operator.clone(),
                lineage: spec.lineage.clone(),
                key: o.request.new_operator_key.clone(),
                pop: o.request.new_operator_pop.clone(),
                leaf_index,
            },
        );
        self.revoke(&old_sub, now)?;
        self.ownerships[i].state = TransferState::Completed { sub };
        Ok(rec)
    }
}
