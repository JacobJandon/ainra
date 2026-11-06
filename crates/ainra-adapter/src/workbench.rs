// SPDX-License-Identifier: Apache-2.0 OR MIT
//! PLAN-M52 steps 5–8 — what a directory change request, a proposal, an assembled epoch and a publication mean, and
//! the rules each one is held to.
//!
//! The root's one act is a new directory epoch. This module is the only place the bytes of that act are interpreted:
//! a **change request** (R0) filed by the party it concerns; a **proposal** — an UNSIGNED epoch N+1 drafted from
//! epoch N and a batch of requests (R1–R4); the **assembly** of a proposal with the two root signatures (R6); and the
//! **publication** check (R7). Every function here is pure, like the rest of this crate: no I/O, no clock, no keys.
//! It decides; the CLI reads files and writes them. Nothing here can sign anything, and nothing here can make a
//! proposal the directory — only five FROST shares and the SLH-DSA root can, offline.
//!
//! Every refusal names the check that refused it. The list of checks, [`CHECKS`], is the code's own; it is what
//! `docs/ACCREDITATION-CHECKS.md` is generated from (`ainra directory check-request --list-checks`), and
//! `make accreditation-checks` fails when the two disagree. A refusal whose check is not in the list fails the tests.
//!
//! WITNESS: the tests below refuse one request, proposal, assembly and publication per check, each by its id, and
//! accept the honest one; `make sign-epoch-rehearsal` takes one change through request → proposal → ceremony →
//! publish across nine custodian processes and shows each refusal of steps 5–8 red.

use std::collections::BTreeSet;

use ainra_core::directory::{Directory, DirectoryEntry};
use ainra_core::{b64, canon, checkpoint, crypto};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{WireDelegateCert, WireSig};

/// The request format's name and version (v1).
pub const REQUEST_KIND: &str = "ainra/directory-change-request";
/// The proposal format's name and version (v1).
pub const PROPOSAL_KIND: &str = "ainra/directory-proposal";
/// Every request's message starts with this; what each key signs is this prefix followed by the request's digest in
/// hex. It is not JSON, so an issuer key's signature over it can never stand in for one over a passport.
pub const REQUEST_MESSAGE_PREFIX: &str = "ainra/directory-change-request/v1 ";
/// No legal entity exists yet (PLAN-M52 R0, ROLES): until one does, a registrar is accredited only under TEST-ROOT.
/// Turning this on is a decision with its own record, never an edit to make a request pass.
pub const LEGAL_ENTITY_EXISTS: bool = false;

/// The six request types of R0.
pub const TYPES: [&str; 6] = [
    "ACCREDIT",
    "WITHDRAW",
    "DISTRUST_FROM_LEAF",
    "REVOKE_DELEGATE",
    "REGISTRAR_KEY_ROLL",
    "ROOT_KEY_ROLL",
];

// ── the checks ───────────────────────────────────────────────────────────────────────────────────────────────────

/// One check the workbench runs (or names as not built). `stage` is the command that runs it.
pub struct Check {
    pub id: &'static str,
    pub stage: &'static str,
    pub built: bool,
    pub rule: &'static str,
}

/// The compliance ladder's numbers (D-094 item 11, built D-096): the cure window runs at least 30 days from notice 1,
/// notices are at least 14 days apart, and holders get at least 90 days from the public breach record (notice 3 or
/// later) before an adverse WITHDRAW, to move to another registrar.
pub const CURE_MIN_SECS: u64 = 30 * 86_400;
pub const NOTICE_GAP_MIN_SECS: u64 = 14 * 86_400;
pub const HOLDER_GRACE_SECS: u64 = 90 * 86_400;

/// Every check, in the order each command runs them. The generated document is this list and nothing else.
pub const CHECKS: &[Check] = &[
    // ── change requests: `ainra directory check-request` (R0–R2) ──
    Check { id: "request-shape", stage: "check-request", built: true,
        rule: "The request is version 1 of `ainra/directory-change-request`, names one of the six types, carries no field outside the format at any level, and canonicalizes (its digest is the SHA-256 of its canonical JSON without `proofs`)." },
    Check { id: "root-key-roll", stage: "check-request", built: true,
        rule: "ROOT_KEY_ROLL is refused: it runs on its own track (PLAN-M52 step 9), which is not built." },
    Check { id: "request-subject", stage: "check-request", built: true,
        rule: "`registrar` is a registrar id (ASCII lowercase letters, digits and `-`, at most 63) and `filer` is not empty." },
    Check { id: "request-base", stage: "check-request", built: true,
        rule: "The current directory the request is checked against verifies under both roots (FROST Ed25519 and SLH-DSA). With no directory, the request is checked for the first epoch." },
    Check { id: "moves-trust", stage: "check-request", built: true,
        rule: "A request that moves trust is refused: REGISTRAR_KEY_ROLL, or an ACCREDIT that changes a key or the status URI of a registrar already in the directory. It needs a declared offline approver set (D-088 R0; an ADR and a schema change, not built)." },
    Check { id: "subject-in-directory", stage: "check-request", built: true,
        rule: "WITHDRAW, DISTRUST_FROM_LEAF and REVOKE_DELEGATE name a registrar in the current directory; ACCREDIT names one that is not." },
    Check { id: "delegate-owned", stage: "check-request", built: true,
        rule: "REVOKE_DELEGATE is filed by the registrar itself and carries the delegate certificate; the certificate is signed by that registrar's log root (SLH-DSA) as the current directory lists it, and its fingerprint is not already revoked. The fingerprint is derived from the certificate, never taken from the request." },
    Check { id: "cutoff-monotone", stage: "check-request", built: true,
        rule: "DISTRUST_FROM_LEAF never lifts a cutoff or moves one later; an existing cutoff can only move earlier (until the owner rules otherwise, PLAN-M52 item 12)." },
    Check { id: "self-signature", stage: "check-request", built: true,
        rule: "A request a registrar files about its own entry (REVOKE_DELEGATE, its own DISTRUST_FROM_LEAF or WITHDRAW) carries a hybrid signature (Ed25519 and ML-DSA-65) over the request message by the registrar's CURRENT issuer key, as the current directory lists it." },
    Check { id: "adverse-proof", stage: "check-request", built: true,
        rule: "An adverse DISTRUST_FROM_LEAF may instead carry a fork proof: two checkpoints of the registrar's own log (origin `ainra-log/<registrar>`), each signed under the log root epoch N lists for it (directly, or by a delegate it certified that epoch N has not revoked), at one size with different roots. It then skips the notice chain, cure window and reproductions (R3: an emergency that only closes things skips the wait, not the publication), and its cutoff is at or below that size. A pair that agrees, a signature that does not verify, or another log's origin is refused (D-098)." },
    Check { id: "adverse-notice-chain", stage: "check-request", built: true,
        rule: "An adverse request (DISTRUST_FROM_LEAF or WITHDRAW filed against another registrar) carries a compliance record: at least two notices, numbered 1, 2, … in time order and at least 14 days apart, each named by its SHA-256, and a cure window that ends at least 30 days after notice 1 and before the request was filed (D-094 item 11)." },
    Check { id: "adverse-vantage", stage: "check-request", built: true,
        rule: "The compliance record reproduces the failure after the cure window ended, no later than the filing, from at least two vantage points on distinct networks, each report named by its SHA-256." },
    Check { id: "adverse-grace", stage: "check-request", built: true,
        rule: "An adverse WITHDRAW comes only after distrust: the registrar already carries a distrust cutoff in epoch N, the record names a public breach record (notice 3 or later), and the request is filed at least 90 days after it, so holders have had time to move (D-094 item 11)." },
    Check { id: "entry-shape", stage: "check-request", built: true,
        rule: "An ACCREDIT entry is for the request's registrar, decodes every key at its exact size (Ed25519 32 B, ML-DSA-65 1952 B, SLH-DSA 32 B), carries status keys and a status URI, and sets no distrust cutoff." },
    Check { id: "proof-of-possession", stage: "check-request", built: true,
        rule: "An ACCREDIT proves possession of every new key: a hybrid signature by the issuer key, a hybrid signature by the status key, and an SLH-DSA signature by the log root, each over the request message." },
    Check { id: "accreditation-match", stage: "check-request", built: true,
        rule: "When a copy of the registrar's served `/accreditation` is given (`--accreditation`), the entry's keys and status URI equal it." },
    Check { id: "prerequisites", stage: "check-request", built: true,
        rule: "An ACCREDIT of a new registrar carries the Standard §3 prerequisites as named file digests: the signed identical agreement, the independence attestation, the funded competitor monitor, and the audit with its date (YYYY-MM-DD)." },
    Check { id: "test-root-only", stage: "check-request", built: true,
        rule: "Until a legal entity exists, an ACCREDIT is accepted only with `test_root: true`." },
    Check { id: "live-endpoints", stage: "check-request", built: false,
        rule: "Not built here: the registrar's endpoints answer, `/witness-feed` serves a consistency proof, `status_uri` serves a list that verifies under the entry's status key, and the compliance probe reports COMPLIANT. These need the network and the workbench is offline; the probe (`make probe-drill`) measures them against a live registrar." },
    // ── proposals: `ainra directory propose` and `check-proposal` (R1–R5) ──
    Check { id: "proposal-shape", stage: "check-proposal", built: true,
        rule: "The proposal is version 1 of `ainra/directory-proposal` and carries no field outside the format." },
    Check { id: "proposal-base", stage: "check-proposal", built: true,
        rule: "Epoch N verifies under both roots, and the proposal names it: its base epoch and the SHA-256 of its signing bytes. A first epoch names no base." },
    Check { id: "proposal-epoch", stage: "check-proposal", built: true,
        rule: "The proposal is for epoch N+1 exactly; no epoch is skipped." },
    Check { id: "proposal-issued-at", stage: "check-proposal", built: true,
        rule: "The new directory's `issued_at` is later than epoch N's." },
    Check { id: "proposal-schema", stage: "check-proposal", built: true,
        rule: "The new directory carries no field outside the frozen directory schema, carries no signature yet, and lists its entries sorted and unique." },
    Check { id: "proposal-requests", stage: "check-proposal", built: true,
        rule: "Each request the proposal applies is listed under the SHA-256 it really has, passes every request check against epoch N, appears once, and is the only request about its registrar (several REVOKE_DELEGATE excepted)." },
    Check { id: "proposal-no-drop", stage: "check-proposal", built: true,
        rule: "Every entry of epoch N is still present unless a WITHDRAW in the proposal names it." },
    Check { id: "proposal-cutoff", stage: "check-proposal", built: true,
        rule: "No distrust cutoff of epoch N is lifted or moved later." },
    Check { id: "proposal-revocations-kept", stage: "check-proposal", built: true,
        rule: "Every delegate revoked in epoch N is still revoked." },
    Check { id: "proposal-rederive", stage: "check-proposal", built: true,
        rule: "The new directory is exactly what epoch N and the listed requests produce, re-derived from those alone." },
    Check { id: "proposal-diff", stage: "check-proposal", built: true,
        rule: "The human-readable diff, with the request each line cites, is exactly the re-derived one." },
    Check { id: "proposal-digest", stage: "check-proposal", built: true,
        rule: "`signing_bytes_sha256` is the SHA-256 of the re-derived directory's signing bytes: the exact message the custodians sign." },
    // ── signing: `ainra directory assemble` (R6) ──
    Check { id: "assemble-both-roots", stage: "assemble", built: true,
        rule: "Both root signatures — the FROST 5-of-9 Ed25519 aggregate and the SLH-DSA signature — verify over the proposal's signing bytes under the pinned roots; one alone is refused." },
    // ── publication: `ainra directory publish` (R7–R8) ──
    Check { id: "publish-both-roots", stage: "publish", built: true,
        rule: "The directory verifies under both pinned roots; a directory with one root's signature is refused." },
    Check { id: "publish-next-epoch", stage: "publish", built: true,
        rule: "Its epoch is exactly the archive's last epoch + 1, and the proposal was drafted on that last archived epoch (same digest)." },
    Check { id: "publish-approved", stage: "publish", built: true,
        rule: "The directory is the approved proposal: same epoch, and the SHA-256 of its signing bytes equals the proposal's." },
    Check { id: "publish-transcript", stage: "publish", built: true,
        rule: "The ceremony transcript names that proposal (its digest), that directory (its signing-bytes SHA-256 and epoch) and both of its signatures, lists at least five distinct signers, and — when its published SHA-256 is given — hashes to it." },
];

/// A refusal: the check that refused, and why, in words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub check: &'static str,
    pub reason: String,
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[{}] {}", self.check, self.reason)
    }
}

fn refusal(check: &'static str, reason: impl Into<String>) -> Refusal {
    // A refusal names a check in the published list, or it is a bug: the document would not say why.
    debug_assert!(
        CHECKS.iter().any(|c| c.id == check),
        "refusal names a check that is not in CHECKS: {check}"
    );
    Refusal {
        check,
        reason: reason.into(),
    }
}

fn refuse<T>(check: &'static str, reason: impl Into<String>) -> Result<T, Refusal> {
    Err(refusal(check, reason))
}

/// The generated document (`docs/ACCREDITATION-CHECKS.md`), from [`CHECKS`] alone.
pub fn checks_markdown() -> String {
    let mut s = String::new();
    s.push_str("<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->\n");
    s.push_str("<!-- GENERATED by `ainra directory check-request --list-checks` from crates/ainra-adapter/src/workbench.rs. Do not edit: change the code, then run `node tools/accreditation-checks.mjs --write`. `make accreditation-checks` fails when this file and the code disagree. -->\n");
    s.push_str("# Accreditation and directory-change checks\n\n");
    s.push_str("Every check the directory workbench runs before a change can reach the root's ceremony (PLAN-M52 R0–R7), in the\n");
    s.push_str("order each command runs them. A refusal names its check by the id in the first column, so a filer can reproduce\n");
    s.push_str("it from the published inputs. Nothing here signs anything: the workbench reads, proposes and checks, and only\n");
    s.push_str("five FROST shares and the SLH-DSA root, offline, make a proposal the directory. Rows marked *not built* are\n");
    s.push_str("named so that their absence is visible, not implied.\n");
    let stages = [
        (
            "check-request",
            "Change requests — `ainra directory check-request`",
        ),
        (
            "check-proposal",
            "Proposals — `ainra directory propose` and `ainra directory check-proposal`",
        ),
        ("assemble", "Signing — `ainra directory assemble`"),
        ("publish", "Publication — `ainra directory publish`"),
    ];
    for (stage, title) in stages {
        s.push_str(&format!(
            "\n## {title}\n\n| Check | Built | Rule |\n| --- | --- | --- |\n"
        ));
        for c in CHECKS.iter().filter(|c| c.stage == stage) {
            s.push_str(&format!(
                "| `{}` | {} | {} |\n",
                c.id,
                if c.built { "yes" } else { "*not built*" },
                c.rule
            ));
        }
    }
    s
}

// ── the request format (v1) ──────────────────────────────────────────────────────────────────────────────────────

/// A directory change request (R0). `proofs` is not part of what is signed: the digest is the SHA-256 of the
/// canonical JSON of everything else, and every proof is a signature over [`request_message`] of that digest.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeRequest {
    pub version: u64,
    pub kind: String,
    #[serde(rename = "type")]
    pub change_type: String,
    /// The registrar whose entry the request concerns.
    pub registrar: String,
    /// Who files it. A request is a self-request when the filer is the registrar.
    pub filer: String,
    /// When it was filed (unix seconds).
    pub filed_at: u64,
    #[serde(default)]
    pub test_root: bool,
    #[serde(default)]
    pub change: Change,
    #[serde(default)]
    pub evidence: Evidence,
    #[serde(default, skip_serializing_if = "Proofs::is_empty")]
    pub proofs: Proofs,
}

/// What changes. ACCREDIT carries `entry`, DISTRUST_FROM_LEAF `leaf`, REVOKE_DELEGATE `cert`.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<DirectoryEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaf: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<WireDelegateCert>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prerequisites: Option<Prerequisites>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<Compliance>,
}

/// Standard §3: what a new registrar brings, each as a named file and its SHA-256 (the files stay with the filer and
/// the steward; the request carries their digests).
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prerequisites {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agreement: Option<Artifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub independence_attestation: Option<Artifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub competitor_monitor: Option<Artifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<Artifact>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub file: String,
    pub sha256: String,
    /// The audit's date (YYYY-MM-DD); the other artifacts carry none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
}

/// The record an adverse request cites (R0; step 11 builds the monitor that writes it).
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Compliance {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notices: Vec<Notice>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cure_window_ends: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reproductions: Vec<Reproduction>,
    /// PLAN-M53 step 1 (D-098): self-verifying evidence that the registrar's log forked — two checkpoints of its log,
    /// signed under the key the directory lists, at one size with different roots. With it, an adverse
    /// DISTRUST_FROM_LEAF skips the compliance ladder: there is nothing to cure in a forked log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_proof: Option<ForkProof>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// Two signed checkpoints of one registrar log that cannot both be true.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkProof {
    pub a: SignedCheckpoint,
    pub b: SignedCheckpoint,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCheckpoint {
    pub checkpoint: crate::WireCheckpoint,
    pub checkpoint_sig: crate::WireCheckpointSig,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notice {
    pub n: u64,
    pub at: u64,
    pub sha256: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reproduction {
    pub vantage: String,
    pub network: String,
    pub at: u64,
    pub report_sha256: String,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proofs {
    /// A self-request: the registrar's current issuer key over the message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filer: Option<WireSig>,
    /// An ACCREDIT: each new key over the message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub possession: Option<Possession>,
}

impl Proofs {
    fn is_empty(&self) -> bool {
        self.filer.is_none() && self.possession.is_none()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Possession {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<WireSig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<WireSig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_root_slh: Option<String>,
}

fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn is_registrar_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// Parse a request; anything outside the format is `request-shape`.
pub fn parse_request(json: &str) -> Result<ChangeRequest, Refusal> {
    serde_json::from_str::<ChangeRequest>(json)
        .map_err(|e| refusal("request-shape", format!("not a v1 change request: {e}")))
}

/// The request's digest (hex): SHA-256 of its canonical JSON without `proofs`.
pub fn request_digest(r: &ChangeRequest) -> Result<String, Refusal> {
    let mut v = serde_json::to_value(r)
        .map_err(|e| refusal("request-shape", format!("does not serialize: {e}")))?;
    if let Some(o) = v.as_object_mut() {
        o.remove("proofs");
    }
    let c = canon::canonicalize_value(&v)
        .map_err(|e| refusal("request-shape", format!("does not canonicalize: {e}")))?;
    Ok(sha256_hex(c.as_bytes()))
}

/// What every key signs for a request with digest `digest_hex`.
pub fn request_message(digest_hex: &str) -> String {
    format!("{REQUEST_MESSAGE_PREFIX}{digest_hex}")
}

/// The digest and message of a request given as JSON (for the filer's signing tool).
pub fn request_digest_json(json: &str) -> Result<(String, String), Refusal> {
    let r = parse_request(json)?;
    let d = request_digest(&r)?;
    let m = request_message(&d);
    Ok((d, m))
}

fn roots_of(roots_json: &str) -> Option<([u8; 32], Vec<u8>)> {
    let v: Value = serde_json::from_str(roots_json).ok()?;
    let ed = b64::decode_array::<32>(v["root_ed25519"].as_str()?).ok()?;
    let slh = b64::decode(v["root_slh"].as_str()?).ok()?;
    Some((ed, slh))
}

/// Parse a directory and require it to verify under both roots; `check` names the refusal if it does not.
pub fn authentic_directory(
    directory_json: &str,
    roots_json: &str,
    check: &'static str,
) -> Result<Directory, Refusal> {
    let d = serde_json::from_str::<Directory>(directory_json)
        .map_err(|e| refusal(check, format!("not a directory: {e}")))?;
    let (ed, slh) = roots_of(roots_json).ok_or_else(|| {
        refusal(
            check,
            "the roots file does not name root_ed25519 and root_slh",
        )
    })?;
    d.accredit(&ed, &slh).map_err(|_| {
        refusal(
            check,
            format!(
                "epoch {} does not verify under both roots (FROST Ed25519 + SLH-DSA)",
                d.epoch
            ),
        )
    })?;
    Ok(d)
}

fn hybrid_public(ed: &str, ml: &str) -> Option<crypto::HybridPublic> {
    Some(crypto::HybridPublic {
        ed25519: b64::decode_array::<32>(ed).ok()?,
        mldsa65: b64::decode(ml).ok()?,
    })
}

fn hybrid_sig(s: &WireSig) -> Option<crypto::HybridSig> {
    Some(crypto::HybridSig {
        ed25519: b64::decode(&s.ed25519).ok()?,
        mldsa65: b64::decode(&s.mldsa65).ok()?,
    })
}

fn verify_hybrid_b64(ed: &str, ml: &str, msg: &[u8], sig: &WireSig) -> bool {
    match (hybrid_public(ed, ml), hybrid_sig(sig)) {
        (Some(pk), Some(s)) => crypto::verify_hybrid(&pk, msg, &s).is_ok(),
        _ => false,
    }
}

fn cert_of(w: &WireDelegateCert) -> Option<checkpoint::DelegateCert> {
    Some(checkpoint::DelegateCert {
        delegate_ed25519: b64::decode_array::<32>(&w.delegate_ed25519).ok()?,
        scopes: w.scopes.clone(),
        nbf: w.nbf,
        exp: w.exp,
        sig_slh: b64::decode(&w.sig_slh).ok()?,
    })
}

/// The fields in which two entries of one registrar differ.
fn changed_fields(a: &DirectoryEntry, b: &DirectoryEntry) -> Vec<&'static str> {
    let mut f = Vec::new();
    if a.issuer_ed25519 != b.issuer_ed25519 {
        f.push("issuer_ed25519");
    }
    if a.issuer_mldsa65 != b.issuer_mldsa65 {
        f.push("issuer_mldsa65");
    }
    if a.log_root_slh != b.log_root_slh {
        f.push("log_root_slh");
    }
    if a.status_ed25519 != b.status_ed25519 {
        f.push("status_ed25519");
    }
    if a.status_mldsa65 != b.status_mldsa65 {
        f.push("status_mldsa65");
    }
    if a.status_uri != b.status_uri {
        f.push("status_uri");
    }
    if a.distrust_from_leaf != b.distrust_from_leaf {
        f.push("distrust_from_leaf");
    }
    f
}

/// A request that passed every check.
#[derive(Debug, Clone)]
pub struct Accepted {
    pub digest: String,
    pub change_type: String,
    pub registrar: String,
    pub passed: Vec<&'static str>,
}

/// Check one request against the current directory (`None` for the first epoch), and, if given, a copy of the
/// registrar's served `/accreditation`. The caller has already authenticated `base` (`request-base`).
pub fn check_request(
    r: &ChangeRequest,
    base: Option<&Directory>,
    accreditation: Option<&Value>,
) -> Result<Accepted, Refusal> {
    let mut passed = Vec::new();
    let t = r.change_type.as_str();

    // request-shape — what serde cannot say.
    if r.version != 1 || r.kind != REQUEST_KIND {
        return refuse(
            "request-shape",
            format!(
                "version {} of {:?}; this is v1 of {REQUEST_KIND}",
                r.version, r.kind
            ),
        );
    }
    if !TYPES.contains(&t) {
        return refuse(
            "request-shape",
            format!("unknown type {t:?}; the types are {}", TYPES.join(", ")),
        );
    }
    let allowed = match t {
        "ACCREDIT" => (true, false, false),
        "DISTRUST_FROM_LEAF" => (false, true, false),
        "REVOKE_DELEGATE" => (false, false, true),
        _ => (false, false, false),
    };
    let present = (
        r.change.entry.is_some(),
        r.change.leaf.is_some(),
        r.change.cert.is_some(),
    );
    if (present.0 && !allowed.0) || (present.1 && !allowed.1) || (present.2 && !allowed.2) {
        return refuse(
            "request-shape",
            format!(
                "{t} carries a change field another type uses (entry is ACCREDIT's, leaf DISTRUST_FROM_LEAF's, cert REVOKE_DELEGATE's)"
            ),
        );
    }
    let digest = request_digest(r)?;
    let msg = request_message(&digest);
    passed.push("request-shape");

    if t == "ROOT_KEY_ROLL" {
        return refuse(
            "root-key-roll",
            "ROOT_KEY_ROLL runs on its own track (PLAN-M52 step 9), not built",
        );
    }
    if !is_registrar_id(&r.registrar) || r.filer.trim().is_empty() {
        return refuse(
            "request-subject",
            format!(
                "registrar {:?} is not a registrar id, or the filer is empty",
                r.registrar
            ),
        );
    }
    passed.push("request-subject");
    passed.push("request-base");
    if t == "REGISTRAR_KEY_ROLL" {
        return refuse(
            "moves-trust",
            format!(
                "REGISTRAR_KEY_ROLL for {} moves trust: it needs a declared offline approver set (D-088 R0; an ADR and a schema change, not built)",
                r.registrar
            ),
        );
    }

    let epoch = base.map(|d| d.epoch).unwrap_or(0);
    let current = base.and_then(|d| d.entries.iter().find(|e| e.registrar == r.registrar));
    let self_filed = r.filer == r.registrar;

    if t == "ACCREDIT" {
        let Some(entry) = r.change.entry.as_ref() else {
            return refuse("entry-shape", "ACCREDIT carries no change.entry");
        };
        if let Some(cur) = current {
            let fields = changed_fields(cur, entry);
            if fields.is_empty() {
                return refuse(
                    "subject-in-directory",
                    format!(
                        "{} is already accredited in epoch {epoch} with exactly this entry; nothing would change",
                        r.registrar
                    ),
                );
            }
            return refuse(
                "moves-trust",
                format!(
                    "ACCREDIT of {}, already accredited in epoch {epoch}, changes {}: a key or endpoint change moves trust and needs a declared offline approver set (D-088 R0; an ADR and a schema change, not built)",
                    r.registrar,
                    fields.join(", ")
                ),
            );
        }
        passed.push("moves-trust");
        passed.push("subject-in-directory");

        // entry-shape
        let sizes_ok = entry.registrar == r.registrar
            && b64::decode_array::<32>(&entry.issuer_ed25519).is_ok()
            && b64::decode(&entry.issuer_mldsa65).is_ok_and(|v| v.len() == crypto::MLDSA65_PK)
            && b64::decode(&entry.log_root_slh).is_ok_and(|v| v.len() == crypto::SLHDSA128S_PK)
            && b64::decode_array::<32>(&entry.status_ed25519).is_ok()
            && b64::decode(&entry.status_mldsa65).is_ok_and(|v| v.len() == crypto::MLDSA65_PK)
            && !entry.status_uri.is_empty()
            && entry.distrust_from_leaf.is_none();
        if !sizes_ok {
            return refuse(
                "entry-shape",
                format!(
                    "the entry is not a well-formed new entry for {}: it must name this registrar, carry every key at its exact size, status keys and a status URI, and no distrust cutoff",
                    r.registrar
                ),
            );
        }
        passed.push("entry-shape");

        // proof-of-possession: each NEW key, over the request message.
        let p = r.proofs.possession.clone().unwrap_or_default();
        let m = msg.as_bytes();
        let mut missing = Vec::new();
        if !p
            .issuer
            .as_ref()
            .is_some_and(|s| verify_hybrid_b64(&entry.issuer_ed25519, &entry.issuer_mldsa65, m, s))
        {
            missing.push("the issuer key (hybrid)");
        }
        if !p
            .status
            .as_ref()
            .is_some_and(|s| verify_hybrid_b64(&entry.status_ed25519, &entry.status_mldsa65, m, s))
        {
            missing.push("the status key (hybrid)");
        }
        let log_root = b64::decode(&entry.log_root_slh).unwrap_or_default();
        if !p
            .log_root_slh
            .as_deref()
            .is_some_and(|s| b64::decode(s).is_ok_and(|sig| crypto::slh_verify(&log_root, m, &sig)))
        {
            missing.push("the log root (SLH-DSA)");
        }
        if !missing.is_empty() {
            return refuse(
                "proof-of-possession",
                format!(
                    "no valid proof of possession over this request's digest by {}",
                    missing.join(", ")
                ),
            );
        }
        passed.push("proof-of-possession");

        if let Some(a) = accreditation {
            let pairs = [
                (
                    "registrar",
                    a["registrar"].as_str(),
                    entry.registrar.as_str(),
                ),
                (
                    "issuer_ed25519",
                    a["issuer_key"]["ed25519"].as_str(),
                    entry.issuer_ed25519.as_str(),
                ),
                (
                    "issuer_mldsa65",
                    a["issuer_key"]["mldsa65"].as_str(),
                    entry.issuer_mldsa65.as_str(),
                ),
                (
                    "log_root_slh",
                    a["log_root_key"].as_str(),
                    entry.log_root_slh.as_str(),
                ),
                (
                    "status_ed25519",
                    a["status_key"]["ed25519"].as_str(),
                    entry.status_ed25519.as_str(),
                ),
                (
                    "status_mldsa65",
                    a["status_key"]["mldsa65"].as_str(),
                    entry.status_mldsa65.as_str(),
                ),
                (
                    "status_uri",
                    a["status_uri"].as_str(),
                    entry.status_uri.as_str(),
                ),
            ];
            let differ: Vec<&str> = pairs
                .iter()
                .filter(|(_, served, asked)| *served != Some(*asked))
                .map(|(f, _, _)| *f)
                .collect();
            if !differ.is_empty() {
                return refuse(
                    "accreditation-match",
                    format!(
                        "the entry differs from the registrar's served /accreditation in {}",
                        differ.join(", ")
                    ),
                );
            }
            passed.push("accreditation-match");
        }

        let pre = r.evidence.prerequisites.clone().unwrap_or_default();
        let named = |a: &Option<Artifact>| {
            a.as_ref()
                .is_some_and(|a| !a.file.trim().is_empty() && is_hex64(&a.sha256))
        };
        let mut lacking = Vec::new();
        if !named(&pre.agreement) {
            lacking.push("the signed identical agreement");
        }
        if !named(&pre.independence_attestation) {
            lacking.push("the independence attestation");
        }
        if !named(&pre.competitor_monitor) {
            lacking.push("the funded competitor monitor");
        }
        let audit_dated = pre
            .audit
            .as_ref()
            .and_then(|a| a.date.as_deref())
            .is_some_and(|d| {
                d.len() == 10
                    && d.bytes().enumerate().all(|(i, c)| {
                        if i == 4 || i == 7 {
                            c == b'-'
                        } else {
                            c.is_ascii_digit()
                        }
                    })
            });
        if !named(&pre.audit) || !audit_dated {
            lacking.push("the audit with its date");
        }
        if !lacking.is_empty() {
            return refuse(
                "prerequisites",
                format!(
                    "ACCREDIT of a new registrar lacks the Standard §3 prerequisite(s), each as a named file and its SHA-256: {}",
                    lacking.join(", ")
                ),
            );
        }
        passed.push("prerequisites");
        if !LEGAL_ENTITY_EXISTS && !r.test_root {
            return refuse(
                "test-root-only",
                "no legal entity exists yet, so a registrar is accredited only under TEST-ROOT: the request must say test_root: true (PLAN-M52 R0)",
            );
        }
        passed.push("test-root-only");
    } else {
        // WITHDRAW, DISTRUST_FROM_LEAF, REVOKE_DELEGATE — they close something about an existing entry.
        let Some(cur) = current else {
            return refuse(
                "subject-in-directory",
                format!(
                    "{} is not in the current directory (epoch {epoch}); {t} needs an existing entry",
                    r.registrar
                ),
            );
        };
        passed.push("moves-trust");
        passed.push("subject-in-directory");
        if t == "REVOKE_DELEGATE" {
            if !self_filed {
                return refuse(
                    "delegate-owned",
                    format!(
                        "REVOKE_DELEGATE is filed only by the registrar whose delegate it is; {:?} is not {}",
                        r.filer, r.registrar
                    ),
                );
            }
            let Some(cert) = r.change.cert.as_ref().and_then(cert_of) else {
                return refuse(
                    "delegate-owned",
                    "REVOKE_DELEGATE carries no decodable delegate certificate (change.cert)",
                );
            };
            let log_root = b64::decode(&cur.log_root_slh).unwrap_or_default();
            let signed = cert
                .signing_bytes()
                .is_ok_and(|m| crypto::slh_verify(&log_root, &m, &cert.sig_slh));
            if !signed {
                return refuse(
                    "delegate-owned",
                    format!(
                        "the delegate certificate is not signed by {}'s log root as epoch {epoch} lists it",
                        r.registrar
                    ),
                );
            }
            let fp = b64::encode(&cert.fingerprint());
            if base.is_some_and(|d| d.revoked_delegates.contains(&fp)) {
                return refuse(
                    "delegate-owned",
                    format!("delegate {fp} is already revoked in epoch {epoch}"),
                );
            }
            passed.push("delegate-owned");
        }
        if t == "DISTRUST_FROM_LEAF" {
            let Some(leaf) = r.change.leaf else {
                return refuse("request-shape", "DISTRUST_FROM_LEAF carries no change.leaf");
            };
            if let Some(old) = cur.distrust_from_leaf {
                if leaf >= old {
                    return refuse(
                        "cutoff-monotone",
                        format!(
                            "{} is already distrusted from leaf {old}; a cutoff is never lifted or moved later (asked: leaf {leaf})",
                            r.registrar
                        ),
                    );
                }
            }
            passed.push("cutoff-monotone");
        }
        if self_filed {
            let ok = r.proofs.filer.as_ref().is_some_and(|s| {
                verify_hybrid_b64(&cur.issuer_ed25519, &cur.issuer_mldsa65, msg.as_bytes(), s)
            });
            if !ok {
                return refuse(
                    "self-signature",
                    format!(
                        "{t} filed by {} about itself is not signed by its CURRENT issuer key in epoch {epoch} (hybrid, over this request's digest)",
                        r.registrar
                    ),
                );
            }
            passed.push("self-signature");
        } else {
            // An adverse request: the compliance record carries it, not a key.
            let Some(c) = r.evidence.compliance.as_ref() else {
                return refuse(
                    "adverse-notice-chain",
                    format!(
                        "an adverse {t} against {}, filed by {:?}, carries no compliance record (notice chain, cure window, reproductions)",
                        r.registrar, r.filer
                    ),
                );
            };
            if let Some(fp) = c.fork_proof.as_ref() {
                if t != "DISTRUST_FROM_LEAF" {
                    return refuse(
                        "adverse-proof",
                        format!("a fork proof stops issuance (DISTRUST_FROM_LEAF); a {t} still waits for the ladder and the holders' grace"),
                    );
                }
                let origin = format!("ainra-log/{}", r.registrar);
                let log_root = b64::decode(&cur.log_root_slh).unwrap_or_default();
                let revoked = |w: &crate::WireCheckpointSig| {
                    w.cert.as_ref().is_some_and(|c| {
                        base.is_some_and(|d| {
                            b64::decode(&c.delegate_ed25519).is_ok_and(|pk| {
                                let cert = ainra_core::checkpoint::DelegateCert {
                                    delegate_ed25519: pk.as_slice().try_into().unwrap_or([0; 32]),
                                    scopes: c.scopes.clone(),
                                    nbf: c.nbf,
                                    exp: c.exp,
                                    sig_slh: b64::decode(&c.sig_slh).unwrap_or_default(),
                                };
                                d.revoked_delegates
                                    .contains(&b64::encode(&cert.fingerprint()))
                            })
                        })
                    })
                };
                let mut parsed = Vec::new();
                for (label, sc) in [("a", &fp.a), ("b", &fp.b)] {
                    let cp = &sc.checkpoint;
                    if cp.origin != origin {
                        return refuse(
                            "adverse-proof",
                            format!("checkpoint {label} is of log {:?}, not {origin}", cp.origin),
                        );
                    }
                    let Ok(root) = crate::decode32(&cp.root) else {
                        return refuse(
                            "adverse-proof",
                            format!("checkpoint {label} has no 32-byte root"),
                        );
                    };
                    let Ok(sig) = crate::decode_cp_sig(&sc.checkpoint_sig) else {
                        return refuse(
                            "adverse-proof",
                            format!("checkpoint {label}'s signature is not in a known mode"),
                        );
                    };
                    if revoked(&sc.checkpoint_sig) {
                        return refuse("adverse-proof", format!("checkpoint {label} is signed by a delegate epoch {epoch} already revoked — the registrar disowned that key"));
                    }
                    // a delegate signature is judged inside its own certificate's window; a root signature has none
                    let at = sc.checkpoint_sig.cert.as_ref().map(|c| c.nbf).unwrap_or(0);
                    let c = ainra_core::checkpoint::Checkpoint {
                        origin: cp.origin.clone(),
                        tree_size: cp.size,
                        root,
                    };
                    if c.verify_sig_mode(&log_root, &sig, at).is_err() {
                        return refuse("adverse-proof", format!("checkpoint {label} does not verify under {}'s log root as epoch {epoch} lists it", r.registrar));
                    }
                    parsed.push(c);
                }
                if parsed[0].tree_size != parsed[1].tree_size || parsed[0].root == parsed[1].root {
                    return refuse(
                        "adverse-proof",
                        format!(
                            "the two checkpoints (sizes {} and {}) are not a fork: a fork is one size with two roots",
                            parsed[0].tree_size, parsed[1].tree_size
                        ),
                    );
                }
                let n = parsed[0].tree_size;
                if r.change.leaf.is_none_or(|l| l > n) {
                    return refuse(
                        "adverse-proof",
                        format!(
                            "the cutoff must be at or below the fork's size {n} (asked: {:?})",
                            r.change.leaf
                        ),
                    );
                }
                passed.push("adverse-proof");
                return Ok(Accepted {
                    digest,
                    change_type: t.to_string(),
                    registrar: r.registrar.clone(),
                    passed,
                });
            }
            if c.notices.len() < 2 {
                return refuse(
                    "adverse-notice-chain",
                    format!(
                        "the compliance record lists {} notice(s); the ladder sends notice 1 and notice 2 before any adverse request",
                        c.notices.len()
                    ),
                );
            }
            let mut last = 0u64;
            for (i, n) in c.notices.iter().enumerate() {
                if n.n != i as u64 + 1 || n.at <= last || !is_hex64(&n.sha256) || n.at > r.filed_at
                {
                    return refuse(
                        "adverse-notice-chain",
                        format!(
                            "notice {} breaks the chain: notices are numbered 1, 2, … in time order, each named by a SHA-256, none after the filing",
                            i + 1
                        ),
                    );
                }
                if i > 0 && n.at - last < NOTICE_GAP_MIN_SECS {
                    return refuse(
                        "adverse-notice-chain",
                        format!(
                            "notice {} came {} day(s) after notice {}; notices are at least 14 days apart",
                            i + 1,
                            (n.at - last) / 86_400,
                            i
                        ),
                    );
                }
                last = n.at;
            }
            if c.cure_window_ends < c.notices[0].at + CURE_MIN_SECS {
                return refuse(
                    "adverse-notice-chain",
                    format!(
                        "the cure window ends {} day(s) after notice 1; it runs at least 30 days",
                        c.cure_window_ends.saturating_sub(c.notices[0].at) / 86_400
                    ),
                );
            }
            if c.cure_window_ends <= c.notices[0].at || c.cure_window_ends >= r.filed_at {
                return refuse(
                    "adverse-notice-chain",
                    format!(
                        "the cure window ends at {}, which must be after the first notice ({}) and before the request was filed ({})",
                        c.cure_window_ends, c.notices[0].at, r.filed_at
                    ),
                );
            }
            passed.push("adverse-notice-chain");
            for (i, rep) in c.reproductions.iter().enumerate() {
                if rep.vantage.trim().is_empty()
                    || rep.network.trim().is_empty()
                    || !is_hex64(&rep.report_sha256)
                    || rep.at <= c.cure_window_ends
                    || rep.at > r.filed_at
                {
                    return refuse(
                        "adverse-vantage",
                        format!(
                            "reproduction {} does not count: it needs a vantage point, a network, a report SHA-256, and a time after the cure window ended and no later than the filing",
                            i + 1
                        ),
                    );
                }
            }
            let vantages: BTreeSet<&str> =
                c.reproductions.iter().map(|x| x.vantage.as_str()).collect();
            let networks: BTreeSet<&str> =
                c.reproductions.iter().map(|x| x.network.as_str()).collect();
            if vantages.len() < 2 || networks.len() < 2 {
                return refuse(
                    "adverse-vantage",
                    format!(
                        "reproduced from {} vantage point(s) on {} distinct network(s); at least two vantage points on distinct networks are needed",
                        vantages.len(),
                        networks.len()
                    ),
                );
            }
            passed.push("adverse-vantage");
            if t == "WITHDRAW" {
                let breach = c.notices.iter().rev().find(|n| n.n >= 3);
                if cur.distrust_from_leaf.is_none() {
                    return refuse(
                        "adverse-grace",
                        format!(
                            "an adverse WITHDRAW of {} comes after distrust, and epoch {epoch} carries no distrust cutoff for it",
                            r.registrar
                        ),
                    );
                }
                let Some(b) = breach else {
                    return refuse(
                        "adverse-grace",
                        "an adverse WITHDRAW names the public breach record (notice 3 or later), and this record has none",
                    );
                };
                if r.filed_at < b.at + HOLDER_GRACE_SECS {
                    return refuse(
                        "adverse-grace",
                        format!(
                            "filed {} day(s) after the breach record; holders get at least 90 days to move first",
                            (r.filed_at - b.at) / 86_400
                        ),
                    );
                }
                passed.push("adverse-grace");
            }
        }
    }
    Ok(Accepted {
        digest,
        change_type: t.to_string(),
        registrar: r.registrar.clone(),
        passed,
    })
}

/// [`check_request`] from JSON: the request, the current directory and roots (both or neither), and optionally a copy
/// of the registrar's `/accreditation`.
pub fn check_request_json(
    request_json: &str,
    directory_and_roots: Option<(&str, &str)>,
    accreditation_json: Option<&str>,
) -> Result<Accepted, Refusal> {
    let r = parse_request(request_json)?;
    let base = match directory_and_roots {
        Some((d, roots)) => Some(authentic_directory(d, roots, "request-base")?),
        None => None,
    };
    let acc = match accreditation_json {
        Some(a) => Some(serde_json::from_str::<Value>(a).map_err(|e| {
            refusal(
                "accreditation-match",
                format!("the /accreditation copy is not JSON: {e}"),
            )
        })?),
        None => None,
    };
    check_request(&r, base.as_ref(), acc.as_ref())
}

// ── proposals (step 6) ───────────────────────────────────────────────────────────────────────────────────────────

/// One line of the human-readable diff, citing the request that causes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiffLine {
    pub change: String,
    pub request: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalRequest {
    pub digest: String,
    pub request: ChangeRequest,
}

/// An UNSIGNED epoch N+1: what the custodians are asked to sign, and everything needed to re-derive it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub version: u64,
    pub kind: String,
    /// Says, in words, that this is not a directory.
    pub note: String,
    /// Epoch N (0 for the first epoch).
    pub base_epoch: u64,
    /// SHA-256 of epoch N's signing bytes; absent for the first epoch.
    #[serde(default)]
    pub base_digest: Option<String>,
    pub epoch: u64,
    pub requests: Vec<ProposalRequest>,
    /// The new directory, unsigned. Kept as JSON here so a field outside the frozen schema is refused by name.
    pub directory: Value,
    pub diff: Vec<DiffLine>,
    pub signing_bytes_sha256: String,
}

fn digest_of(d: &Directory) -> Result<(Vec<u8>, String), Refusal> {
    let b = d
        .signing_bytes()
        .map_err(|e| refusal("proposal-schema", format!("does not canonicalize: {e}")))?;
    let h = sha256_hex(&b);
    Ok((b, h))
}

/// Apply requests (already checked against `base`) to epoch N: the new unsigned directory and its diff.
fn apply(
    base: Option<&Directory>,
    reqs: &[ProposalRequest],
    issued_at: u64,
) -> Result<(Directory, Vec<DiffLine>), Refusal> {
    let mut entries: Vec<DirectoryEntry> = base.map(|d| d.entries.clone()).unwrap_or_default();
    let mut revoked: Vec<String> = base
        .map(|d| d.revoked_delegates.clone())
        .unwrap_or_default();
    let mut diff = Vec::new();
    for pr in reqs {
        let r = &pr.request;
        let id = r.registrar.clone();
        let line = |change: String| DiffLine {
            change,
            request: pr.digest.clone(),
        };
        match r.change_type.as_str() {
            "ACCREDIT" => {
                let e =
                    r.change.entry.clone().ok_or_else(|| {
                        refusal("proposal-requests", "an ACCREDIT without an entry")
                    })?;
                entries.push(e);
                diff.push(line(format!("+ accredit {id}")));
            }
            "WITHDRAW" => {
                entries.retain(|e| e.registrar != id);
                diff.push(line(format!("- withdraw {id}")));
            }
            "DISTRUST_FROM_LEAF" => {
                let leaf = r.change.leaf.unwrap_or(0);
                for e in entries.iter_mut().filter(|e| e.registrar == id) {
                    let was = e
                        .distrust_from_leaf
                        .map(|n| format!("leaf {n}"))
                        .unwrap_or_else(|| "none".into());
                    e.distrust_from_leaf = Some(leaf);
                    diff.push(line(format!(
                        "~ distrust {id} from leaf {leaf} (was {was})"
                    )));
                }
            }
            "REVOKE_DELEGATE" => {
                let cert = r.change.cert.as_ref().and_then(cert_of).ok_or_else(|| {
                    refusal(
                        "proposal-requests",
                        "a REVOKE_DELEGATE without a certificate",
                    )
                })?;
                let fp = b64::encode(&cert.fingerprint());
                revoked.push(fp.clone());
                diff.push(line(format!("+ revoke delegate {fp} of {id}")));
            }
            other => {
                return refuse(
                    "proposal-requests",
                    format!("{other} cannot be applied to a directory"),
                )
            }
        }
    }
    entries.sort_by(|a, b| a.registrar.cmp(&b.registrar));
    let d = Directory {
        epoch: base.map(|d| d.epoch).unwrap_or(0) + 1,
        issued_at,
        entries,
        revoked_delegates: revoked,
        sig_root_ed25519: String::new(),
        sig_root_slh: String::new(),
    };
    Ok((d, diff))
}

/// Check every request against `base`, refuse duplicates and conflicting requests about one registrar.
fn checked_requests(
    base: Option<&Directory>,
    reqs: &[ProposalRequest],
    accreditations: &[Value],
) -> Result<(), Refusal> {
    let mut digests = BTreeSet::new();
    let mut by_registrar: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
    for pr in reqs {
        let real =
            request_digest(&pr.request).map_err(|e| refusal("proposal-requests", e.reason))?;
        if real != pr.digest {
            return refuse(
                "proposal-requests",
                format!(
                    "a request is listed as {} but its digest is {real}",
                    pr.digest
                ),
            );
        }
        if !digests.insert(real.clone()) {
            return refuse(
                "proposal-requests",
                format!("request {real} is listed twice"),
            );
        }
        let acc = accreditations
            .iter()
            .find(|a| a["registrar"].as_str() == Some(pr.request.registrar.as_str()));
        check_request(&pr.request, base, acc).map_err(|e| {
            refusal(
                "proposal-requests",
                format!("request {}… fails against epoch N: {e}", &real[..16]),
            )
        })?;
        by_registrar
            .entry(pr.request.registrar.as_str())
            .or_default()
            .push(pr.request.change_type.as_str());
    }
    for (id, types) in by_registrar {
        if types.len() > 1 && types.iter().any(|t| *t != "REVOKE_DELEGATE") {
            return refuse(
                "proposal-requests",
                format!(
                    "{id} has {} requests in one proposal ({}); only several REVOKE_DELEGATE may share an epoch",
                    types.len(),
                    types.join(", ")
                ),
            );
        }
    }
    Ok(())
}

/// Draft epoch N+1 from epoch N (`None` for the first epoch) and requests. Refuses anything [`check_proposal`] would.
pub fn propose(
    base: Option<&Directory>,
    requests: Vec<ChangeRequest>,
    issued_at: u64,
    accreditations: &[Value],
) -> Result<Proposal, Refusal> {
    if requests.is_empty() {
        return refuse(
            "proposal-requests",
            "a proposal applies at least one request",
        );
    }
    let mut reqs = Vec::new();
    for r in requests {
        let digest = request_digest(&r)?;
        reqs.push(ProposalRequest { digest, request: r });
    }
    checked_requests(base, &reqs, accreditations)?;
    if let Some(b) = base {
        if issued_at <= b.issued_at {
            return refuse(
                "proposal-issued-at",
                format!(
                    "issued_at {issued_at} is not later than epoch {}'s {}",
                    b.epoch, b.issued_at
                ),
            );
        }
    }
    let (dir, diff) = apply(base, &reqs, issued_at)?;
    let (_, h) = digest_of(&dir)?;
    let base_digest = match base {
        Some(b) => Some(digest_of(b)?.1),
        None => None,
    };
    Ok(Proposal {
        version: 1,
        kind: PROPOSAL_KIND.into(),
        note: format!(
            "UNSIGNED: a proposal for epoch {}. It is not a directory until both roots sign its signing bytes in a ceremony (PLAN-M52 R6).",
            dir.epoch
        ),
        base_epoch: base.map(|b| b.epoch).unwrap_or(0),
        base_digest,
        epoch: dir.epoch,
        requests: reqs,
        directory: serde_json::to_value(&dir).map_err(|e| refusal("proposal-schema", e.to_string()))?,
        diff,
        signing_bytes_sha256: h,
    })
}

/// [`propose`] from JSON.
pub fn propose_json(
    base: Option<(&str, &str)>,
    requests: &[String],
    issued_at: u64,
    accreditations: &[String],
) -> Result<Proposal, Refusal> {
    let b = match base {
        Some((d, roots)) => Some(authentic_directory(d, roots, "proposal-base")?),
        None => None,
    };
    let mut reqs = Vec::new();
    for r in requests {
        reqs.push(parse_request(r)?);
    }
    let accs: Vec<Value> = accreditations
        .iter()
        .filter_map(|a| serde_json::from_str(a).ok())
        .collect();
    propose(b.as_ref(), reqs, issued_at, &accs)
}

/// The proposal's digest (hex): SHA-256 of its canonical JSON. This is what a custodian compares across mirrors and
/// what the transcript names.
pub fn proposal_digest_json(proposal_json: &str) -> Result<String, Refusal> {
    let v: Value = serde_json::from_str(proposal_json)
        .map_err(|e| refusal("proposal-shape", format!("not JSON: {e}")))?;
    let c = canon::canonicalize_value(&v)
        .map_err(|e| refusal("proposal-shape", format!("does not canonicalize: {e}")))?;
    Ok(sha256_hex(c.as_bytes()))
}

fn parse_proposal(proposal_json: &str) -> Result<(Proposal, Directory), Refusal> {
    let p = serde_json::from_str::<Proposal>(proposal_json)
        .map_err(|e| refusal("proposal-shape", format!("not a v1 proposal: {e}")))?;
    if p.version != 1 || p.kind != PROPOSAL_KIND {
        return refuse(
            "proposal-shape",
            format!(
                "version {} of {:?}; this is v1 of {PROPOSAL_KIND}",
                p.version, p.kind
            ),
        );
    }
    let d = serde_json::from_value::<Directory>(p.directory.clone()).map_err(|e| {
        refusal(
            "proposal-schema",
            format!("the new directory is outside the frozen directory schema: {e}"),
        )
    })?;
    Ok((p, d))
}

/// What a proposal that passed every check is.
#[derive(Debug, Clone)]
pub struct ProposalOk {
    pub epoch: u64,
    pub base_epoch: u64,
    pub requests: usize,
    pub proposal_digest: String,
    pub signing_bytes_hex: String,
    pub signing_bytes_sha256: String,
    pub diff: Vec<DiffLine>,
}

/// Re-derive a proposal from epoch N (`None` for the first epoch) and its own requests alone, and refuse it unless
/// the directory, the diff and the digest are exactly what that produces.
pub fn check_proposal(
    proposal_json: &str,
    base: Option<&Directory>,
    accreditations: &[Value],
) -> Result<ProposalOk, Refusal> {
    let (p, d) = parse_proposal(proposal_json)?;
    let proposal_digest = proposal_digest_json(proposal_json)?;

    // proposal-base
    match base {
        Some(b) => {
            let bd = digest_of(b)?.1;
            if p.base_epoch != b.epoch || p.base_digest.as_deref() != Some(bd.as_str()) {
                return refuse(
                    "proposal-base",
                    format!(
                        "the proposal names base epoch {} ({}), but epoch N here is {} ({})",
                        p.base_epoch,
                        p.base_digest.as_deref().unwrap_or("none"),
                        b.epoch,
                        bd
                    ),
                );
            }
        }
        None => {
            if p.base_epoch != 0 || p.base_digest.is_some() {
                return refuse(
                    "proposal-base",
                    format!(
                        "the proposal names base epoch {}, but no epoch N was given",
                        p.base_epoch
                    ),
                );
            }
        }
    }
    let n = base.map(|b| b.epoch).unwrap_or(0);
    // proposal-epoch
    if p.epoch != n + 1 || d.epoch != n + 1 {
        return refuse(
            "proposal-epoch",
            format!(
                "the proposal is for epoch {} (its directory says {}); after epoch {n} only epoch {} may follow",
                p.epoch,
                d.epoch,
                n + 1
            ),
        );
    }
    // proposal-issued-at
    if let Some(b) = base {
        if d.issued_at <= b.issued_at {
            return refuse(
                "proposal-issued-at",
                format!(
                    "issued_at {} is not later than epoch {n}'s {}",
                    d.issued_at, b.issued_at
                ),
            );
        }
    }
    // proposal-schema (serde refused unknown fields already)
    if !d.sig_root_ed25519.is_empty() || !d.sig_root_slh.is_empty() {
        return refuse(
            "proposal-schema",
            "the new directory already carries a root signature; a proposal is unsigned",
        );
    }
    if d.entries
        .windows(2)
        .any(|w| w[0].registrar >= w[1].registrar)
        || d.entries
            .iter()
            .any(|e| !e.registrar.is_ascii() || e.registrar.is_empty())
    {
        return refuse(
            "proposal-schema",
            "the new directory's entries are not sorted and unique",
        );
    }
    // proposal-requests
    checked_requests(base, &p.requests, accreditations)?;
    let withdrawn: BTreeSet<&str> = p
        .requests
        .iter()
        .filter(|r| r.request.change_type == "WITHDRAW")
        .map(|r| r.request.registrar.as_str())
        .collect();
    // proposal-no-drop, proposal-cutoff, proposal-revocations-kept: invariants between N and N+1, each by name.
    if let Some(b) = base {
        for old in &b.entries {
            match d.entries.iter().find(|e| e.registrar == old.registrar) {
                None if !withdrawn.contains(old.registrar.as_str()) => {
                    return refuse(
                        "proposal-no-drop",
                        format!(
                            "{} is in epoch {n} and missing from epoch {}, and no WITHDRAW names it",
                            old.registrar, p.epoch
                        ),
                    );
                }
                Some(new) => {
                    if let Some(cut) = old.distrust_from_leaf {
                        if new.distrust_from_leaf.is_none_or(|c| c > cut) {
                            return refuse(
                                "proposal-cutoff",
                                format!(
                                    "{}'s cutoff at leaf {cut} in epoch {n} is {} in epoch {}",
                                    old.registrar,
                                    new.distrust_from_leaf
                                        .map(|c| format!("moved later, to leaf {c},"))
                                        .unwrap_or_else(|| "lifted".into()),
                                    p.epoch
                                ),
                            );
                        }
                    }
                }
                None => {}
            }
        }
        for fp in &b.revoked_delegates {
            if !d.revoked_delegates.contains(fp) {
                return refuse(
                    "proposal-revocations-kept",
                    format!(
                        "delegate {fp} is revoked in epoch {n} and not in epoch {}",
                        p.epoch
                    ),
                );
            }
        }
    }
    // proposal-rederive
    let (re, diff) = apply(base, &p.requests, d.issued_at)?;
    if re != d {
        let mut what = Vec::new();
        if re.entries != d.entries {
            what.push("the entries");
        }
        if re.revoked_delegates != d.revoked_delegates {
            what.push("the revoked delegates");
        }
        return refuse(
            "proposal-rederive",
            format!(
                "the new directory is not what epoch {n} and the {} listed request(s) produce ({} differ)",
                p.requests.len(),
                if what.is_empty() { "the header".into() } else { what.join(" and ") }
            ),
        );
    }
    // proposal-diff
    if diff != p.diff {
        return refuse(
            "proposal-diff",
            "the diff is not the re-derived one (every line, and the request each cites, must match)",
        );
    }
    // proposal-digest
    let (bytes, h) = digest_of(&re)?;
    if h != p.signing_bytes_sha256 {
        return refuse(
            "proposal-digest",
            format!(
                "signing_bytes_sha256 is {}, the re-derived signing bytes hash to {h}",
                p.signing_bytes_sha256
            ),
        );
    }
    Ok(ProposalOk {
        epoch: p.epoch,
        base_epoch: p.base_epoch,
        requests: p.requests.len(),
        proposal_digest,
        signing_bytes_hex: bytes.iter().map(|x| format!("{x:02x}")).collect(),
        signing_bytes_sha256: h,
        diff,
    })
}

/// [`check_proposal`] from JSON.
pub fn check_proposal_json(
    proposal_json: &str,
    base: Option<(&str, &str)>,
    accreditations: &[String],
) -> Result<ProposalOk, Refusal> {
    let b = match base {
        Some((d, roots)) => Some(authentic_directory(d, roots, "proposal-base")?),
        None => None,
    };
    let accs: Vec<Value> = accreditations
        .iter()
        .filter_map(|a| serde_json::from_str(a).ok())
        .collect();
    check_proposal(proposal_json, b.as_ref(), &accs)
}

/// The exact message the custodians sign: the proposal directory's signing bytes (hex) and their SHA-256, refused if
/// the proposal's own `signing_bytes_sha256` says otherwise. This checks the proposal against itself only — a
/// custodian runs `check-proposal` against epoch N first.
pub fn sign_request_json(proposal_json: &str) -> Result<(String, String, String), Refusal> {
    let (p, d) = parse_proposal(proposal_json)?;
    let (bytes, h) = digest_of(&d)?;
    if h != p.signing_bytes_sha256 {
        return refuse(
            "proposal-digest",
            format!(
                "the proposal says {}, its directory's signing bytes hash to {h}",
                p.signing_bytes_sha256
            ),
        );
    }
    Ok((
        bytes.iter().map(|x| format!("{x:02x}")).collect(),
        h,
        proposal_digest_json(proposal_json)?,
    ))
}

// ── assembly (step 7) ────────────────────────────────────────────────────────────────────────────────────────────

/// Put both root signatures on a proposal's directory. Refused unless EACH verifies over the proposal's signing bytes
/// under the pinned roots. Returns the signed directory as JSON.
pub fn assemble_json(
    proposal_json: &str,
    sig_ed25519_b64: &str,
    sig_slh_b64: &str,
    roots_json: &str,
) -> Result<String, Refusal> {
    let (p, mut d) = parse_proposal(proposal_json)?;
    let (bytes, h) = digest_of(&d)?;
    if h != p.signing_bytes_sha256 {
        return refuse(
            "proposal-digest",
            format!(
                "the proposal says {}, its directory's signing bytes hash to {h}",
                p.signing_bytes_sha256
            ),
        );
    }
    let (ed, slh) = roots_of(roots_json).ok_or_else(|| {
        refusal(
            "assemble-both-roots",
            "the roots file does not name root_ed25519 and root_slh",
        )
    })?;
    let ed_ok = b64::decode_array::<64>(sig_ed25519_b64)
        .is_ok_and(|s| crypto::ed25519_verify(&ed, &bytes, &s));
    let slh_ok = b64::decode(sig_slh_b64).is_ok_and(|s| crypto::slh_verify(&slh, &bytes, &s));
    if !ed_ok || !slh_ok {
        let mut bad = Vec::new();
        if !ed_ok {
            bad.push("the FROST Ed25519 signature");
        }
        if !slh_ok {
            bad.push("the SLH-DSA signature");
        }
        return refuse(
            "assemble-both-roots",
            format!(
                "{} does not verify over epoch {}'s signing bytes under the pinned roots; a directory needs both",
                bad.join(" and "),
                d.epoch
            ),
        );
    }
    d.sig_root_ed25519 = sig_ed25519_b64.to_string();
    d.sig_root_slh = sig_slh_b64.to_string();
    if d.accredit(&ed, &slh).is_err() {
        return refuse(
            "assemble-both-roots",
            "the assembled directory does not verify under both roots",
        );
    }
    serde_json::to_string_pretty(&d)
        .map(|s| s + "\n")
        .map_err(|e| refusal("assemble-both-roots", e.to_string()))
}

// ── publication (step 8) ─────────────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PublishOk {
    pub epoch: u64,
    pub digest: String,
    pub proposal_digest: String,
}

/// Every check `ainra directory publish` makes before it writes anything. `last` is the archive's last epoch and
/// digest (`None`: the target has no epoch history). `transcript_sha256` is the transcript's published hash, if given.
pub fn publish_check_json(
    directory_json: &str,
    roots_json: &str,
    proposal_json: &str,
    transcript_json: &str,
    last: Option<(u64, &str)>,
    transcript_sha256: Option<&str>,
) -> Result<PublishOk, Refusal> {
    let d = serde_json::from_str::<Directory>(directory_json)
        .map_err(|e| refusal("publish-both-roots", format!("not a directory: {e}")))?;
    let (ed, slh) = roots_of(roots_json).ok_or_else(|| {
        refusal(
            "publish-both-roots",
            "the roots file does not name root_ed25519 and root_slh",
        )
    })?;
    let bytes = d
        .signing_bytes()
        .map_err(|e| refusal("publish-both-roots", e.to_string()))?;
    let ed_ok = b64::decode_array::<64>(&d.sig_root_ed25519)
        .is_ok_and(|s| crypto::ed25519_verify(&ed, &bytes, &s));
    let slh_ok = b64::decode(&d.sig_root_slh).is_ok_and(|s| crypto::slh_verify(&slh, &bytes, &s));
    if !ed_ok || !slh_ok || d.accredit(&ed, &slh).is_err() {
        let which = match (ed_ok, slh_ok) {
            (true, false) => {
                "it carries the FROST Ed25519 signature but no valid SLH-DSA signature"
            }
            (false, true) => {
                "it carries the SLH-DSA signature but no valid FROST Ed25519 signature"
            }
            (false, false) => "neither root signature verifies",
            (true, true) => "it is not canonical",
        };
        return refuse(
            "publish-both-roots",
            format!(
                "epoch {} is not signed by both pinned roots: {which}",
                d.epoch
            ),
        );
    }
    let digest = sha256_hex(&bytes);
    let Some((last_epoch, last_digest)) = last else {
        return refuse(
            "publish-next-epoch",
            "the target has no epoch history: publish extends an archive (archive the first epoch with `ainra directory archive`)",
        );
    };
    if d.epoch != last_epoch + 1 {
        return refuse(
            "publish-next-epoch",
            format!(
                "epoch {} is not the archive's last epoch {last_epoch} + 1",
                d.epoch
            ),
        );
    }
    let (p, _) = parse_proposal(proposal_json)?;
    let proposal_digest = proposal_digest_json(proposal_json)?;
    if p.base_epoch != last_epoch || p.base_digest.as_deref() != Some(last_digest) {
        return refuse(
            "publish-next-epoch",
            format!(
                "the proposal was drafted on epoch {} ({}), the archive's last is epoch {last_epoch} ({last_digest})",
                p.base_epoch,
                p.base_digest.as_deref().unwrap_or("none")
            ),
        );
    }
    if p.epoch != d.epoch || p.signing_bytes_sha256 != digest {
        return refuse(
            "publish-approved",
            format!(
                "this authentic epoch {} (signing bytes {digest}) is not the approved proposal (epoch {}, {})",
                d.epoch, p.epoch, p.signing_bytes_sha256
            ),
        );
    }
    if let Some(want) = transcript_sha256 {
        let got = sha256_hex(transcript_json.as_bytes());
        if got != want.trim() {
            return refuse(
                "publish-transcript",
                format!(
                    "the transcript hashes to {got}, its published SHA-256 is {}",
                    want.trim()
                ),
            );
        }
    }
    let t: Value = serde_json::from_str(transcript_json).map_err(|e| {
        refusal(
            "publish-transcript",
            format!("the transcript is not JSON: {e}"),
        )
    })?;
    let signers: BTreeSet<u64> = t["signers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_u64)
        .collect();
    let mut wrong = Vec::new();
    if t["proposal_digest"].as_str() != Some(proposal_digest.as_str()) {
        wrong.push("the proposal digest");
    }
    if t["signing_bytes_sha256"].as_str() != Some(digest.as_str()) {
        wrong.push("the signing-bytes SHA-256");
    }
    if t["epoch"].as_u64() != Some(d.epoch) {
        wrong.push("the epoch");
    }
    if t["sig_root_ed25519"].as_str() != Some(d.sig_root_ed25519.as_str()) {
        wrong.push("the FROST signature");
    }
    if t["sig_root_slh"].as_str() != Some(d.sig_root_slh.as_str()) {
        wrong.push("the SLH-DSA signature");
    }
    if signers.len() < 5 {
        wrong.push("five distinct signers");
    }
    if !wrong.is_empty() {
        return refuse(
            "publish-transcript",
            format!(
                "the transcript does not name this epoch's {}",
                wrong.join(", ")
            ),
        );
    }
    Ok(PublishOk {
        epoch: d.epoch,
        digest,
        proposal_digest,
    })
}

/// A short summary for an accepted request, for the CLI.
pub fn accepted_json(a: &Accepted) -> Value {
    json!({ "ok": true, "digest": a.digest, "type": a.change_type, "registrar": a.registrar, "passed": a.passed })
}

#[cfg(test)]
mod tests {
    //! One refusal per check, each by its id, and the honest path accepted. Every key is generated here from a fixed
    //! seed and labelled TEST; a plain Ed25519 key stands in for the FROST group key, which emits the same RFC 8032
    //! signatures (the ceremony crate and `make sign-epoch-rehearsal` prove the real 5-of-9 path).
    use super::*;
    use rand_core::SeedableRng;
    use std::sync::OnceLock;

    struct Reg {
        id: String,
        issuer: crypto::HybridKeypair,
        status: crypto::HybridKeypair,
        log: crypto::TestRootSlh,
    }

    impl Reg {
        fn entry(&self) -> DirectoryEntry {
            let i = self.issuer.public();
            let s = self.status.public();
            DirectoryEntry {
                registrar: self.id.clone(),
                issuer_ed25519: b64::encode(&i.ed25519),
                issuer_mldsa65: b64::encode(&i.mldsa65),
                log_root_slh: b64::encode(&self.log.public()),
                status_ed25519: b64::encode(&s.ed25519),
                status_mldsa65: b64::encode(&s.mldsa65),
                distrust_from_leaf: None,
                status_uri: format!("status://{}/1", self.id),
            }
        }
    }

    fn wsig(s: &crypto::HybridSig) -> WireSig {
        WireSig {
            ed25519: b64::encode(&s.ed25519),
            mldsa65: b64::encode(&s.mldsa65),
        }
    }

    struct World {
        root_ed: crypto::TestDelegate,
        root_slh: crypto::TestRootSlh,
        a: Reg,
        b: Reg,
        newcomer: Reg,
        cert: WireDelegateCert,
        base: Directory,
        roots: String,
        accredit_new: ChangeRequest,
    }

    fn sign_dir(w_ed: &crypto::TestDelegate, w_slh: &crypto::TestRootSlh, d: &mut Directory) {
        let m = d.signing_bytes().unwrap();
        d.sig_root_ed25519 = b64::encode(&w_ed.sign(&m));
        d.sig_root_slh = b64::encode(&w_slh.sign(&m).unwrap());
    }

    fn base_request(t: &str, registrar: &str, filer: &str) -> ChangeRequest {
        ChangeRequest {
            version: 1,
            kind: REQUEST_KIND.into(),
            change_type: t.into(),
            registrar: registrar.into(),
            filer: filer.into(),
            filed_at: 2_000_000,
            test_root: false,
            change: Change::default(),
            evidence: Evidence::default(),
            proofs: Proofs::default(),
        }
    }

    fn art(file: &str) -> Option<Artifact> {
        Some(Artifact {
            file: file.into(),
            sha256: "ab".repeat(32),
            date: None,
        })
    }

    fn world() -> &'static World {
        static W: OnceLock<World> = OnceLock::new();
        W.get_or_init(|| {
            let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x0052_0005);
            let mut reg = |id: &str| Reg {
                id: id.into(),
                issuer: crypto::HybridKeypair::generate(&mut rng),
                status: crypto::HybridKeypair::generate(&mut rng),
                log: crypto::TestRootSlh::generate(&mut rng),
            };
            let (a, b, newcomer) = (reg("registrar-07"), reg("registrar-11"), reg("registrar-23"));
            let root_ed = crypto::TestDelegate::generate(&mut rng);
            let root_slh = crypto::TestRootSlh::generate(&mut rng);
            let delegate = crypto::TestDelegate::generate(&mut rng);
            let cert = checkpoint::DelegateCert::issue_test_root(
                &a.log,
                delegate.public(),
                vec![checkpoint::SCOPE_CHECKPOINT.into()],
                1_000_000,
                1_000_000 + 86_400,
            )
            .unwrap();
            let mut base = Directory {
                epoch: 4,
                issued_at: 1_500_000,
                entries: vec![a.entry(), {
                    let mut e = b.entry();
                    e.distrust_from_leaf = Some(40);
                    e
                }],
                revoked_delegates: vec![b64::encode(&[9u8; 32])],
                sig_root_ed25519: String::new(),
                sig_root_slh: String::new(),
            };
            sign_dir(&root_ed, &root_slh, &mut base);
            let roots = json!({ "root_ed25519": b64::encode(&root_ed.public()), "root_slh": b64::encode(&root_slh.public()) }).to_string();

            let mut acc = base_request("ACCREDIT", "registrar-23", "registrar-23");
            acc.test_root = true;
            acc.change.entry = Some(newcomer.entry());
            acc.evidence.prerequisites = Some(Prerequisites {
                agreement: art("agreement.pdf"),
                independence_attestation: art("independence.pdf"),
                competitor_monitor: art("monitor-funding.pdf"),
                audit: Some(Artifact {
                    file: "audit.pdf".into(),
                    sha256: "cd".repeat(32),
                    date: Some("2027-01-15".into()),
                }),
            });
            let acc = with_pop(acc, &newcomer);
            World {
                root_ed,
                root_slh,
                a,
                b,
                newcomer,
                cert: crate::cert_wire(&cert).into_wire(),
                base,
                roots,
                accredit_new: acc,
            }
        })
    }

    // `cert_wire` returns the delta-vector shape; the two shapes have the same fields.
    trait IntoWire {
        fn into_wire(self) -> WireDelegateCert;
    }
    impl IntoWire for crate::WireDeltaCert {
        fn into_wire(self) -> WireDelegateCert {
            WireDelegateCert {
                delegate_ed25519: self.delegate_ed25519,
                scopes: self.scopes,
                nbf: self.nbf,
                exp: self.exp,
                sig_slh: self.sig_slh,
            }
        }
    }

    /// Sign an ACCREDIT's digest with each of the newcomer's keys (redone after any edit, since the digest moves).
    fn with_pop(mut r: ChangeRequest, by: &Reg) -> ChangeRequest {
        let m = request_message(&request_digest(&r).unwrap());
        r.proofs.possession = Some(Possession {
            issuer: Some(wsig(&by.issuer.sign(m.as_bytes()).unwrap())),
            status: Some(wsig(&by.status.sign(m.as_bytes()).unwrap())),
            log_root_slh: Some(b64::encode(&by.log.sign(m.as_bytes()).unwrap())),
        });
        r
    }

    fn self_signed(mut r: ChangeRequest, by: &Reg) -> ChangeRequest {
        let m = request_message(&request_digest(&r).unwrap());
        r.proofs.filer = Some(wsig(&by.issuer.sign(m.as_bytes()).unwrap()));
        r
    }

    fn revoke(w: &World) -> ChangeRequest {
        let mut r = base_request("REVOKE_DELEGATE", "registrar-07", "registrar-07");
        r.change.cert = Some(w.cert.clone());
        self_signed(r, &w.a)
    }

    // the ladder at D-094's numbers: notice 1, notice 2 fifteen days later, the cure window closing 31 days after
    // notice 1, then two reproductions from distinct networks; the adverse request is filed at ADV_FILED
    const DAY: u64 = 86_400;
    const ADV_FILED: u64 = 20_000_000;
    const N1: u64 = ADV_FILED - 70 * DAY;

    fn compliance() -> Compliance {
        Compliance {
            notices: vec![
                Notice {
                    n: 1,
                    at: N1,
                    sha256: "01".repeat(32),
                },
                Notice {
                    n: 2,
                    at: N1 + 15 * DAY,
                    sha256: "02".repeat(32),
                },
            ],
            cure_window_ends: N1 + 31 * DAY,
            reproductions: vec![
                Reproduction {
                    vantage: "vp-a".into(),
                    network: "net-1".into(),
                    at: N1 + 32 * DAY,
                    report_sha256: "03".repeat(32),
                },
                Reproduction {
                    vantage: "vp-b".into(),
                    network: "net-2".into(),
                    at: N1 + 32 * DAY + 100,
                    report_sha256: "04".repeat(32),
                },
            ],
            fork_proof: None,
        }
    }

    // D-098: a checkpoint of `origin` at `size` with `root`, signed directly by a registrar's log root
    fn signed_cp(
        log: &crypto::TestRootSlh,
        origin: &str,
        size: u64,
        root: [u8; 32],
    ) -> SignedCheckpoint {
        let c = ainra_core::checkpoint::Checkpoint {
            origin: origin.into(),
            tree_size: size,
            root,
        };
        SignedCheckpoint {
            checkpoint: crate::WireCheckpoint {
                origin: origin.into(),
                size,
                root: b64::encode(&root),
            },
            checkpoint_sig: crate::WireCheckpointSig {
                mode: "root".into(),
                slh: Some(b64::encode(&c.sign_test_root(log).unwrap())),
                cert: None,
                sig_ed25519: None,
            },
        }
    }

    // an adverse DISTRUST of registrar-11 carrying only a fork proof: its own log at size 25, two roots
    fn forked(w: &World) -> ChangeRequest {
        let mut r = base_request("DISTRUST_FROM_LEAF", "registrar-11", "monitor-01");
        r.change.leaf = Some(20);
        let o = "ainra-log/registrar-11";
        r.evidence.compliance = Some(Compliance {
            notices: vec![],
            cure_window_ends: 0,
            reproductions: vec![],
            fork_proof: Some(ForkProof {
                a: signed_cp(&w.b.log, o, 25, [1; 32]),
                b: signed_cp(&w.b.log, o, 25, [2; 32]),
            }),
        });
        r
    }

    fn adverse(w: &World) -> ChangeRequest {
        let _ = w;
        let mut r = base_request("DISTRUST_FROM_LEAF", "registrar-11", "monitor-01");
        r.change.leaf = Some(30);
        r.filed_at = ADV_FILED;
        r.evidence.compliance = Some(compliance());
        r
    }

    // an adverse WITHDRAW of registrar-11 (distrusted from leaf 40 in the base epoch): the breach record (notice 3)
    // 91 days before the filing
    fn adverse_withdraw(w: &World) -> ChangeRequest {
        let _ = w;
        let mut r = base_request("WITHDRAW", "registrar-11", "monitor-01");
        r.filed_at = ADV_FILED + 120 * DAY;
        let mut c = compliance();
        c.notices.push(Notice {
            n: 3,
            at: r.filed_at - 91 * DAY,
            sha256: "05".repeat(32),
        });
        r.evidence.compliance = Some(c);
        r
    }

    fn check(r: &ChangeRequest) -> Result<Accepted, Refusal> {
        check_request(r, Some(&world().base), None)
    }

    fn refused_by(r: Result<Accepted, Refusal>, id: &str) {
        match r {
            Err(e) => assert_eq!(e.check, id, "refused by the wrong check: {e}"),
            Ok(a) => panic!("accepted, wanted [{id}]: {:?}", a.passed),
        }
    }

    /// Big-stack runner: ML-DSA keygen and signing need more than the default test-thread stack in a debug build.
    fn big<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(64 << 20)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn every_check_has_a_unique_id_and_the_document_lists_it() {
        let ids: BTreeSet<&str> = CHECKS.iter().map(|c| c.id).collect();
        assert_eq!(ids.len(), CHECKS.len(), "duplicate check id");
        let md = checks_markdown();
        for c in CHECKS {
            assert!(md.contains(&format!("| `{}` |", c.id)), "{} missing", c.id);
            assert!(!c.rule.contains('|'), "{}: a rule may not contain |", c.id);
        }
    }

    #[test]
    fn honest_requests_are_accepted() {
        big(|| {
            let w = world();
            assert!(check(&w.accredit_new).is_ok());
            assert!(check(&revoke(w)).is_ok());
            assert!(check(&adverse(w)).is_ok());
            let mut wd = base_request("WITHDRAW", "registrar-07", "registrar-07");
            wd = self_signed(wd, &w.a);
            assert!(check(&wd).is_ok());
            // genesis: an ACCREDIT against no directory
            assert!(check_request(&w.accredit_new, None, None).is_ok());
        });
    }

    #[test]
    fn each_request_refusal_is_named() {
        big(|| {
            let w = world();
            // request-shape: a field another type uses; an unknown type; an unknown field (via JSON)
            let mut r = revoke(w);
            r.change.leaf = Some(1);
            refused_by(check(&r), "request-shape");
            let mut r = revoke(w);
            r.change_type = "TRANSFER".into();
            refused_by(check(&r), "request-shape");
            let mut v = serde_json::to_value(revoke(w)).unwrap();
            v["approvers"] = json!([]);
            assert_eq!(
                parse_request(&v.to_string()).err().unwrap().check,
                "request-shape"
            );
            // root-key-roll
            refused_by(
                check(&base_request("ROOT_KEY_ROLL", "root", "steward")),
                "root-key-roll",
            );
            // request-subject
            refused_by(
                check(&base_request("WITHDRAW", "Registrar 7", "x")),
                "request-subject",
            );
            // request-base: a directory that does not verify
            let mut forged = w.base.clone();
            forged.issued_at += 1;
            let r = check_request_json(
                &serde_json::to_string(&revoke(w)).unwrap(),
                Some((&serde_json::to_string(&forged).unwrap(), &w.roots)),
                None,
            );
            refused_by(r, "request-base");
            // moves-trust: a key roll, and an ACCREDIT that changes an existing entry's keys
            refused_by(
                check(&base_request(
                    "REGISTRAR_KEY_ROLL",
                    "registrar-07",
                    "registrar-07",
                )),
                "moves-trust",
            );
            let mut roll = w.accredit_new.clone();
            roll.registrar = "registrar-07".into();
            let mut e = w.newcomer.entry();
            e.registrar = "registrar-07".into();
            roll.change.entry = Some(e);
            refused_by(check(&roll), "moves-trust");
            // subject-in-directory: the same entry again; a withdrawal of an unknown registrar
            let mut same = w.accredit_new.clone();
            same.registrar = "registrar-07".into();
            same.change.entry = Some(w.a.entry());
            refused_by(check(&same), "subject-in-directory");
            refused_by(
                check(&self_signed(
                    base_request("WITHDRAW", "registrar-99", "registrar-99"),
                    &w.a,
                )),
                "subject-in-directory",
            );
            // delegate-owned: filed by someone else; a cert another log root signed; an already revoked one
            let mut r = revoke(w);
            r.filer = "registrar-11".into();
            refused_by(check(&r), "delegate-owned");
            let mut r = base_request("REVOKE_DELEGATE", "registrar-11", "registrar-11");
            r.change.cert = Some(w.cert.clone());
            refused_by(check(&self_signed(r, &w.b)), "delegate-owned");
            let mut revoked = w.base.clone();
            let c = cert_of(&w.cert).unwrap();
            revoked
                .revoked_delegates
                .push(b64::encode(&c.fingerprint()));
            refused_by(
                check_request(&revoke(w), Some(&revoked), None),
                "delegate-owned",
            );
            // cutoff-monotone: registrar-11 is distrusted from leaf 40; 40 and 50 are refused, 30 is fine
            for leaf in [40, 50] {
                let mut r = base_request("DISTRUST_FROM_LEAF", "registrar-11", "registrar-11");
                r.change.leaf = Some(leaf);
                refused_by(check(&self_signed(r, &w.b)), "cutoff-monotone");
            }
            // self-signature: signed by another registrar's key; unsigned
            let mut r = base_request("REVOKE_DELEGATE", "registrar-07", "registrar-07");
            r.change.cert = Some(w.cert.clone());
            refused_by(check(&self_signed(r.clone(), &w.b)), "self-signature");
            refused_by(check(&r), "self-signature");
            // adverse-notice-chain: none; cure window not over at filing; notices out of order
            let mut r = adverse(w);
            r.evidence.compliance = None;
            refused_by(check(&r), "adverse-notice-chain");
            let mut r = adverse(w);
            r.evidence.compliance.as_mut().unwrap().cure_window_ends = r.filed_at;
            refused_by(check(&r), "adverse-notice-chain");
            let mut r = adverse(w);
            r.evidence.compliance.as_mut().unwrap().notices[1].n = 3;
            refused_by(check(&r), "adverse-notice-chain");
            // adverse-vantage: one vantage point; two on one network; a reproduction inside the cure window
            let mut r = adverse(w);
            r.evidence.compliance.as_mut().unwrap().reproductions.pop();
            refused_by(check(&r), "adverse-vantage");
            let mut r = adverse(w);
            r.evidence.compliance.as_mut().unwrap().reproductions[1].network = "net-1".into();
            refused_by(check(&r), "adverse-vantage");
            let mut r = adverse(w);
            r.evidence.compliance.as_mut().unwrap().reproductions[0].at = N1 + 20 * DAY;
            refused_by(check(&r), "adverse-vantage");
            // D-098 adverse-proof: a real fork is accepted with no notice, cure or reproduction; each way a
            // proof can fail is refused by name; without the proof the ladder still applies
            assert!(
                check(&forked(w)).is_ok(),
                "{:?}",
                check(&forked(w)).err().map(|e| e.to_string())
            );
            let proof = |r: &mut ChangeRequest| {
                r.evidence
                    .compliance
                    .as_mut()
                    .unwrap()
                    .fork_proof
                    .as_mut()
                    .unwrap()
                    .clone()
            };
            let o = "ainra-log/registrar-11";
            let mut r = forked(w);
            let mut fp = proof(&mut r);
            fp.b = signed_cp(&w.b.log, o, 25, [1; 32]);
            r.evidence.compliance.as_mut().unwrap().fork_proof = Some(fp);
            refused_by(check(&r), "adverse-proof"); // the two agree: not a fork
            let mut r = forked(w);
            let mut fp = proof(&mut r);
            fp.b = signed_cp(&w.b.log, o, 26, [2; 32]);
            r.evidence.compliance.as_mut().unwrap().fork_proof = Some(fp);
            refused_by(check(&r), "adverse-proof"); // two sizes: not self-evident
            let mut r = forked(w);
            let mut fp = proof(&mut r);
            fp.b = signed_cp(&w.a.log, o, 25, [2; 32]);
            r.evidence.compliance.as_mut().unwrap().fork_proof = Some(fp);
            refused_by(check(&r), "adverse-proof"); // signed by another registrar's log root
            let mut r = forked(w);
            let mut fp = proof(&mut r);
            fp.a = signed_cp(&w.b.log, "ainra-log/registrar-07", 25, [1; 32]);
            r.evidence.compliance.as_mut().unwrap().fork_proof = Some(fp);
            refused_by(check(&r), "adverse-proof"); // another log's origin
            let mut r = forked(w);
            r.change.leaf = Some(30);
            refused_by(check(&r), "adverse-proof"); // a cutoff above the fork
            let mut r = forked(w);
            r.change_type = "WITHDRAW".into();
            r.change.leaf = None;
            refused_by(check(&r), "adverse-proof"); // a fork proof never skips the holders' grace
            let mut r = forked(w);
            r.evidence.compliance.as_mut().unwrap().fork_proof = None;
            refused_by(check(&r), "adverse-notice-chain"); // no proof: the ladder
                                                           // D-094 item 11's numbers: one notice; notices 10 days apart; a 20-day cure window
            let mut r = adverse(w);
            r.evidence.compliance.as_mut().unwrap().notices.pop();
            refused_by(check(&r), "adverse-notice-chain");
            let mut r = adverse(w);
            r.evidence.compliance.as_mut().unwrap().notices[1].at = N1 + 10 * DAY;
            refused_by(check(&r), "adverse-notice-chain");
            let mut r = adverse(w);
            r.evidence.compliance.as_mut().unwrap().cure_window_ends = N1 + 20 * DAY;
            refused_by(check(&r), "adverse-notice-chain");
            // adverse-grace: an adverse WITHDRAW 91 days after the breach record of a distrusted registrar passes;
            // 60 days after it, with no breach record, or of a registrar never distrusted, it is refused
            assert!(
                check(&adverse_withdraw(w)).is_ok(),
                "{:?}",
                check(&adverse_withdraw(w)).err().map(|e| e.to_string())
            );
            let mut r = adverse_withdraw(w);
            r.evidence.compliance.as_mut().unwrap().notices[2].at = r.filed_at - 60 * DAY;
            refused_by(check(&r), "adverse-grace");
            let mut r = adverse_withdraw(w);
            r.evidence.compliance.as_mut().unwrap().notices.pop();
            refused_by(check(&r), "adverse-grace");
            let mut r = adverse_withdraw(w);
            r.registrar = "registrar-07".into();
            refused_by(check(&r), "adverse-grace");
            // entry-shape: a cutoff set on a new entry
            let mut r = w.accredit_new.clone();
            r.change.entry.as_mut().unwrap().distrust_from_leaf = Some(1);
            refused_by(check(&r), "entry-shape");
            // proof-of-possession: none; one key missing; a signature over another request
            let mut r = w.accredit_new.clone();
            r.proofs = Proofs::default();
            refused_by(check(&r), "proof-of-possession");
            let mut r = w.accredit_new.clone();
            r.proofs.possession.as_mut().unwrap().log_root_slh = None;
            refused_by(check(&r), "proof-of-possession");
            let mut r = w.accredit_new.clone();
            r.filed_at += 1; // the digest changes; the old proofs no longer cover it
            refused_by(check(&r), "proof-of-possession");
            // accreditation-match
            let served = json!({ "registrar": "registrar-23", "issuer_key": { "ed25519": "x", "mldsa65": "y" } });
            refused_by(
                check_request(&w.accredit_new, Some(&w.base), Some(&served)),
                "accreditation-match",
            );
            // prerequisites: none; an audit without a date
            // (each edit moves the digest, so the proofs are redone: only the check under test may fail)
            let mut r = w.accredit_new.clone();
            r.evidence.prerequisites = None;
            refused_by(check(&with_pop(r, &w.newcomer)), "prerequisites");
            let mut r = w.accredit_new.clone();
            r.evidence
                .prerequisites
                .as_mut()
                .unwrap()
                .audit
                .as_mut()
                .unwrap()
                .date = None;
            refused_by(check(&with_pop(r, &w.newcomer)), "prerequisites");
            // test-root-only
            let mut r = w.accredit_new.clone();
            r.test_root = false;
            refused_by(check(&with_pop(r, &w.newcomer)), "test-root-only");
        });
    }

    fn proposal_of(w: &World, reqs: Vec<ChangeRequest>) -> Value {
        serde_json::to_value(propose(Some(&w.base), reqs, 1_600_000, &[]).unwrap()).unwrap()
    }

    fn check_p(w: &World, p: &Value) -> Result<ProposalOk, Refusal> {
        check_proposal(&p.to_string(), Some(&w.base), &[])
    }

    fn proposal_refused_by(r: Result<ProposalOk, Refusal>, id: &str) {
        match r {
            Err(e) => assert_eq!(e.check, id, "refused by the wrong check: {e}"),
            Ok(_) => panic!("accepted, wanted [{id}]"),
        }
    }

    /// Recompute what a careful forger would, so that only the invariant under test is broken.
    fn reseal(p: &mut Value) {
        let d: Directory = serde_json::from_value(p["directory"].clone()).unwrap();
        p["signing_bytes_sha256"] = json!(sha256_hex(&d.signing_bytes().unwrap()));
    }

    #[test]
    fn an_honest_proposal_passes_and_each_proposal_refusal_is_named() {
        big(|| {
            let w = world();
            let p = proposal_of(w, vec![revoke(w), w.accredit_new.clone()]);
            let ok = check_p(w, &p).expect("the honest proposal");
            assert_eq!(ok.epoch, 5);
            assert_eq!(ok.diff.len(), 2);
            // the signing request agrees with check-proposal
            let (hex, sha, pd) = sign_request_json(&p.to_string()).unwrap();
            assert_eq!(
                (sha.as_str(), pd.as_str()),
                (
                    ok.signing_bytes_sha256.as_str(),
                    ok.proposal_digest.as_str()
                )
            );
            assert_eq!(hex, ok.signing_bytes_hex);

            // proposal-shape
            let mut x = p.clone();
            x["approved_by"] = json!("steward");
            proposal_refused_by(check_p(w, &x), "proposal-shape");
            // proposal-base
            let mut x = p.clone();
            x["base_digest"] = json!("00".repeat(32));
            proposal_refused_by(check_p(w, &x), "proposal-base");
            // proposal-epoch: a skipped epoch
            let mut x = p.clone();
            x["epoch"] = json!(6);
            x["directory"]["epoch"] = json!(6);
            reseal(&mut x);
            proposal_refused_by(check_p(w, &x), "proposal-epoch");
            // proposal-issued-at
            let mut x = p.clone();
            x["directory"]["issued_at"] = json!(1_400_000);
            reseal(&mut x);
            proposal_refused_by(check_p(w, &x), "proposal-issued-at");
            // proposal-schema: a field outside the frozen schema; a signature already on it
            let mut x = p.clone();
            x["directory"]["entries"][0]["approvers"] = json!(["k1", "k2"]);
            proposal_refused_by(check_p(w, &x), "proposal-schema");
            let mut x = p.clone();
            x["directory"]["sig_root_slh"] = json!("AAAA");
            proposal_refused_by(check_p(w, &x), "proposal-schema");
            // proposal-requests: a digest that lies; a request listed twice; a request that fails its checks
            let mut x = p.clone();
            x["requests"][0]["digest"] = json!("11".repeat(32));
            proposal_refused_by(check_p(w, &x), "proposal-requests");
            let mut x = p.clone();
            let first = x["requests"][0].clone();
            x["requests"].as_array_mut().unwrap().push(first);
            proposal_refused_by(check_p(w, &x), "proposal-requests");
            let mut x = p.clone();
            x["requests"][0]["request"]["proofs"] = json!({});
            proposal_refused_by(check_p(w, &x), "proposal-requests");
            // proposal-no-drop: registrar-11 dropped with no WITHDRAW (diff and digest resealed)
            let mut x = p.clone();
            x["directory"]["entries"]
                .as_array_mut()
                .unwrap()
                .retain(|e| e["registrar"] != "registrar-11");
            reseal(&mut x);
            proposal_refused_by(check_p(w, &x), "proposal-no-drop");
            // proposal-cutoff: registrar-11's cutoff at 40 lifted, and moved later
            for cut in [Value::Null, json!(41)] {
                let mut x = p.clone();
                for e in x["directory"]["entries"].as_array_mut().unwrap() {
                    if e["registrar"] == "registrar-11" {
                        if cut.is_null() {
                            e.as_object_mut().unwrap().remove("distrust_from_leaf");
                        } else {
                            e["distrust_from_leaf"] = cut.clone();
                        }
                    }
                }
                reseal(&mut x);
                proposal_refused_by(check_p(w, &x), "proposal-cutoff");
            }
            // proposal-revocations-kept
            let mut x = p.clone();
            x["directory"]["revoked_delegates"]
                .as_array_mut()
                .unwrap()
                .remove(0);
            reseal(&mut x);
            proposal_refused_by(check_p(w, &x), "proposal-revocations-kept");
            // proposal-rederive: registrar-07's issuer key swapped, self-consistently
            let mut x = p.clone();
            for e in x["directory"]["entries"].as_array_mut().unwrap() {
                if e["registrar"] == "registrar-07" {
                    e["issuer_ed25519"] = json!(b64::encode(&w.newcomer.issuer.public().ed25519));
                }
            }
            reseal(&mut x);
            proposal_refused_by(check_p(w, &x), "proposal-rederive");
            // proposal-diff
            let mut x = p.clone();
            x["diff"][0]["change"] = json!("+ nothing to see");
            proposal_refused_by(check_p(w, &x), "proposal-diff");
            // proposal-digest
            let mut x = p.clone();
            x["signing_bytes_sha256"] = json!("22".repeat(32));
            proposal_refused_by(check_p(w, &x), "proposal-digest");
            assert_eq!(
                sign_request_json(&x.to_string()).err().unwrap().check,
                "proposal-digest"
            );
            // two non-revocation requests about one registrar
            let mut wd = base_request("WITHDRAW", "registrar-07", "registrar-07");
            wd = self_signed(wd, &w.a);
            assert_eq!(
                propose(Some(&w.base), vec![revoke(w), wd], 1_600_000, &[])
                    .err()
                    .unwrap()
                    .check,
                "proposal-requests"
            );
            // a withdrawal really drops the entry, and that passes
            let mut wd = base_request("WITHDRAW", "registrar-07", "registrar-07");
            wd = self_signed(wd, &w.a);
            assert!(check_p(w, &proposal_of(w, vec![wd])).is_ok());
        });
    }

    #[test]
    fn assembly_and_publication_need_both_roots_the_approved_digest_and_a_transcript_naming_it() {
        big(|| {
            let w = world();
            let p = proposal_of(w, vec![revoke(w)]);
            let ps = p.to_string();
            let (hex, sha, pd) = sign_request_json(&ps).unwrap();
            let bytes: Vec<u8> = (0..hex.len() / 2)
                .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
                .collect();
            let ed = b64::encode(&w.root_ed.sign(&bytes));
            let slh = b64::encode(&w.root_slh.sign(&bytes).unwrap());
            // assemble-both-roots: one signature alone, either way round
            assert_eq!(
                assemble_json(&ps, &ed, "", &w.roots).err().unwrap().check,
                "assemble-both-roots"
            );
            assert_eq!(
                assemble_json(&ps, "", &slh, &w.roots).err().unwrap().check,
                "assemble-both-roots"
            );
            assert_eq!(
                assemble_json(&ps, &slh, &ed, &w.roots).err().unwrap().check,
                "assemble-both-roots"
            );
            let d = assemble_json(&ps, &ed, &slh, &w.roots).expect("both roots");
            let base_digest = sha256_hex(&w.base.signing_bytes().unwrap());
            let last = Some((4u64, base_digest.as_str()));
            let transcript =
                json!({ "epoch": 5, "proposal_digest": pd, "signing_bytes_sha256": sha,
                "sig_root_ed25519": ed, "sig_root_slh": slh, "signers": [1, 3, 5, 7, 9] })
                .to_string();
            let ok = publish_check_json(&d, &w.roots, &ps, &transcript, last, None)
                .expect("publishable");
            assert_eq!(ok.epoch, 5);
            // publish-both-roots: the SLH signature removed
            let mut one: Value = serde_json::from_str(&d).unwrap();
            one["sig_root_slh"] = json!("");
            assert_eq!(
                publish_check_json(&one.to_string(), &w.roots, &ps, &transcript, last, None)
                    .err()
                    .unwrap()
                    .check,
                "publish-both-roots"
            );
            // publish-next-epoch: no history; an archive already at 5; a proposal drafted on another epoch 4
            assert_eq!(
                publish_check_json(&d, &w.roots, &ps, &transcript, None, None)
                    .err()
                    .unwrap()
                    .check,
                "publish-next-epoch"
            );
            assert_eq!(
                publish_check_json(&d, &w.roots, &ps, &transcript, Some((5, "x")), None)
                    .err()
                    .unwrap()
                    .check,
                "publish-next-epoch"
            );
            assert_eq!(
                publish_check_json(&d, &w.roots, &ps, &transcript, Some((4, "x")), None)
                    .err()
                    .unwrap()
                    .check,
                "publish-next-epoch"
            );
            // publish-approved: an authentic epoch 5 that is not this proposal
            let other = proposal_of(w, vec![w.accredit_new.clone()]).to_string();
            let (ohex, _, _) = sign_request_json(&other).unwrap();
            let ob: Vec<u8> = (0..ohex.len() / 2)
                .map(|i| u8::from_str_radix(&ohex[2 * i..2 * i + 2], 16).unwrap())
                .collect();
            let od = assemble_json(
                &other,
                &b64::encode(&w.root_ed.sign(&ob)),
                &b64::encode(&w.root_slh.sign(&ob).unwrap()),
                &w.roots,
            )
            .unwrap();
            assert_eq!(
                publish_check_json(&od, &w.roots, &ps, &transcript, last, None)
                    .err()
                    .unwrap()
                    .check,
                "publish-approved"
            );
            // publish-transcript: a transcript for another proposal; fewer than five signers; a hash that does not match
            assert_eq!(
                publish_check_json(&od, &w.roots, &other, &transcript, last, None)
                    .err()
                    .unwrap()
                    .check,
                "publish-transcript"
            );
            let four = transcript.replace("[1,3,5,7,9]", "[1,3,5,7]");
            assert_eq!(
                publish_check_json(&d, &w.roots, &ps, &four, last, None)
                    .err()
                    .unwrap()
                    .check,
                "publish-transcript"
            );
            let h = sha256_hex(transcript.as_bytes());
            assert!(publish_check_json(&d, &w.roots, &ps, &transcript, last, Some(&h)).is_ok());
            let flipped = transcript.replacen("\"epoch\":5", "\"epoch\":6", 1);
            assert_eq!(
                publish_check_json(&d, &w.roots, &ps, &flipped, last, Some(&h))
                    .err()
                    .unwrap()
                    .check,
                "publish-transcript"
            );
        });
    }
}
