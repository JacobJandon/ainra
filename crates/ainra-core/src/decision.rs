// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Signed decision records (D-079): what a gate decided, provably, after the fact.
//!
//! Every gate decision can be written as one small record: who decided (the gate's key), when, about what (a
//! passport, or a linked key), the verdict and its reason, a digest of the request's signed components (never the
//! request), the status and checkpoint the decision relied on, and the gate's policy. Each record is signed by the
//! gate's own Ed25519 key and names the digest of the record before it, so the log is a chain: a deleted, reordered,
//! edited or inserted record is detectable by anyone holding the gate's public key.
//!
//! **No personal data, by construction.** The field set is closed (`deny_unknown_fields`) and every value is a name,
//! a digest, a number or a word from a fixed vocabulary. There is nowhere to put a request body, an address or an
//! account.
//!
//! The core has no clock and no keys of its own: the gate signs [`DecisionRecord::signing_bytes`] with its key, and
//! [`verify_chain`] checks a chain against the gate's public key. The result vocabulary is the chain's own
//! ([`ChainProblem`]) — the frozen reasons describe credentials, not logs.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::name::AinraName;
use crate::verdict::Reason;
use crate::verify::TrustAnchors;
use crate::{b64, canon, checkpoint, crypto, link, merkle};

/// The record's version tag. Frozen: it is inside what the gate signs.
pub const DECISION_V: &str = "ainra-decision-1";
/// The outcome a link-mode gate records for a key with no link: not a credential reason, so not in the frozen set.
pub const NOT_LINKED: &str = "not_linked";

/// The status publication a decision relied on: its URI, when it was issued, and the digest of the list itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionStatus {
    pub uri: String,
    pub issued_at: u64,
    /// base64url SHA-256 of the compressed list as presented (its base64url text's bytes).
    pub list: String,
}

/// The checkpoint a decision relied on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionCheckpoint {
    pub origin: String,
    pub size: u64,
    pub root: String,
}

/// The gate's own policy at the time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionPolicy {
    pub freshness: String,
    pub audience: String,
}

/// One decision. Field names are frozen: they are what the gate signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRecord {
    pub v: String,
    /// RFC 7638 thumbprint of the gate's Ed25519 key: who decided.
    pub gate: String,
    pub seq: u64,
    /// The gate's clock, unix seconds.
    pub at: u64,
    /// `passport` or `link`.
    pub kind: String,
    /// The passport's name (`passport`) or the presented key's thumbprint (`link`).
    pub subject: String,
    /// For a link decision: the passport the key was attributed to, when one was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// `valid` or `invalid`.
    pub verdict: String,
    /// Present exactly when `verdict` is `invalid`: a frozen credential reason, a request-signature reason
    /// (`presentation_*`, the request was not bound to the credential), or `not_linked`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// base64url SHA-256 of the request's signature base — its signed components, never its body.
    pub request: String,
    /// Absent when the decision was made before any status was read (a schema refusal, say).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<DecisionStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<DecisionCheckpoint>,
    pub policy: DecisionPolicy,
    /// base64url SHA-256 of the previous record's full canonical bytes (signature included); empty at `seq` 0.
    pub prev: String,
    /// base64url Ed25519 signature by the gate's key over [`DecisionRecord::signing_bytes`].
    pub sig: String,
}

/// Why a chain does not hold, at the first record that breaks it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainProblem {
    /// Not a well-formed version-1 record in canonical form, or a value outside its vocabulary.
    Schema,
    /// The record names a different gate than the key the chain is checked against.
    Gate,
    /// The gate's signature does not verify: the record was altered, or another key signed it.
    Signature,
    /// The sequence number is not the next one: a record was deleted, reordered or inserted.
    Sequence,
    /// `prev` does not name the record before it.
    Link,
    /// The gate's clock went backwards.
    Clock,
    /// The chain ends before the record a logged head names (D-081): records were cut from the end.
    Truncated,
    /// The record at a logged head's `seq` is not the one the head names: the log was replaced after it was anchored.
    Forked,
}

impl ChainProblem {
    pub const fn as_str(self) -> &'static str {
        match self {
            ChainProblem::Schema => "schema",
            ChainProblem::Gate => "gate",
            ChainProblem::Signature => "signature",
            ChainProblem::Sequence => "sequence",
            ChainProblem::Link => "link",
            ChainProblem::Clock => "clock",
            ChainProblem::Truncated => "truncated",
            ChainProblem::Forked => "forked",
        }
    }
}

/// Where a chain broke: the zero-based position in what was checked, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainBreak {
    pub index: usize,
    pub problem: ChainProblem,
}

/// The last record a chain segment continues from: its `seq`, `at` and digest. `None` means the segment starts the
/// chain, at `seq` 0 with an empty `prev`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainAnchor {
    pub seq: u64,
    pub at: u64,
    pub digest: [u8; 32],
}

impl DecisionRecord {
    /// What the gate signs: the canonical record without `sig`.
    pub fn signing_bytes(&self) -> core::result::Result<Vec<u8>, Reason> {
        let mut v = serde_json::to_value(self).map_err(|_| Reason::SchemaViolation)?;
        if let Some(o) = v.as_object_mut() {
            o.remove("sig");
        }
        Ok(canon::canonicalize(&v)
            .map_err(|_| Reason::SchemaViolation)?
            .into_bytes())
    }

    /// The record's full canonical bytes, signature included: one line of a decision log.
    pub fn to_line(&self) -> core::result::Result<Vec<u8>, Reason> {
        Ok(canon::canonicalize(self)
            .map_err(|_| Reason::SchemaViolation)?
            .into_bytes())
    }

    /// The digest the next record's `prev` names.
    pub fn digest(&self) -> core::result::Result<[u8; 32], Reason> {
        Ok(Sha256::digest(self.to_line()?).into())
    }

    /// Parse one log line, refusing anything that is not a well-formed version-1 record in canonical form.
    pub fn parse_checked(line: &[u8]) -> Option<Self> {
        let r: DecisionRecord = serde_json::from_slice(line).ok()?;
        if r.to_line().ok()?.as_slice() != line {
            return None;
        }
        if r.v != DECISION_V {
            return None;
        }
        b64::decode_array::<32>(&r.gate).ok()?;
        b64::decode_array::<32>(&r.request).ok()?;
        b64::decode_array::<64>(&r.sig).ok()?;
        if !(r.seq == 0 && r.prev.is_empty()) {
            b64::decode_array::<32>(&r.prev).ok()?;
        }
        match r.kind.as_str() {
            "passport" => {
                AinraName::parse(&r.subject).ok()?;
                if r.passport.is_some() {
                    return None;
                }
            }
            "link" => {
                b64::decode_array::<32>(&r.subject).ok()?;
                if let Some(p) = &r.passport {
                    AinraName::parse(p).ok()?;
                }
            }
            _ => return None,
        }
        match (r.verdict.as_str(), r.reason.as_deref()) {
            ("valid", None) => {}
            ("invalid", Some(NOT_LINKED)) if r.kind == "link" => {}
            ("invalid", Some(reason))
                if Reason::from_wire(reason).is_some()
                    || crate::presentation::PresentationReason::ALL
                        .iter()
                        .any(|p| p.as_str() == reason) => {}
            _ => return None,
        }
        if let Some(op) = &r.operator {
            if op.is_empty() || op.len() > 63 {
                return None;
            }
        }
        if let Some(s) = &r.status {
            b64::decode_array::<32>(&s.list).ok()?;
        }
        if let Some(c) = &r.checkpoint {
            b64::decode_array::<32>(&c.root).ok()?;
        }
        if !matches!(r.policy.freshness.as_str(), "F1" | "F2" | "F3") {
            return None;
        }
        Some(r)
    }
}

/// The digest a record keeps of a request: base64url SHA-256 over the canonical `{authority, content_digest, method,
/// path}` — what the request's signature covers, never its body. `content_digest` is the header's value, or "".
/// One definition, so every gate (Node, edge, Python) records the same bytes for the same request.
pub fn request_digest(method: &str, authority: &str, path: &str, content_digest: &str) -> String {
    #[derive(Serialize)]
    struct Req<'a> {
        authority: &'a str,
        content_digest: &'a str,
        method: &'a str,
        path: &'a str,
    }
    let c = canon::canonicalize(&Req {
        authority,
        content_digest,
        method,
        path,
    })
    .unwrap_or_default();
    b64::encode(&Sha256::digest(c.as_bytes()))
}

/// The digest of one log line: what the next record's `prev` names, and what a gate publishes as its head.
pub fn line_digest(line: &[u8]) -> [u8; 32] {
    Sha256::digest(line).into()
}

/// The gate identity a chain is checked against: the RFC 7638 thumbprint of its Ed25519 key.
pub fn gate_id(gate_key: &[u8; 32]) -> String {
    link::jwk_thumbprint_ed25519(gate_key)
}

/// Check a decision log (one canonical record per line) against the gate's public key. `Ok(n)` when all `n` records
/// hold; otherwise the first break. Per record, in this order: schema, gate, signature, sequence, link, clock — so an
/// edited record reads `signature`, and only genuinely signed records can read as deleted, reordered or re-dated.
pub fn verify_chain(
    lines: &[&[u8]],
    gate_key: &[u8; 32],
    anchor: Option<ChainAnchor>,
) -> core::result::Result<usize, ChainBreak> {
    let gate = gate_id(gate_key);
    let mut last = anchor;
    for (index, line) in lines.iter().enumerate() {
        let fail = |problem| ChainBreak { index, problem };
        let r = DecisionRecord::parse_checked(line).ok_or(fail(ChainProblem::Schema))?;
        if r.gate != gate {
            return Err(fail(ChainProblem::Gate));
        }
        let sig: [u8; 64] = b64::decode_array(&r.sig).map_err(|_| fail(ChainProblem::Schema))?;
        let msg = r.signing_bytes().map_err(|_| fail(ChainProblem::Schema))?;
        if !crypto::ed25519_verify(gate_key, &msg, &sig) {
            return Err(fail(ChainProblem::Signature));
        }
        let (want_seq, want_prev) = match last {
            None => (0, String::new()),
            Some(a) => (a.seq.wrapping_add(1), b64::encode(&a.digest)),
        };
        if last.is_some_and(|a| a.seq == u64::MAX) || r.seq != want_seq {
            return Err(fail(ChainProblem::Sequence));
        }
        if r.prev != want_prev {
            return Err(fail(ChainProblem::Link));
        }
        if last.is_some_and(|a| r.at < a.at) {
            return Err(fail(ChainProblem::Clock));
        }
        last = Some(ChainAnchor {
            seq: r.seq,
            at: r.at,
            digest: line_digest(line),
        });
    }
    Ok(lines.len())
}

// ── Logged heads (D-081) ─────────────────────────────────────────────────────────────────────────────────────────
// A chain shows every edit, deletion and reordering, but not records cut from its end. A gate closes that by signing
// a head statement — where its log stood — and having a registrar append it to its transparency log. The registrar
// sees a digest, never a decision. Once a head is logged, a log that stops short of it reads `truncated`, and one that
// has a different record at that position reads `forked`.

/// The head statement's version tag. Frozen: it is inside what the gate signs.
pub const HEAD_V: &str = "ainra-decision-head-1";

/// A gate's signed statement of where its decision log stood. Field names are frozen: they are what the gate signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadStatement {
    pub v: String,
    /// RFC 7638 thumbprint of the gate's Ed25519 key.
    pub gate: String,
    /// The `seq` of the last record the head covers.
    pub seq: u64,
    /// That record's `at`.
    pub at: u64,
    /// base64url line digest of that record ([`line_digest`]).
    pub head: String,
    /// base64url Ed25519 signature by the gate's key over [`HeadStatement::signing_bytes`].
    pub sig: String,
}

impl HeadStatement {
    /// What the gate signs: the canonical statement without `sig`.
    pub fn signing_bytes(&self) -> core::result::Result<Vec<u8>, Reason> {
        let mut v = serde_json::to_value(self).map_err(|_| Reason::SchemaViolation)?;
        if let Some(o) = v.as_object_mut() {
            o.remove("sig");
        }
        Ok(canon::canonicalize(&v)
            .map_err(|_| Reason::SchemaViolation)?
            .into_bytes())
    }

    /// The full canonical statement, signature included: what the registrar logs and a receipt carries.
    pub fn to_line(&self) -> core::result::Result<Vec<u8>, Reason> {
        Ok(canon::canonicalize(self)
            .map_err(|_| Reason::SchemaViolation)?
            .into_bytes())
    }

    /// Parse a statement line, refusing anything that is not a well-formed version-1 statement in canonical form.
    pub fn parse_checked(line: &[u8]) -> Option<Self> {
        let h: HeadStatement = serde_json::from_slice(line).ok()?;
        if h.to_line().ok()?.as_slice() != line || h.v != HEAD_V {
            return None;
        }
        b64::decode_array::<32>(&h.gate).ok()?;
        b64::decode_array::<32>(&h.head).ok()?;
        b64::decode_array::<64>(&h.sig).ok()?;
        Some(h)
    }

    /// Check the statement was signed by `gate_key` and names that key. What a registrar checks before logging it.
    pub fn verify(line: &[u8], gate_key: &[u8; 32]) -> core::result::Result<Self, Reason> {
        let h = Self::parse_checked(line).ok_or(Reason::SchemaViolation)?;
        if h.gate != gate_id(gate_key) {
            return Err(Reason::SigInvalid);
        }
        let sig: [u8; 64] = b64::decode_array(&h.sig).map_err(|_| Reason::SchemaViolation)?;
        let msg = h.signing_bytes()?;
        if !crypto::ed25519_verify(gate_key, &msg, &sig) {
            return Err(Reason::SigInvalid);
        }
        Ok(h)
    }
}

/// A registrar's receipt for a logged head, as a checker holds it.
#[derive(Debug, Clone, Copy)]
pub struct HeadReceiptCheck<'a> {
    /// The statement line, exactly as logged.
    pub statement: &'a [u8],
    /// The gate key the checker holds; the statement must name it and be signed by it.
    pub gate_key: [u8; 32],
    /// The registrar that logged it, looked up in the checker's trust anchors.
    pub registrar: &'a str,
    pub checkpoint: &'a checkpoint::Checkpoint,
    pub checkpoint_sig: &'a checkpoint::CheckpointSig,
    pub leaf_index: u64,
    pub inclusion_proof: &'a [[u8; 32]],
    pub revoked_delegates: &'a BTreeSet<[u8; 32]>,
    pub now: u64,
}

/// Check a head receipt: the statement (schema, gate, signature), then that it is logged at `leaf_index` under a
/// checkpoint the registrar's log key signed — the same machinery, in the same order, as a link's step 8. First
/// failure wins, in the frozen vocabulary: `schema_violation`, `sig_invalid`, `unknown_registrar`,
/// `checkpoint_invalid`, `not_logged`.
pub fn verify_head_receipt(
    chk: &HeadReceiptCheck,
    anchors: &TrustAnchors,
) -> core::result::Result<HeadStatement, Reason> {
    let h = HeadStatement::verify(chk.statement, &chk.gate_key)?;
    let reg = anchors
        .registrars
        .get(chk.registrar)
        .ok_or(Reason::UnknownRegistrar)?;
    chk.checkpoint
        .verify_sig_mode(&reg.log_root_key, chk.checkpoint_sig, chk.now)?;
    if let checkpoint::CheckpointSig::Delegate { cert, .. } = chk.checkpoint_sig {
        if chk.revoked_delegates.contains(&cert.fingerprint()) {
            return Err(Reason::CheckpointInvalid);
        }
    }
    checkpoint::verify_logged(
        &merkle::hash_leaf(chk.statement),
        chk.leaf_index,
        chk.checkpoint,
        chk.inclusion_proof,
    )?;
    Ok(h)
}

/// Check a decision log against a logged head: the chain as [`verify_chain`] checks it, then — if the head's record
/// falls in or just before this segment — that the log reaches it and holds exactly that record there. A log that
/// grew after the head was logged is fine; one that stops short is `truncated`; a different record is `forked`.
pub fn verify_chain_to_head(
    lines: &[&[u8]],
    gate_key: &[u8; 32],
    anchor: Option<ChainAnchor>,
    head: &HeadStatement,
) -> core::result::Result<usize, ChainBreak> {
    if head.gate != gate_id(gate_key) {
        return Err(ChainBreak {
            index: 0,
            problem: ChainProblem::Gate,
        });
    }
    let n = verify_chain(lines, gate_key, anchor)?;
    let want: [u8; 32] = b64::decode_array(&head.head).map_err(|_| ChainBreak {
        index: 0,
        problem: ChainProblem::Schema,
    })?;
    let first = anchor.map_or(0, |a| a.seq.wrapping_add(1));
    if head.seq < first {
        // The head is at or before where this segment starts. Only the record just before it can be compared: the
        // anchor itself.
        return match anchor {
            Some(a) if a.seq == head.seq && a.digest != want => Err(ChainBreak {
                index: 0,
                problem: ChainProblem::Forked,
            }),
            _ => Ok(n),
        };
    }
    let Ok(at) = usize::try_from(head.seq - first) else {
        return Err(ChainBreak {
            index: n,
            problem: ChainProblem::Truncated,
        });
    };
    if at >= n {
        return Err(ChainBreak {
            index: n,
            problem: ChainProblem::Truncated,
        });
    }
    if line_digest(lines[at]) != want {
        return Err(ChainBreak {
            index: at,
            problem: ChainProblem::Forked,
        });
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use rand_core::SeedableRng;

    fn key(seed: u64) -> crypto::TestDelegate {
        crypto::TestDelegate::generate(&mut rand_chacha::ChaCha20Rng::seed_from_u64(seed))
    }

    fn base(gate: &crypto::TestDelegate, seq: u64, at: u64, prev: String) -> DecisionRecord {
        DecisionRecord {
            v: DECISION_V.to_string(),
            gate: gate_id(&gate.public()),
            seq,
            at,
            kind: "link".to_string(),
            subject: b64::encode(&[7u8; 32]),
            passport: Some("ainra:registrar-07:acme:invoicing@1.0.0".to_string()),
            operator: Some("acme".to_string()),
            verdict: "valid".to_string(),
            reason: None,
            request: b64::encode(&[9u8; 32]),
            status: Some(DecisionStatus {
                uri: "status://registrar-07/1".to_string(),
                issued_at: at - 5,
                list: b64::encode(&[1u8; 32]),
            }),
            checkpoint: Some(DecisionCheckpoint {
                origin: "ainra-log/registrar-07".to_string(),
                size: 12,
                root: b64::encode(&[2u8; 32]),
            }),
            policy: DecisionPolicy {
                freshness: "F1".to_string(),
                audience: "https://shop.example".to_string(),
            },
            prev,
            sig: String::new(),
        }
    }

    fn signed(gate: &crypto::TestDelegate, mut r: DecisionRecord) -> DecisionRecord {
        r.sig = b64::encode(&gate.sign(&r.signing_bytes().unwrap()));
        r
    }

    /// Three genuine records, chained.
    fn chain(gate: &crypto::TestDelegate) -> Vec<DecisionRecord> {
        let mut out: Vec<DecisionRecord> = Vec::new();
        for i in 0..3u64 {
            let prev = out
                .last()
                .map(|r| b64::encode(&r.digest().unwrap()))
                .unwrap_or_default();
            let mut r = base(gate, i, 1000 + i * 10, prev);
            if i == 1 {
                r.verdict = "invalid".to_string();
                r.reason = Some("revoked".to_string());
            }
            out.push(signed(gate, r));
        }
        out
    }

    fn lines(rs: &[DecisionRecord]) -> Vec<Vec<u8>> {
        rs.iter().map(|r| r.to_line().unwrap()).collect()
    }

    fn check(
        ls: &[Vec<u8>],
        gate: &crypto::TestDelegate,
    ) -> core::result::Result<usize, ChainBreak> {
        let refs: Vec<&[u8]> = ls.iter().map(|l| l.as_slice()).collect();
        verify_chain(&refs, &gate.public(), None)
    }

    fn broke(index: usize, problem: ChainProblem) -> core::result::Result<usize, ChainBreak> {
        Err(ChainBreak { index, problem })
    }

    #[test]
    fn the_request_digest_matches_the_typescript_sdk() {
        // values printed by @ainra/sdk decisionRequestDigest for the same inputs (2026-10-29)
        assert_eq!(
            request_digest("GET", "shop.example", "/orders?id=7", ""),
            "tHlRA9FaC4JbQTLk_5luMTNLhNGamRFVfC1G1OQ7otQ"
        );
        assert_eq!(
            request_digest(
                "POST",
                "api.example:8443",
                "/pay",
                "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
            ),
            "2h0UIrY1A-lEvewXmT_tj9P-5QKfE1Yoqmqf27UyO3Q"
        );
    }

    #[test]
    fn a_genuine_chain_holds() {
        let g = key(1);
        assert_eq!(check(&lines(&chain(&g)), &g), Ok(3));
        assert_eq!(check(&[], &g), Ok(0));
    }

    #[test]
    fn an_edited_record_breaks_its_signature() {
        let g = key(1);
        let mut rs = chain(&g);
        rs[1].reason = Some("stale_status".to_string());
        assert_eq!(check(&lines(&rs), &g), broke(1, ChainProblem::Signature));
    }

    #[test]
    fn a_deleted_record_breaks_the_sequence() {
        let g = key(1);
        let mut ls = lines(&chain(&g));
        ls.remove(1);
        assert_eq!(check(&ls, &g), broke(1, ChainProblem::Sequence));
    }

    #[test]
    fn reordered_records_break_the_sequence() {
        let g = key(1);
        let mut ls = lines(&chain(&g));
        ls.swap(1, 2);
        assert_eq!(check(&ls, &g), broke(1, ChainProblem::Sequence));
    }

    #[test]
    fn a_record_re_signed_with_the_wrong_prev_breaks_the_link() {
        let g = key(1);
        let mut rs = chain(&g);
        rs[2].prev = b64::encode(&[0u8; 32]);
        let fixed = signed(&g, rs[2].clone());
        rs[2] = fixed;
        assert_eq!(check(&lines(&rs), &g), broke(2, ChainProblem::Link));
    }

    #[test]
    fn a_clock_that_goes_backwards_is_refused() {
        let g = key(1);
        let mut rs = chain(&g);
        rs[2].at = 900;
        let fixed = signed(&g, rs[2].clone());
        rs[2] = fixed;
        assert_eq!(check(&lines(&rs), &g), broke(2, ChainProblem::Clock));
    }

    #[test]
    fn another_gates_chain_is_not_this_gates() {
        let (g, other) = (key(1), key(2));
        assert_eq!(
            check(&lines(&chain(&other)), &g),
            broke(0, ChainProblem::Gate)
        );
        // Claiming this gate's identity does not help: the signature is still the other key's.
        let mut r = base(&g, 0, 1000, String::new());
        r.sig = b64::encode(&other.sign(&r.signing_bytes().unwrap()));
        assert_eq!(check(&lines(&[r]), &g), broke(0, ChainProblem::Signature));
    }

    #[test]
    fn nothing_outside_the_vocabulary_fits() {
        let g = key(1);
        let cases: Vec<fn(&mut DecisionRecord)> = vec![
            |r| r.reason = Some("revoked".to_string()), // a reason on a valid verdict
            |r| r.verdict = "maybe".to_string(),
            |r| {
                r.verdict = "invalid".to_string();
                r.reason = Some("blocked_for_fun".to_string()); // not a frozen reason
            },
            |r| r.kind = "person".to_string(),
            |r| r.subject = "alice@example.org".to_string(), // a link subject must be a thumbprint
            |r| r.policy.freshness = "F9".to_string(),
            |r| r.v = "ainra-decision-2".to_string(),
        ];
        for mutate in cases {
            let mut r = base(&g, 0, 1000, String::new());
            mutate(&mut r);
            assert_eq!(
                check(&lines(&[signed(&g, r)]), &g),
                broke(0, ChainProblem::Schema)
            );
        }
        // not_linked only for a link decision
        let mut p = base(&g, 0, 1000, String::new());
        p.kind = "passport".to_string();
        p.subject = "ainra:registrar-07:acme:invoicing@1.0.0".to_string();
        p.passport = None;
        p.verdict = "invalid".to_string();
        p.reason = Some(NOT_LINKED.to_string());
        assert_eq!(
            check(&lines(&[signed(&g, p.clone())]), &g),
            broke(0, ChainProblem::Schema)
        );
        p.reason = Some("revoked".to_string());
        assert_eq!(check(&lines(&[signed(&g, p.clone())]), &g), Ok(1));
        // a passport decision names its subject once; a second `passport` field is a place to hide something
        p.passport = Some("ainra:registrar-07:acme:other@1.0.0".to_string());
        assert_eq!(
            check(&lines(&[signed(&g, p)]), &g),
            broke(0, ChainProblem::Schema)
        );
    }

    #[test]
    fn an_unknown_field_or_a_non_canonical_line_is_refused() {
        let g = key(1);
        let r = signed(&g, base(&g, 0, 1000, String::new()));
        let line = String::from_utf8(r.to_line().unwrap()).unwrap();
        let extra = line.replacen("{", "{\"email\":\"a@b.c\",", 1);
        assert_eq!(
            check(&[extra.into_bytes()], &g),
            broke(0, ChainProblem::Schema)
        );
        let spaced = line.replacen(",", ", ", 1);
        assert_eq!(
            check(&[spaced.into_bytes()], &g),
            broke(0, ChainProblem::Schema)
        );
    }

    #[test]
    fn a_segment_continues_from_its_anchor() {
        let g = key(1);
        let rs = chain(&g);
        let ls = lines(&rs);
        let anchor = ChainAnchor {
            seq: rs[0].seq,
            at: rs[0].at,
            digest: rs[0].digest().unwrap(),
        };
        let tail: Vec<&[u8]> = ls[1..].iter().map(|l| l.as_slice()).collect();
        assert_eq!(verify_chain(&tail, &g.public(), Some(anchor)), Ok(2));
        let wrong = ChainAnchor {
            digest: [0u8; 32],
            ..anchor
        };
        assert_eq!(
            verify_chain(&tail, &g.public(), Some(wrong)),
            broke(0, ChainProblem::Link)
        );
    }

    // ── D-081 logged heads ─────────────────────────────────────────────────────────────────────────────────────────

    fn head_of(gate: &crypto::TestDelegate, r: &DecisionRecord) -> HeadStatement {
        let mut h = HeadStatement {
            v: HEAD_V.to_string(),
            gate: gate_id(&gate.public()),
            seq: r.seq,
            at: r.at,
            head: b64::encode(&r.digest().unwrap()),
            sig: String::new(),
        };
        h.sig = b64::encode(&gate.sign(&h.signing_bytes().unwrap()));
        h
    }

    fn to_head(
        ls: &[Vec<u8>],
        gate: &crypto::TestDelegate,
        anchor: Option<ChainAnchor>,
        h: &HeadStatement,
    ) -> core::result::Result<usize, ChainBreak> {
        let refs: Vec<&[u8]> = ls.iter().map(|l| l.as_slice()).collect();
        verify_chain_to_head(&refs, &gate.public(), anchor, h)
    }

    #[test]
    fn a_log_that_reaches_its_logged_head_holds_and_may_have_grown() {
        let g = key(1);
        let rs = chain(&g);
        let ls = lines(&rs);
        assert_eq!(to_head(&ls, &g, None, &head_of(&g, &rs[2])), Ok(3));
        assert_eq!(to_head(&ls, &g, None, &head_of(&g, &rs[1])), Ok(3));
    }

    #[test]
    fn a_cut_tail_reads_truncated_once_its_head_is_logged() {
        let g = key(1);
        let rs = chain(&g);
        let ls = lines(&rs);
        // Without a head, the shorter log is a perfectly good chain — the gap D-081 closes.
        assert_eq!(check(&ls[..2], &g), Ok(2));
        assert_eq!(
            to_head(&ls[..2], &g, None, &head_of(&g, &rs[2])),
            broke(2, ChainProblem::Truncated)
        );
    }

    #[test]
    fn a_replaced_record_reads_forked() {
        let g = key(1);
        let rs = chain(&g);
        let h = head_of(&g, &rs[2]);
        let mut other = rs.clone();
        let mut r = base(&g, 2, 1030, b64::encode(&rs[1].digest().unwrap()));
        r.verdict = "invalid".to_string();
        r.reason = Some("expired".to_string());
        other[2] = signed(&g, r);
        assert_eq!(
            to_head(&lines(&other), &g, None, &h),
            broke(2, ChainProblem::Forked)
        );
    }

    #[test]
    fn a_segment_is_checked_against_a_head_at_its_anchor() {
        let g = key(1);
        let rs = chain(&g);
        let ls = lines(&rs);
        let anchor = ChainAnchor {
            seq: rs[0].seq,
            at: rs[0].at,
            digest: rs[0].digest().unwrap(),
        };
        assert_eq!(
            to_head(&ls[1..], &g, Some(anchor), &head_of(&g, &rs[0])),
            Ok(2)
        );
        let mut forged = head_of(&g, &rs[0]);
        forged.head = b64::encode(&[3u8; 32]);
        assert_eq!(
            to_head(&ls[1..], &g, Some(anchor), &forged),
            broke(0, ChainProblem::Forked)
        );
        assert_eq!(
            to_head(&ls[1..], &g, Some(anchor), &head_of(&g, &rs[2])),
            Ok(2)
        );
    }

    #[test]
    fn a_head_names_and_is_signed_by_its_gate() {
        let g = key(1);
        let rs = chain(&g);
        let line = head_of(&g, &rs[2]).to_line().unwrap();
        assert!(HeadStatement::verify(&line, &g.public()).is_ok());
        assert_eq!(
            HeadStatement::verify(&line, &key(2).public()),
            Err(Reason::SigInvalid)
        );
        let mut spaced = String::from_utf8(line.clone()).unwrap();
        spaced.insert(1, ' ');
        assert_eq!(
            HeadStatement::verify(spaced.as_bytes(), &g.public()),
            Err(Reason::SchemaViolation)
        );
        assert_eq!(
            to_head(&lines(&rs), &key(2), None, &head_of(&g, &rs[2])),
            broke(0, ChainProblem::Gate)
        );
    }

    #[test]
    fn a_receipt_proves_the_head_was_logged_by_the_registrar() {
        use crate::verify::RegistrarInfo;
        use alloc::collections::BTreeMap;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xD0_81);
        let root = crypto::TestRootSlh::generate(&mut rng);
        let issuer = crypto::HybridKeypair::generate(&mut rng);
        let g = key(1);
        let line = head_of(&g, &chain(&g)[2]).to_line().unwrap();
        let mut log = merkle::TestLog::new();
        log.append(b"another entry");
        let leaf_index = log.append(&line);
        log.append(b"a later entry");
        let cp = checkpoint::Checkpoint {
            origin: "ainra-log/registrar-01".to_string(),
            tree_size: log.size(),
            root: log.root(),
        };
        let cp_sig = checkpoint::CheckpointSig::Root {
            slh: cp.sign_test_root(&root).unwrap(),
        };
        let proof = log.inclusion_proof(leaf_index).unwrap();
        let other_proof = log.inclusion_proof(0).unwrap();
        let mut registrars = BTreeMap::new();
        registrars.insert(
            "registrar-01".to_string(),
            RegistrarInfo {
                issuer_key: issuer.public(),
                log_root_key: root.public(),
                distrust_from_leaf: None,
            },
        );
        let anchors = TrustAnchors { registrars };
        let none = BTreeSet::new();
        let chk = HeadReceiptCheck {
            statement: &line,
            gate_key: g.public(),
            registrar: "registrar-01",
            checkpoint: &cp,
            checkpoint_sig: &cp_sig,
            leaf_index,
            inclusion_proof: &proof,
            revoked_delegates: &none,
            now: 1_000,
        };
        assert!(verify_head_receipt(&chk, &anchors).is_ok());
        let wrong_proof = HeadReceiptCheck {
            inclusion_proof: &other_proof,
            ..chk
        };
        assert_eq!(
            verify_head_receipt(&wrong_proof, &anchors),
            Err(Reason::NotLogged)
        );
        let elsewhere = HeadReceiptCheck {
            registrar: "registrar-99",
            ..chk
        };
        assert_eq!(
            verify_head_receipt(&elsewhere, &anchors),
            Err(Reason::UnknownRegistrar)
        );
        let other_root = crypto::TestRootSlh::generate(&mut rng);
        let forged_sig = checkpoint::CheckpointSig::Root {
            slh: cp.sign_test_root(&other_root).unwrap(),
        };
        let forged = HeadReceiptCheck {
            checkpoint_sig: &forged_sig,
            ..chk
        };
        assert!(verify_head_receipt(&forged, &anchors).is_err());
        let other_gate = HeadReceiptCheck {
            gate_key: key(2).public(),
            ..chk
        };
        assert_eq!(
            verify_head_receipt(&other_gate, &anchors),
            Err(Reason::SigInvalid)
        );
    }
}
