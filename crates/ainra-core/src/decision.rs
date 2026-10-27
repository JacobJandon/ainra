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

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::name::AinraName;
use crate::verdict::Reason;
use crate::{b64, canon, crypto, link};

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
}
