// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The passport claim-set (SD-JWT-VC body) and its schema gate.
//!
//! Spec: MTS §15 (data model) — the field set that WINS over Standard §5's illustrative JSON (DECISIONS D-001).
//! `vct` is fixed to [`crate::PASSPORT_VCT`]. Two structural rules are enforced here and nowhere else:
//!   * every MUST field is present and the two hybrid keys are BOTH carried (a passport may not ship one algorithm);
//!   * NO forbidden field — the passport is neutral identity, so PII / score / price are rejected with
//!     [`Reason::SchemaViolation`] (DECISIONS D-002). This is enforced two ways: `deny_unknown_fields` rejects
//!     stray top-level keys, and a recursive denylist scan rejects forbidden keys nested in free-form maps.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::name::AinraName;
use crate::verdict::Reason;

/// Authority class — how the agent's authority is rooted (MTS §15). A1 self-asserted … A4 principal-proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthClass {
    A1,
    A2,
    A3,
    A4,
}

/// Accreditation tier L0…L4 (MTS §15). L0 = anchored-only; higher tiers carry stronger issuer diligence.
/// The root NEVER scores; tier is a coarse accreditation level, not a reputation number (Charter S / D-002).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    L0,
    L1,
    L2,
    L3,
    L4,
}

/// The two-signature hybrid key pair a verifier chains to. BOTH are mandatory (brief §0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    /// base64url(Ed25519 public key, 32 B).
    pub ed25519: String,
    /// base64url(ML-DSA-65 public key, 1952 B).
    pub mldsa65: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub class: AuthClass,
    /// Opaque proof reference (e.g. a hash of a principal-control attestation). Never PII.
    pub principal_proof: String,
}

/// Reference into a Token Status List (draft-ietf-oauth-status-list): which bit, at which signed list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusRef {
    pub idx: u64,
    pub uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub status_list: StatusRef,
}

/// The transparency-log anchor: the passport's leaf, the tree root it was included under, and the checkpoint id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogRef {
    /// base64url(leaf hash, 32 B).
    pub leaf: String,
    /// base64url(Merkle root, 32 B).
    pub root: String,
    /// Checkpoint identifier the root belongs to.
    pub checkpoint: String,
}

/// One delegation hop recorded in the passport's `act_chain` (owner → agent → subagent …).
/// The ∩-narrowing rules are evaluated in [`crate::chain`]; here it is only the on-wire shape.
///
/// M2 (MTS §15 / Standard §6 A3, DECISIONS D-012): every hop is **dual-signed** — the delegator AND the delegatee
/// both sign the same canonical hop bytes (the counter-signature proves the delegatee consented, killing
/// delegation laundering) — and carries `log_leaf`, the RFC 6962 leaf hash of those bytes, which must prove
/// inclusion under the presented checkpoint (logged-before-valid applies to delegation events too).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActLink {
    /// Delegator name (`ainra:…`).
    pub from: String,
    /// Delegate name (`ainra:…`).
    pub to: String,
    /// Capabilities granted on this hop (MUST be ⊆ delegator's effective set).
    pub granted: Vec<String>,
    /// Hop expiry (unix seconds; MUST be ≤ delegator's).
    pub exp: u64,
    /// base64url(Ed25519 sig, 64 B) by the DELEGATOR.
    pub sig_ed25519: String,
    /// base64url(ML-DSA-65 sig, 3309 B) by the DELEGATOR.
    pub sig_mldsa65: String,
    /// base64url(Ed25519 sig, 64 B) by the DELEGATEE (counter-signature — consent).
    pub sig_child_ed25519: String,
    /// base64url(ML-DSA-65 sig, 3309 B) by the DELEGATEE.
    pub sig_child_mldsa65: String,
    /// base64url(RFC 6962 leaf hash, 32 B) of the canonical hop bytes — the hop's transparency-log anchor.
    pub log_leaf: String,
}

/// The passport claim-set. `deny_unknown_fields` is load-bearing: a stray `score`/`price`/`email` top-level key is
/// a schema violation, not a silently-ignored extra (D-002).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Passport {
    /// Credential type — MUST equal [`crate::PASSPORT_VCT`].
    pub vct: String,
    /// Issuer DID (`did:ainra:…`) — the accrediting registrar.
    pub iss: String,
    /// Subject name (`ainra:…`) — the agent lineage.
    pub sub: String,
    /// Not-before (unix seconds).
    pub nbf: u64,
    /// Expiry (unix seconds).
    pub exp: u64,
    pub authority: Authority,
    pub tier: Tier,
    pub capabilities: Vec<String>,
    /// The maximum authority this lineage may ever wield; delegations narrow within it (MTS §15).
    pub scope_ceiling: Vec<String>,
    /// Hybrid public keys. MUST be non-empty; each entry carries BOTH algorithms.
    pub keys: Vec<KeyEntry>,
    /// Holder-binding confirmation (opaque; e.g. a JWK thumbprint). Free-form map, denylist-scanned.
    pub cnf: Value,
    pub status: Status,
    pub log: LogRef,
    /// Delegation chain (may be empty for a root-issued passport).
    #[serde(default)]
    pub act_chain: Vec<ActLink>,
    /// The operative mandate path (root→…→operative), authenticated by the issuer signature. Empty = no mandate
    /// gate. Because it lives in the signed body, a presenter cannot drop a revoked ancestor (MTS §18; D-009).
    #[serde(default)]
    pub mandates: Vec<crate::mandate::MandateNode>,
    /// **M3-reserved.** base64url(RFC 6962 Merkle root) of a lineage's DYNAMIC (post-issue, AP2-style) mandate tree.
    /// Binding the operative mandate to a specific credential/action needs the AP2 mandate-object model, so the M2
    /// verifier **rejects** any passport carrying this field (fail closed, `schema_violation`) — see D-013 revised.
    #[serde(default)]
    pub mandates_root: Option<String>,
    /// **M3-reserved.** Tree size `mandates_root` would commit to. Rejected by M2 for the same reason (D-013).
    #[serde(default)]
    pub mandates_size: Option<u64>,
    /// Prior holders, if the lineage was transferred (opaque records; denylist-scanned).
    #[serde(default)]
    pub transfer_history: Vec<Value>,
}

/// Keys that MUST NOT appear anywhere in a passport (recursively). AINRA is neutral identity: no personal data,
/// no reputation number, no money. Matching is case-insensitive on the exact key (D-002). Extend deliberately.
const FORBIDDEN_KEYS: &[&str] = &[
    // personal data
    "email",
    "phone",
    "name",
    "full_name",
    "given_name",
    "family_name",
    "surname",
    "address",
    "street",
    "city",
    "postcode",
    "zip",
    "ssn",
    "national_id",
    "dob",
    "birthdate",
    "gender",
    "photo",
    "ip",
    "geolocation",
    // reputation / scoring — the root never scores
    "score",
    "trust_score",
    "reputation",
    "rating",
    "ranking",
    "karma",
    "credit_score",
    // money / pricing — identity carries no commerce
    "price",
    "amount",
    "fee",
    "cost",
    "payment",
    "balance",
    "invoice_total",
    "currency",
    "wallet",
    "iban",
];

impl Passport {
    /// Parse + schema-gate a passport from canonical JSON bytes. Returns [`Reason::SchemaViolation`] for any
    /// structural failure (unknown/forbidden field, missing MUST value, malformed name, wrong `vct`).
    ///
    /// This is the schema step ONLY — it performs no crypto, status, or log checks (those are later verify steps).
    pub fn parse_checked(bytes: &[u8]) -> core::result::Result<Self, Reason> {
        // First pass: a raw Value so we can run the recursive forbidden-key scan even over free-form maps.
        let raw: Value = serde_json::from_slice(bytes).map_err(|_| Reason::SchemaViolation)?;
        scan_forbidden(&raw)?;
        // Second pass: strict typed decode (deny_unknown_fields catches stray top-level keys).
        let p: Passport = serde_json::from_slice(bytes).map_err(|_| Reason::SchemaViolation)?;
        p.validate_structure()?;
        Ok(p)
    }

    fn validate_structure(&self) -> core::result::Result<(), Reason> {
        if self.vct != crate::PASSPORT_VCT {
            return Err(Reason::SchemaViolation);
        }
        // Subject MUST be a well-formed ainra name; issuer MUST be a well-formed did:ainra.
        AinraName::parse(&self.sub).map_err(|_| Reason::NameMalformed)?;
        AinraName::parse_did(&self.iss).map_err(|_| Reason::NameMalformed)?;
        // At least one hybrid key, and every entry carries BOTH algorithms (non-empty strings).
        if self.keys.is_empty() {
            return Err(Reason::SchemaViolation);
        }
        for k in &self.keys {
            if k.ed25519.is_empty() || k.mldsa65.is_empty() {
                return Err(Reason::SchemaViolation);
            }
        }
        // Validity window must be ordered.
        if self.exp <= self.nbf {
            return Err(Reason::SchemaViolation);
        }
        // Delegation hops: every hop MUST carry both signature pairs and the log anchor (D-012). The chain must
        // also be structurally linked: hop[i+1].from == hop[i].to, and the last hop's delegate is this passport's
        // subject — a chain of unrelated (even individually well-signed) hops is a forgery.
        for hop in &self.act_chain {
            if hop.sig_ed25519.is_empty()
                || hop.sig_mldsa65.is_empty()
                || hop.sig_child_ed25519.is_empty()
                || hop.sig_child_mldsa65.is_empty()
                || hop.log_leaf.is_empty()
            {
                return Err(Reason::SchemaViolation);
            }
            AinraName::parse(&hop.from).map_err(|_| Reason::NameMalformed)?;
            AinraName::parse(&hop.to).map_err(|_| Reason::NameMalformed)?;
        }
        for w in self.act_chain.windows(2) {
            if w[1].from != w[0].to {
                return Err(Reason::SchemaViolation);
            }
        }
        if let Some(last) = self.act_chain.last() {
            if last.to != self.sub {
                return Err(Reason::SchemaViolation);
            }
        }
        // Dynamic (post-issue, AP2-style) mandates are **M3** (DECISIONS D-013 revised): binding the operative
        // mandate to a specific credential/action needs the AP2 mandate-object model, not just Merkle inclusion.
        // Until then the M2 verifier cannot soundly evaluate them, so a passport carrying `mandates_root`/
        // `mandates_size` is rejected — fail closed rather than ship a presenter-picks-any-path bypass. The fields
        // stay reserved (a future M3 passport carries them; M2 rejects them explicitly, not silently).
        if self.mandates_root.is_some() || self.mandates_size.is_some() {
            return Err(Reason::SchemaViolation);
        }
        Ok(())
    }
}

/// Recursively reject any object key in [`FORBIDDEN_KEYS`] (case-insensitive). Arrays are descended into.
fn scan_forbidden(v: &Value) -> core::result::Result<(), Reason> {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                let lk = k.to_ascii_lowercase();
                if FORBIDDEN_KEYS.contains(&lk.as_str()) {
                    return Err(Reason::SchemaViolation);
                }
                scan_forbidden(child)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for it in items {
                scan_forbidden(it)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn base() -> Value {
        serde_json::json!({
            "vct": crate::PASSPORT_VCT,
            "iss": "did:ainra:registrar-01:acme:invoicing",
            "sub": "ainra:registrar-01:acme:invoicing@1.0.0",
            "nbf": 1_000,
            "exp": 2_000,
            "authority": { "class": "A2", "principal_proof": "deadbeef" },
            "tier": "L1",
            "capabilities": ["read:invoices", "sign:invoice"],
            "scope_ceiling": ["read:invoices", "sign:invoice", "pay:invoice"],
            "keys": [ { "ed25519": "AAAA", "mldsa65": "BBBB" } ],
            "cnf": { "jkt": "thumb" },
            "status": { "status_list": { "idx": 7, "uri": "status://registrar-01/1" } },
            "log": { "leaf": "bGVhZg", "root": "cm9vdA", "checkpoint": "cp-1" }
        })
    }

    fn bytes(v: &Value) -> Vec<u8> {
        serde_json::to_vec(v).unwrap()
    }

    #[test]
    fn good_passport_parses() {
        let p = Passport::parse_checked(&bytes(&base())).expect("valid passport");
        assert_eq!(p.tier, Tier::L1);
        assert_eq!(p.authority.class, AuthClass::A2);
        assert_eq!(p.keys.len(), 1);
        assert!(p.act_chain.is_empty());
    }

    #[test]
    fn forbidden_top_level_key_is_schema_violation() {
        for bad in ["score", "price", "email"] {
            let mut v = base();
            v.as_object_mut()
                .unwrap()
                .insert(bad.to_string(), serde_json::json!("x"));
            assert_eq!(
                Passport::parse_checked(&bytes(&v)),
                Err(Reason::SchemaViolation),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn forbidden_nested_key_is_schema_violation() {
        // hide a PII field deep in the free-form cnf map — the recursive scan must still catch it.
        let mut v = base();
        v["cnf"] = serde_json::json!({ "jkt": "thumb", "holder": { "email": "a@b.example" } });
        assert_eq!(
            Passport::parse_checked(&bytes(&v)),
            Err(Reason::SchemaViolation)
        );
    }

    #[test]
    fn missing_second_algorithm_key_is_schema_violation() {
        let mut v = base();
        v["keys"] = serde_json::json!([ { "ed25519": "AAAA", "mldsa65": "" } ]);
        assert_eq!(
            Passport::parse_checked(&bytes(&v)),
            Err(Reason::SchemaViolation)
        );
    }

    #[test]
    fn wrong_vct_and_bad_name_rejected() {
        let mut v = base();
        v["vct"] = serde_json::json!("something/else/v1");
        assert_eq!(
            Passport::parse_checked(&bytes(&v)),
            Err(Reason::SchemaViolation)
        );

        let mut v2 = base();
        v2["sub"] = serde_json::json!("ainra:REGISTRAR:acme:x@1.0.0"); // uppercase label → malformed
        assert_eq!(
            Passport::parse_checked(&bytes(&v2)),
            Err(Reason::NameMalformed)
        );
    }

    #[test]
    fn unordered_window_rejected() {
        let mut v = base();
        v["exp"] = serde_json::json!(500); // exp < nbf
        assert_eq!(
            Passport::parse_checked(&bytes(&v)),
            Err(Reason::SchemaViolation)
        );
    }

    #[test]
    fn dynamic_mandate_fields_rejected() {
        // Dynamic (post-issue) mandates are M3 (D-013 revised): a passport carrying mandates_root/mandates_size
        // is fail-closed rejected, so the M2 verifier never honours a presenter-supplied (unbindable) path.
        let mut v = base();
        v["mandates_root"] = serde_json::json!("cm9vdA");
        v["mandates_size"] = serde_json::json!(2);
        assert_eq!(
            Passport::parse_checked(&bytes(&v)),
            Err(Reason::SchemaViolation)
        );
        let mut v2 = base();
        v2["mandates_root"] = serde_json::json!("cm9vdA"); // even root alone is rejected
        assert_eq!(
            Passport::parse_checked(&bytes(&v2)),
            Err(Reason::SchemaViolation)
        );
    }
}
