// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Verdicts and the CLOSED reason enum.
//!
//! Spec: brief §2. The reason strings are FROZEN (DECISIONS D-004): the CC0 conformance vectors reference these
//! exact strings, so `serde` renders them verbatim and the round-trip is asserted in tests.

use serde::{Deserialize, Serialize};

/// The result of verifying a credential: exactly VALID, or INVALID with a single machine-readable reason.
///
/// A well-formed-but-invalid credential is a *domain result*, not an [`crate::Error`]. Fail closed: any check
/// that cannot be completed (e.g. stale status) yields `Invalid`, never `Valid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// All four verify steps passed (MTS §8): chain-to-root, both signatures, fresh status, log inclusion.
    Valid,
    /// A single closed-enum reason. First failure short-circuits; evaluation order is fixed and documented
    /// per check so the reason is deterministic across implementations (needed for the diff-harness).
    Invalid {
        #[serde(rename = "reason")]
        reason: Reason,
    },
}

impl Verdict {
    pub const fn invalid(reason: Reason) -> Self {
        Verdict::Invalid { reason }
    }
    pub const fn is_valid(&self) -> bool {
        matches!(self, Verdict::Valid)
    }
    /// The reason, if invalid.
    pub const fn reason(&self) -> Option<Reason> {
        match self {
            Verdict::Valid => None,
            Verdict::Invalid { reason } => Some(*reason),
        }
    }
}

/// The closed set of INVALID reasons (brief §2). Exact wire strings via `snake_case`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Reason {
    /// A required signature failed to verify.
    SigInvalid,
    /// A mandated signature (Ed25519 or ML-DSA-65) was absent — hybrid means hybrid (brief §0).
    AlgDowngrade,
    /// `exp` is in the past.
    Expired,
    /// `nbf` is in the future.
    NotYetValid,
    /// The lineage/version is revoked in the status list.
    Revoked,
    /// A mandate in the presented subtree is revoked (kills the whole subtree).
    MandateRevoked,
    /// A delegation link granted more than its parent's effective authority.
    ChainWidening,
    /// A delegation link's expiry exceeds its parent's.
    ChainExpired,
    /// The credential lacks a Merkle inclusion proof to a signed checkpoint.
    NotLogged,
    /// The checkpoint signature (root/delegate + witnesses per policy) did not verify.
    CheckpointInvalid,
    /// Status material is older than the freshness class allows (fails closed).
    StaleStatus,
    /// A name violated the namespace grammar.
    NameMalformed,
    /// A requested capability exceeds the scope ceiling.
    CeilingExceeded,
    /// The issuing registrar is not in the signed directory.
    UnknownRegistrar,
    /// The credential violated the passport schema (missing MUST field or a forbidden field present).
    SchemaViolation,
}

impl Reason {
    /// The exact frozen wire string (matches the CC0 vectors).
    pub const fn as_str(self) -> &'static str {
        match self {
            Reason::SigInvalid => "sig_invalid",
            Reason::AlgDowngrade => "alg_downgrade",
            Reason::Expired => "expired",
            Reason::NotYetValid => "not_yet_valid",
            Reason::Revoked => "revoked",
            Reason::MandateRevoked => "mandate_revoked",
            Reason::ChainWidening => "chain_widening",
            Reason::ChainExpired => "chain_expired",
            Reason::NotLogged => "not_logged",
            Reason::CheckpointInvalid => "checkpoint_invalid",
            Reason::StaleStatus => "stale_status",
            Reason::NameMalformed => "name_malformed",
            Reason::CeilingExceeded => "ceiling_exceeded",
            Reason::UnknownRegistrar => "unknown_registrar",
            Reason::SchemaViolation => "schema_violation",
        }
    }
}

impl core::fmt::Display for Reason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The 15 frozen strings, in enum order. If this list changes, vectors break — that is the point.
    const ALL: [(Reason, &str); 15] = [
        (Reason::SigInvalid, "sig_invalid"),
        (Reason::AlgDowngrade, "alg_downgrade"),
        (Reason::Expired, "expired"),
        (Reason::NotYetValid, "not_yet_valid"),
        (Reason::Revoked, "revoked"),
        (Reason::MandateRevoked, "mandate_revoked"),
        (Reason::ChainWidening, "chain_widening"),
        (Reason::ChainExpired, "chain_expired"),
        (Reason::NotLogged, "not_logged"),
        (Reason::CheckpointInvalid, "checkpoint_invalid"),
        (Reason::StaleStatus, "stale_status"),
        (Reason::NameMalformed, "name_malformed"),
        (Reason::CeilingExceeded, "ceiling_exceeded"),
        (Reason::UnknownRegistrar, "unknown_registrar"),
        (Reason::SchemaViolation, "schema_violation"),
    ];

    #[test]
    fn reason_strings_are_frozen_and_serde_matches() {
        for (r, s) in ALL {
            assert_eq!(r.as_str(), s, "as_str drift");
            // serde must render the same frozen string (as a bare enum value).
            let j = serde_json::to_string(&r).expect("serialize reason");
            assert_eq!(j, alloc::format!("\"{s}\""), "serde drift for {s}");
            let back: Reason = serde_json::from_str(&j).expect("deserialize reason");
            assert_eq!(back, r);
        }
    }

    #[test]
    fn verdict_roundtrip() {
        let v = Verdict::invalid(Reason::AlgDowngrade);
        let j = serde_json::to_string(&v).expect("ser");
        assert_eq!(j, r#"{"verdict":"invalid","reason":"alg_downgrade"}"#);
        assert_eq!(serde_json::from_str::<Verdict>(&j).expect("de"), v);
        let ok = Verdict::Valid;
        assert_eq!(
            serde_json::to_string(&ok).expect("ser"),
            r#"{"verdict":"valid"}"#
        );
        assert!(ok.is_valid());
        assert_eq!(v.reason(), Some(Reason::AlgDowngrade));
    }
}
