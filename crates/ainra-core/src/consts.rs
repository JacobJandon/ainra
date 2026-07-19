// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Validity-duration constants — the single source every layer cites (ADR-002, ADR-017).
//!
//! ADR-017's ladder: **identity is eternal** (the lineage + AINRA Number never expire); **credentials are
//! bounded** (each layer's lifetime shrinks with its blast radius); **renewal is invisible** (ACME-style at
//! T−`RENEWAL_LEAD_SECS`, overlap issuance, a logged REISSUE with `prev_leaf` continuity). Long passport
//! validity is affordable *because* revocation fails closed in <60 s — the opposite trade from Web PKI's
//! shrinking certificates. There is **no grace period anywhere**: expiry is expiry (a skewed or grace-extended
//! window would convert expiry into advice).
//!
//! ADR-016's ±30 s skew tolerance applies to **freshness-layer signed timestamps** (heads/checkpoints), never
//! to the passport validity window — the window comparison is exact: `nbf ≤ now < exp`.

/// Default passport validity — **366 days** (ADR-017). Leap-year-proof one year: a passport issued any calendar
/// day renews on or before the same day next year.
pub const PASSPORT_VALIDITY_DEFAULT_SECS: u64 = 366 * 24 * 60 * 60;

/// Renewal lead — REISSUE at **T−30 days** before `exp` (ADR-017's ACME-style rhythm). The lead is a client /
/// deployment cadence, not a protocol rule: the protocol only defines overlap issuance + `prev_leaf` continuity.
pub const RENEWAL_LEAD_SECS: u64 = 30 * 24 * 60 * 60;

/// Maximum delegate certificate lifetime — **≤ 92 days** (ADR-002). Enforced fail-closed at cert build AND at
/// verify ([`crate::checkpoint`], which re-exports this constant).
pub const DELEGATE_CERT_MAX_SECS: u64 = 92 * 24 * 60 * 60;

/// Default instance-credential lifetime — **1 hour** (ADR-017: minutes–hours). RESERVED: the instance-credential
/// layer (SPIFFE-style short-lived running-copy creds under the passport) is future work; the constant pins the
/// ADR-017 ceiling here so the ladder has one home and later machinery cannot invent its own number.
pub const INSTANCE_CRED_DEFAULT_SECS: u64 = 60 * 60;

#[cfg(test)]
// Asserting on constants is the entire point of these tests: they pin the ADR-017 ladder so a future edit to any
// one constant that breaks the ordering (or a silent value change) fails loudly instead of shipping.
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;

    /// The ADR-017 lifetime ladder is strictly ordered: instance ≪ delegate ≪ passport, and the renewal lead
    /// fits many times inside the passport window (a T−30 d rhythm on a 366 d credential).
    #[test]
    fn ladder_is_ordered() {
        assert!(INSTANCE_CRED_DEFAULT_SECS < DELEGATE_CERT_MAX_SECS);
        assert!(DELEGATE_CERT_MAX_SECS < PASSPORT_VALIDITY_DEFAULT_SECS);
        assert!(RENEWAL_LEAD_SECS < DELEGATE_CERT_MAX_SECS);
        assert!(PASSPORT_VALIDITY_DEFAULT_SECS / RENEWAL_LEAD_SECS >= 12);
    }

    #[test]
    fn exact_values() {
        assert_eq!(PASSPORT_VALIDITY_DEFAULT_SECS, 31_622_400); // 366 d
        assert_eq!(RENEWAL_LEAD_SECS, 2_592_000); // 30 d
        assert_eq!(DELEGATE_CERT_MAX_SECS, 7_948_800); // 92 d
        assert_eq!(INSTANCE_CRED_DEFAULT_SECS, 3_600); // 1 h
    }
}
