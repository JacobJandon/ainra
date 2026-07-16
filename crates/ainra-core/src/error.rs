// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Error taxonomy (MTS §6 engineering standards: `thiserror`; no `unwrap` outside tests).
//!
//! `Error` is the *operational* error type (malformed input, a not-yet-implemented path, an encoding failure).
//! It is distinct from a verification [`crate::Verdict`], which is a *domain result*: a well-formed credential
//! that is simply INVALID for a stated [`crate::Reason`] is NOT an `Error` — it is `Verdict::Invalid(reason)`.

use alloc::string::String;

/// Crate result alias.
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A name / passport / structure violated its grammar or schema. Carries the offending detail.
    #[error("malformed: {0}")]
    Malformed(String),

    /// A forbidden field (PII-shaped, `score`, or `price`) was present. Spec: brief §2, DECISIONS D-002.
    #[error("forbidden field: {0}")]
    ForbiddenField(String),

    /// Canonical-encoding failure. Spec: MTS §14, DECISIONS D-003.
    #[error("canonical encoding: {0}")]
    Canon(String),

    /// A JSON (de)serialization failure.
    #[error("json: {0}")]
    Json(String),

    /// A cryptographic dependency reported a value of the wrong size — treated as a broken dependency,
    /// never silently accepted. Spec: brief §3 (size-conformance asserts).
    #[error("crypto size: expected {expected} bytes, got {got}")]
    CryptoSize { expected: usize, got: usize },

    /// A path that is deliberately not implemented in this milestone. NEVER a mocked success (brief §0).
    /// The `&'static str` names the spec section that owns the future implementation.
    #[error("not implemented (M1): {0}")]
    NotImplemented(&'static str),
}

impl Error {
    /// Convenience constructor for malformed-input errors.
    pub fn malformed(msg: impl Into<String>) -> Self {
        Error::Malformed(msg.into())
    }
}
