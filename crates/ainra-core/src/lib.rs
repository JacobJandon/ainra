// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// AINRA reference verify/issue core.
//
// This crate is THE product (MTS §23): it holds every consensus-critical type and the verify path —
// canonical encoding, hybrid sign/verify, delegation-chain + mandate evaluation, TSL/freshness, and RFC 6962
// Merkle inclusion. It performs NO I/O and has NO network dependency (N7 / brief §0): it is a pure library.
//
// The passport's nine steps run first; step 10 is the ADR-019 INSTANCE RUNG ([`instance`]), checked only when a
// presentation carries an instance credential — the short, narrowed, holder-bound credential a RUNNING COPY
// carries so it need not hold the lineage's key. The ordering is load-bearing: a revoked passport is refused at
// step 7 with `revoked`, so the reason names the lineage rather than the container.
//
// Prime directives encoded here (brief §0): nothing fake (unimplemented paths return a typed error, never a
// mocked success); both signatures or invalid (`alg_downgrade`); logged-before-valid (no VALID without a Merkle
// inclusion proof to a signed checkpoint); no bespoke cryptography (only the audited libraries in Cargo.toml).
//
// Spec anchors are cited inline as `// Spec: MTS §x` / `// Spec: Standard §x`.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

extern crate alloc;

pub mod b64;
pub mod canon;
pub mod chain;
pub mod checkpoint;
pub mod consts;
pub mod crypto;
pub mod directory;
pub mod error;
pub mod instance;
pub mod mandate;
pub mod merkle;
pub mod name;
pub mod passport;
pub mod status;
pub mod verdict;
pub mod verify;

pub use directory::{AccreditedSet, Directory, DirectoryEntry};
pub use error::{Error, Result};
pub use name::{AinraName, DID_METHOD};
pub use verdict::{Reason, Verdict};

/// The credential-type value every AINRA passport carries. Spec: MTS §15 / brief §2.
pub const PASSPORT_VCT: &str = "ainra/passport/v1";
