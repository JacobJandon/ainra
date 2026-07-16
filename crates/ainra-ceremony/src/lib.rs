// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AINRA root ceremony — the SIGNING side (never in the verify path).
//!
//! FROST 5-of-9 threshold Ed25519 (`frost`) + an SLH-DSA-SHA2-128s ceremony root produce the **dual-root-signed
//! genesis directory** and delegate certificates. The verify path (`ainra-core`) sees only standard Ed25519 +
//! SLH-DSA signatures — it never links against FROST. See `bin/ceremony.rs` for the orchestrated rehearsal.

pub mod ceremony;
pub mod frost;
