// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AINRA M2 reference services, thin over `ainra-core` (which owns every consensus-critical primitive: RFC 6962
//! Merkle inclusion + consistency, hybrid + SLH-DSA signing, the ADR-002 delegate signer). Nothing security-critical
//! is reimplemented here — these daemons persist, sequence, and serve; they do not decide validity by their own
//! logic. Production `logd` swaps its storage for Tessera (DECISIONS D-011); the RFC 6962 semantics are identical
//! because they come from the same core.

pub mod http;
pub mod log;
pub mod registrar;
pub mod status;
pub mod tree;
pub mod witness;
