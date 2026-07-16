// SPDX-License-Identifier: Apache-2.0 OR MIT
//! base64url (unpadded) helpers — the single encoding used for all binary fields on the wire (MTS §15).
//! Constant-time codec from the audited `base64ct` crate; no bespoke base64.

use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64UrlUnpadded, Encoding};

use crate::error::{Error, Result};

/// Encode bytes as unpadded base64url.
pub fn encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Decode unpadded base64url; any malformed input is a [`Error::Malformed`].
pub fn decode(s: &str) -> Result<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(s).map_err(|_| Error::malformed("invalid base64url"))
}

/// Decode into a fixed-size array, rejecting a wrong length (e.g. a 33-byte "Ed25519 key").
pub fn decode_array<const N: usize>(s: &str) -> Result<[u8; N]> {
    let v = decode(s)?;
    v.try_into()
        .map_err(|_| Error::malformed("base64url wrong decoded length"))
}
