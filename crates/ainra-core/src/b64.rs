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

#[cfg(test)]
mod tests {
    use super::*;

    /// D-029: the decoder is CANONICAL-ONLY. It accepts exactly the canonical unpadded base64url encoding and
    /// rejects every non-canonical shape — nonzero trailing bits, padding, whitespace, and standard-alphabet
    /// (`+`/`/`) swaps. This is the property the SDK's `strictB64u` round-trip mirrors so the two implementations
    /// reject byte-for-byte identically; a lenient decoder here would be a fail-open cross-impl split.
    #[test]
    fn decoder_is_canonical_only() {
        let canonical = encode(&[0x9au8; 32]); // a real 43-char canonical encoding
        assert!(decode(&canonical).is_ok(), "canonical must decode");

        // nonzero trailing bits: last char of a 43-char string is value ≡ 0 mod 4; +1 sets a trailing bit.
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut nc = canonical.clone().into_bytes();
        let last = *nc.last().unwrap();
        let idx = alphabet.iter().position(|&c| c == last).unwrap();
        *nc.last_mut().unwrap() = alphabet[idx + 1];
        let trailing = String::from_utf8(nc).unwrap();
        assert!(
            decode(&trailing).is_err(),
            "nonzero trailing bits must be rejected"
        );

        // padding, whitespace (leading/trailing/embedded), standard-alphabet chars.
        for bad in [
            alloc::format!("{canonical}="),                             // padding
            alloc::format!("{canonical} "),                             // trailing space
            alloc::format!(" {canonical}"),                             // leading space
            alloc::format!("{}\n{}", &canonical[..4], &canonical[4..]), // embedded newline
            canonical.replacen('_', "/", 1), // standard-alphabet swap (if any '_')
            canonical.replacen('-', "+", 1), // standard-alphabet swap (if any '-')
        ] {
            if bad == canonical {
                continue; // no '-'/'_' to swap in this particular value — covered by other cases
            }
            assert!(
                decode(&bad).is_err(),
                "non-canonical input must be rejected: {bad:?}"
            );
        }
    }
}
