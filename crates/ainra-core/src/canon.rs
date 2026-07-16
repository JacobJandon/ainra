// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Canonical serialization — the one signing input (MTS §14, DECISIONS D-003).
//!
//! Scheme: recursively **sorted object keys**, **no whitespace**, standard JSON scalar escaping. This matches the
//! P0 cli-node's `cjson` so all three implementations byte-match (P-5) without editing P0. `serde_json`'s default
//! `Map` is a `BTreeMap`, so `to_string` already emits keys in sorted (byte/UTF-8) order; our keys are ASCII, so
//! that equals the JS `.sort()` order the P0 CLI uses.
//!
//! Three input classes are REJECTED because Rust (`serde_json` BTreeMap / UTF-8) and the P0 cli-node JS reference
//! (`Object.keys().sort()` / UTF-16, `JSON.stringify`) would diverge on them — the stricter reading (brief §8),
//! which keeps the byte-match property total instead of relying on an unenforced "keys are ASCII" premise:
//!   * **Floats** — `1` vs `1.0` renders differently across languages.
//!   * **Non-ASCII object keys** — JS `.sort()` orders by UTF-16 code units; serde_json's BTreeMap orders by UTF-8
//!     bytes (== Unicode scalar order). These agree for ASCII but DISAGREE for astral-plane (>U+FFFF) keys, so a
//!     non-ASCII key could canonicalize to a different byte order in Rust vs JS. We reject any non-ASCII key.
//!   * **Integers outside the JS safe range** (|n| > 2^53−1) — JS `JSON.stringify` cannot represent them exactly.
//!
//! The AINRA schema uses only ASCII keys, JS-safe integers, strings, booleans, and null, so none of this rejects a
//! conformant credential; it only closes cross-implementation drift.

use alloc::string::{String, ToString};
use serde::Serialize;
use serde_json::Value;

use crate::error::{Error, Result};

/// Largest integer JS `Number` represents exactly (`Number.MAX_SAFE_INTEGER`).
const JS_SAFE_INT_MAX: u64 = (1u64 << 53) - 1;

/// Canonicalize any `Serialize` value into the AINRA canonical byte string.
pub fn canonicalize<T: Serialize>(value: &T) -> Result<String> {
    let v = serde_json::to_value(value).map_err(|e| Error::Json(e.to_string()))?;
    canonicalize_value(&v)
}

/// Canonicalize an already-parsed JSON value.
pub fn canonicalize_value(v: &Value) -> Result<String> {
    validate_canonical(v)?;
    // serde_json::Map is a BTreeMap (default features) ⇒ `to_string` writes keys sorted, compact, no whitespace.
    serde_json::to_string(v).map_err(|e| Error::Canon(e.to_string()))
}

/// Reject the input classes on which Rust and the JS reference would produce different bytes (see module docs).
fn validate_canonical(v: &Value) -> Result<()> {
    match v {
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                if u > JS_SAFE_INT_MAX {
                    return Err(Error::Canon(
                        "integer exceeds the JS-safe range (2^53-1)".to_string(),
                    ));
                }
                Ok(())
            } else if let Some(i) = n.as_i64() {
                if i < -(JS_SAFE_INT_MAX as i64) {
                    return Err(Error::Canon(
                        "integer below the JS-safe range (-(2^53-1))".to_string(),
                    ));
                }
                Ok(())
            } else {
                // f64-only ⇒ a real float
                Err(Error::Canon(
                    "floating-point numbers are not allowed in canonical input".to_string(),
                ))
            }
        }
        Value::Array(a) => a.iter().try_for_each(validate_canonical),
        Value::Object(o) => {
            for (k, child) in o {
                if !k.is_ascii() {
                    return Err(Error::Canon(
                        "non-ASCII object keys are not allowed in canonical input".to_string(),
                    ));
                }
                validate_canonical(child)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// SHA-256 of the canonical bytes — the message digest fed to signers/verifiers.
pub fn canonical_digest<T: Serialize>(value: &T) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let s = canonicalize(value)?;
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let out = h.finalize();
    let mut d = [0u8; 32];
    d.copy_from_slice(&out);
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn golden_sorted_no_whitespace() {
        // Keys out of order + nested; canonical output is sorted, compact.
        let v = json!({"b": 1, "a": {"z": true, "y": [3, 2, 1]}, "c": "x\"q"});
        let got = canonicalize_value(&v).expect("canon");
        // Golden string (byte-for-byte): sorted keys at every level, no spaces, escaped quote preserved.
        assert_eq!(got, r#"{"a":{"y":[3,2,1],"z":true},"b":1,"c":"x\"q"}"#);
    }

    #[test]
    fn integers_are_stable_floats_rejected() {
        assert_eq!(
            canonicalize_value(&json!({"n": 1000000})).unwrap(),
            r#"{"n":1000000}"#
        );
        assert_eq!(
            canonicalize_value(&json!([0, -5, 42])).unwrap(),
            "[0,-5,42]"
        );
        assert!(canonicalize_value(&json!({"x": 1.5})).is_err());
        assert!(canonicalize_value(&json!(2.0)).is_err());
    }

    #[test]
    fn out_of_range_integers_rejected() {
        // JS Number.MAX_SAFE_INTEGER is exactly representable; one above it is not.
        assert!(canonicalize_value(&json!({"n": 9007199254740991u64})).is_ok()); // 2^53-1
        assert!(canonicalize_value(&json!({"n": 9007199254740992u64})).is_err()); // 2^53
        assert!(canonicalize_value(&json!({"n": u64::MAX})).is_err());
        assert!(canonicalize_value(&json!({"n": -9007199254740992i64})).is_err());
    }

    #[test]
    fn non_ascii_keys_rejected() {
        // ASCII keys canonicalize fine; a non-ASCII key (here an astral-plane emoji) is rejected because Rust and
        // the JS reference would sort it into a different position.
        assert!(canonicalize_value(&json!({"a": 1, "b": 2})).is_ok());
        assert!(canonicalize_value(&json!({"\u{1F600}": 1})).is_err()); // 😀
        assert!(canonicalize_value(&json!({"café": 1})).is_err()); // BMP non-ASCII too
                                                                   // nested non-ASCII key is also caught
        assert!(canonicalize_value(&json!({"outer": {"n아me": 1}})).is_err());
    }

    #[test]
    fn digest_is_over_canonical_bytes() {
        use sha2::{Digest, Sha256};
        let v = json!({"a": 1, "b": 2});
        let s = canonicalize_value(&v).unwrap();
        assert_eq!(s, r#"{"a":1,"b":2}"#);
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(canonical_digest(&v).unwrap(), want);
    }
}
