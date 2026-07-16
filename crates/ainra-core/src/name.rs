// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The AINRA namespace grammar.
//!
//! Spec: Standard §2, MTS §15, brief §2.
//! Canonical form: `ainra:{registrar}:{operator}:{lineage}@{version}`
//! DID form:       `did:ainra:{registrar}:{operator}:{lineage}`
//!
//! Rules (the stricter reading is taken per brief §8; deviations are noted):
//! * Each of `registrar`, `operator`, `lineage` is a *label*: 1–63 chars, `[a-z0-9-]`, and (stricter, DNS-LDH
//!   convention + confusable defense) MUST start and end with `[a-z0-9]` — no leading/trailing hyphen.
//! * Homoglyph defense: NFC-normalize then reject any non-ASCII. Our alphabet is pure ASCII, and pure-ASCII text
//!   is already in NFC, so "NFC then reject non-ASCII" reduces to "reject any non-ASCII byte" — which we do
//!   directly, catching every homoglyph (they are non-ASCII). Documented so no unicode-normalization dep is needed.
//! * `version` is 1–3 numeric fields (`major[.minor[.patch]]`), each ASCII digits with no leading zero (except `0`).
//! * Property: `parse ∘ format = identity` (proptest P in tests).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};

/// The DID method literal.
pub const DID_METHOD: &str = "did:ainra:";
const MAX_LABEL: usize = 63;

/// A parsed, validated AINRA name. Field bytes equal the input substrings, so `format` reproduces the input
/// exactly (round-trip identity).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AinraName {
    registrar: String,
    operator: String,
    lineage: String,
    version: String,
}

impl AinraName {
    pub fn registrar(&self) -> &str {
        &self.registrar
    }
    pub fn operator(&self) -> &str {
        &self.operator
    }
    pub fn lineage(&self) -> &str {
        &self.lineage
    }
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Parse the canonical `ainra:reg:op:lin@ver` form.
    // Spec: Standard §2 / brief §2.
    pub fn parse(s: &str) -> Result<Self> {
        let rest = s
            .strip_prefix("ainra:")
            .ok_or_else(|| Error::malformed("name must begin with `ainra:`"))?;
        let (body, version) = rest
            .rsplit_once('@')
            .ok_or_else(|| Error::malformed("name must contain `@version`"))?;
        let parts: Vec<&str> = body.split(':').collect();
        if parts.len() != 3 {
            return Err(Error::malformed(
                "name body must be exactly registrar:operator:lineage",
            ));
        }
        validate_label(parts[0], "registrar")?;
        validate_label(parts[1], "operator")?;
        validate_label(parts[2], "lineage")?;
        validate_version(version)?;
        Ok(AinraName {
            registrar: parts[0].to_string(),
            operator: parts[1].to_string(),
            lineage: parts[2].to_string(),
            version: version.to_string(),
        })
    }

    /// Parse the `did:ainra:reg:op:lin` form (carries no version).
    // Spec: MTS ADR-014.
    pub fn parse_did(s: &str) -> Result<(String, String, String)> {
        let rest = s
            .strip_prefix(DID_METHOD)
            .ok_or_else(|| Error::malformed("DID must begin with `did:ainra:`"))?;
        let parts: Vec<&str> = rest.split(':').collect();
        if parts.len() != 3 {
            return Err(Error::malformed(
                "DID must be did:ainra:registrar:operator:lineage",
            ));
        }
        validate_label(parts[0], "registrar")?;
        validate_label(parts[1], "operator")?;
        validate_label(parts[2], "lineage")?;
        Ok((
            parts[0].to_string(),
            parts[1].to_string(),
            parts[2].to_string(),
        ))
    }

    /// Render the canonical `ainra:reg:op:lin@ver` form.
    pub fn format(&self) -> String {
        alloc::format!(
            "ainra:{}:{}:{}@{}",
            self.registrar,
            self.operator,
            self.lineage,
            self.version
        )
    }

    /// Render the DID (`did:ainra:reg:op:lin`) — the versionless identity of the lineage.
    pub fn to_did(&self) -> String {
        alloc::format!(
            "did:ainra:{}:{}:{}",
            self.registrar,
            self.operator,
            self.lineage
        )
    }

    /// ADR-014 `did:web` mapping, for stock DID tooling: `did:web:{domain}:ainra:{reg}:{op}:{lin}`.
    /// `domain` is the registrar's serving domain (resolved out-of-band from the root-signed registrar directory —
    /// the core never resolves anything). The registrar id stays IN the path, so the mapping inverts without the
    /// directory. Pure string transform; no I/O (N7).
    pub fn to_did_web(&self, domain: &str) -> Result<String> {
        validate_domain(domain)?;
        Ok(alloc::format!(
            "did:web:{}:ainra:{}:{}:{}",
            domain,
            self.registrar,
            self.operator,
            self.lineage
        ))
    }

    /// Invert the ADR-014 mapping: `did:web:{domain}:ainra:{reg}:{op}:{lin}` → (domain, registrar, operator,
    /// lineage). Rejects anything that is not exactly that shape (fail closed — a did:web that merely LOOKS
    /// AINRA-ish must not silently half-parse).
    pub fn parse_did_web(s: &str) -> Result<(String, String, String, String)> {
        let rest = s
            .strip_prefix("did:web:")
            .ok_or_else(|| Error::malformed("missing did:web: prefix"))?;
        let parts: alloc::vec::Vec<&str> = rest.split(':').collect();
        if parts.len() != 5 || parts[1] != "ainra" {
            return Err(Error::malformed(
                "did:web form is did:web:{domain}:ainra:{reg}:{op}:{lin}",
            ));
        }
        validate_domain(parts[0])?;
        validate_label(parts[2], "registrar")?;
        validate_label(parts[3], "operator")?;
        validate_label(parts[4], "lineage")?;
        Ok((
            String::from(parts[0]),
            String::from(parts[2]),
            String::from(parts[3]),
            String::from(parts[4]),
        ))
    }
}

/// A serving domain for the did:web mapping: dot-separated LDH labels (each validated like a name label).
/// No ports/paths/percent-encoding — the registrar directory publishes bare hosts (stricter reading).
fn validate_domain(domain: &str) -> Result<()> {
    if domain.is_empty() || domain.len() > 253 {
        return Err(Error::malformed("domain length out of range"));
    }
    let labels: alloc::vec::Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return Err(Error::malformed("domain needs at least two labels"));
    }
    for l in &labels {
        validate_label(l, "domain label")?;
    }
    Ok(())
}

impl core::fmt::Display for AinraName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.format())
    }
}

/// A DNS-LDH-style label: 1–63 ASCII chars from `[a-z0-9-]`, no leading/trailing hyphen. Rejects all non-ASCII.
fn validate_label(label: &str, what: &str) -> Result<()> {
    if label.is_empty() {
        return Err(Error::malformed(alloc::format!("{what} label is empty")));
    }
    if label.len() > MAX_LABEL {
        return Err(Error::malformed(alloc::format!(
            "{what} label exceeds {MAX_LABEL} chars"
        )));
    }
    // `.len()` is byte length; any multibyte (non-ASCII) char makes byte-length > char-count, but we reject
    // non-ASCII per-char below regardless, so the 63 bound is on characters for the ASCII alphabet we allow.
    let bytes = label.as_bytes();
    for &b in bytes {
        let ok = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
        if !ok {
            return Err(Error::malformed(alloc::format!(
                "{what} label has an illegal character (only [a-z0-9-] ASCII allowed)"
            )));
        }
    }
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return Err(Error::malformed(alloc::format!(
            "{what} label may not start or end with a hyphen"
        )));
    }
    Ok(())
}

/// 1–3 numeric fields, each ASCII digits, no leading zero (except the single digit `0`).
fn validate_version(v: &str) -> Result<()> {
    if v.is_empty() {
        return Err(Error::malformed("version is empty"));
    }
    let fields: Vec<&str> = v.split('.').collect();
    if fields.is_empty() || fields.len() > 3 {
        return Err(Error::malformed("version must be 1–3 numeric fields"));
    }
    for f in fields {
        if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::malformed("version field must be ASCII digits"));
        }
        if f.len() > 1 && f.as_bytes()[0] == b'0' {
            return Err(Error::malformed("version field has a leading zero"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_round_trips() {
        let s = "ainra:registrar-07:acme:invoicing@4.2.1";
        let n = AinraName::parse(s).expect("valid");
        assert_eq!(n.registrar(), "registrar-07");
        assert_eq!(n.operator(), "acme");
        assert_eq!(n.lineage(), "invoicing");
        assert_eq!(n.version(), "4.2.1");
        assert_eq!(n.format(), s); // parse ∘ format = identity
        assert_eq!(n.to_did(), "did:ainra:registrar-07:acme:invoicing");
    }

    #[test]
    fn did_web_mapping_round_trips() {
        // ADR-014: did:web:{domain}:ainra:{reg}:{op}:{lin} ↔ the ainra identity, domain from the directory.
        let n = AinraName::parse("ainra:registrar-07:acme:invoicing@4.2.1").unwrap();
        let dw = n.to_did_web("registrar-07.example").unwrap();
        assert_eq!(
            dw,
            "did:web:registrar-07.example:ainra:registrar-07:acme:invoicing"
        );
        let (domain, reg, op, lin) = AinraName::parse_did_web(&dw).unwrap();
        assert_eq!(domain, "registrar-07.example");
        assert_eq!(
            (reg.as_str(), op.as_str(), lin.as_str()),
            ("registrar-07", "acme", "invoicing")
        );

        // rejections: bad domain, missing the ainra marker, wrong arity, non-ASCII domain
        assert!(n.to_did_web("nodots").is_err());
        assert!(n.to_did_web("UPPER.example").is_err());
        assert!(
            AinraName::parse_did_web("did:web:x.example:other:registrar-07:acme:invoicing")
                .is_err()
        );
        assert!(AinraName::parse_did_web("did:web:x.example:ainra:acme:invoicing").is_err());
        assert!(AinraName::parse_did_web("did:web:\u{0430}.example:ainra:r:o:l").is_err());
        assert!(AinraName::parse_did_web("did:ainra:registrar-07:acme:invoicing").is_err());
    }

    #[test]
    fn version_arities() {
        for v in ["1", "1.2", "1.2.3", "0", "0.1.0", "10.20.30"] {
            let s = alloc::format!("ainra:registrar-01:acme:lin@{v}");
            assert!(AinraName::parse(&s).is_ok(), "{v} should be valid");
        }
        for v in ["1.2.3.4", "01", "1.", ".1", "1.02", "v1", "1-2", ""] {
            let s = alloc::format!("ainra:registrar-01:acme:lin@{v}");
            assert!(AinraName::parse(&s).is_err(), "{v} should be invalid");
        }
    }

    #[test]
    fn rejects_homoglyphs_and_bad_labels() {
        // Cyrillic 'а' (U+0430) homoglyph of ASCII 'a' — must be rejected (non-ASCII).
        assert!(AinraName::parse("ainra:registrar-01:\u{0430}cme:lin@1").is_err());
        // uppercase, spaces, empty label, over-length, leading/trailing hyphen
        assert!(AinraName::parse("ainra:Registrar:acme:lin@1").is_err());
        assert!(AinraName::parse("ainra:registrar 1:acme:lin@1").is_err());
        assert!(AinraName::parse("ainra::acme:lin@1").is_err());
        assert!(AinraName::parse("ainra:-reg:acme:lin@1").is_err());
        assert!(AinraName::parse("ainra:reg-:acme:lin@1").is_err());
        let long = "a".repeat(64);
        assert!(AinraName::parse(&alloc::format!("ainra:{long}:acme:lin@1")).is_err());
        assert!(AinraName::parse(&alloc::format!("ainra:{}:acme:lin@1", "a".repeat(63))).is_ok());
        // wrong shape
        assert!(AinraName::parse("ainra:reg:acme@1").is_err());
        assert!(AinraName::parse("ainra:reg:acme:lin:extra@1").is_err());
        assert!(AinraName::parse("reg:acme:lin@1").is_err());
        assert!(AinraName::parse("ainra:reg:acme:lin").is_err());
    }

    #[test]
    fn did_round_trip() {
        let (r, o, l) =
            AinraName::parse_did("did:ainra:registrar-07:acme:invoicing").expect("valid did");
        assert_eq!(
            (r.as_str(), o.as_str(), l.as_str()),
            ("registrar-07", "acme", "invoicing")
        );
        assert!(AinraName::parse_did("did:web:example.com").is_err());
        assert!(AinraName::parse_did("did:ainra:reg:acme").is_err());
    }

    proptest::proptest! {
        // P: parse ∘ format = identity, over generated valid names.
        #[test]
        fn prop_round_trip(
            reg in "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?",
            op  in "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?",
            lin in "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?",
            maj in 0u32..1000, min in 0u32..1000, pat in 0u32..1000,
        ) {
            let s = alloc::format!("ainra:{reg}:{op}:{lin}@{maj}.{min}.{pat}");
            let n = AinraName::parse(&s).expect("generated name must parse");
            proptest::prop_assert_eq!(n.format(), s);
        }
    }
}
