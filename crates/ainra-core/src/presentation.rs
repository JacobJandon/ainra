// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9421 HTTP Message Signatures for an AINRA presentation (D-062) — the core's statement of the profile.
//!
//! The TypeScript SDK implemented this first, which is the wrong way round for this repository: the corpus is what
//! makes four implementations agree, and the core generates the corpus (PLAN-M34 Task 3–4). This module is the
//! profile stated in the core, so `vectors/v1-presentation` can say what the answer is and every implementation can
//! be held to it.
//!
//! WHO SIGNS. The running copy's instance key; `keyid` names the instance credential (ADR-019, D-062).
//!
//! WHAT IS COVERED, exactly and in this order: `@method`, `@authority`, `@path`, `content-digest` when there is a
//! body, and the presentation header. Parameters `created`, `keyid`, `alg`, `nonce`. The parser accepts exactly
//! the shape this profile emits and refuses everything else — a permissive parser at a trust root's front door is a
//! liability.
//!
//! THE ORDER OF CHECKS IS PART OF THE PROFILE, because it decides which reason a request that is wrong in several
//! ways receives, and implementations must agree on the reason, not only on "invalid": signature headers present →
//! `signature-input` shape → `alg` → `keyid` → covered set → freshness → body digest → signature field → signature →
//! nonce. The nonce is checked LAST, and only after the signature verified: checking it first would let an
//! unauthenticated caller fill someone else's replay cache.
//!
//! WHAT IT DOES NOT DO. It holds no state (N7), so it cannot remember nonces: a caller passes `seen`, and without it
//! a captured signature stays usable against that exact target for the acceptance window. It binds a presentation to
//! one method, host and path inside five minutes; that is a bound, not a cure.

extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64, Base64Unpadded, Encoding};
use sha2::{Digest, Sha256};

use crate::crypto::{self, HybridKeypair, HybridPublic, HybridSig, ED25519_SIG, MLDSA65_SIG};
use crate::error::{Error, Result};

/// The label AINRA signs under.
pub const SIG_LABEL: &str = "ainra";
/// Private-use algorithm name for the hybrid: both signatures, concatenated at fixed lengths.
pub const SIG_ALG: &str = "ainra-hybrid-v1";
/// The header a presentation (or, since D-065, its digest reference) travels in. Covered by the signature.
pub const PRESENTATION_HEADER: &str = "x-ainra-passport";
/// Acceptance window (MTS T-P3).
pub const MAX_AGE_SECS: u64 = 300;
/// Tolerance for a signer whose clock runs ahead.
pub const MAX_FUTURE_SECS: u64 = 30;

/// Why a request's signature was refused. A SEPARATE vocabulary from the frozen credential reasons on purpose: a
/// perfectly good credential on a request it was not signed for is not `sig_invalid` (D-047, D-062).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresentationReason {
    Unsigned,
    SigInvalid,
    Stale,
    Replayed,
}

impl PresentationReason {
    pub const ALL: [PresentationReason; 4] = [
        PresentationReason::Unsigned,
        PresentationReason::SigInvalid,
        PresentationReason::Stale,
        PresentationReason::Replayed,
    ];
    pub fn as_str(&self) -> &'static str {
        match self {
            PresentationReason::Unsigned => "presentation_unsigned",
            PresentationReason::SigInvalid => "presentation_sig_invalid",
            PresentationReason::Stale => "presentation_stale",
            PresentationReason::Replayed => "presentation_replayed",
        }
    }
}

/// The request, reduced to what gets signed. Header names are matched case-insensitively; the FIRST matching
/// header wins, and its value is trimmed (RFC 9421 §2.1).
pub struct SignableRequest<'a> {
    pub method: &'a str,
    /// host or host:port — no scheme, no path.
    pub authority: &'a str,
    /// path with its query, exactly as sent.
    pub path: &'a str,
    pub headers: &'a [(String, String)],
    pub body: Option<&'a [u8]>,
}

impl SignableRequest<'_> {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim())
    }
    fn has_body(&self) -> bool {
        self.body.is_some_and(|b| !b.is_empty())
    }
}

/// `sha-256=:<base64>:` — RFC 9530.
pub fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", Base64::encode_string(&Sha256::digest(body)))
}

/// The components AINRA covers, in order.
pub fn covered_components(has_body: bool) -> &'static [&'static str] {
    if has_body {
        &[
            "@method",
            "@authority",
            "@path",
            "content-digest",
            PRESENTATION_HEADER,
        ]
    } else {
        &["@method", "@authority", "@path", PRESENTATION_HEADER]
    }
}

/// RFC 9421 §2.5 signature base. `None` when a covered component is absent: an unsignable request.
pub fn signature_base(
    req: &SignableRequest<'_>,
    components: &[&str],
    created: u64,
    keyid: &str,
    nonce: &str,
) -> Option<String> {
    let mut lines: Vec<String> = Vec::with_capacity(components.len() + 1);
    for c in components {
        let v: String = match *c {
            "@method" => req.method.to_uppercase(),
            "@authority" => req.authority.to_lowercase(),
            "@path" => req.path.into(),
            other if other.starts_with('@') => return None,
            other => req.header(other)?.into(),
        };
        lines.push(format!("\"{c}\": {v}"));
    }
    let list: Vec<String> = components.iter().map(|c| format!("\"{c}\"")).collect();
    lines.push(format!(
        "\"@signature-params\": ({});created={created};keyid=\"{keyid}\";alg=\"{SIG_ALG}\";nonce=\"{nonce}\"",
        list.join(" ")
    ));
    Some(lines.join("\n"))
}

struct Params<'s> {
    components: Vec<&'s str>,
    created: u64,
    keyid: &'s str,
    alg: &'s str,
    nonce: &'s str,
}

/// Take a `"`-free quoted run of `min..=max` characters, returning it and the rest after the closing quote.
fn quoted(s: &str, max: usize, ok: impl Fn(char) -> bool) -> Option<(&str, &str)> {
    let end = s.find('"')?;
    let v = &s[..end];
    let n = v.chars().count();
    if n == 0 || n > max || !v.chars().all(ok) {
        return None;
    }
    Some((v, &s[end + 1..]))
}

/// Parse exactly `ainra=(<list>);created=<1–15 digits>;keyid="<1–64>";alg="<1–32>";nonce="<1–128 of A-Za-z0-9._~->"`.
fn parse_input(input: &str) -> Option<Params<'_>> {
    let rest = input.strip_prefix("ainra=(")?;
    let close = rest.find(')')?;
    let list = &rest[..close];
    let rest = rest[close..].strip_prefix(");created=")?;
    let digits = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    if digits == 0 || digits > 15 {
        return None;
    }
    let created: u64 = rest[..digits].parse().ok()?;
    let rest = rest[digits..].strip_prefix(";keyid=\"")?;
    let (keyid, rest) = quoted(rest, 64, |_| true)?;
    let rest = rest.strip_prefix(";alg=\"")?;
    let (alg, rest) = quoted(rest, 32, |_| true)?;
    let rest = rest.strip_prefix(";nonce=\"")?;
    let (nonce, rest) = quoted(rest, 128, |c| {
        c.is_ascii_alphanumeric() || "._~-".contains(c)
    })?;
    if !rest.is_empty() {
        return None;
    }
    // Split on single spaces and drop one surrounding quote each side — exactly what the TS profile does.
    let components = if list.is_empty() {
        Vec::new()
    } else {
        list.split(' ')
            .map(|s| {
                let s = s.strip_prefix('"').unwrap_or(s);
                s.strip_suffix('"').unwrap_or(s)
            })
            .collect()
    };
    Some(Params {
        components,
        created,
        keyid,
        alg,
        nonce,
    })
}

/// `ainra=:<standard base64>:` → the 3373 signature bytes. Padding is optional, as in the TS profile.
fn parse_signature(field: &str) -> Option<HybridSig> {
    let inner = field.strip_prefix("ainra=:")?.strip_suffix(':')?;
    let body = inner.trim_end_matches('=');
    if body.is_empty()
        || inner.len() - body.len() > 2
        || !body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
    {
        return None;
    }
    let raw = Base64Unpadded::decode_vec(body).ok()?;
    if raw.len() != ED25519_SIG + MLDSA65_SIG {
        return None;
    }
    Some(HybridSig {
        ed25519: raw[..ED25519_SIG].to_vec(),
        mldsa65: raw[ED25519_SIG..].to_vec(),
    })
}

/// Verify the signature over a request, for the instance credential `iid` whose key is `ikey`.
///
/// Returns `(nonce, created)` on success so the caller can keep the replay cache this layer cannot. `seen` is asked
/// only after the signature is known good.
pub fn verify_presentation(
    req: &SignableRequest<'_>,
    iid: &str,
    ikey: &HybridPublic,
    now: u64,
    max_age_secs: u64,
    mut seen: impl FnMut(&str) -> bool,
) -> core::result::Result<(String, u64), PresentationReason> {
    use PresentationReason::*;
    let (Some(input), Some(signature)) = (req.header("signature-input"), req.header("signature"))
    else {
        return Err(Unsigned);
    };
    let p = parse_input(input).ok_or(SigInvalid)?;
    if p.alg != SIG_ALG || p.keyid != iid {
        return Err(SigInvalid);
    }
    let has_body = req.has_body();
    if p.components.as_slice() != covered_components(has_body) {
        return Err(SigInvalid);
    }
    let age = i128::from(now) - i128::from(p.created);
    if age > i128::from(max_age_secs) || -age > i128::from(MAX_FUTURE_SECS) {
        return Err(Stale);
    }
    if has_body {
        let expected = content_digest(req.body.unwrap_or_default());
        if req.header("content-digest") != Some(expected.as_str()) {
            return Err(SigInvalid);
        }
    }
    let sig = parse_signature(signature).ok_or(SigInvalid)?;
    let base = signature_base(req, &p.components, p.created, p.keyid, p.nonce).ok_or(SigInvalid)?;
    crypto::verify_hybrid(ikey, base.as_bytes(), &sig).map_err(|_| SigInvalid)?;
    if seen(p.nonce) {
        return Err(Replayed);
    }
    Ok((p.nonce.into(), p.created))
}

/// Sign a request with a running copy's instance key. Returns the headers to add, in order: `content-digest` (only
/// when there is a body), `signature-input`, `signature`. The vector generator and the tests use this; a real agent
/// signs with its own key through an SDK.
pub fn sign_presentation(
    req: &SignableRequest<'_>,
    keyid: &str,
    nonce: &str,
    created: u64,
    key: &HybridKeypair,
) -> Result<Vec<(String, String)>> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut headers: Vec<(String, String)> = req.headers.to_vec();
    if req.has_body() {
        let d = content_digest(req.body.unwrap_or_default());
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-digest"));
        headers.push(("content-digest".into(), d.clone()));
        out.push(("content-digest".into(), d));
    }
    let components = covered_components(req.has_body());
    let view = SignableRequest {
        headers: &headers,
        ..*req
    };
    let base = signature_base(&view, components, created, keyid, nonce)
        .ok_or_else(|| Error::malformed("cannot sign: a covered component is missing"))?;
    let sig = key.sign(base.as_bytes())?;
    let mut joined = Vec::with_capacity(ED25519_SIG + MLDSA65_SIG);
    joined.extend_from_slice(&sig.ed25519);
    joined.extend_from_slice(&sig.mldsa65);
    let list: Vec<String> = components.iter().map(|c| format!("\"{c}\"")).collect();
    out.push((
        "signature-input".into(),
        format!("{SIG_LABEL}=({});created={created};keyid=\"{keyid}\";alg=\"{SIG_ALG}\";nonce=\"{nonce}\"", list.join(" ")),
    ));
    out.push((
        "signature".into(),
        format!("{SIG_LABEL}=:{}:", Base64::encode_string(&joined)),
    ));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use rand_chacha::rand_core::SeedableRng;

    const NOW: u64 = 1_775_866_600;

    fn key(seed: u64) -> HybridKeypair {
        HybridKeypair::generate(&mut rand_chacha::ChaCha20Rng::seed_from_u64(seed))
    }
    fn base_headers() -> Vec<(String, String)> {
        vec![(
            PRESENTATION_HEADER.into(),
            "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:".into(),
        )]
    }
    fn signed(
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        k: &HybridKeypair,
        created: u64,
    ) -> Vec<(String, String)> {
        let h = base_headers();
        let req = SignableRequest {
            method,
            authority: "shop.example",
            path,
            headers: &h,
            body,
        };
        let mut all = h.clone();
        for (n, v) in sign_presentation(&req, "i-1", "n-1", created, k).unwrap() {
            all.retain(|(k2, _)| !k2.eq_ignore_ascii_case(&n));
            all.push((n, v));
        }
        all
    }
    fn check(
        method: &str,
        path: &str,
        h: &[(String, String)],
        body: Option<&[u8]>,
        k: &HybridPublic,
    ) -> core::result::Result<(String, u64), PresentationReason> {
        let req = SignableRequest {
            method,
            authority: "shop.example",
            path,
            headers: h,
            body,
        };
        verify_presentation(&req, "i-1", k, NOW, MAX_AGE_SECS, |_| false)
    }

    #[test]
    fn a_signed_request_verifies_and_returns_its_nonce() {
        let k = key(1);
        let h = signed("POST", "/orders", Some(b"{\"q\":1}"), &k, NOW);
        assert_eq!(
            check("POST", "/orders", &h, Some(b"{\"q\":1}"), &k.public()),
            Ok(("n-1".into(), NOW))
        );
        let g = signed("GET", "/orders", None, &k, NOW);
        assert!(check("GET", "/orders", &g, None, &k.public()).is_ok());
    }

    #[test]
    fn each_thing_moved_is_refused_by_name() {
        let k = key(1);
        let pk = k.public();
        let h = signed("POST", "/orders", Some(b"x"), &k, NOW);
        assert_eq!(
            check("POST", "/admin", &h, Some(b"x"), &pk),
            Err(PresentationReason::SigInvalid),
            "moved path"
        );
        assert_eq!(
            check("PUT", "/orders", &h, Some(b"x"), &pk),
            Err(PresentationReason::SigInvalid),
            "altered method"
        );
        assert_eq!(
            check("POST", "/orders", &h, Some(b"y"), &pk),
            Err(PresentationReason::SigInvalid),
            "altered body"
        );
        assert_eq!(
            check("POST", "/orders", &h, Some(b"x"), &key(2).public()),
            Err(PresentationReason::SigInvalid),
            "wrong key"
        );
        assert_eq!(
            check("POST", "/orders", &base_headers(), Some(b"x"), &pk),
            Err(PresentationReason::Unsigned)
        );
    }

    #[test]
    fn freshness_is_bounded_both_ways_and_inclusive_at_the_edges() {
        let k = key(1);
        let pk = k.public();
        for (created, ok) in [
            (NOW - 300, true),
            (NOW - 301, false),
            (NOW + 30, true),
            (NOW + 31, false),
        ] {
            let h = signed("GET", "/", None, &k, created);
            assert_eq!(
                check("GET", "/", &h, None, &pk).is_ok(),
                ok,
                "created = now {:+}",
                created as i128 - NOW as i128
            );
        }
    }

    #[test]
    fn the_nonce_is_asked_only_after_the_signature_holds() {
        let k = key(1);
        let pk = k.public();
        let h = signed("GET", "/", None, &k, NOW);
        let req = SignableRequest {
            method: "GET",
            authority: "shop.example",
            path: "/",
            headers: &h,
            body: None,
        };
        assert_eq!(
            verify_presentation(&req, "i-1", &pk, NOW, MAX_AGE_SECS, |_| true),
            Err(PresentationReason::Replayed)
        );
        let mut asked = false;
        let moved = SignableRequest { path: "/x", ..req };
        let r = verify_presentation(&moved, "i-1", &pk, NOW, MAX_AGE_SECS, |_| {
            asked = true;
            true
        });
        assert_eq!(r, Err(PresentationReason::SigInvalid));
        assert!(
            !asked,
            "an unauthenticated request must never reach the replay cache"
        );
    }

    #[test]
    fn one_valid_half_is_not_a_signature() {
        let k = key(1);
        let pk = k.public();
        let h = signed("GET", "/", None, &k, NOW);
        let sig = h.iter().find(|(n, _)| n == "signature").unwrap().1.clone();
        let raw = Base64::decode_vec(
            sig.strip_prefix("ainra=:")
                .unwrap()
                .strip_suffix(':')
                .unwrap(),
        )
        .unwrap();
        for zero in [0..ED25519_SIG, ED25519_SIG..raw.len()] {
            let mut r = raw.clone();
            for b in &mut r[zero] {
                *b = 0;
            }
            let mut h2 = h.clone();
            h2.retain(|(n, _)| n != "signature");
            h2.push((
                "signature".into(),
                format!("ainra=:{}:", Base64::encode_string(&r)),
            ));
            assert_eq!(
                check("GET", "/", &h2, None, &pk),
                Err(PresentationReason::SigInvalid)
            );
        }
    }
}
