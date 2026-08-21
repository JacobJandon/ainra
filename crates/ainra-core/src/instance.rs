// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The fourth rung of ADR-017's validity ladder: the credential a **running copy** carries (ADR-019 / D-047).
//!
//! Before this module, a running container held the lineage's long-lived private key and presented a bundle that
//! every verifier accepted as a **bearer token** — whoever had the bytes was the agent, for the remainder of a
//! 366-day window, with the passport's full capabilities. This rung replaces that with a credential that is
//! **short** (≤1 h), **narrower** (capabilities ⊆ the passport's), and **holder-bound** (the presenter proves it
//! holds the instance key), while remaining **killable from outside**: revoking the passport kills every instance
//! under it through the status check that was already there.
//!
//! Two objects:
//!
//! * [`InstanceCredential`] — minted by the passport's control key, which never enters the container. It binds to
//!   the passport by that passport's *already-logged* leaf, so instance credentials need no log entries of their
//!   own while `logged-before-valid` keeps deciding something: a credential cannot be minted for a passport that
//!   was never logged.
//! * [`InstancePop`] — a proof-of-possession the presenter signs with the instance key at presentation time. This
//!   is what converts the presentation from bearer to holder-bound.
//!
//! What this rung does NOT do, stated here so nobody has to infer it: it does not make a compromised container
//! harmless. An attacker with live access holds the instance key and acts as the agent until the credential
//! expires. It makes that compromise bounded in time, bounded in scope, and killable — three things it was not.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::consts::INSTANCE_CRED_DEFAULT_SECS;
use crate::crypto::{self, HybridPublic, HybridSig};
use crate::verdict::Reason;

/// How far a proof-of-possession timestamp may sit from the verifier's clock, in seconds.
///
/// This is a **freshness-layer** tolerance, which is the only layer ADR-016 permits one at — the PoP `ts` is a
/// signed timestamp, exactly like a checkpoint's, and not a validity window. The instance credential's own
/// `nbf`/`exp` window is compared exactly, with no skew, like every other window in the system (ADR-017: expiry is
/// expiry). Conflating the two is how a grace period gets introduced by accident.
pub const POP_MAX_SKEW_SECS: u64 = 30;

/// A credential for one running copy of an agent, minted under a passport.
#[derive(Clone)]
pub struct InstanceCredential {
    /// The passport subject this copy runs under.
    pub sub: String,
    /// Opaque instance id. Non-PII by construction: random, never a hostname, never a user identifier.
    pub iid: String,
    /// The instance's OWN hybrid public key. The matching secret is the only key material in the container.
    pub ikey: HybridPublic,
    /// Validity window, compared exactly: `nbf ≤ now < exp`.
    pub nbf: u64,
    pub exp: u64,
    /// Capabilities for this copy. MUST be a subset of the passport's.
    pub capabilities: Vec<String>,
    /// The audience this credential may be presented to.
    pub aud: String,
    /// `prelog_leaf` of the passport claims — binds this credential to an already-logged passport.
    pub passport_leaf: [u8; 32],
    /// Hybrid signature by the PASSPORT's control key over [`InstanceCredential::signing_bytes`].
    pub sig: HybridSig,
}

/// The presenter's proof it holds the instance key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstancePop {
    /// MUST equal the credential's `aud` and the verifier's own audience.
    pub aud: String,
    /// Carried and signed. Enforcing single-use is the CALLER's business, not core's — a replay cache is state,
    /// and `ainra-core` is N7 (no I/O, no clock, no state). See [`verify_instance`]'s docs.
    pub nonce: String,
    /// When the presenter signed. Compared against the verifier's clock within [`POP_MAX_SKEW_SECS`].
    pub ts: u64,
    /// Hybrid signature by the INSTANCE key over [`InstancePop::signing_bytes`].
    pub sig: HybridSig,
}

fn b64u(bytes: &[u8]) -> String {
    crate::b64::encode(bytes)
}

impl InstanceCredential {
    /// Canonical bytes the passport's control key signs. Field order is fixed here and mirrored byte-for-byte by
    /// the TS and Python implementations; the four-way differential is what keeps them honest.
    pub fn signing_bytes(&self) -> core::result::Result<Vec<u8>, Reason> {
        let body = serde_json::json!({
            "aud": self.aud,
            "capabilities": self.capabilities,
            "exp": self.exp,
            "iid": self.iid,
            "ikey": { "ed25519": b64u(&self.ikey.ed25519), "mldsa65": b64u(&self.ikey.mldsa65) },
            "nbf": self.nbf,
            "passport_leaf": b64u(&self.passport_leaf),
            "sub": self.sub,
        });
        Ok(crate::canon::canonicalize(&body)
            .map_err(|_| Reason::InstanceSigInvalid)?
            .into_bytes())
    }
}

impl InstancePop {
    /// Canonical bytes the instance key signs.
    pub fn signing_bytes(&self) -> core::result::Result<Vec<u8>, Reason> {
        let body = serde_json::json!({ "aud": self.aud, "nonce": self.nonce, "ts": self.ts });
        Ok(crate::canon::canonicalize(&body)
            .map_err(|_| Reason::InstancePopInvalid)?
            .into_bytes())
    }
}

/// Verify the instance rung, in a fixed order, first-failure-wins.
///
/// # This function is MEANINGLESS on its own
///
/// It checks the instance credential **and nothing else**. It takes no status list, so it cannot see revocation;
/// it takes no checkpoint, so it cannot see whether the passport was ever logged. Handed a credential whose
/// lineage was revoked an hour ago it returns `Ok(())`, because deciding that is not its job.
///
/// The coupling ADR-019 promises — "revoking the passport kills every live instance" — is **ordinal**: it holds
/// because [`crate::verify::verify`] runs the nine passport steps first and never reaches step 10 when one of them
/// refuses. Call this directly and you have opted out of all nine. Callers wanting the guarantee must use
/// [`crate::verify::verify`]. Flagged by the M30 adversarial review, which observed that the obvious-looking name
/// invites exactly the misuse this paragraph exists to prevent.
///
/// Inputs the VERIFIER supplies and a presenter cannot influence: `now`, `expected_aud`, the passport's
/// `passport_key` and `passport_caps`, and `passport_leaf`. Everything else comes off the wire.
///
/// **Order is deliberate:** binding → window → scope → credential signature → proof-of-possession. Binding first,
/// because a credential minted for a different passport must be refused before any of its own claims are weighed;
/// signature before PoP, because a PoP over a credential that was never validly minted proves nothing.
///
/// **Single-use is NOT enforced here.** The nonce is bound into the signed bytes so a caller CAN enforce it, but
/// core holds no state by design (N7). A caller that needs single-use must keep the cache itself; a caller that
/// does not is exposed to replay inside the `ts` window, against this audience, by someone who already has the
/// bundle. That is stated plainly rather than papered over.
#[allow(clippy::too_many_arguments)]
pub fn verify_instance(
    ic: &InstanceCredential,
    pop: &InstancePop,
    passport_sub: &str,
    passport_caps: &[String],
    passport_leaf: &[u8; 32],
    passport_key: &HybridPublic,
    now: u64,
    expected_aud: &str,
) -> core::result::Result<(), Reason> {
    // (1) BINDING — this credential must belong to the passport that was actually presented and proven logged.
    // `passport_leaf` is recomputed by the caller from the presented claims, never taken from the wire.
    if ic.sub != passport_sub || &ic.passport_leaf != passport_leaf {
        return Err(Reason::InstanceSigInvalid);
    }

    // (2) WINDOW — exact, no skew (ADR-017: expiry is expiry), plus the ADR-019 ceiling enforced at VERIFY and not
    // merely at issuance, so a cooperative minter is not the only thing standing between us and a year-long
    // "instance" credential.
    if ic.exp <= ic.nbf || ic.exp - ic.nbf > INSTANCE_CRED_DEFAULT_SECS {
        return Err(Reason::InstanceExpired);
    }
    if now < ic.nbf || now >= ic.exp {
        return Err(Reason::InstanceExpired);
    }

    // (3) SCOPE — narrowing only. The ∩ rule one rung down from the delegation chain.
    if !ic
        .capabilities
        .iter()
        .all(|c| passport_caps.iter().any(|p| p == c))
    {
        return Err(Reason::InstanceScopeExceeds);
    }

    // (4) CREDENTIAL SIGNATURE — hybrid, both-or-invalid, under the PASSPORT's control key. `verify_hybrid`
    // returns AlgDowngrade on a missing half; at this rung that is still an instance-signature failure, and
    // mapping it keeps a debugging integrator at the right layer.
    let msg = ic.signing_bytes()?;
    crypto::verify_hybrid(passport_key, &msg, &ic.sig).map_err(|_| Reason::InstanceSigInvalid)?;

    // (5) PROOF-OF-POSSESSION — audience, freshness, then the signature under the INSTANCE key.
    if ic.aud != expected_aud || pop.aud != expected_aud {
        return Err(Reason::InstancePopInvalid);
    }
    if pop.ts.abs_diff(now) > POP_MAX_SKEW_SECS {
        return Err(Reason::InstancePopInvalid);
    }
    let pop_msg = pop.signing_bytes()?;
    crypto::verify_hybrid(&ic.ikey, &pop_msg, &pop.sig).map_err(|_| Reason::InstancePopInvalid)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::HybridKeypair;
    use rand_chacha::rand_core::SeedableRng;

    fn kp(seed: u8) -> HybridKeypair {
        HybridKeypair::generate(&mut rand_chacha::ChaCha20Rng::from_seed([seed; 32]))
    }

    struct Fix {
        ic: InstanceCredential,
        pop: InstancePop,
        pkey: HybridPublic,
        caps: Vec<String>,
        leaf: [u8; 32],
    }

    /// A credential and PoP that MUST verify. Every negative test below mutates exactly one thing about this
    /// fixture, so a failure names the field that caused it.
    fn good(now: u64) -> Fix {
        let passport = kp(1);
        let instance = kp(2);
        let leaf = [7u8; 32];
        let caps: Vec<String> = alloc::vec![String::from("read:x"), String::from("write:y")];
        let mut ic = InstanceCredential {
            sub: String::from("ainra:registrar-07:acme:billing@1.0.0"),
            iid: String::from("i-0f3a"),
            ikey: instance.public(),
            nbf: now - 60,
            exp: now + 600,
            capabilities: alloc::vec![String::from("read:x")],
            aud: String::from("https://api.example"),
            passport_leaf: leaf,
            sig: HybridSig {
                ed25519: alloc::vec![],
                mldsa65: alloc::vec![],
            },
        };
        ic.sig = passport.sign(&ic.signing_bytes().unwrap()).unwrap();
        let mut pop = InstancePop {
            aud: String::from("https://api.example"),
            nonce: String::from("n-1"),
            ts: now,
            sig: HybridSig {
                ed25519: alloc::vec![],
                mldsa65: alloc::vec![],
            },
        };
        pop.sig = instance.sign(&pop.signing_bytes().unwrap()).unwrap();
        Fix {
            ic,
            pop,
            pkey: passport.public(),
            caps,
            leaf,
        }
    }

    /// Run at a clock, re-signing the PoP AT that clock.
    ///
    /// Without this, a window test would change two things at once — the validity window AND the PoP's freshness —
    /// and the first version of `window_is_exact_with_no_skew` did exactly that: it moved the clock 599 s to reach
    /// `exp - 1` and got `InstancePopInvalid`, which is a true answer to a question the test was not asking. A test
    /// that cannot fail for the reason it names is as useless as one that cannot fail at all.
    fn run_at(f: &Fix, now: u64) -> core::result::Result<(), Reason> {
        let mut pop = f.pop.clone();
        pop.ts = now;
        pop.sig = kp(2).sign(&pop.signing_bytes().unwrap()).unwrap();
        verify_instance(
            &f.ic,
            &pop,
            "ainra:registrar-07:acme:billing@1.0.0",
            &f.caps,
            &f.leaf,
            &f.pkey,
            now,
            "https://api.example",
        )
    }

    fn run(f: &Fix, now: u64) -> core::result::Result<(), Reason> {
        verify_instance(
            &f.ic,
            &f.pop,
            "ainra:registrar-07:acme:billing@1.0.0",
            &f.caps,
            &f.leaf,
            &f.pkey,
            now,
            "https://api.example",
        )
    }

    // WITNESS: the acceptance case. Could it have seen a failure? Yes — every negative test below is the same
    // fixture with one field changed, and each returns a DIFFERENT reason. If this test were the only one, it
    // would be decoration: a verifier that returned Ok unconditionally would also pass it.
    #[test]
    fn good_instance_credential_verifies() {
        let now = 1_776_729_600;
        assert_eq!(run(&good(now), now), Ok(()));
    }

    // WITNESS: the window. Could it have seen a failure? Yes — the same fixture verifies at `now`, so the only
    // difference is the clock, and the boundary cases below prove the comparison is exact rather than fuzzy.
    #[test]
    fn window_is_exact_with_no_skew() {
        let now = 1_776_729_600;
        let f = good(now);
        assert_eq!(
            run_at(&f, f.ic.exp - 1),
            Ok(()),
            "last valid second must be VALID"
        );
        assert_eq!(
            run_at(&f, f.ic.exp),
            Err(Reason::InstanceExpired),
            "exp is exclusive"
        );
        assert_eq!(run_at(&f, f.ic.nbf), Ok(()), "nbf is inclusive");
        assert_eq!(
            run_at(&f, f.ic.nbf - 1),
            Err(Reason::InstanceExpired),
            "before nbf"
        );
        // The PoP skew tolerance must NOT leak into the validity window: one second past exp is expired even
        // though it is well inside POP_MAX_SKEW_SECS. This is the assertion that would catch someone "helpfully"
        // reusing the freshness skew here and turning expiry into advice.
        assert_eq!(
            run_at(&f, f.ic.exp + (POP_MAX_SKEW_SECS - 1)),
            Err(Reason::InstanceExpired)
        );
    }

    // WITNESS: the ADR-019 ceiling. Could it have seen a failure? Yes — the fixture's own 660 s window passes,
    // and only widening it past the ceiling flips this, so the check is reading the duration and not something else.
    #[test]
    fn lifetime_ceiling_is_enforced_at_verify_not_only_at_issuance() {
        let now = 1_776_729_600;
        let passport = kp(1);
        let mut f = good(now);
        f.ic.exp = f.ic.nbf + INSTANCE_CRED_DEFAULT_SECS + 1;
        f.ic.sig = passport.sign(&f.ic.signing_bytes().unwrap()).unwrap(); // re-sign: a VALID signature over a too-long window
        assert_eq!(run(&f, now), Err(Reason::InstanceExpired));
        // …and exactly at the ceiling it is accepted, which is what makes the line above mean "too long" rather
        // than "any window at all is rejected".
        f.ic.exp = f.ic.nbf + INSTANCE_CRED_DEFAULT_SECS;
        f.ic.sig = passport.sign(&f.ic.signing_bytes().unwrap()).unwrap();
        assert_eq!(run(&f, now), Ok(()));
    }

    // WITNESS: the ∩ rule. Could it have seen a failure? Yes — the fixture asks for a strict subset and passes;
    // asking for one capability the passport lacks is the only change here.
    #[test]
    fn capabilities_may_narrow_but_never_widen() {
        let now = 1_776_729_600;
        let passport = kp(1);
        let mut f = good(now);
        f.ic.capabilities = alloc::vec![String::from("read:x"), String::from("admin:everything")];
        f.ic.sig = passport.sign(&f.ic.signing_bytes().unwrap()).unwrap(); // properly signed, still refused
        assert_eq!(run(&f, now), Err(Reason::InstanceScopeExceeds));
        // The empty set is the narrowest possible narrowing and must be allowed — otherwise "narrowing only"
        // would quietly mean "narrowing, but not too much".
        f.ic.capabilities = alloc::vec![];
        f.ic.sig = passport.sign(&f.ic.signing_bytes().unwrap()).unwrap();
        assert_eq!(run(&f, now), Ok(()));
    }

    // WITNESS: the binding. Could it have seen a failure? Yes — the fixture's leaf matches and passes; a
    // credential minted under a different passport is the only difference, and it is refused before its own
    // (perfectly valid) signature is ever checked.
    #[test]
    fn credential_is_bound_to_the_passport_that_was_presented() {
        let now = 1_776_729_600;
        let passport = kp(1);
        let mut f = good(now);
        f.ic.passport_leaf = [9u8; 32];
        f.ic.sig = passport.sign(&f.ic.signing_bytes().unwrap()).unwrap();
        assert_eq!(
            run(&f, now),
            Err(Reason::InstanceSigInvalid),
            "different passport leaf"
        );
        let mut f2 = good(now);
        f2.ic.sub = String::from("ainra:registrar-07:acme:other@1.0.0");
        f2.ic.sig = passport.sign(&f2.ic.signing_bytes().unwrap()).unwrap();
        assert_eq!(
            run(&f2, now),
            Err(Reason::InstanceSigInvalid),
            "different subject"
        );
    }

    // WITNESS: the signer. Could it have seen a failure? Yes — the fixture is signed by the passport key and
    // passes; signing with any other key is refused even though the signature itself is perfectly well-formed.
    #[test]
    fn only_the_passports_control_key_may_mint() {
        let now = 1_776_729_600;
        let mut f = good(now);
        f.ic.sig = kp(3).sign(&f.ic.signing_bytes().unwrap()).unwrap(); // a real signature, wrong signer
        assert_eq!(run(&f, now), Err(Reason::InstanceSigInvalid));
    }

    // WITNESS: proof-of-possession. Could it have seen a failure? Yes — this is the check that makes the
    // credential holder-bound rather than bearer, so a PoP signed by anyone else must fail while the fixture's
    // own PoP passes. If this test could not fail, the rung would be bearer again and the milestone pointless.
    #[test]
    fn pop_must_be_signed_by_the_instance_key() {
        let now = 1_776_729_600;
        let mut f = good(now);
        f.pop.sig = kp(4).sign(&f.pop.signing_bytes().unwrap()).unwrap();
        assert_eq!(run(&f, now), Err(Reason::InstancePopInvalid));
    }

    // WITNESS: audience + PoP freshness. Could it have seen a failure? Yes — same fixture, one field moved.
    #[test]
    fn pop_binds_audience_and_time() {
        let now = 1_776_729_600;
        let instance = kp(2);
        let mut f = good(now);
        // Wrong audience: refused even with a valid signature over that wrong audience.
        f.pop.aud = String::from("https://elsewhere.example");
        f.pop.sig = instance.sign(&f.pop.signing_bytes().unwrap()).unwrap();
        assert_eq!(run(&f, now), Err(Reason::InstancePopInvalid));
        // Stale PoP, correctly signed.
        let mut f2 = good(now);
        f2.pop.ts = now - (POP_MAX_SKEW_SECS + 1);
        f2.pop.sig = instance.sign(&f2.pop.signing_bytes().unwrap()).unwrap();
        assert_eq!(run(&f2, now), Err(Reason::InstancePopInvalid));
        // …and just inside the tolerance it is accepted, so the line above means "too old" and not "any ts fails".
        let mut f3 = good(now);
        f3.pop.ts = now - POP_MAX_SKEW_SECS;
        f3.pop.sig = instance.sign(&f3.pop.signing_bytes().unwrap()).unwrap();
        assert_eq!(run(&f3, now), Ok(()));
    }

    // WITNESS: both-or-invalid at this rung. Could it have seen a failure? Yes — dropping either half of either
    // hybrid signature is refused, and the fixture with both halves passes.
    #[test]
    fn hybrid_is_both_or_invalid_at_this_rung_too() {
        let now = 1_776_729_600;
        let mut f = good(now);
        f.ic.sig.mldsa65.clear();
        assert_eq!(
            run(&f, now),
            Err(Reason::InstanceSigInvalid),
            "credential missing the PQ half"
        );
        let mut f2 = good(now);
        f2.pop.sig.ed25519.clear();
        assert_eq!(
            run(&f2, now),
            Err(Reason::InstancePopInvalid),
            "PoP missing the classical half"
        );
    }
}
