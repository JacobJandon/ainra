// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Delegation chain evaluation — monotone ∩-narrowing (MTS §17).
//!
//! An `act_chain` records hops owner → agent → subagent …. Authority may only ever *shrink* along the chain:
//!   * **capabilities narrow** — each hop's `granted` set MUST be a subset of the delegator's effective set
//!     (a hop granting anything its delegator lacks is [`Reason::ChainWidening`]);
//!   * **expiry narrows** — each hop's `exp` MUST be ≤ the delegator's effective expiry ([`Reason::ChainExpired`]);
//!   * **both signatures** — each hop is signed by the delegator with the hybrid pair, verified over the hop's
//!     canonical bytes (a missing/failing signature is [`Reason::AlgDowngrade`]/[`Reason::SigInvalid`]).
//!
//! Capability matching is **exact-string** in M1 (the stricter reading, brief §8): hierarchical scopes like
//! `read:*` ⊇ `read:invoices` are NOT expanded here — a hop must name exactly what it inherited or a subset of it.
//! Hierarchical scope algebra is deferred to M2 (DECISIONS D-007) so we never *widen* by accident.

use alloc::string::String;
use alloc::vec::Vec;

use serde::Serialize;

use crate::passport::ActLink;
use crate::verdict::Reason;
use crate::{b64, canon, crypto};

/// The effective authority reached after walking a (prefix of a) chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    pub capabilities: Vec<String>,
    pub exp: u64,
}

/// Walk the chain applying ∩-narrowing, starting from the lineage's own `(capabilities, exp)`.
/// Returns the delegate's effective authority, or the first narrowing violation (evaluation order is fixed:
/// widening is checked before expiry within each hop, so the reason is deterministic across implementations).
pub fn narrow(
    root_caps: &[String],
    root_exp: u64,
    chain: &[ActLink],
) -> core::result::Result<Effective, Reason> {
    let mut eff: Vec<String> = root_caps.to_vec();
    let mut eff_exp = root_exp;
    for hop in chain {
        // capabilities may only shrink: granted ⊆ effective
        if !is_subset(&hop.granted, &eff) {
            return Err(Reason::ChainWidening);
        }
        // expiry may only shrink
        if hop.exp > eff_exp {
            return Err(Reason::ChainExpired);
        }
        eff = hop.granted.clone();
        eff_exp = hop.exp;
    }
    Ok(Effective {
        capabilities: eff,
        exp: eff_exp,
    })
}

fn is_subset(sub: &[String], sup: &[String]) -> bool {
    sub.iter().all(|c| sup.contains(c))
}

/// The exact bytes a delegation hop is signed over: `{exp, from, granted (as authored), to}`, canonicalized.
/// The signature fields themselves are excluded (a signature never signs itself).
#[derive(Serialize)]
struct HopSigning<'a> {
    from: &'a str,
    to: &'a str,
    granted: &'a [String],
    exp: u64,
}

/// The canonical bytes a delegation hop is signed over (delegator-side + verifier-side share this).
pub fn hop_signing_bytes(link: &ActLink) -> core::result::Result<Vec<u8>, Reason> {
    let s = canon::canonicalize(&HopSigning {
        from: &link.from,
        to: &link.to,
        granted: &link.granted,
        exp: link.exp,
    })
    .map_err(|_| Reason::SchemaViolation)?;
    Ok(s.into_bytes())
}

/// Verify BOTH parties' hybrid signatures on one hop (D-012 / Standard §6 A3 "every hop dual-signed"):
/// the DELEGATOR authorizes the grant, the DELEGATEE counter-signs to prove consent — both over the same
/// canonical hop bytes. Fixed order (deterministic reason): delegator downgrade→verify, then delegatee
/// downgrade→verify. Key resolution is the caller's job (hop-aligned, from the parties' passports).
pub fn verify_hop_sig(
    link: &ActLink,
    delegator_pk: &crypto::HybridPublic,
    delegatee_pk: &crypto::HybridPublic,
) -> core::result::Result<(), Reason> {
    let msg = hop_signing_bytes(link)?;
    let parent_sig = crypto::HybridSig {
        ed25519: b64::decode(&link.sig_ed25519).map_err(|_| Reason::AlgDowngrade)?,
        mldsa65: b64::decode(&link.sig_mldsa65).map_err(|_| Reason::AlgDowngrade)?,
    };
    crypto::verify_hybrid(delegator_pk, &msg, &parent_sig)?;
    let child_sig = crypto::HybridSig {
        ed25519: b64::decode(&link.sig_child_ed25519).map_err(|_| Reason::AlgDowngrade)?,
        mldsa65: b64::decode(&link.sig_child_mldsa65).map_err(|_| Reason::AlgDowngrade)?,
    };
    crypto::verify_hybrid(delegatee_pk, &msg, &child_sig)
}

/// The RFC 6962 leaf hash a hop's `log_leaf` MUST equal: `hash_leaf(canonical hop bytes)` — the same bytes both
/// parties sign, so the log anchors exactly what was authorized.
pub fn hop_leaf(link: &ActLink) -> core::result::Result<[u8; 32], Reason> {
    Ok(crate::merkle::hash_leaf(&hop_signing_bytes(link)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use rand_core::SeedableRng;

    fn caps(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn link(from: &str, to: &str, granted: &[&str], exp: u64) -> ActLink {
        ActLink {
            from: from.to_string(),
            to: to.to_string(),
            granted: caps(granted),
            exp,
            sig_ed25519: String::new(),
            sig_mldsa65: String::new(),
            sig_child_ed25519: String::new(),
            sig_child_mldsa65: String::new(),
            log_leaf: String::new(),
        }
    }

    /// Dual-sign a hop with the given delegator + delegatee keypairs and fill its log_leaf.
    fn sign_link(
        l: &mut ActLink,
        delegator: &crypto::HybridKeypair,
        delegatee: &crypto::HybridKeypair,
    ) {
        let msg = hop_signing_bytes(l).unwrap();
        let ps = delegator.sign(&msg).unwrap();
        l.sig_ed25519 = b64::encode(&ps.ed25519);
        l.sig_mldsa65 = b64::encode(&ps.mldsa65);
        let cs = delegatee.sign(&msg).unwrap();
        l.sig_child_ed25519 = b64::encode(&cs.ed25519);
        l.sig_child_mldsa65 = b64::encode(&cs.mldsa65);
        l.log_leaf = b64::encode(&hop_leaf(l).unwrap());
    }

    #[test]
    fn valid_chain_narrows() {
        let chain = [
            link(
                "ainra:registrar-01:acme:owner@1.0.0",
                "ainra:registrar-01:acme:agent@1.0.0",
                &["read:x", "write:x"],
                900,
            ),
            link(
                "ainra:registrar-01:acme:agent@1.0.0",
                "ainra:registrar-01:acme:sub@1.0.0",
                &["read:x"],
                800,
            ),
        ];
        let eff = narrow(&caps(&["read:x", "write:x", "admin:x"]), 1000, &chain).unwrap();
        assert_eq!(eff.capabilities, caps(&["read:x"]));
        assert_eq!(eff.exp, 800);
    }

    #[test]
    fn widening_is_rejected() {
        // hop grants write:x which the owner never held
        let chain = [link("a", "b", &["read:x", "write:x"], 900)];
        assert_eq!(
            narrow(&caps(&["read:x"]), 1000, &chain),
            Err(Reason::ChainWidening)
        );
    }

    #[test]
    fn expiry_extension_is_rejected() {
        let chain = [link("a", "b", &["read:x"], 1100)]; // beyond owner's 1000
        assert_eq!(
            narrow(&caps(&["read:x"]), 1000, &chain),
            Err(Reason::ChainExpired)
        );
    }

    #[test]
    fn hop_dual_signature_roundtrip_and_failures() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xDE_16_A7_10);
        let delegator = crypto::HybridKeypair::generate(&mut rng);
        let delegatee = crypto::HybridKeypair::generate(&mut rng);
        let (dpk, cpk) = (delegator.public(), delegatee.public());
        let mut l = link("a", "b", &["read:x"], 900);
        sign_link(&mut l, &delegator, &delegatee);
        assert_eq!(verify_hop_sig(&l, &dpk, &cpk), Ok(()));
        // the anchored leaf equals the recomputed hop leaf
        assert_eq!(
            b64::decode(&l.log_leaf).unwrap(),
            hop_leaf(&l).unwrap().to_vec()
        );

        // drop the delegator's PQ signature → alg_downgrade
        let mut m = l.clone();
        m.sig_mldsa65 = String::new();
        assert_eq!(verify_hop_sig(&m, &dpk, &cpk), Err(Reason::AlgDowngrade));

        // drop the DELEGATEE's counter-signature → alg_downgrade (consent is not optional)
        let mut m2 = l.clone();
        m2.sig_child_ed25519 = String::new();
        assert_eq!(verify_hop_sig(&m2, &dpk, &cpk), Err(Reason::AlgDowngrade));

        // the delegatee "counter-signature" was actually made by the delegator → sig_invalid
        let mut m3 = link("a", "b", &["read:x"], 900);
        sign_link(&mut m3, &delegator, &delegator); // both sigs by the delegator
        assert_eq!(verify_hop_sig(&m3, &dpk, &cpk), Err(Reason::SigInvalid));

        // tamper the granted set → both parties' signatures no longer match → sig_invalid
        let mut m4 = l.clone();
        m4.granted = caps(&["read:x", "write:x"]);
        assert_eq!(verify_hop_sig(&m4, &dpk, &cpk), Err(Reason::SigInvalid));
    }
}
