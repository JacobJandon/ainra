// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `witnessd` — an independent consistency cosigner (C2SP tlog-witness role). It remembers the last checkpoint it
//! cosigned for a log, and will cosign a NEW checkpoint only if the log proves — with an RFC 6962 consistency proof
//! — that the new tree is an append-only extension of the old one. A log that FORKS (rewrites history, or serves
//! two different roots at the same size) cannot produce such a proof, so the witness refuses and raises an alarm.
//! This is the "injected fork caught by them, not by us" property (MTS §29 DoD), demonstrated at M2 scale.
//!
//! All the security math (`verify_consistency`) is `ainra-core`'s; the witness only sequences and signs.

use std::collections::BTreeSet;

use ainra_core::checkpoint::{Checkpoint, CheckpointSig};
use ainra_core::crypto;

pub struct Witness {
    /// The witness's Ed25519 cosigning key (in production, an independently-operated key on separate infra).
    key: crypto::TestDelegate,
    /// Last checkpoint this witness cosigned, per log origin: (tree_size, root).
    seen: std::collections::BTreeMap<String, (u64, [u8; 32])>,
    /// The log's own SLH-DSA root public key, per origin — a witness cosigns only checkpoints the LOG itself
    /// signed (registered on first contact; a real witness gets this from the log's accreditation).
    log_keys: std::collections::BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WitnessOutcome {
    /// First time this witness has seen the log — trust-on-first-use; it records and cosigns.
    CosignedFirstSight,
    /// The new checkpoint is a proven append-only extension of the last one — cosigned.
    Cosigned,
    /// The log tried to move BACKWARDS (smaller tree) — refused.
    RefusedRegression,
    /// The consistency proof did not verify — a FORK. Refused + alarm.
    RefusedFork,
    /// The checkpoint is not validly signed by the log's own key — refused (review finding #11).
    RefusedUnsigned,
}

impl Witness {
    pub fn new(key: crypto::TestDelegate) -> Self {
        Self {
            key,
            seen: std::collections::BTreeMap::new(),
            log_keys: std::collections::BTreeMap::new(),
        }
    }

    pub fn public(&self) -> [u8; 32] {
        self.key.public()
    }

    /// Register the SLH-DSA root key a given log signs its checkpoints with. A real witness learns this from the
    /// log's accreditation; here it is set explicitly so the witness can authenticate what it cosigns.
    pub fn register_log(&mut self, origin: &str, log_root_key: Vec<u8>) {
        self.log_keys.insert(origin.to_string(), log_root_key);
    }

    /// Consider a new checkpoint for cosigning. It is cosigned only if (0) it is validly signed by the LOG's own
    /// key (a witness attests append-only growth of an *authenticated* log, review #11), and (1) it appends onto
    /// the last-seen checkpoint via a valid consistency proof (ignored on first sight). Returns the outcome; on
    /// `Cosigned*` the caller may read [`Self::cosign`]. `now` is for the delegate-cert window (ADR-002).
    pub fn consider(
        &mut self,
        cp: &Checkpoint,
        sig: &CheckpointSig,
        now: u64,
        consistency_proof: &[[u8; 32]],
    ) -> WitnessOutcome {
        // (0) the checkpoint must be validly signed by the log's own key (root or ADR-002 delegate mode).
        match self.log_keys.get(&cp.origin) {
            Some(log_key) if cp.verify_sig_mode(log_key, sig, now).is_ok() => {}
            _ => return WitnessOutcome::RefusedUnsigned,
        }
        match self.seen.get(&cp.origin).copied() {
            None => {
                self.seen.insert(cp.origin.clone(), (cp.tree_size, cp.root));
                WitnessOutcome::CosignedFirstSight
            }
            Some((last_size, last_root)) => {
                if cp.tree_size < last_size {
                    return WitnessOutcome::RefusedRegression;
                }
                if cp.tree_size == last_size {
                    // same size ⇒ must be the identical root, else it's an equivocation fork
                    if cp.root == last_root {
                        return WitnessOutcome::Cosigned;
                    }
                    return WitnessOutcome::RefusedFork;
                }
                if merkle_consistency(
                    last_size,
                    cp.tree_size,
                    &last_root,
                    &cp.root,
                    consistency_proof,
                ) {
                    self.seen.insert(cp.origin.clone(), (cp.tree_size, cp.root));
                    WitnessOutcome::Cosigned
                } else {
                    WitnessOutcome::RefusedFork
                }
            }
        }
    }

    /// The witness's cosignature over the checkpoint's canonical bytes (only meaningful after a `Cosigned*` outcome).
    pub fn cosign(&self, cp: &Checkpoint) -> Vec<u8> {
        self.key
            .sign(&cp.signing_bytes().expect("checkpoint bytes"))
    }
}

fn merkle_consistency(
    first: u64,
    second: u64,
    first_root: &[u8; 32],
    second_root: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    ainra_core::merkle::verify_consistency(first, second, first_root, second_root, proof)
}

// ── Witness quorum (MTS §29 DoD — "a fork caught by THEM, not by us", at k-of-N) ─────────────────────────────────
//
// One witness catching a fork is trust-in-one-operator. A **quorum** of N independently-keyed witnesses with a
// threshold k removes that single point of trust: a checkpoint is CERTIFIED only when ≥ k distinct witnesses cosign
// it. Because each honest witness refuses to cosign a checkpoint that forks the head it already cosigned, an
// equivocating fork can gather cosignatures from at most the adversarial/partitioned witnesses — so as long as fewer
// than k witnesses are adversarial, the fork can NEVER reach quorum while the honest head still can. The catch is
// the quorum's, verifiable by anyone holding the witness roster; we assert nothing.

/// A verifiable quorum certificate over one checkpoint: the cosignatures collected from a [`WitnessQuorum`]. A
/// relying party verifies each cosignature against its KNOWN witness-key roster; the checkpoint is
/// [`Self::certified`] iff at least the **relying party's own threshold** of **distinct, known** witnesses have a
/// **valid** cosignature. The cosignature covers the checkpoint's canonical signing bytes (the same bytes the log
/// signs).
///
/// SECURITY: the certificate deliberately carries **no threshold** of its own. The k-of-N threshold is the relying
/// party's trust *policy*, not the producer's — a certificate is an untrusted, third-party-transmittable artifact, so
/// if it named its own bar an equivocating log could author a certificate that sets `k = 0` and "certify" a fork with
/// zero honest cosignatures. The relying party always supplies its own `threshold` to [`Self::certified`].
#[derive(Debug, Clone)]
pub struct QuorumCertificate {
    pub origin: String,
    pub tree_size: u64,
    pub root: [u8; 32],
    /// `(witness Ed25519 public key, cosignature)` for every witness that cosigned this checkpoint.
    pub cosigners: Vec<([u8; 32], Vec<u8>)>,
}

impl QuorumCertificate {
    /// How many **distinct, known** witnesses have a **cryptographically valid** cosignature over `cp` here. A
    /// cosignature from a key not in `known`, a malformed/invalid signature, or a duplicate key does not count —
    /// fail-closed counting, so a certificate cannot be padded with junk or non-roster keys to fake a quorum.
    pub fn valid_cosigns(&self, cp: &Checkpoint, known: &BTreeSet<[u8; 32]>) -> usize {
        // The certificate must be ABOUT this exact checkpoint (origin+size+root), else it certifies nothing here.
        if cp.origin != self.origin || cp.tree_size != self.tree_size || cp.root != self.root {
            return 0;
        }
        let msg = match cp.signing_bytes() {
            Ok(m) => m,
            Err(_) => return 0,
        };
        let mut counted: BTreeSet<[u8; 32]> = BTreeSet::new();
        for (pk, sig) in &self.cosigners {
            if !known.contains(pk) || counted.contains(pk) {
                continue;
            }
            let s: [u8; crypto::ED25519_SIG] = match sig.as_slice().try_into() {
                Ok(s) => s,
                Err(_) => continue,
            };
            if crypto::ed25519_verify(pk, &msg, &s) {
                counted.insert(*pk);
            }
        }
        counted.len()
    }

    /// The checkpoint is certified iff ≥ `threshold` distinct known witnesses have a valid cosignature over it, where
    /// `threshold` is the **RELYING PARTY's** required k (not any value carried by the certificate) — so a
    /// certificate cannot lower its own bar to certify a fork.
    pub fn certified(&self, cp: &Checkpoint, known: &BTreeSet<[u8; 32]>, threshold: usize) -> bool {
        threshold >= 1 && self.valid_cosigns(cp, known) >= threshold
    }
}

/// A quorum of independently-keyed witnesses (C2SP tlog-witness role, k-of-N).
pub struct WitnessQuorum {
    witnesses: Vec<Witness>,
    threshold: usize,
}

impl WitnessQuorum {
    /// Build a quorum. `threshold` must be in `1..=witnesses.len()`.
    pub fn new(witnesses: Vec<Witness>, threshold: usize) -> Self {
        assert!(
            threshold >= 1 && threshold <= witnesses.len(),
            "quorum threshold must be within 1..=N"
        );
        Self {
            witnesses,
            threshold,
        }
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }
    pub fn len(&self) -> usize {
        self.witnesses.len()
    }
    pub fn is_empty(&self) -> bool {
        self.witnesses.is_empty()
    }

    /// The public keys of every witness in this quorum — a relying party's known-witness roster.
    pub fn roster(&self) -> BTreeSet<[u8; 32]> {
        self.witnesses.iter().map(|w| w.public()).collect()
    }

    /// Register the log's checkpoint-signing root key with every witness in the quorum.
    pub fn register_log(&mut self, origin: &str, log_root_key: Vec<u8>) {
        for w in &mut self.witnesses {
            w.register_log(origin, log_root_key.clone());
        }
    }

    /// Present a checkpoint to every witness; each independently accepts (append-only growth) or refuses (fork /
    /// regression / unsigned). Returns the [`QuorumCertificate`] (cosignatures of those that accepted) plus each
    /// witness's [`WitnessOutcome`] in roster order, so a drill can show exactly who refused a fork. The same
    /// `consistency_proof` is offered to every witness (valid when the quorum is in lock-step, as in the drill).
    pub fn certify(
        &mut self,
        cp: &Checkpoint,
        sig: &CheckpointSig,
        now: u64,
        consistency_proof: &[[u8; 32]],
    ) -> (QuorumCertificate, Vec<WitnessOutcome>) {
        let mut cosigners = Vec::new();
        let mut outcomes = Vec::with_capacity(self.witnesses.len());
        for w in &mut self.witnesses {
            let o = w.consider(cp, sig, now, consistency_proof);
            if matches!(
                o,
                WitnessOutcome::Cosigned | WitnessOutcome::CosignedFirstSight
            ) {
                cosigners.push((w.public(), w.cosign(cp)));
            }
            outcomes.push(o);
        }
        (
            QuorumCertificate {
                origin: cp.origin.clone(),
                tree_size: cp.tree_size,
                root: cp.root,
                cosigners,
            },
            outcomes,
        )
    }
}
