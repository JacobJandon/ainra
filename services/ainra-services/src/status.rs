// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `statusd` — a Token Status List publisher (draft-ietf-oauth-status-list). Maintains a 1-bit-per-lineage list,
//! signs the compressed list with the registrar's hybrid key together with an `issued_at` timestamp, and serves it.
//! The codec + fail-closed freshness semantics are `ainra-core`'s; this service only owns the mutable bit vector
//! and the publish/sign cadence.
//!
//! M3 (ADR-007 / MTS §16): the publisher also emits **signed deltas** and a **30-second fresh head**. A revocation
//! now produces a `StatusDelta` (registrar-signed + delegate-countersigned) that advances a monotonic `seq`; clients
//! that hold an older head fetch only the deltas since their `seq` instead of the whole list. The fresh head is a
//! tiny delegate-signed statement of the current head identity, refreshed every ≤30 s so a withheld list/stream
//! fails closed. All delta/head crypto is `ainra-core`'s [`status::StatusDelta`] / [`status::FreshHead`]; this
//! service only sequences and serves.

use ainra_core::checkpoint::{DelegateCert, SCOPE_DELTA, SCOPE_FRESH_HEAD};
use ainra_core::{b64, canon, crypto, status};
use serde::{Deserialize, Serialize};

/// The online delegate that countersigns deltas and signs fresh heads (ADR-002). Present iff the publisher was
/// configured with [`Statusd::with_delegate`]; without it the publisher still serves the full signed list but
/// cannot emit the delta stream or fresh heads (and says so, rather than faking them).
struct DeltaSigner {
    delegate: crypto::TestDelegate,
    cert: DelegateCert,
    root_pub: Vec<u8>,
}

pub struct Statusd {
    uri: String,
    bits: Vec<bool>,
    signer: crypto::HybridKeypair,
    /// Monotonic head sequence. Starts at 0; each accepted delta advances it by exactly one.
    seq: u64,
    /// Every delta emitted, in order — replayed to clients via `deltas_since`.
    delta_log: Vec<status::StatusDelta>,
    delta_signer: Option<DeltaSigner>,
}

/// A signed status-list publication: the compressed list, its length, when it was issued, and the hybrid signature
/// over all of that. A verifier checks the signature, then the freshness of `issued_at` against its class.
#[derive(Serialize, Deserialize, Clone)]
pub struct SignedStatusList {
    pub uri: String,
    pub status_list_b64: String,
    pub bit_len: u64,
    pub issued_at: u64,
    pub sig_ed25519: String,
    pub sig_mldsa65: String,
}

#[derive(Serialize)]
struct StatusSigning<'a> {
    bit_len: u64,
    issued_at: u64,
    status_list: &'a str,
    uri: &'a str,
}

impl Statusd {
    pub fn new(uri: &str, len: usize, signer: crypto::HybridKeypair) -> Self {
        Self {
            uri: uri.to_string(),
            bits: vec![false; len],
            signer,
            seq: 0,
            delta_log: Vec::new(),
            delta_signer: None,
        }
    }

    /// Enable the delta stream + fresh heads by installing a root-certified online delegate. The `root` certifies
    /// the `delegate` for BOTH `delta-countersign` and `fresh-head` over `[now, now + validity]` (validity ≤ 92
    /// days, enforced by the core). Without this, `revoke_delta`/`fresh_head` return `None` — the publisher never
    /// fabricates an unauthorized delta.
    pub fn with_delegate(
        mut self,
        root: &crypto::TestRootSlh,
        delegate: crypto::TestDelegate,
        now: u64,
        validity: u64,
    ) -> Result<Self, ainra_core::Error> {
        let cert = DelegateCert::issue_test_root(
            root,
            delegate.public(),
            vec![SCOPE_DELTA.to_string(), SCOPE_FRESH_HEAD.to_string()],
            now,
            now + validity,
        )?;
        self.delta_signer = Some(DeltaSigner {
            delegate,
            cert,
            root_pub: root.public(),
        });
        Ok(self)
    }

    pub fn public(&self) -> crypto::HybridPublic {
        self.signer.public()
    }

    /// The SLH-DSA root public key the delta/fresh-head delegate cert chains to (if configured). A verifier needs
    /// this to authenticate deltas and fresh heads.
    pub fn root_public(&self) -> Option<&[u8]> {
        self.delta_signer.as_ref().map(|d| d.root_pub.as_slice())
    }

    /// The delegate cert authorizing deltas + fresh heads (if configured) — published so verifiers can check the chain.
    pub fn delegate_cert(&self) -> Option<&DelegateCert> {
        self.delta_signer.as_ref().map(|d| &d.cert)
    }

    pub fn current_seq(&self) -> u64 {
        self.seq
    }
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Revoke a lineage index (idempotent). Out-of-range is a no-op false — the codec fails closed on read anyway.
    /// Mutates the bulk list WITHOUT emitting a delta; use [`Self::revoke_delta`] for the signed-stream path.
    pub fn revoke(&mut self, idx: usize) -> bool {
        if idx < self.bits.len() {
            self.bits[idx] = true;
            true
        } else {
            false
        }
    }

    /// Revoke one or more lineage indices AND emit a signed, delegate-countersigned [`status::StatusDelta`] that
    /// advances the head sequence. Returns `None` if no delegate is configured. The delta is built + verified +
    /// applied THROUGH the core (single source of truth): a delta the core would reject (out-of-range index, etc.)
    /// leaves the list unchanged and returns an error. `now` stamps the delta.
    ///
    /// AINRA policy is revoke-only (monotonic), so `new_status` is always `true`; already-revoked indices in the
    /// batch are harmless (the delta simply re-asserts them).
    pub fn revoke_delta(
        &mut self,
        idx: &[usize],
        now: u64,
    ) -> Option<Result<status::StatusDelta, ainra_core::verdict::Reason>> {
        let signer = self.delta_signer.as_ref()?;
        let idx_u64: Vec<u64> = idx.iter().map(|&i| i as u64).collect();
        let delta = match status::StatusDelta::build(
            &self.uri,
            self.seq,
            now,
            idx_u64,
            true,
            &self.signer,
            &signer.delegate,
        ) {
            Ok(d) => d,
            Err(_) => return Some(Err(ainra_core::verdict::Reason::StaleStatus)),
        };
        // Apply through the core so the service never diverges from the codec's rules.
        let mut list = status::StatusList::from_bits(self.bits.clone());
        if let Err(r) = delta.apply(&mut list, self.seq) {
            return Some(Err(r)); // e.g. out-of-range index → no mutation
        }
        self.bits = list.into_bits();
        self.seq = delta.seq;
        self.delta_log.push(delta.clone());
        Some(Ok(delta))
    }

    /// A delegate-signed fresh head for the current list at the current `seq`, stamped `now`. `None` without a
    /// configured delegate.
    pub fn fresh_head(&self, now: u64) -> Option<status::FreshHead> {
        let signer = self.delta_signer.as_ref()?;
        let list = status::StatusList::from_bits(self.bits.clone());
        status::FreshHead::build(&self.uri, self.seq, now, &list, &signer.delegate).ok()
    }

    /// The deltas a client at head sequence `since` still needs, in order (each advances the head by one).
    pub fn deltas_since(&self, since: u64) -> Vec<status::StatusDelta> {
        self.delta_log
            .iter()
            .filter(|d| d.from_seq >= since)
            .cloned()
            .collect()
    }

    /// Replay a previously-emitted delta (reload path): **verify BOTH signatures first**, then apply through the
    /// core and record it. The delta must chain onto the current head; a gap/out-of-range index fails closed. Used
    /// by [`crate::registrar::RegistrarBox::load`] to restore status state from a persisted snapshot.
    ///
    /// SECURITY (review finding #1): the snapshot on disk is untrusted input. A forged/edited delta (empty or wrong
    /// signatures, flipped bits, extra indices) MUST NOT be applied — otherwise the reconstructed status could be
    /// re-signed by the live key on `publish` and laundered into a validly-signed list. So this re-runs the full
    /// core [`status::StatusDelta::verify`] (both-signatures-or-invalid + delegate cert) against the registrar's own
    /// signer + the configured root/delegate cert, at the delta's own timestamp, and fails closed on any mismatch.
    pub fn replay_delta(
        &mut self,
        delta: status::StatusDelta,
    ) -> Result<(), ainra_core::verdict::Reason> {
        // Bind the delta to THIS segment's list (defense in depth, review #12): a delta signed for a different
        // `uri` must never mutate this list, even though its signatures are individually valid.
        if delta.uri != self.uri {
            return Err(ainra_core::verdict::Reason::StaleStatus);
        }
        let signer = self
            .delta_signer
            .as_ref()
            .ok_or(ainra_core::verdict::Reason::CheckpointInvalid)?; // no delegate ⇒ cannot authenticate ⇒ fail closed
        let reg_pub = self.signer.public();
        delta.verify(&reg_pub, &signer.root_pub, &signer.cert, delta.ts)?;
        let mut list = status::StatusList::from_bits(self.bits.clone());
        delta.apply(&mut list, self.seq)?;
        self.bits = list.into_bits();
        self.seq = delta.seq;
        self.delta_log.push(delta);
        Ok(())
    }

    pub fn is_revoked(&self, idx: usize) -> bool {
        self.bits.get(idx).copied().unwrap_or(true) // fail closed
    }

    /// Sign + publish the current list stamped at `now`.
    pub fn publish(&self, now: u64) -> SignedStatusList {
        let list = status::StatusList::from_bits(self.bits.clone());
        let compressed = list.encode().expect("encode status list");
        let status_list_b64 = b64::encode(&compressed);
        let bit_len = self.bits.len() as u64;
        let signing = canon::canonicalize(&StatusSigning {
            bit_len,
            issued_at: now,
            status_list: &status_list_b64,
            uri: &self.uri,
        })
        .expect("canon status signing");
        let sig = self
            .signer
            .sign(signing.as_bytes())
            .expect("sign status list");
        SignedStatusList {
            uri: self.uri.clone(),
            status_list_b64,
            bit_len,
            issued_at: now,
            sig_ed25519: b64::encode(&sig.ed25519),
            sig_mldsa65: b64::encode(&sig.mldsa65),
        }
    }
}

/// Verify a published status list against the registrar's key, then read one lineage's status with fail-closed
/// freshness (this is what a verifier does; it lives here so the daemon and its tests share one truth).
pub fn verify_publication(
    pub_key: &crypto::HybridPublic,
    published: &SignedStatusList,
    now: u64,
    freshness: status::Freshness,
    idx: u64,
) -> Result<status::LineageStatus, status::Freshness> {
    let signing = canon::canonicalize(&StatusSigning {
        bit_len: published.bit_len,
        issued_at: published.issued_at,
        status_list: &published.status_list_b64,
        uri: &published.uri,
    })
    .expect("canon");
    let sig = crypto::HybridSig {
        ed25519: b64::decode(&published.sig_ed25519).unwrap_or_default(),
        mldsa65: b64::decode(&published.sig_mldsa65).unwrap_or_default(),
    };
    if crypto::verify_hybrid(pub_key, signing.as_bytes(), &sig).is_err() {
        return Err(freshness); // bad signature → fail closed (caller treats as unavailable)
    }
    if freshness.check(now, published.issued_at).is_err() {
        return Err(freshness); // stale → fail closed
    }
    let compressed = b64::decode(&published.status_list_b64).unwrap_or_default();
    let list = status::StatusList::decode(&compressed, published.bit_len as usize)
        .map_err(|_| freshness)?;
    Ok(list.status_of(idx))
}

// ── JSON wire forms for the delta stream + fresh head (base64url for all binary fields) ──────────────────────────

/// Wire form of an ADR-002 delegate certificate (base64url binary).
#[derive(Serialize, serde::Deserialize, Clone, Debug)]
pub struct WireDelegateCert {
    pub delegate_ed25519: String,
    pub scopes: Vec<String>,
    pub nbf: u64,
    pub exp: u64,
    pub sig_slh: String,
}

impl WireDelegateCert {
    pub fn from_core(c: &DelegateCert) -> Self {
        Self {
            delegate_ed25519: b64::encode(&c.delegate_ed25519),
            scopes: c.scopes.clone(),
            nbf: c.nbf,
            exp: c.exp,
            sig_slh: b64::encode(&c.sig_slh),
        }
    }
    /// Decode back to a core cert; a malformed field yields `None` (the caller fails closed).
    pub fn to_core(&self) -> Option<DelegateCert> {
        Some(DelegateCert {
            delegate_ed25519: b64::decode(&self.delegate_ed25519).ok()?.try_into().ok()?,
            scopes: self.scopes.clone(),
            nbf: self.nbf,
            exp: self.exp,
            sig_slh: b64::decode(&self.sig_slh).ok()?,
        })
    }
}

/// Wire form of a signed status delta (spec §202 shape).
#[derive(Serialize, serde::Deserialize, Clone, Debug)]
pub struct WireDelta {
    pub uri: String,
    pub from_seq: u64,
    pub seq: u64,
    pub ts: u64,
    pub idx: Vec<u64>,
    pub new_status: bool,
    pub sig_registrar_ed25519: String,
    pub sig_registrar_mldsa65: String,
    pub countersig_delegate: String,
}

impl WireDelta {
    pub fn from_core(d: &status::StatusDelta) -> Self {
        Self {
            uri: d.uri.clone(),
            from_seq: d.from_seq,
            seq: d.seq,
            ts: d.ts,
            idx: d.idx.clone(),
            new_status: d.new_status,
            sig_registrar_ed25519: b64::encode(&d.sig_registrar.ed25519),
            sig_registrar_mldsa65: b64::encode(&d.sig_registrar.mldsa65),
            countersig_delegate: b64::encode(&d.countersig_delegate),
        }
    }
    pub fn to_core(&self) -> Option<status::StatusDelta> {
        Some(status::StatusDelta {
            uri: self.uri.clone(),
            from_seq: self.from_seq,
            seq: self.seq,
            ts: self.ts,
            idx: self.idx.clone(),
            new_status: self.new_status,
            sig_registrar: crypto::HybridSig {
                ed25519: b64::decode(&self.sig_registrar_ed25519).ok()?,
                mldsa65: b64::decode(&self.sig_registrar_mldsa65).ok()?,
            },
            countersig_delegate: b64::decode(&self.countersig_delegate).ok()?,
        })
    }
}

/// Wire form of a delegate-signed fresh head.
#[derive(Serialize, serde::Deserialize, Clone, Debug)]
pub struct WireFreshHead {
    pub uri: String,
    pub seq: u64,
    pub ts: u64,
    pub status_hash: String,
    pub sig_delegate: String,
}

impl WireFreshHead {
    pub fn from_core(h: &status::FreshHead) -> Self {
        Self {
            uri: h.uri.clone(),
            seq: h.seq,
            ts: h.ts,
            status_hash: b64::encode(&h.status_hash),
            sig_delegate: b64::encode(&h.sig_delegate),
        }
    }
    pub fn to_core(&self) -> Option<status::FreshHead> {
        Some(status::FreshHead {
            uri: self.uri.clone(),
            seq: self.seq,
            ts: self.ts,
            status_hash: b64::decode(&self.status_hash).ok()?.try_into().ok()?,
            sig_delegate: b64::decode(&self.sig_delegate).ok()?,
        })
    }
}
