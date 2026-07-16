// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Token Status List codec + freshness classes.
//!
//! Spec: MTS §16 / draft-ietf-oauth-status-list-21. One status bit per lineage index, LSB-first within each byte
//! (draft §4.1), zlib-DEFLATE compressed. M1 uses 1-bit statuses: `0` = valid, `1` = revoked.
//!
//! Two fail-closed rules (brief §0 "fail closed"):
//!   * an index at or beyond the list length resolves to **revoked** — never "assume valid past the end" (this is
//!     the exact status-list fail-OPEN bug we must not reproduce);
//!   * status material older than its [`Freshness`] class allows yields [`Reason::StaleStatus`], never a pass.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use std::io::{Read, Write};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::checkpoint::{DelegateCert, SCOPE_DELTA, SCOPE_FRESH_HEAD};
use crate::error::{Error, Result};
use crate::verdict::Reason;
use crate::{b64, canon, crypto};

/// Hard cap on a status list's declared length: 2^24 lineages (~2 MiB decompressed bitmap). A larger `bit_len` is
/// rejected in [`StatusList::decode`] so a hostile header cannot force an enormous allocation or an unbounded
/// inflate. Kept byte-identical to the sdk-ts `unpackStatus` cap (both fail closed on an oversized list).
pub const MAX_STATUS_BITS: usize = 1 << 24;

/// Freshness class → maximum tolerated age of the status material (MTS §16). All fail closed on exceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// F1 — ≤ 30 s (hot revocation paths).
    F1,
    /// F2 — ≤ 5 min.
    F2,
    /// F3 — ≤ 24 h.
    F3,
}

impl Freshness {
    /// Maximum age, in seconds, this class tolerates.
    pub const fn max_age_secs(self) -> u64 {
        match self {
            Freshness::F1 => 30,
            Freshness::F2 => 5 * 60,
            Freshness::F3 => 24 * 60 * 60,
        }
    }

    /// Fail-closed freshness check. `now`/`issued_at` are unix seconds supplied by the caller (the core has no
    /// clock — N7). Returns [`Reason::StaleStatus`] if the material is older than the class allows, OR if
    /// `issued_at` is in the future (a clock/forgery anomaly is treated as stale, never trusted).
    pub fn check(self, now: u64, issued_at: u64) -> core::result::Result<(), Reason> {
        if issued_at > now {
            return Err(Reason::StaleStatus); // future-dated → suspect → fail closed
        }
        if now - issued_at > self.max_age_secs() {
            return Err(Reason::StaleStatus);
        }
        Ok(())
    }
}

/// A decoded 1-bit-per-index status list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusList {
    bits: Vec<bool>,
}

impl StatusList {
    pub fn from_bits(bits: Vec<bool>) -> Self {
        Self { bits }
    }

    pub fn len(&self) -> usize {
        self.bits.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    /// Consume the list, returning its raw bits (`true` = revoked). Lets a stateful publisher round-trip a delta
    /// through the core [`StatusDelta::apply`] instead of reimplementing bit-flipping (single source of truth).
    pub fn into_bits(self) -> Vec<bool> {
        self.bits
    }

    /// zlib-compress the LSB-first packed bitstring (draft §4.1 wire form).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let n_bytes = self.bits.len().div_ceil(8);
        let mut packed = vec![0u8; n_bytes];
        for (i, &b) in self.bits.iter().enumerate() {
            if b {
                packed[i / 8] |= 1u8 << (i % 8); // LSB-first
            }
        }
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&packed)
            .map_err(|e| Error::Canon(alloc::format!("zlib write: {e}")))?;
        enc.finish()
            .map_err(|e| Error::Canon(alloc::format!("zlib finish: {e}")))
    }

    /// Decode a zlib-compressed status list of `bit_len` entries (the length is carried out-of-band in the signed
    /// list header, so trailing pad bits in the final byte are not mistaken for real entries).
    pub fn decode(compressed: &[u8], bit_len: usize) -> Result<Self> {
        // Bound the declared length BEFORE allocating, so a hostile header cannot force an enormous bitmap or drive
        // an unbounded inflate (the decompressed size is capped to what `bit_len` needs). Mirrors the sdk-ts
        // `unpackStatus` cap so both implementations fail closed identically on an oversized/zlib-bomb list.
        if bit_len > MAX_STATUS_BITS {
            return Err(Error::malformed(
                "status list length exceeds MAX_STATUS_BITS",
            ));
        }
        let need = bit_len.div_ceil(8);
        let max_out = need + 8; // the list needs `need` bytes; a little slack, anything past it is an attack
        let mut dec = flate2::read::ZlibDecoder::new(compressed).take((max_out + 1) as u64);
        let mut packed = Vec::new();
        dec.read_to_end(&mut packed)
            .map_err(|e| Error::Canon(alloc::format!("zlib read: {e}")))?;
        if packed.len() > max_out {
            return Err(Error::malformed("status list inflates past bound")); // zlib bomb → fail closed
        }
        if packed.len() < need {
            return Err(Error::malformed("status list shorter than declared length"));
        }
        let mut bits = Vec::with_capacity(bit_len);
        for i in 0..bit_len {
            bits.push((packed[i / 8] >> (i % 8)) & 1 == 1);
        }
        Ok(Self { bits })
    }

    /// Resolve one index. **Fail closed**: an index at/beyond the list length is `Revoked`, never valid.
    pub fn status_of(&self, idx: u64) -> LineageStatus {
        match usize::try_from(idx) {
            Ok(i) if i < self.bits.len() && !self.bits[i] => LineageStatus::Valid,
            _ => LineageStatus::Revoked,
        }
    }

    /// The canonical identity of this list at a given `uri`: `SHA-256` over the same canonical bytes a signed
    /// publication commits to (`{bit_len, status_list, uri}`), so a [`FreshHead`] and a full [`SignedStatusList`]
    /// name the *same* head. Never mixes the raw packed bytes with the framing — always the canonical JSON.
    pub fn head_hash(&self, uri: &str) -> Result<[u8; 32]> {
        let compressed = self.encode()?;
        let body = canon::canonicalize(&HeadIdentity {
            bit_len: self.bits.len() as u64,
            status_list: &b64::encode(&compressed),
            uri,
        })?;
        Ok(Sha256::digest(body.as_bytes()).into())
    }
}

/// The exact struct whose canonicalization is the head identity (feeds [`StatusList::head_hash`]). Field
/// names/order are frozen — they are hashed and cross-checked by verifiers.
#[derive(Serialize)]
struct HeadIdentity<'a> {
    bit_len: u64,
    status_list: &'a str,
    uri: &'a str,
}

/// Resolved status of a single lineage index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineageStatus {
    Valid,
    Revoked,
}

// ── Signed delta stream (MTS §16 / ADR-007) ────────────────────────────────────────────────────────────────────
//
// The bulk status list is large; pushing the whole thing on every revocation is wasteful. Instead the registrar
// emits **signed deltas**: `{list_uri, idx[], new_status, seq, ts, sig_registrar, countersig_delegate}` (spec
// §202). A delta advances the head by exactly one sequence number and is authorized by BOTH the registrar's hybrid
// key AND a root-certified online delegate (scope `delta-countersign`, ADR-002) — both-or-invalid, fail closed.
//
// Two failure planes, two reasons (kept distinct so the surfaced verdict is deterministic):
//   * the delta is not authorized by the root's delegate chain (bad cert / bad countersig) → [`Reason::CheckpointInvalid`]
//     — the same trust boundary as a checkpoint signature;
//   * the delta is structurally unusable or not registrar-signed (gap, wrong `from_seq`, out-of-range index, bad
//     registrar sig) → [`Reason::StaleStatus`] — the head cannot be advanced, so status is treated as unavailable
//     and we fail closed to stale, never to valid.

/// A signed status-list delta. Applying it flips `idx[]` to `new_status` and advances the head `from_seq → seq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusDelta {
    /// Which list this applies to (matches the [`SignedStatusList`]/[`FreshHead`] `uri`).
    pub uri: String,
    /// The head sequence this delta applies onto. MUST equal the current head's `seq`.
    pub from_seq: u64,
    /// The new head sequence. MUST be exactly `from_seq + 1` (single-step, strictly monotonic).
    pub seq: u64,
    /// When the registrar built this delta (unix seconds; the core has no clock — supplied by the caller).
    pub ts: u64,
    /// The lineage indices whose status changes (ascending, de-duplicated).
    pub idx: Vec<u64>,
    /// The status every listed index takes (`true` = revoked). AINRA registrar policy only ever pushes `true`
    /// (revocation is one-way); the codec stays a faithful, general Token Status List delta.
    pub new_status: bool,
    /// Registrar hybrid signature (Ed25519 + ML-DSA-65) over the canonical body — both-or-invalid.
    pub sig_registrar: crypto::HybridSig,
    /// Delegate Ed25519 countersignature over the *same* canonical body (scope `delta-countersign`).
    pub countersig_delegate: Vec<u8>,
}

/// The exact struct that gets canonicalized for signing/countersigning a delta. Frozen field names/order.
#[derive(Serialize)]
struct DeltaSigning<'a> {
    from_seq: u64,
    idx: &'a [u64],
    new_status: bool,
    seq: u64,
    ts: u64,
    uri: &'a str,
}

impl StatusDelta {
    /// Canonical signing input — both the registrar signature and the delegate countersignature cover these bytes.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let s = canon::canonicalize(&DeltaSigning {
            from_seq: self.from_seq,
            idx: &self.idx,
            new_status: self.new_status,
            seq: self.seq,
            ts: self.ts,
            uri: &self.uri,
        })?;
        Ok(s.into_bytes())
    }

    /// Build + doubly-sign a delta (registrar-side; services/fixtures). The registrar signs with its hybrid key and
    /// the online delegate countersigns the identical bytes. `idx` is normalized (sorted + de-duplicated) so the
    /// signed body is canonical regardless of caller order.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        uri: &str,
        from_seq: u64,
        ts: u64,
        mut idx: Vec<u64>,
        new_status: bool,
        registrar: &crypto::HybridKeypair,
        delegate: &crypto::TestDelegate,
    ) -> Result<Self> {
        idx.sort_unstable();
        idx.dedup();
        let mut d = StatusDelta {
            uri: uri.into(),
            from_seq,
            seq: from_seq + 1,
            ts,
            idx,
            new_status,
            sig_registrar: crypto::HybridSig {
                ed25519: Vec::new(),
                mldsa65: Vec::new(),
            },
            countersig_delegate: Vec::new(),
        };
        let msg = d.signing_bytes()?;
        d.sig_registrar = registrar.sign(&msg)?;
        d.countersig_delegate = delegate.sign(&msg);
        Ok(d)
    }

    /// Verify a delta is authentic and structurally sound, WITHOUT applying it. Fixed, documented order so the
    /// reason is deterministic across implementations:
    ///   1. structural: `seq == from_seq + 1`, `idx` ascending + unique          → [`Reason::StaleStatus`]
    ///   2. registrar hybrid signature over the canonical body                    → registrar's own reason (downgrade/sig)
    ///   3. delegate cert chains to root, in-window at `now`, scope `delta-countersign` → [`Reason::CheckpointInvalid`]
    ///   4. delegate Ed25519 countersignature over the same body                  → [`Reason::CheckpointInvalid`]
    ///
    /// Step 2's reason is the registrar signature's ([`Reason::AlgDowngrade`]/[`Reason::SigInvalid`]); a caller that
    /// wants the coarse "status unavailable" mapping treats any non-`Ok` as fail-closed-to-stale (see
    /// [`Self::verify_stale`]).
    pub fn verify(
        &self,
        registrar_pk: &crypto::HybridPublic,
        root_pk_slh: &[u8],
        cert: &DelegateCert,
        now: u64,
    ) -> core::result::Result<(), Reason> {
        // (1) structure — a gap, a non-single-step advance, or a non-canonical index vector is unusable → stale.
        if self.seq != self.from_seq.wrapping_add(1) || self.seq == 0 {
            return Err(Reason::StaleStatus);
        }
        if !self.idx.windows(2).all(|w| w[0] < w[1]) {
            return Err(Reason::StaleStatus); // not strictly ascending ⇒ not normalized/duplicated
        }
        let msg = self.signing_bytes().map_err(|_| Reason::StaleStatus)?;
        // (2) registrar hybrid signature (both-or-invalid).
        crypto::verify_hybrid(registrar_pk, &msg, &self.sig_registrar)?;
        // (3) delegate cert authorizes delta countersignatures, and (4) the countersignature verifies.
        cert.verify(root_pk_slh, now, SCOPE_DELTA)?;
        let sig: [u8; crypto::ED25519_SIG] = self
            .countersig_delegate
            .as_slice()
            .try_into()
            .map_err(|_| Reason::CheckpointInvalid)?;
        if crypto::ed25519_verify(&cert.delegate_ed25519, &msg, &sig) {
            Ok(())
        } else {
            Err(Reason::CheckpointInvalid)
        }
    }

    /// Coarse fail-closed wrapper: any verification failure collapses to [`Reason::StaleStatus`] ("the head could
    /// not be advanced from trusted material, so status is unavailable"). Used where a passport's freshness gate
    /// only needs "usable or not," not which link broke.
    pub fn verify_stale(
        &self,
        registrar_pk: &crypto::HybridPublic,
        root_pk_slh: &[u8],
        cert: &DelegateCert,
        now: u64,
    ) -> core::result::Result<(), Reason> {
        self.verify(registrar_pk, root_pk_slh, cert, now)
            .map_err(|_| Reason::StaleStatus)
    }

    /// Apply a *verified* delta to a list at `current_seq`, returning the new head sequence. Re-checks the head
    /// linkage (`from_seq == current_seq`) and that every index is in range — both fail closed to
    /// [`Reason::StaleStatus`] (an out-of-range write or a wrong base means the head is not what the delta expects).
    ///
    /// SECURITY: call [`Self::verify`] (or [`Self::verify_stale`]) FIRST. This method trusts the bytes; it does not
    /// re-check signatures (so a caller can verify once and apply a batch). Applying an unverified delta is a bug.
    pub fn apply(
        &self,
        list: &mut StatusList,
        current_seq: u64,
    ) -> core::result::Result<u64, Reason> {
        if self.from_seq != current_seq || self.seq != current_seq.wrapping_add(1) {
            return Err(Reason::StaleStatus);
        }
        // Bounds-check every index BEFORE mutating, so a bad delta cannot leave the list half-applied.
        for &i in &self.idx {
            let iu = usize::try_from(i).map_err(|_| Reason::StaleStatus)?;
            if iu >= list.bits.len() {
                return Err(Reason::StaleStatus);
            }
        }
        for &i in &self.idx {
            list.bits[i as usize] = self.new_status;
        }
        Ok(self.seq)
    }
}

// ── Fresh head (ADR-007 / MTS §16) — the 30-second F1 revocation heartbeat ───────────────────────────────────────
//
// A [`FreshHead`] is a tiny delegate-signed statement "list `uri` is at sequence `seq` with identity `status_hash`
// as of `ts`." It carries no bits — just the head's identity. A payments-grade (F1) verifier fetches it, checks the
// delegate signature + 30-second freshness, and confirms the head it holds hashes to `status_hash`. That closes the
// window where a full list or a delta stream could be silently withheld: no fresh head within 30 s ⇒ fail closed.

/// A delegate-signed fresh head: the identity of a status list at a point in time (ADR-007's F1 heartbeat).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshHead {
    pub uri: String,
    pub seq: u64,
    pub ts: u64,
    /// `SHA-256` of the canonical head body — MUST equal the held list's [`StatusList::head_hash`].
    pub status_hash: [u8; 32],
    /// Delegate Ed25519 signature over the canonical head statement (scope `fresh-head`).
    pub sig_delegate: Vec<u8>,
}

/// The exact struct that gets canonicalized for signing a fresh head. Frozen field names/order.
#[derive(Serialize)]
struct FreshHeadSigning<'a> {
    seq: u64,
    status_hash: &'a str, // base64url(status_hash)
    ts: u64,
    uri: &'a str,
}

impl FreshHead {
    /// Canonical signing input for this fresh head.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let s = canon::canonicalize(&FreshHeadSigning {
            seq: self.seq,
            status_hash: &b64::encode(&self.status_hash),
            ts: self.ts,
            uri: &self.uri,
        })?;
        Ok(s.into_bytes())
    }

    /// Build + delegate-sign a fresh head for `list` at `uri`/`seq`/`ts` (registrar/service side).
    pub fn build(
        uri: &str,
        seq: u64,
        ts: u64,
        list: &StatusList,
        delegate: &crypto::TestDelegate,
    ) -> Result<Self> {
        let mut h = FreshHead {
            uri: uri.into(),
            seq,
            ts,
            status_hash: list.head_hash(uri)?,
            sig_delegate: Vec::new(),
        };
        h.sig_delegate = delegate.sign(&h.signing_bytes()?);
        Ok(h)
    }

    /// Verify the fresh head: (1) delegate cert chains to root, in-window at `now`, scope `fresh-head`
    /// → [`Reason::CheckpointInvalid`]; (2) delegate signature over the canonical statement
    /// → [`Reason::CheckpointInvalid`]; (3) `ts` is within the `freshness` class → [`Reason::StaleStatus`].
    ///
    /// This authenticates the head's *identity* and *recency*. The caller MUST still confirm the list it holds
    /// hashes to [`Self::status_hash`] (use [`Self::binds`]) — a valid fresh head for a list you don't have is not a
    /// pass for that list.
    pub fn verify(
        &self,
        root_pk_slh: &[u8],
        cert: &DelegateCert,
        now: u64,
        freshness: Freshness,
    ) -> core::result::Result<(), Reason> {
        cert.verify(root_pk_slh, now, SCOPE_FRESH_HEAD)?;
        let msg = self
            .signing_bytes()
            .map_err(|_| Reason::CheckpointInvalid)?;
        let sig: [u8; crypto::ED25519_SIG] = self
            .sig_delegate
            .as_slice()
            .try_into()
            .map_err(|_| Reason::CheckpointInvalid)?;
        if !crypto::ed25519_verify(&cert.delegate_ed25519, &msg, &sig) {
            return Err(Reason::CheckpointInvalid);
        }
        freshness.check(now, self.ts)?; // → StaleStatus if too old / future-dated
        Ok(())
    }

    /// Does this fresh head name the list the verifier holds? Constant-length compare of the 32-byte hash and the
    /// `uri`. A mismatch means the head is for a *different* head/list — fail closed at the call site.
    pub fn binds(&self, uri: &str, held: &StatusList) -> bool {
        match held.head_hash(uri) {
            Ok(h) => self.uri == uri && h == self.status_hash,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_roundtrip_lsb_first() {
        // idx 0=1, 1=0, 2=1  → byte0 = 0b0000_0101 = 0x05 (LSB-first)
        let list = StatusList::from_bits(vec![true, false, true]);
        let comp = list.encode().unwrap();
        let back = StatusList::decode(&comp, 3).unwrap();
        assert_eq!(back, list);
    }

    #[test]
    fn status_resolution_and_fail_closed_past_end() {
        let list = StatusList::from_bits(vec![false, true, false]);
        assert_eq!(list.status_of(0), LineageStatus::Valid);
        assert_eq!(list.status_of(1), LineageStatus::Revoked);
        assert_eq!(list.status_of(2), LineageStatus::Valid);
        // past the end → fail closed → revoked (NOT the fail-open bug)
        assert_eq!(list.status_of(3), LineageStatus::Revoked);
        assert_eq!(list.status_of(u64::MAX), LineageStatus::Revoked);
    }

    #[test]
    fn freshness_fails_closed() {
        assert_eq!(Freshness::F1.check(1000, 990), Ok(())); // 10s old, within 30s
        assert_eq!(Freshness::F1.check(1000, 900), Err(Reason::StaleStatus)); // 100s old
        assert_eq!(Freshness::F2.check(1000, 900), Ok(())); // within 5min
        assert_eq!(Freshness::F3.check(1000, 900), Ok(())); // within 24h
                                                            // future-dated status is suspect → stale
        assert_eq!(Freshness::F3.check(1000, 1001), Err(Reason::StaleStatus));
    }

    #[test]
    fn larger_bitstring_roundtrips() {
        let bits: Vec<bool> = (0..131).map(|i| i % 7 == 0).collect();
        let list = StatusList::from_bits(bits.clone());
        let back = StatusList::decode(&list.encode().unwrap(), 131).unwrap();
        assert_eq!(back.bits, bits);
        for (i, &b) in bits.iter().enumerate() {
            let want = if b {
                LineageStatus::Revoked
            } else {
                LineageStatus::Valid
            };
            assert_eq!(list.status_of(i as u64), want);
        }
    }

    // ── delta + fresh-head codec (M3) ───────────────────────────────────────────────────────────────────────────
    use crate::checkpoint::{DelegateCert, SCOPE_DELTA, SCOPE_FRESH_HEAD};
    use rand_core::SeedableRng;

    const URI: &str = "status://registrar-07/1";

    struct Env {
        registrar: crypto::HybridKeypair,
        reg_pk: crypto::HybridPublic,
        root: crypto::TestRootSlh,
        root_pk: Vec<u8>,
        delegate: crypto::TestDelegate,
        now: u64,
    }

    fn env() -> Env {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x5747_A715);
        let registrar = crypto::HybridKeypair::generate(&mut rng);
        let reg_pk = registrar.public();
        let root = crypto::TestRootSlh::generate(&mut rng);
        let root_pk = root.public();
        let delegate = crypto::TestDelegate::generate(&mut rng);
        Env {
            registrar,
            reg_pk,
            root,
            root_pk,
            delegate,
            now: 1_000_000,
        }
    }

    fn cert(e: &Env, scope: &str) -> DelegateCert {
        DelegateCert::issue_test_root(
            &e.root,
            e.delegate.public(),
            vec![scope.into()],
            e.now - 100,
            e.now + 86_400,
        )
        .unwrap()
    }

    #[test]
    fn delta_build_verify_apply_roundtrip() {
        let e = env();
        let c = cert(&e, SCOPE_DELTA);
        let mut list = StatusList::from_bits(vec![false; 8]);
        // revoke indices 5 and 2 (given out of order → normalized to [2,5]).
        let d =
            StatusDelta::build(URI, 0, e.now, vec![5, 2], true, &e.registrar, &e.delegate).unwrap();
        assert_eq!(d.idx, vec![2, 5], "indices normalized ascending+unique");
        assert_eq!(d.seq, 1);
        assert_eq!(d.verify(&e.reg_pk, &e.root_pk, &c, e.now), Ok(()));
        assert_eq!(d.apply(&mut list, 0), Ok(1));
        assert_eq!(list.status_of(2), LineageStatus::Revoked);
        assert_eq!(list.status_of(5), LineageStatus::Revoked);
        assert_eq!(list.status_of(0), LineageStatus::Valid);
    }

    #[test]
    fn delta_bad_registrar_sig_is_registrars_reason() {
        let e = env();
        let c = cert(&e, SCOPE_DELTA);
        let mut d =
            StatusDelta::build(URI, 0, e.now, vec![1], true, &e.registrar, &e.delegate).unwrap();
        // strip the ML-DSA half → downgrade (registrar's own reason, not a checkpoint reason)
        d.sig_registrar.mldsa65.clear();
        assert_eq!(
            d.verify(&e.reg_pk, &e.root_pk, &c, e.now),
            Err(Reason::AlgDowngrade)
        );
        // and the coarse wrapper collapses it to stale (status unavailable)
        assert_eq!(
            d.verify_stale(&e.reg_pk, &e.root_pk, &c, e.now),
            Err(Reason::StaleStatus)
        );
    }

    #[test]
    fn delta_bad_delegate_countersig_is_checkpoint_invalid() {
        let e = env();
        let c = cert(&e, SCOPE_DELTA);
        let mut d =
            StatusDelta::build(URI, 0, e.now, vec![1], true, &e.registrar, &e.delegate).unwrap();
        d.countersig_delegate[0] ^= 0xff; // corrupt the countersignature
        assert_eq!(
            d.verify(&e.reg_pk, &e.root_pk, &c, e.now),
            Err(Reason::CheckpointInvalid)
        );
    }

    #[test]
    fn delta_wrong_scope_cert_is_checkpoint_invalid() {
        let e = env();
        let wrong = cert(&e, SCOPE_FRESH_HEAD); // fresh-head cert cannot authorize a delta
        let d =
            StatusDelta::build(URI, 0, e.now, vec![1], true, &e.registrar, &e.delegate).unwrap();
        assert_eq!(
            d.verify(&e.reg_pk, &e.root_pk, &wrong, e.now),
            Err(Reason::CheckpointInvalid)
        );
    }

    #[test]
    fn delta_expired_cert_is_checkpoint_invalid() {
        let e = env();
        let c = cert(&e, SCOPE_DELTA);
        let d =
            StatusDelta::build(URI, 0, e.now, vec![1], true, &e.registrar, &e.delegate).unwrap();
        assert_eq!(
            d.verify(&e.reg_pk, &e.root_pk, &c, c.exp + 1),
            Err(Reason::CheckpointInvalid)
        );
    }

    #[test]
    fn delta_gap_and_wrong_base_fail_closed_stale() {
        let e = env();
        let c = cert(&e, SCOPE_DELTA);
        let mut list = StatusList::from_bits(vec![false; 4]);
        // A delta from seq 0 → 1 cannot be applied onto a head already at seq 1.
        let d =
            StatusDelta::build(URI, 0, e.now, vec![1], true, &e.registrar, &e.delegate).unwrap();
        assert_eq!(d.apply(&mut list, 1), Err(Reason::StaleStatus));
        // A hand-forged non-single-step delta is rejected structurally at verify.
        let mut skip = d.clone();
        skip.seq = 5;
        assert_eq!(
            skip.verify(&e.reg_pk, &e.root_pk, &c, e.now),
            Err(Reason::StaleStatus)
        );
    }

    #[test]
    fn delta_out_of_range_index_does_not_half_apply() {
        let e = env();
        let mut list = StatusList::from_bits(vec![false; 3]);
        // index 9 is past the end; index 0 is in range. Neither must be written.
        let d =
            StatusDelta::build(URI, 0, e.now, vec![0, 9], true, &e.registrar, &e.delegate).unwrap();
        assert_eq!(d.apply(&mut list, 0), Err(Reason::StaleStatus));
        assert_eq!(list.status_of(0), LineageStatus::Valid, "no partial write");
    }

    #[test]
    fn delta_tampered_index_breaks_signature() {
        let e = env();
        let c = cert(&e, SCOPE_DELTA);
        let mut d =
            StatusDelta::build(URI, 0, e.now, vec![1], true, &e.registrar, &e.delegate).unwrap();
        d.idx = vec![2]; // move the revocation to a different lineage after signing
        assert_eq!(
            d.verify(&e.reg_pk, &e.root_pk, &c, e.now),
            Err(Reason::SigInvalid)
        );
    }

    #[test]
    fn fresh_head_build_verify_and_bind() {
        let e = env();
        let c = cert(&e, SCOPE_FRESH_HEAD);
        let list = StatusList::from_bits(vec![false, true, false, false]);
        let head = FreshHead::build(URI, 3, e.now, &list, &e.delegate).unwrap();
        // F1 (30 s) passes when fresh, and the head binds to the exact list.
        assert_eq!(
            head.verify(&e.root_pk, &c, e.now + 10, Freshness::F1),
            Ok(())
        );
        assert!(head.binds(URI, &list));
        // a different list (one more bit flipped) must NOT bind
        let other = StatusList::from_bits(vec![false, true, true, false]);
        assert!(!head.binds(URI, &other));
    }

    #[test]
    fn fresh_head_stale_past_f1_but_ok_in_f2() {
        let e = env();
        let c = cert(&e, SCOPE_FRESH_HEAD);
        let list = StatusList::from_bits(vec![false; 4]);
        let head = FreshHead::build(URI, 1, e.now, &list, &e.delegate).unwrap();
        // 100 s old: past F1 (30 s) → stale, but within F2 (5 min) → ok.
        assert_eq!(
            head.verify(&e.root_pk, &c, e.now + 100, Freshness::F1),
            Err(Reason::StaleStatus)
        );
        assert_eq!(
            head.verify(&e.root_pk, &c, e.now + 100, Freshness::F2),
            Ok(())
        );
    }

    #[test]
    fn fresh_head_wrong_scope_and_bad_sig_are_checkpoint_invalid() {
        let e = env();
        let list = StatusList::from_bits(vec![false; 2]);
        // wrong scope (delta cert cannot sign a fresh head)
        let wrong = cert(&e, SCOPE_DELTA);
        let head = FreshHead::build(URI, 1, e.now, &list, &e.delegate).unwrap();
        assert_eq!(
            head.verify(&e.root_pk, &wrong, e.now, Freshness::F1),
            Err(Reason::CheckpointInvalid)
        );
        // right scope, corrupted signature
        let c = cert(&e, SCOPE_FRESH_HEAD);
        let mut bad = head.clone();
        bad.sig_delegate[0] ^= 0xff;
        assert_eq!(
            bad.verify(&e.root_pk, &c, e.now, Freshness::F1),
            Err(Reason::CheckpointInvalid)
        );
    }
}
