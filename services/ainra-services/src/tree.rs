// SPDX-License-Identifier: Apache-2.0 OR MIT
//! An **incremental** RFC 6962 tree for the reference log — O(log N) per-issue work at any log size.
//!
//! `ainra-core::merkle` owns the *semantics* (leaf/node hashing, the audit-path and consistency verifiers, and a
//! minimal recursive builder). That builder recomputes the whole tree per query — O(N) per root/proof — which is
//! fine for fixtures but would make the registrar's per-issue checkpoint+proof degrade linearly with log size
//! (scale review, HIGH). Production log storage is Tessera tiles with O(log N) paths (D-011); this module gives the
//! REFERENCE log the same asymptotics so the measured issuance rate genuinely holds at millions of records.
//!
//! **No novel security logic**: this structure must produce byte-identical roots and audit paths to
//! `ainra_core::merkle`'s builder — enforced by exhaustive differential tests below (every index at every size
//! 0..=300, plus large spot checks re-verified with the core *verifier*). The recursion in [`Self::proof_range`]
//! is literally core `path()` with `mth(range)` replaced by cached-node lookups.
//!
//! Memory: ~2·N·32 B (all levels). Consistency proofs (checkpoint/witness cadence, not per-issue) reuse the core's
//! O(N) subproof over the stored leaves — honest about where the fast path matters.

use ainra_core::merkle::{hash_leaf, hash_node};

/// Append-only Merkle tree with cached interior levels.
/// `levels[0]` = leaf hashes; `levels[k][j]` = parent of `levels[k-1][2j..2j+2]` (complete pairs only).
#[derive(Default)]
pub struct IncrementalTree {
    levels: Vec<Vec<[u8; 32]>>,
}

/// Largest power of two strictly less than `n` (RFC 6962 `k`; n ≥ 2).
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while k < n {
        k <<= 1;
    }
    k >> 1
}

impl IncrementalTree {
    pub fn new() -> Self {
        Self { levels: Vec::new() }
    }

    pub fn size(&self) -> u64 {
        self.levels.first().map(|l| l.len() as u64).unwrap_or(0)
    }

    /// Append leaf DATA (hashed with the 0x00 prefix); returns its 0-based index. Amortized O(1) hashes.
    pub fn append(&mut self, data: &[u8]) -> u64 {
        if self.levels.is_empty() {
            self.levels.push(Vec::new());
        }
        let idx = self.levels[0].len() as u64;
        self.levels[0].push(hash_leaf(data));
        // Cascade: whenever a level's count becomes even, its last pair has a (new) parent.
        let mut k = 0usize;
        while self.levels[k].len().is_multiple_of(2) {
            let len = self.levels[k].len();
            let parent = hash_node(&self.levels[k][len - 2], &self.levels[k][len - 1]);
            if self.levels.len() == k + 1 {
                self.levels.push(Vec::new());
            }
            self.levels[k + 1].push(parent);
            k += 1;
        }
        idx
    }

    /// MTH over `leaves[lo..hi)` from cached nodes. `lo` is always block-aligned by construction of the callers,
    /// so a power-of-two, aligned range is exactly one cached node; anything else splits at the RFC 6962 `k`
    /// (largest power of two < len) — the same recursion as core `mth`, with subtree recomputation replaced by
    /// cache lookups. O(log(hi−lo)) hashes.
    fn range_root(&self, lo: usize, hi: usize) -> [u8; 32] {
        debug_assert!(lo < hi);
        let len = hi - lo;
        if len.is_power_of_two() && lo.is_multiple_of(len) {
            let level = len.trailing_zeros() as usize;
            return self.levels[level][lo >> level];
        }
        let k = split(len);
        hash_node(&self.range_root(lo, lo + k), &self.range_root(lo + k, hi))
    }

    /// Current tree root (empty-tree root for size 0). O(log N).
    pub fn root(&self) -> [u8; 32] {
        let n = self.size() as usize;
        if n == 0 {
            use sha2::{Digest, Sha256};
            return Sha256::new().finalize().into(); // MTH({}) — matches core
        }
        self.range_root(0, n)
    }

    /// Root of the tree truncated to its first `size` leaves. `size == current` is the per-issue hot path —
    /// O(log N); a strict prefix (witness/checkpoint history) falls back to the core builder over stored leaves.
    pub fn root_at(&self, size: u64) -> Option<[u8; 32]> {
        let n = self.size();
        if size > n {
            return None;
        }
        if size == n {
            return Some(self.root());
        }
        if size == 0 {
            use sha2::{Digest, Sha256};
            return Some(Sha256::new().finalize().into());
        }
        // Prefix roots are needed at checkpoint/witness cadence only; O(size) via range decomposition is still
        // cheaper than a full rebuild, and any aligned sub-block comes from cache.
        Some(self.range_root_general(0, size as usize))
    }

    /// Like [`Self::range_root`] but without the alignment fast-path requirement on the WHOLE range (prefixes are
    /// aligned at 0, so sub-ranges still hit the cache wherever blocks are aligned+complete).
    fn range_root_general(&self, lo: usize, hi: usize) -> [u8; 32] {
        // Identical recursion — range_root already handles unaligned/partial ranges by splitting.
        self.range_root(lo, hi)
    }

    /// RFC 6962 audit path for the leaf at `index`. O(log² N) cache lookups/hashes. Byte-identical to core
    /// `TestLog::inclusion_proof` (differentially tested).
    pub fn inclusion_proof(&self, index: u64) -> Option<Vec<[u8; 32]>> {
        let n = self.size() as usize;
        if index >= n as u64 {
            return None;
        }
        Some(self.proof_range(index as usize, 0, n))
    }

    /// PATH(m, D[lo..hi)) — core `path()` with `mth` swapped for [`Self::range_root`].
    fn proof_range(&self, m: usize, lo: usize, hi: usize) -> Vec<[u8; 32]> {
        let n = hi - lo;
        if n == 1 {
            return Vec::new();
        }
        let k = split(n);
        if m < k {
            let mut p = self.proof_range(m, lo, lo + k);
            p.push(self.range_root(lo + k, hi));
            p
        } else {
            let mut p = self.proof_range(m - k, lo + k, hi);
            p.push(self.range_root(lo, lo + k));
            p
        }
    }

    /// RFC 6962 §2.1.2 consistency proof (checkpoint/witness cadence — not the per-issue path). Reuses the core
    /// builder over the stored leaves so the bytes are exactly the audited implementation's.
    pub fn consistency_proof(&self, first: u64) -> Option<Vec<[u8; 32]>> {
        let n = self.size();
        if first > n {
            return None;
        }
        if first == n || first == 0 {
            return Some(Vec::new());
        }
        // Rebuild through the core's TestLog on demand — O(N), at checkpoint cadence. The leaves are identical
        // (level 0), so the proof is byte-identical to the audited path.
        let mut core = ainra_core::merkle::TestLog::new();
        for h in &self.levels[0] {
            core.append_hash(*h);
        }
        core.consistency_proof(first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainra_core::merkle::{verify_inclusion, TestLog};

    fn leaf_data(i: usize) -> Vec<u8> {
        format!("leaf-{i}").into_bytes()
    }

    /// Exhaustive differential: roots byte-equal the core builder at EVERY size 0..=300.
    #[test]
    fn roots_match_core_exhaustively() {
        let mut inc = IncrementalTree::new();
        let mut core = TestLog::new();
        assert_eq!(inc.root(), core.root(), "empty tree");
        for i in 0..300 {
            inc.append(&leaf_data(i));
            core.append(&leaf_data(i));
            assert_eq!(inc.root(), core.root(), "root at size {}", i + 1);
        }
    }

    /// Exhaustive differential: audit paths byte-equal the core builder for EVERY index at EVERY size 1..=300.
    #[test]
    fn proofs_match_core_exhaustively() {
        let mut inc = IncrementalTree::new();
        let mut core = TestLog::new();
        for i in 0..300usize {
            inc.append(&leaf_data(i));
            core.append(&leaf_data(i));
            for idx in 0..=(i as u64) {
                assert_eq!(
                    inc.inclusion_proof(idx),
                    core.inclusion_proof(idx),
                    "proof for index {idx} at size {}",
                    i + 1
                );
            }
        }
    }

    /// Large spot check: proofs at a non-power-of-two size verify under the CORE verifier against our root.
    #[test]
    fn large_tree_proofs_verify_under_core() {
        let n: usize = (1 << 14) + 1234;
        let mut inc = IncrementalTree::new();
        for i in 0..n {
            inc.append(&leaf_data(i));
        }
        let root = inc.root();
        for &idx in &[0u64, 1, 4095, 4096, 4097, (n as u64) / 2, n as u64 - 1] {
            let proof = inc.inclusion_proof(idx).expect("proof");
            let leaf = hash_leaf(&leaf_data(idx as usize));
            assert!(
                verify_inclusion(&leaf, idx, n as u64, &proof, &root),
                "core verifier must accept our proof for index {idx}"
            );
        }
        // and root_at over a strict prefix equals the core builder's
        let mut core = TestLog::new();
        for i in 0..1000 {
            core.append(&leaf_data(i));
        }
        assert_eq!(inc.root_at(1000), Some(core.root()));
    }

    /// Consistency proofs come from the core code path itself — sanity-check one round trip.
    #[test]
    fn consistency_matches_core() {
        let mut inc = IncrementalTree::new();
        let mut core = TestLog::new();
        for i in 0..97 {
            inc.append(&leaf_data(i));
            core.append(&leaf_data(i));
        }
        for first in [0u64, 1, 5, 64, 96, 97] {
            assert_eq!(inc.consistency_proof(first), core.consistency_proof(first));
        }
    }
}
