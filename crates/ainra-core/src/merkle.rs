// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 6962 Merkle tree: leaf prefix `0x00`, interior prefix `0x01`, over SHA-256 (MTS §14, brief §3).
//!
//! Provides: leaf/node hashing, an audit-path *verifier* (the hot path — "logged-before-valid"), and a minimal
//! in-crate tree *builder* used only to mint fixture proofs to a real signed checkpoint (DECISIONS D-008). The
//! production log is Tessera (M2, `services/logd`); this builder is not it.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// H(0x00 || leaf_data) — the RFC 6962 leaf hash.
pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(data);
    h.finalize().into()
}

/// H(0x01 || left || right) — the RFC 6962 interior node hash.
pub fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Verify an inclusion (audit) path for `leaf_hash` at 0-based `index` in a tree of `tree_size` leaves against
/// `root`. Exactly the RFC 6962 §2.1.1 verification algorithm; returns `false` on any inconsistency (fail closed).
pub fn verify_inclusion(
    leaf_hash: &[u8; 32],
    index: u64,
    tree_size: u64,
    proof: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    if index >= tree_size {
        return false;
    }
    let mut fnn = index;
    let mut sn = tree_size - 1;
    let mut r = *leaf_hash;
    for p in proof {
        if sn == 0 {
            return false; // proof longer than the tree can justify
        }
        if (fnn & 1) == 1 || fnn == sn {
            r = hash_node(p, &r);
            if (fnn & 1) == 0 {
                // shift right until LSB(fn) set or fn == 0
                while (fnn & 1) == 0 && fnn != 0 {
                    fnn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = hash_node(&r, p);
        }
        fnn >>= 1;
        sn >>= 1;
    }
    sn == 0 && r == *root
}

/// Largest power of two strictly less than `n` (defined for n >= 2). Spec: RFC 6962 `k`.
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while k < n {
        k <<= 1;
    }
    k >> 1
}

/// Merkle Tree Hash over a slice of already-computed leaf hashes (RFC 6962 §2.1).
fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => Sha256::new().finalize().into(), // MTH({}) = SHA-256() of the empty string
        1 => leaves[0],
        n => {
            let k = split(n);
            let l = mth(&leaves[..k]);
            let r = mth(&leaves[k..]);
            hash_node(&l, &r)
        }
    }
}

/// Audit path for the leaf at 0-based `m` within `leaves` (RFC 6962 §2.1.1 PATH).
fn path(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if n == 1 {
        return Vec::new();
    }
    let k = split(n);
    if m < k {
        let mut p = path(m, &leaves[..k]);
        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = path(m - k, &leaves[k..]);
        p.push(mth(&leaves[..k]));
        p
    }
}

/// Verify an RFC 6962 §2.1.4.2 consistency proof: the tree of size `first` with root `first_root` is a prefix of
/// the tree of size `second` with root `second_root`. This is THE witness primitive (append-only, no equivocation):
/// a log that forks cannot produce a valid consistency path between the divergent checkpoints. Fails closed.
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_root: &[u8; 32],
    second_root: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    if first > second {
        return false;
    }
    if first == second {
        // same size ⇒ same tree; the proof must be empty and the roots identical
        return proof.is_empty() && first_root == second_root;
    }
    if first == 0 {
        // the empty tree is a prefix of everything; nothing to prove (proof must be empty)
        return proof.is_empty();
    }
    // step 2: if `first` is an exact power of two, prepend first_root to the path
    let mut path: Vec<[u8; 32]> = Vec::with_capacity(proof.len() + 1);
    if first.is_power_of_two() {
        path.push(*first_root);
    }
    path.extend_from_slice(proof);
    if path.is_empty() {
        return false;
    }

    let mut fnn = first - 1;
    let mut sn = second - 1;
    // step 4: shift off the common trailing 1-bits
    while (fnn & 1) == 1 {
        fnn >>= 1;
        sn >>= 1;
    }
    let mut fr = path[0];
    let mut sr = path[0];
    for c in &path[1..] {
        if sn == 0 {
            return false;
        }
        if (fnn & 1) == 1 || fnn == sn {
            fr = hash_node(c, &fr);
            sr = hash_node(c, &sr);
            if (fnn & 1) == 0 {
                while (fnn & 1) == 0 && fnn != 0 {
                    fnn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = hash_node(&sr, c);
        }
        fnn >>= 1;
        sn >>= 1;
    }
    sn == 0 && fr == *first_root && sr == *second_root
}

/// RFC 6962 §2.1.2 SUBPROOF over a slice of leaf hashes.
fn subproof(m: usize, leaves: &[[u8; 32]], complete: bool) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if m == n {
        if complete {
            return Vec::new();
        }
        return alloc::vec![mth(leaves)];
    }
    let k = split(n);
    if m <= k {
        let mut p = subproof(m, &leaves[..k], complete);
        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = subproof(m - k, &leaves[k..], false);
        p.push(mth(&leaves[..k]));
        p
    }
}

/// A minimal append-only Merkle log — FIXTURE USE ONLY (DECISIONS D-008). Not the production log.
#[derive(Debug, Default, Clone)]
pub struct TestLog {
    leaves: Vec<[u8; 32]>,
}

impl TestLog {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }
    /// Append leaf DATA (hashed with the 0x00 prefix); returns its 0-based index.
    pub fn append(&mut self, data: &[u8]) -> u64 {
        let idx = self.leaves.len() as u64;
        self.leaves.push(hash_leaf(data));
        idx
    }
    /// Append an already-computed RFC 6962 leaf hash (a 0x00-prefixed digest). For callers that store leaf
    /// hashes rather than entry bytes (e.g. the services' incremental tree bridging back into this builder).
    pub fn append_hash(&mut self, leaf_hash: [u8; 32]) -> u64 {
        let idx = self.leaves.len() as u64;
        self.leaves.push(leaf_hash);
        idx
    }
    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }
    /// Current tree root (empty-tree root for size 0).
    pub fn root(&self) -> [u8; 32] {
        mth(&self.leaves)
    }
    /// Audit path proving the leaf at `index`.
    pub fn inclusion_proof(&self, index: u64) -> Option<Vec<[u8; 32]>> {
        if index >= self.size() {
            return None;
        }
        Some(path(index as usize, &self.leaves))
    }
    /// RFC 6962 §2.1.2 consistency proof: the tree at size `first` is a prefix of the current tree.
    pub fn consistency_proof(&self, first: u64) -> Option<Vec<[u8; 32]>> {
        let n = self.size();
        if first > n {
            return None;
        }
        if first == n || first == 0 {
            return Some(Vec::new());
        }
        Some(subproof(first as usize, &self.leaves, true))
    }
    /// Root of the tree truncated to its first `size` leaves (what the log's root WAS at that size).
    pub fn root_at(&self, size: u64) -> Option<[u8; 32]> {
        if size > self.size() {
            return None;
        }
        Some(mth(&self.leaves[..size as usize]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_single() {
        let t = TestLog::new();
        assert_eq!(t.root(), <[u8; 32]>::from(Sha256::new().finalize()));
        let mut t = TestLog::new();
        let i = t.append(b"hello");
        assert_eq!(i, 0);
        assert_eq!(t.root(), hash_leaf(b"hello"));
        // single-leaf inclusion: empty path, verifies against root == leaf hash
        let proof = t.inclusion_proof(0).unwrap();
        assert!(proof.is_empty());
        assert!(verify_inclusion(
            &hash_leaf(b"hello"),
            0,
            1,
            &proof,
            &t.root()
        ));
    }

    #[test]
    fn build_then_verify_all_leaves() {
        // Cross-check the builder against the verifier for every leaf across many tree sizes.
        for n in 1..=33usize {
            let mut t = TestLog::new();
            let mut datas = Vec::new();
            for k in 0..n {
                let d = alloc::format!("leaf-{k}").into_bytes();
                t.append(&d);
                datas.push(d);
            }
            let root = t.root();
            for (k, data) in datas.iter().enumerate() {
                let proof = t.inclusion_proof(k as u64).unwrap();
                let ok = verify_inclusion(&hash_leaf(data), k as u64, n as u64, &proof, &root);
                assert!(ok, "inclusion must verify for leaf {k} in tree of {n}");
                // a wrong leaf must NOT verify
                let bad = hash_leaf(b"not-in-tree");
                assert!(!verify_inclusion(&bad, k as u64, n as u64, &proof, &root));
                // a tampered root must NOT verify
                let mut bad_root = root;
                bad_root[0] ^= 0xff;
                assert!(!verify_inclusion(
                    &hash_leaf(data),
                    k as u64,
                    n as u64,
                    &proof,
                    &bad_root
                ));
            }
        }
    }

    #[test]
    fn known_two_leaf_root() {
        // RFC 6962 shape: root of two leaves = H(0x01 || H(0x00||a) || H(0x00||b)).
        let mut t = TestLog::new();
        t.append(b"a");
        t.append(b"b");
        let want = hash_node(&hash_leaf(b"a"), &hash_leaf(b"b"));
        assert_eq!(t.root(), want);
    }

    #[test]
    fn consistency_all_size_pairs() {
        // Exhaustive cross-check: for every 0 ≤ m ≤ n ≤ 33, PROOF(m, D_n) verifies m-prefix consistency, and a
        // FORKED history (one early leaf changed) never verifies against the honest old root.
        let mut honest = TestLog::new();
        let mut forked = TestLog::new();
        for k in 0..33usize {
            honest.append(alloc::format!("leaf-{k}").as_bytes());
            forked.append(alloc::format!("leaf-{}", if k == 1 { 999 } else { k }).as_bytes());
        }
        for n in 1..=33u64 {
            for m in 0..=n {
                let root_n = honest.root_at(n).unwrap();
                let root_m = honest.root_at(m).unwrap();
                // build the proof from the log AS IT WAS at size n
                let mut log_n = TestLog::new();
                for k in 0..n as usize {
                    log_n.append(alloc::format!("leaf-{k}").as_bytes());
                }
                let proof = log_n.consistency_proof(m).unwrap();
                assert!(
                    verify_consistency(m, n, &root_m, &root_n, &proof),
                    "consistency must verify for m={m} n={n}"
                );
                // the fork: same sizes, honest old root, forked new root — MUST fail (that's the witness alarm)
                if m >= 2 && m < n {
                    let fork_root_n = forked.root_at(n).unwrap();
                    let mut fork_n = TestLog::new();
                    for k in 0..n as usize {
                        fork_n.append(
                            alloc::format!("leaf-{}", if k == 1 { 999 } else { k }).as_bytes(),
                        );
                    }
                    let fork_proof = fork_n.consistency_proof(m).unwrap();
                    assert!(
                        !verify_consistency(m, n, &root_m, &fork_root_n, &fork_proof),
                        "a forked history must NOT be consistent with the honest root at m={m} n={n}"
                    );
                }
            }
        }
    }

    #[test]
    fn consistency_rejects_wrong_roots_and_truncated_proofs() {
        let mut t = TestLog::new();
        for k in 0..20usize {
            t.append(alloc::format!("x{k}").as_bytes());
        }
        let (m, n) = (7u64, 20u64);
        let rm = t.root_at(m).unwrap();
        let rn = t.root_at(n).unwrap();
        let proof = {
            let mut lt = TestLog::new();
            for k in 0..n as usize {
                lt.append(alloc::format!("x{k}").as_bytes());
            }
            lt.consistency_proof(m).unwrap()
        };
        assert!(verify_consistency(m, n, &rm, &rn, &proof));
        // tampered roots fail
        let mut bad = rm;
        bad[0] ^= 0xff;
        assert!(!verify_consistency(m, n, &bad, &rn, &proof));
        let mut bad2 = rn;
        bad2[0] ^= 0xff;
        assert!(!verify_consistency(m, n, &rm, &bad2, &proof));
        // truncated / padded proofs fail
        assert!(!verify_consistency(
            m,
            n,
            &rm,
            &rn,
            &proof[..proof.len() - 1]
        ));
        let mut padded = proof.clone();
        padded.push([0u8; 32]);
        assert!(!verify_consistency(m, n, &rm, &rn, &padded));
        // size games fail
        assert!(!verify_consistency(n, m, &rn, &rm, &proof)); // first > second
        assert!(!verify_consistency(m, n, &rn, &rm, &proof)); // swapped roots
    }
}
