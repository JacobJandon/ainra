// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `logd` — a persistent, append-only RFC 6962 transparency log with ADR-002 delegate-signed checkpoints.
//!
//! Storage is one append-only file of base64url entry bytes, one per line, fsync'd on every append (durability
//! before acknowledgement — the log must never lose an entry it has proven). The Merkle tree is the services'
//! INCREMENTAL RFC 6962 tree (`crate::tree`, O(log N) per-issue root/proof — scale review HIGH), which is
//! byte-identical to `ainra_core::merkle`'s audited builder by exhaustive differential test. Production swaps this
//! file store for Tessera's tiles (D-011); the proofs are byte-identical because the tree math is the same.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use ainra_core::checkpoint::{Checkpoint, CheckpointSig, DelegateCert};
use ainra_core::{b64, crypto};

use crate::tree::IncrementalTree;

pub struct Logd {
    origin: String,
    path: PathBuf,
    tree: IncrementalTree,
    /// The online delegate that signs checkpoints (ADR-002). In production: 2-of-3 FROST among ops nodes.
    delegate: crypto::TestDelegate,
    /// The root-signed certificate authorizing `delegate` for `checkpoint-daily`.
    cert: DelegateCert,
    /// The log's SLH-DSA root public key — what a verifier/witness checks the checkpoint (or its delegate cert)
    /// against. Published in the log's accreditation.
    root_pub: Vec<u8>,
}

/// A checkpoint plus its ADR-002 delegate signature and the log's current size — the artifact a witness consumes.
pub struct SignedCheckpoint {
    pub checkpoint: Checkpoint,
    pub sig: CheckpointSig,
}

impl Logd {
    /// Open (or create) a log at `dir`, rebuilding the tree from any existing entries. `root` certifies `delegate`
    /// for checkpoint signing over `[now, now + validity]` (validity ≤ 92 days, enforced by the core).
    pub fn open(
        dir: &Path,
        origin: &str,
        root: &crypto::TestRootSlh,
        delegate: crypto::TestDelegate,
        now: u64,
        validity: u64,
    ) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("entries.log");
        let mut tree = IncrementalTree::new();
        if path.exists() {
            for line in BufReader::new(File::open(&path)?).lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let data = b64::decode(line.trim()).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "corrupt log line")
                })?;
                tree.append(&data);
            }
        }
        let cert = DelegateCert::issue_test_root(
            root,
            delegate.public(),
            vec![ainra_core::checkpoint::SCOPE_CHECKPOINT.to_string()],
            now,
            now + validity,
        )
        .map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("cert: {e:?}"))
        })?;
        Ok(Self {
            origin: origin.to_string(),
            path,
            tree,
            delegate,
            cert,
            root_pub: root.public(),
        })
    }

    pub fn size(&self) -> u64 {
        self.tree.size()
    }

    /// The log's SLH-DSA root public key — hand this to a witness (`Witness::register_log`) or a verifier so they
    /// can authenticate the checkpoint signature (ADR-002 delegate mode chains to it).
    pub fn root_public(&self) -> &[u8] {
        &self.root_pub
    }

    /// Append entry bytes, durably (fsync), returning the 0-based leaf index. The stored line is base64url(entry).
    pub fn append(&mut self, entry: &[u8]) -> std::io::Result<u64> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{}", b64::encode(entry))?;
        f.sync_all()?; // durable before we acknowledge
        Ok(self.tree.append(entry))
    }

    /// The current checkpoint, signed by the delegate (ADR-002 mode).
    pub fn signed_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            origin: self.origin.clone(),
            tree_size: self.tree.size(),
            root: self.tree.root(),
        }
    }

    pub fn sign_checkpoint(&self, cp: &Checkpoint) -> SignedCheckpoint {
        let sig = CheckpointSig::Delegate {
            cert: self.cert.clone(),
            sig_ed25519: cp.sign_delegate(&self.delegate).expect("delegate sign"),
        };
        SignedCheckpoint {
            checkpoint: cp.clone(),
            sig,
        }
    }

    /// Inclusion proof for the leaf at `index` (RFC 6962), against the current tree.
    pub fn inclusion_proof(&self, index: u64) -> Option<Vec<[u8; 32]>> {
        self.tree.inclusion_proof(index)
    }

    /// Consistency proof that the tree at `first` is a prefix of the current tree (RFC 6962) — the witness input.
    pub fn consistency_proof(&self, first: u64) -> Option<Vec<[u8; 32]>> {
        self.tree.consistency_proof(first)
    }

    pub fn root_at(&self, size: u64) -> Option<[u8; 32]> {
        self.tree.root_at(size)
    }
}
