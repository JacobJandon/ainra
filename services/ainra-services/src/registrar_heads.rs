// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Logged decision heads at the registrar (D-081): a gate hands over a signed statement of where its decision log
//! stood, and the registrar appends it to the same transparency log its passports and links live in. A child module
//! of `registrar`, like `link`; it invents no checks of its own — every statement is read by
//! [`ainra_core::decision::HeadStatement::verify`] before anything is logged.
//!
//! What the registrar sees is a digest, never a decision. Two rules:
//!   * **a statement is self-authenticating.** It names the gate by its key's thumbprint and is signed by that key,
//!     so anyone may submit one; the registrar checks the signature and logs it, nothing more.
//!   * **a gate's head never goes backwards here.** A statement below the highest `seq` already logged for that gate
//!     is refused, and so is a second, different head at the same `seq` — so this log alone shows a gate that tried
//!     to rewind or to fork its own history. Re-submitting the same statement returns the same receipt.

use ainra_core::b64;
use ainra_core::decision::HeadStatement;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{IssueError, RegistrarBox, WireCheckpointSig};

/// A head statement line is about 250 bytes; anything far larger is not one.
const MAX_STATEMENT: usize = 1024;

/// One logged head, as the registrar keeps it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoggedHead {
    pub gate: String,
    pub seq: u64,
    /// The statement line, exactly as logged.
    pub statement: String,
    pub leaf_index: u64,
}

impl RegistrarBox {
    /// Log `statement`, signed by `gate_key` (base64url Ed25519), and return its receipt.
    pub fn log_head(
        &mut self,
        statement: &str,
        gate_key: &str,
    ) -> Result<serde_json::Value, IssueError> {
        if statement.len() > MAX_STATEMENT {
            return Err(IssueError::Malformed("not a head statement".into()));
        }
        let key: [u8; 32] = b64::decode_array(gate_key).map_err(|_| {
            IssueError::Malformed("gate_key must be a base64url Ed25519 key".into())
        })?;
        let h = HeadStatement::verify(statement.as_bytes(), &key).map_err(|r| {
            IssueError::HolderProof(format!(
                "the statement is not a canonical head signed by that gate key ({})",
                r.as_str()
            ))
        })?;
        if let Some(last) = self.decision_heads.get(&h.gate).and_then(|v| v.last()) {
            if last.seq == h.seq && last.statement == statement {
                return self
                    .head_receipt(last)
                    .ok_or_else(|| IssueError::Io("inclusion proof unavailable".into()));
            }
            if h.seq <= last.seq {
                return Err(IssueError::Malformed(format!(
                    "this gate already logged a head at seq {}; a head never goes backwards and is never replaced",
                    last.seq
                )));
            }
        }
        let leaf_index = self
            .log
            .append(statement.as_bytes())
            .map_err(|e| IssueError::Io(e.to_string()))?;
        let entry = LoggedHead {
            gate: h.gate.clone(),
            seq: h.seq,
            statement: statement.to_string(),
            leaf_index,
        };
        let receipt = self.head_receipt(&entry);
        self.decision_heads.entry(h.gate).or_default().push(entry);
        receipt.ok_or_else(|| IssueError::Io("inclusion proof unavailable".into()))
    }

    /// A receipt for one logged head: the statement, where it sits, and the proof under the current checkpoint.
    pub fn head_receipt(&self, e: &LoggedHead) -> Option<serde_json::Value> {
        let cp = self.log.signed_checkpoint();
        let signed = self.log.sign_checkpoint(&cp);
        let proof = self.log.inclusion_proof(e.leaf_index)?;
        Some(json!({
            "v": "ainra-decision-head-receipt-1",
            "registrar": self.id,
            "statement": e.statement,
            "leaf_index": e.leaf_index,
            "inclusion_proof": proof.iter().map(|h| b64::encode(h)).collect::<Vec<_>>(),
            "checkpoint": { "origin": self.log_origin(), "size": cp.tree_size, "root": b64::encode(&cp.root) },
            "checkpoint_sig": WireCheckpointSig::from_core(&signed.sig),
        }))
    }

    /// Every logged head, each proven under the one current checkpoint — fetched whole, like the link index, so
    /// nobody learns which gate a checker cares about.
    pub fn decision_heads_index(&self) -> Option<serde_json::Value> {
        let cp = self.log.signed_checkpoint();
        let signed = self.log.sign_checkpoint(&cp);
        let mut heads = Vec::new();
        for e in self.decision_heads.values().flatten() {
            let proof = self.log.inclusion_proof(e.leaf_index)?;
            heads.push(json!({
                "statement": e.statement,
                "leaf_index": e.leaf_index,
                "inclusion_proof": proof.iter().map(|h| b64::encode(h)).collect::<Vec<_>>(),
            }));
        }
        Some(json!({
            "v": "ainra-decision-heads-1",
            "registrar": self.id,
            "checkpoint": { "origin": self.log_origin(), "size": cp.tree_size, "root": b64::encode(&cp.root) },
            "checkpoint_sig": WireCheckpointSig::from_core(&signed.sig),
            "heads": heads,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{engine, VERIFY_NOW};
    use super::*;
    use ainra_core::crypto::TestDelegate;
    use ainra_core::decision::{gate_id, verify_head_receipt, HeadReceiptCheck, HEAD_V};
    use ainra_core::Reason;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn gate(seed: u64) -> TestDelegate {
        TestDelegate::generate(&mut ChaCha20Rng::seed_from_u64(seed))
    }

    fn statement(g: &TestDelegate, seq: u64, head: [u8; 32]) -> String {
        let mut h = HeadStatement {
            v: HEAD_V.into(),
            gate: gate_id(&g.public()),
            seq,
            at: 1_000 + seq,
            head: b64::encode(&head),
            sig: String::new(),
        };
        h.sig = b64::encode(&g.sign(&h.signing_bytes().unwrap()));
        String::from_utf8(h.to_line().unwrap()).unwrap()
    }

    fn setup(name: &str) -> RegistrarBox {
        let tmp = std::env::temp_dir().join(format!("ainra-rb-heads-{name}"));
        let _ = std::fs::remove_dir_all(&tmp);
        engine(&tmp)
    }

    #[test]
    fn a_logged_head_verifies_through_the_core_as_the_registrar_logged_it() {
        let mut rb = setup("verify");
        let g = gate(1);
        let line = statement(&g, 4, [7u8; 32]);
        let receipt = rb.log_head(&line, &b64::encode(&g.public())).unwrap();
        assert_eq!(receipt["statement"], json!(line));
        let leaf_index = receipt["leaf_index"].as_u64().unwrap();
        let cp = rb.log.signed_checkpoint();
        let signed = rb.log.sign_checkpoint(&cp);
        let proof = rb.log.inclusion_proof(leaf_index).unwrap();
        let none = Default::default();
        let chk = HeadReceiptCheck {
            statement: line.as_bytes(),
            gate_key: g.public(),
            registrar: "registrar-07",
            checkpoint: &cp,
            checkpoint_sig: &signed.sig,
            leaf_index,
            inclusion_proof: &proof,
            revoked_delegates: &none,
            now: VERIFY_NOW,
        };
        assert_eq!(
            verify_head_receipt(&chk, &rb.trust_anchors()).unwrap().seq,
            4
        );
        let index = rb.decision_heads_index().unwrap();
        assert_eq!(index["heads"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn a_gates_head_never_goes_backwards_and_is_never_replaced() {
        let mut rb = setup("floor");
        let g = gate(1);
        let key = b64::encode(&g.public());
        let first = statement(&g, 4, [7u8; 32]);
        let receipt = rb.log_head(&first, &key).unwrap();
        // The same statement again is the same receipt, not a second entry.
        assert_eq!(
            rb.log_head(&first, &key).unwrap()["leaf_index"],
            receipt["leaf_index"]
        );
        let back = rb.log_head(&statement(&g, 3, [7u8; 32]), &key);
        assert!(
            matches!(back, Err(IssueError::Malformed(m)) if m.contains("never goes backwards"))
        );
        let fork = rb.log_head(&statement(&g, 4, [8u8; 32]), &key);
        assert!(matches!(fork, Err(IssueError::Malformed(_))));
        assert!(rb.log_head(&statement(&g, 9, [9u8; 32]), &key).is_ok());
        // Another gate's floor is its own.
        let other = gate(2);
        assert!(rb
            .log_head(
                &statement(&other, 0, [1u8; 32]),
                &b64::encode(&other.public())
            )
            .is_ok());
        assert_eq!(
            rb.decision_heads_index().unwrap()["heads"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn only_a_statement_its_gate_signed_is_logged() {
        let mut rb = setup("signed");
        let g = gate(1);
        let line = statement(&g, 4, [7u8; 32]);
        let wrong_key = rb.log_head(&line, &b64::encode(&gate(2).public()));
        assert!(
            matches!(wrong_key, Err(IssueError::HolderProof(m)) if m.contains(Reason::SigInvalid.as_str()))
        );
        let mut spaced = line.clone();
        spaced.insert(1, ' ');
        assert!(matches!(
            rb.log_head(&spaced, &b64::encode(&g.public())),
            Err(IssueError::HolderProof(_))
        ));
        assert!(rb.decision_heads_index().unwrap()["heads"]
            .as_array()
            .unwrap()
            .is_empty());
    }
}
