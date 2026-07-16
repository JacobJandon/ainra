// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Mandate subtree revocation (MTS §18).
//!
//! Mandates form a tree (a root mandate authorizes narrower child mandates, AP2-style). Revoking a mandate revokes
//! its ENTIRE subtree: if any ancestor on the operative mandate's path is revoked, the action is unauthorized with
//! [`Reason::MandateRevoked`]. A presented path is first checked to be a genuine parent-linked chain (so a forged
//! path cannot omit a revoked ancestor) — a broken linkage is [`Reason::SchemaViolation`].
//!
//! Binding each mandate leaf to the passport's `mandates_root` uses the same RFC 6962 inclusion mechanism as the
//! log (see [`crate::merkle`]); that reuse is intentional and already covered by the merkle tests.

use alloc::collections::BTreeSet;
use alloc::string::String;

use serde::{Deserialize, Serialize};

use crate::verdict::Reason;

/// One node on a mandate path: its id and the id of its parent (`None` only for the root mandate).
///
/// The operative mandate path is carried INSIDE the issuer-signed passport (`Passport::mandates`), not supplied by
/// the presenter — so the issuer signature authenticates it and a presenter cannot omit a revoked ancestor to
/// escape subtree revocation (MTS §18). The presenter only supplies the current revocation set (a trusted verifier
/// input, like the status list). Dynamic post-issue mandate graphs with per-node inclusion proofs are M2
/// (DECISIONS D-009).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MandateNode {
    pub id: String,
    pub parent: Option<String>,
}

/// The set of revoked mandate ids (an ancestor being present here kills the whole subtree).
#[derive(Debug, Clone, Default)]
pub struct RevocationSet {
    revoked: BTreeSet<String>,
}

impl RevocationSet {
    pub fn from_ids<I: IntoIterator<Item = String>>(ids: I) -> Self {
        Self {
            revoked: ids.into_iter().collect(),
        }
    }
    pub fn is_revoked(&self, id: &str) -> bool {
        self.revoked.contains(id)
    }
}

/// Evaluate a mandate path (root → … → operative). An empty path means "no mandate gates this action" → Ok.
/// Fixed order: structural linkage is validated first, then revocation (so the reason is deterministic).
pub fn check_path(
    path: &[MandateNode],
    revoked: &RevocationSet,
) -> core::result::Result<(), Reason> {
    if path.is_empty() {
        return Ok(());
    }
    // The head must be a root (no parent); every subsequent node's parent must be the previous node's id.
    if path[0].parent.is_some() {
        return Err(Reason::SchemaViolation);
    }
    for w in path.windows(2) {
        if w[1].parent.as_deref() != Some(w[0].id.as_str()) {
            return Err(Reason::SchemaViolation);
        }
    }
    // Any revoked node on the path (ancestor or the operative mandate itself) kills it.
    if path.iter().any(|n| revoked.is_revoked(&n.id)) {
        return Err(Reason::MandateRevoked);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    fn node(id: &str, parent: Option<&str>) -> MandateNode {
        MandateNode {
            id: id.to_string(),
            parent: parent.map(|p| p.to_string()),
        }
    }

    fn path() -> Vec<MandateNode> {
        vec![
            node("m-root", None),
            node("m-child", Some("m-root")),
            node("m-leaf", Some("m-child")),
        ]
    }

    #[test]
    fn clean_path_ok() {
        assert_eq!(check_path(&path(), &RevocationSet::default()), Ok(()));
        assert_eq!(check_path(&[], &RevocationSet::default()), Ok(()));
    }

    #[test]
    fn revoking_ancestor_kills_subtree() {
        let rev = RevocationSet::from_ids(["m-child".to_string()]);
        assert_eq!(check_path(&path(), &rev), Err(Reason::MandateRevoked));
    }

    #[test]
    fn revoking_the_operative_mandate_kills_it() {
        let rev = RevocationSet::from_ids(["m-leaf".to_string()]);
        assert_eq!(check_path(&path(), &rev), Err(Reason::MandateRevoked));
    }

    #[test]
    fn unrelated_revocation_does_not_affect() {
        let rev = RevocationSet::from_ids(["m-somewhere-else".to_string()]);
        assert_eq!(check_path(&path(), &rev), Ok(()));
    }

    #[test]
    fn broken_linkage_is_schema_violation() {
        // second node claims a parent that isn't the first node → forged path
        let bad = vec![node("m-root", None), node("m-child", Some("m-imposter"))];
        assert_eq!(
            check_path(&bad, &RevocationSet::default()),
            Err(Reason::SchemaViolation)
        );
        // head with a parent is not a root
        let bad2 = vec![node("m-child", Some("m-root"))];
        assert_eq!(
            check_path(&bad2, &RevocationSet::default()),
            Err(Reason::SchemaViolation)
        );
    }
}
