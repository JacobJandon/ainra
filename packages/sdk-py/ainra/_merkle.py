# SPDX-License-Identifier: Apache-2.0 OR MIT
"""RFC 6962 Merkle hashing (decision D-008): SHA-256 with domain separation.

Leaf hash is ``SHA-256(0x00 || data)``; interior node is
``SHA-256(0x01 || left || right)``. Inclusion is verified by the standard
RFC 6962 §2.1.1 audit-path walk. Written independently from RFC 6962.
"""

from __future__ import annotations

import hashlib


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def root_from_audit_path(leaf: bytes, index: object, proof: list[bytes]) -> bytes | None:
    """Reconstruct the tree root from an audit path using only the leaf index.

    At each level the proof sibling is combined left/right by the current index
    bit (``index & 1``), then the index is shifted down — the method AINRA's
    logs use to emit inclusion proofs. Returns ``None`` on a structurally invalid
    input (fail closed). The caller compares the result to the credential's
    committed ``log.root``.
    """
    if not isinstance(index, int) or index < 0:
        return None
    h = leaf
    i = index
    for sibling in proof:
        if len(sibling) != 32:
            return None
        if i & 1:
            h = _node_hash(sibling, h)
        else:
            h = _node_hash(h, sibling)
        i >>= 1
    return h


def root_from_inclusion(
    leaf: bytes, index: int, tree_size: int, proof: list[bytes]
) -> bytes | None:
    """Reconstruct the tree root from an RFC 6962 inclusion proof.

    Returns the computed root hash, or ``None`` if the (index, size, proof) are
    structurally inconsistent. The caller compares the result to the signed
    checkpoint root — a mismatch (or ``None``) is fail-closed ``not_logged``.
    """
    if index < 0 or tree_size <= 0 or index >= tree_size:
        return None
    fn = index
    sn = tree_size - 1
    h = leaf
    for sibling in proof:
        if len(sibling) != 32:
            return None
        if fn == sn or (fn & 1) == 1:
            h = _node_hash(sibling, h)
            # Ascend past every left-child ancestor.
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            h = _node_hash(h, sibling)
        fn >>= 1
        sn >>= 1
    # A well-formed proof consumes exactly enough siblings to reach the root.
    if sn != 0:
        return None
    return h
