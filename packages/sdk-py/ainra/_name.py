# SPDX-License-Identifier: Apache-2.0 OR MIT
"""AINRA name grammar (The Standard §2).

``ainra:{registrar}:{operator}:{lineage}@{version}`` where each label is
lowercase alphanumerics and hyphens, and ``version`` is a 1–3 field numeric
semver. The issuer is a version-less DID: ``did:ainra:{registrar}:{operator}:{lineage}``.
Written from the grammar; the ``name-malformed`` vectors are the ground truth.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Mirrors crates/ainra-core/src/name.rs exactly (2026-11-07 review, D-104). The regexes used to accept a trailing
# newline (`$`), a hyphen at either end, labels over 63 characters and leading-zero version fields.
_MAX_LABEL = 63


def _label_ok(s: str) -> bool:
    if not 1 <= len(s) <= _MAX_LABEL:
        return False
    if any(not ("a" <= c <= "z" or "0" <= c <= "9" or c == "-") for c in s):
        return False
    return s[0] != "-" and s[-1] != "-"


def _version_ok(v: str) -> bool:
    fields = v.split(".")
    if not 1 <= len(fields) <= 3:
        return False
    for f in fields:
        if not f or any(not "0" <= c <= "9" for c in f):
            return False
        if len(f) > 1 and f[0] == "0":
            return False
    return True


@dataclass(frozen=True)
class SubjectName:
    registrar: str
    operator: str
    lineage: str
    version: str

    @property
    def number(self) -> str:
        """The permanent version-less AINRA Number (a ``did:ainra`` DID)."""
        return f"did:ainra:{self.registrar}:{self.operator}:{self.lineage}"


def parse_subject(name: object) -> SubjectName | None:
    """Parse ``ainra:reg:op:lin@ver``; ``None`` if it violates the grammar."""
    if not isinstance(name, str) or not name.startswith("ainra:") or "@" not in name:
        return None
    body, _, version = name.rpartition("@")
    if not _version_ok(version):
        return None
    parts = body.split(":")
    if len(parts) != 4 or parts[0] != "ainra":
        return None
    reg, op, lin = parts[1], parts[2], parts[3]
    if not (_label_ok(reg) and _label_ok(op) and _label_ok(lin)):
        return None
    return SubjectName(reg, op, lin, version)


def parse_issuer_parts(iss: object) -> tuple[str, str, str] | None:
    """Parse ``did:ainra:reg:op:lin`` into (registrar, operator, lineage), else ``None``."""
    if not isinstance(iss, str):
        return None
    parts = iss.split(":")
    if len(parts) != 5 or parts[0] != "did" or parts[1] != "ainra":
        return None
    reg, op, lin = parts[2], parts[3], parts[4]
    if not (_label_ok(reg) and _label_ok(op) and _label_ok(lin)):
        return None
    return reg, op, lin


def parse_issuer(iss: object) -> str | None:
    """Parse ``did:ainra:reg:op:lin`` and return the registrar id, else ``None``."""
    if not isinstance(iss, str):
        return None
    parts = iss.split(":")
    # ["did", "ainra", reg, op, lin]
    if len(parts) != 5 or parts[0] != "did" or parts[1] != "ainra":
        return None
    reg, op, lin = parts[2], parts[3], parts[4]
    if not (_label_ok(reg) and _label_ok(op) and _label_ok(lin)):
        return None
    return reg
