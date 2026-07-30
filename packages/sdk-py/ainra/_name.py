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

# A label is one or more lowercase alphanumerics / hyphens.
_LABEL = re.compile(r"^[a-z0-9-]+$")
# semver: 1 to 3 dot-separated numeric fields.
_VERSION = re.compile(r"^[0-9]+(\.[0-9]+){0,2}$")


def _label_ok(s: str) -> bool:
    return bool(_LABEL.match(s))


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
    if not isinstance(name, str) or "@" not in name:
        return None
    body, _, version = name.partition("@")
    if not _VERSION.match(version):
        return None
    parts = body.split(":")
    if len(parts) != 4 or parts[0] != "ainra":
        return None
    reg, op, lin = parts[1], parts[2], parts[3]
    if not (_label_ok(reg) and _label_ok(op) and _label_ok(lin)):
        return None
    return SubjectName(reg, op, lin, version)


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
