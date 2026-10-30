# SPDX-License-Identifier: Apache-2.0 OR MIT
"""ainra.conformance — replay the public test vectors.

These functions answer what a VECTOR says, which is the point of a conformance corpus: ``run_vector`` believes the
vector's own clock, freshness class and status list, so it can pin every reason deterministically. That is exactly why
it must never decide whether to trust a presenter — a revoked agent carrying an all-clear list of its own would read
valid (D-075). To decide, use :class:`ainra.Verifier`. This module exists so the difference is in the import, not only
in a docstring. Each function takes one vector (a dict) and returns its comparable result.
"""

from __future__ import annotations

from ._b64 import decode as _b64d
from .decision import run_decision_vector
from .delta import verify_delta_vector as run_delta_vector
from .directory import verify_directory as run_directory_vector
from .presentation import run_presentation_vector
from .verifier import Verifier
from .verify import verify as _verify_fixture


def run_vector(v: dict) -> dict:
    """A passport vector, with fixture semantics: the vector's anchors, clock, class and status are believed."""
    pres = v["presentation"]
    return _verify_fixture(v["anchors"], pres, pres.get("now")).as_result()


def run_gate_vector(v: dict) -> dict:
    """A gate vector (D-073): the directory against both roots, then the GA Verifier at the gate's own policy."""
    gate = Verifier.from_directory(v["directory"], v["roots"]["root_ed25519"], v["roots"]["root_slh"],
                                   audience=v["audience"], freshness=v["freshness"])
    if gate is None:
        return {"verdict": "no_gate"}
    verdict = gate.verify(v["bundle"], v["now"])
    return {"verdict": "valid"} if verdict.valid else {"verdict": "invalid", "reason": verdict.reason}


def run_link_vector(v: dict) -> dict:
    """A link vector (D-078), decided as a gate decides it."""
    gate = Verifier.from_directory(v["directory"], v["roots"]["root_ed25519"], v["roots"]["root_slh"],
                                   freshness=v["freshness"])
    key = _b64d(v.get("presented_key"))
    if gate is None:
        return {"verdict": "no_gate"}
    if key is None or len(key) != 32:
        return {"verdict": "invalid", "reason": "schema_violation"}
    return gate.verify_link(v["link"], key, v["now"], v.get("capability"))


__all__ = ["run_vector", "run_delta_vector", "run_directory_vector", "run_presentation_vector", "run_gate_vector",
           "run_link_vector", "run_decision_vector"]
