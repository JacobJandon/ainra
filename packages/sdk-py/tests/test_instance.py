# SPDX-License-Identifier: Apache-2.0 OR MIT
"""ADR-019 in the Python SDK: the instance rung, and whose audience decides.

WITNESS — could these tests fail? Each runs a REAL accepted instance vector from the corpus and varies exactly one
thing. Remove the audience comparison from ``_verify_instance`` and ``test_wrong_audience_is_refused`` plus
``test_anonymous_verifier_accepts_no_instance_credential`` go red. Pass the bundle's audience through
``Verifier.verify`` again — the fail-open this file was written against — and
``test_presenter_cannot_name_its_own_audience`` goes red while everything else stays green, which is precisely how
that defect survived in Python after being fixed in TypeScript.
"""

from __future__ import annotations

import json
import pathlib
import unittest

from ainra import Verifier
from ainra.verify import verify as verify_presentation

V1 = pathlib.Path(__file__).resolve().parents[3] / "vectors" / "v1"


def _accepted_instance_vector() -> dict:
    for f in sorted(V1.glob("instance-valid-*.json")):
        return json.loads(f.read_text())
    raise AssertionError("the corpus has no accepted instance vectors")


class TestInstanceRung(unittest.TestCase):
    def setUp(self) -> None:
        self.vec = _accepted_instance_vector()
        self.anchors = self.vec["anchors"]
        self.pres = self.vec["presentation"]
        self.now = self.pres["now"]
        self.aud = self.pres["audience"]

    def test_the_fixture_is_genuinely_accepted(self):
        """Otherwise every assertion below proves nothing."""
        self.assertEqual(self.vec["expect"]["verdict"], "valid")
        self.assertIn("instance", self.pres)
        self.assertTrue(self.aud)
        v = verify_presentation(self.anchors, self.pres, self.now)
        self.assertTrue(v.valid, f"expected valid, got {v.reason}")

    def test_wrong_audience_is_refused(self):
        pres = dict(self.pres, audience="https://not-this-service.example")
        v = verify_presentation(self.anchors, pres, self.now)
        self.assertFalse(v.valid)
        self.assertEqual(v.reason, "instance_pop_invalid")

    def test_anonymous_verifier_accepts_no_instance_credential(self):
        """An empty audience is not "any audience" — it is "nobody has told me who I am"."""
        pres = dict(self.pres, audience="")
        v = verify_presentation(self.anchors, pres, self.now)
        self.assertFalse(v.valid)
        self.assertEqual(v.reason, "instance_pop_invalid")

    def test_presenter_cannot_name_its_own_audience(self):
        """The bundle claims to be addressed here; the verifier was configured for somewhere else.

        This is the fail-open that lived in this SDK from M28 until M29: `Verifier.verify` overrode only
        `revoked_delegates`, so `audience` came straight off the wire.
        """
        lying = dict(self.pres, audience=self.aud)  # a presenter asserting the target audience
        v = Verifier(self.anchors, [], "https://somewhere-else.example")
        self.assertFalse(v.verify(lying, self.now).valid)
        self.assertEqual(v.verify(lying, self.now).reason, "instance_pop_invalid")
        # …and the correctly-configured verifier accepts the very same bytes.
        self.assertTrue(Verifier(self.anchors, [], self.aud).verify(lying, self.now).valid)

    def test_default_verifier_is_fail_closed(self):
        v = Verifier(self.anchors)
        self.assertFalse(v.verify(self.pres, self.now).valid)

    def test_each_refusal_keeps_its_own_reason(self):
        """No instance failure may collapse into a reason that would mislead a debugging integrator."""
        for prefix, want in [
            ("instance-expired-", "instance_expired"),
            ("instance-scope-exceeds-", "instance_scope_exceeds"),
            ("instance-wrong-signer-", "instance_sig_invalid"),
            ("instance-pop-wrong-key-", "instance_pop_invalid"),
            ("instance-passport-revoked-", "revoked"),
        ]:
            files = sorted(V1.glob(prefix + "*.json"))
            self.assertTrue(files, f"no vectors for {prefix}")
            vec = json.loads(files[0].read_text())
            v = verify_presentation(vec["anchors"], vec["presentation"], vec["presentation"]["now"])
            self.assertFalse(v.valid, prefix)
            self.assertEqual(v.reason, want, f"{prefix}: got {v.reason}")


if __name__ == "__main__":
    unittest.main()
