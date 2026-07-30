# SPDX-License-Identifier: Apache-2.0 OR MIT
"""The ~5-line Verifier surface: valid, revoked, verifier-owns-the-clock."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from ainra import Verifier

ROOT = Path(__file__).resolve().parents[3]
V1 = ROOT / "vectors" / "v1"


def _vec(name):
    return json.loads((V1 / f"{name}.json").read_text())


class TestVerifierAPI(unittest.TestCase):
    def test_valid_five_line(self):
        v = _vec("valid-0000")
        verifier = Verifier(v["anchors"])
        verdict = verifier.verify(v["presentation"], v["presentation"]["now"])
        self.assertTrue(verdict.valid)
        self.assertIsNone(verdict.reason)
        # The verdict event is well-formed and carries identity.
        event = verdict.event()
        self.assertEqual(event["status"], "valid")
        self.assertTrue(event["number"].startswith("did:ainra:"))
        self.assertEqual(event["tier"], "L1")

    def test_revoked(self):
        v = _vec("revoked-0000")
        verifier = Verifier(v["anchors"])
        verdict = verifier.verify(v["presentation"], v["presentation"]["now"])
        self.assertFalse(verdict.valid)
        self.assertEqual(verdict.reason, "revoked")

    def test_verifier_owns_the_clock(self):
        # A bundle valid at its own `now` is EXPIRED when the caller supplies a
        # `now` at/after `exp` — the presenter cannot forward-date to dodge it.
        v = _vec("valid-0000")
        verifier = Verifier(v["anchors"])
        import base64

        claims = json.loads(
            base64.urlsafe_b64decode(
                v["presentation"]["claims"] + "=" * (-len(v["presentation"]["claims"]) % 4)
            )
        )
        exp = claims["exp"]
        nbf = claims["nbf"]
        own_now = v["presentation"]["now"]
        # Valid at the real presentation time, EXPIRED when the caller's clock
        # reaches `exp`, NOT_YET_VALID when it is before `nbf` — the verifier's
        # own clock decides, never the presenter's.
        self.assertTrue(verifier.verify(v["presentation"], own_now).valid)
        self.assertEqual(verifier.verify(v["presentation"], exp).reason, "expired")
        self.assertEqual(verifier.verify(v["presentation"], nbf - 1).reason, "not_yet_valid")

    def test_never_raises_on_garbage(self):
        verifier = Verifier({})
        self.assertFalse(verifier.verify({"claims": "!!not-base64!!"}, 0).valid)
        self.assertFalse(verifier.verify("not-a-dict", 0).valid)


if __name__ == "__main__":
    unittest.main()
