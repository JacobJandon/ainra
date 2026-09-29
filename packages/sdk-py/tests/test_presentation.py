# SPDX-License-Identifier: Apache-2.0 OR MIT
"""D-062 in the Python SDK: the request is bound to the presentation (PLAN-M34 Task 4).

WITNESS — could these tests fail? The corpus test runs every ``vectors/v1-presentation`` vector, whose answers
ainra-core recorded. Replace the canonical decode in ``_decode_signature`` with a lenient ``base64.b64decode`` and
``p33-signature-noncanonical-base64`` goes red — the defect the corpus found in the TypeScript SDK. Check the nonce
before the signature and ``p31-replayed-but-moved`` goes red. Swap ``$`` semantics back in (``re.match`` with a
trailing newline allowed) and ``test_a_trailing_newline_is_not_the_same_input`` goes red.
"""

from __future__ import annotations

import json
import pathlib
import unittest

from ainra.presentation import run_presentation_vector, verify_presentation

V = pathlib.Path(__file__).resolve().parents[3] / "vectors" / "v1-presentation"


def _vectors() -> list[dict]:
    return [json.loads(f.read_text()) for f in sorted(V.glob("p*.json"))]


class TestPresentationCorpus(unittest.TestCase):
    def test_every_vector_matches_the_core(self):
        vs = _vectors()
        self.assertGreaterEqual(len(vs), 33, "the presentation corpus is missing")
        for v in vs:
            with self.subTest(v["name"]):
                self.assertEqual(run_presentation_vector(v), v["expect"])

    def test_a_trailing_newline_is_not_the_same_input(self):
        v = next(x for x in _vectors() if x["name"] == "p01-valid-get")
        r = v["request"]
        headers = [(k, (val + "\n" if k == "signature-input" else val)) for k, val in r["headers"]]
        # .strip() on the header value removes the newline (RFC 9421 trims), so this still verifies…
        from ainra import _b64
        ik = v["instance"]["ikey"]
        common = dict(method=r["method"], authority=r["authority"], path=r["path"], body=None,
                      iid=v["instance"]["iid"], ikey_ed25519=_b64.decode(ik["ed25519"]),
                      ikey_mldsa65=_b64.decode(ik["mldsa65"]), now=v["now"])
        self.assertTrue(verify_presentation(headers=headers, **common)["ok"])
        # …but a newline INSIDE the value, before a trailing parameter, is a different string and must not parse.
        inner = [(k, (val.replace(';alg=', '\n;alg=') if k == "signature-input" else val)) for k, val in r["headers"]]
        self.assertEqual(verify_presentation(headers=inner, **common)["reason"], "presentation_sig_invalid")


if __name__ == "__main__":
    unittest.main()
