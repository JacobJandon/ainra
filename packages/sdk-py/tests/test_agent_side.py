# SPDX-License-Identifier: Apache-2.0 OR MIT
"""D-071 — the producing side in Python: an agent mints a credential for a running copy and signs its requests.

WITNESS — could these tests fail? Every signature here is made with real keys (Ed25519 + ML-DSA-65 from
``cryptography``) and checked by the verifier the corpus holds to ``ainra-core``: sign over the wrong base, drop the
``content-digest`` for a body, or SET the fields over another signer's and a test goes red. ``make sign-diff`` then
holds the same signatures to the Rust core and the TypeScript SDK; these tests only cover what one process can.
"""

from __future__ import annotations

import base64
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

from ainra import mint_instance_credential, sign_presentation
from ainra import _b64
from ainra._canon import canon_bytes
from ainra._merkle import leaf_hash
from ainra.instance import instance_signing_bytes
from ainra.presentation import PRESENTATION_HEADER, content_digest, verify_presentation

NOW = 1_800_000_000
REF = "sha-256=:" + base64.b64encode(bytes(32)).decode() + ":"
AGENT_INPUT = 'sig1=("@authority" "signature-agent";key="sig1");created=1800000000;expires=1800003600;keyid="op";alg="ed25519";tag="web-bot-auth"'
AGENT_SIG = "sig1=:" + base64.b64encode(bytes(64)).decode() + ":"


class Key:
    """A hybrid key the way a caller holds one: outside the SDK, handed in as a signing callback."""

    def __init__(self):
        self.ed, self.ml = ed25519.Ed25519PrivateKey.generate(), mldsa.MLDSA65PrivateKey.generate()

    def _raw(self, k):
        return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def public(self):
        return {"ed25519": _b64.encode(self._raw(self.ed)), "mldsa65": _b64.encode(self._raw(self.ml))}

    def sign(self, msg: bytes):
        return {"ed25519": _b64.encode(self.ed.sign(msg)), "mldsa65": _b64.encode(self.ml.sign(msg))}

    def check(self, **kw):
        return verify_presentation(iid="i-py", ikey_ed25519=self._raw(self.ed), ikey_mldsa65=self._raw(self.ml),
                                   now=NOW, **kw)


def _signed(key, method="GET", path="/orders", body=None, extra=()):
    headers = [(PRESENTATION_HEADER, REF), *extra]
    add = sign_presentation(method=method, authority="shop.example", path=path, headers=headers, body=body,
                            keyid="i-py", nonce="n-1", created=NOW, instance_sign=key.sign)
    names = {k for k, _ in add}
    return [(k, v) for k, v in headers if k not in names] + add


class TestSignPresentation(unittest.TestCase):
    def setUp(self):
        self.key = Key()

    def test_a_request_signed_here_verifies_and_returns_its_nonce(self):
        h = _signed(self.key)
        self.assertEqual(self.key.check(method="GET", authority="shop.example", path="/orders", headers=h, body=None),
                         {"ok": True, "nonce": "n-1", "created": NOW})

    def test_a_body_is_covered_through_its_digest(self):
        body = b'{"sku":"A-1"}'
        h = _signed(self.key, method="POST", body=body)
        self.assertIn(("content-digest", content_digest(body)), h)
        args = dict(method="POST", authority="shop.example", path="/orders", headers=h)
        self.assertTrue(self.key.check(body=body, **args)["ok"])
        self.assertEqual(self.key.check(body=b'{"sku":"A-2"}', **args)["reason"], "presentation_sig_invalid")

    def test_moved_or_signed_by_another_key_is_refused(self):
        h = _signed(self.key)
        moved = self.key.check(method="GET", authority="shop.example", path="/admin", headers=h, body=None)
        self.assertEqual(moved["reason"], "presentation_sig_invalid")
        other = Key().check(method="GET", authority="shop.example", path="/orders", headers=h, body=None)
        self.assertEqual(other["reason"], "presentation_sig_invalid")

    def test_it_appends_to_another_signers_fields_and_never_overwrites(self):
        h = _signed(self.key, extra=[("signature-input", AGENT_INPUT), ("signature", AGENT_SIG)])
        fields = dict(h)
        self.assertTrue(fields["signature-input"].startswith(AGENT_INPUT + ", ainra=("))
        self.assertTrue(fields["signature"].startswith(AGENT_SIG + ", ainra=:"))
        self.assertTrue(self.key.check(method="GET", authority="shop.example", path="/orders", headers=h, body=None)["ok"])
        with self.assertRaisesRegex(ValueError, "already carries an ainra signature"):
            _signed(self.key, extra=[(k, v) for k, v in h if k.startswith("signature")])
        with self.assertRaisesRegex(ValueError, "half of another signature"):
            _signed(self.key, extra=[("signature-input", AGENT_INPUT)])

    def test_it_refuses_to_emit_what_the_profile_refuses(self):
        base = dict(method="GET", authority="shop.example", path="/", headers=[(PRESENTATION_HEADER, REF)], body=None,
                    created=NOW, instance_sign=self.key.sign)
        with self.assertRaisesRegex(ValueError, "nonce"):
            sign_presentation(keyid="i-py", nonce="has space", **base)
        with self.assertRaisesRegex(ValueError, "keyid"):
            sign_presentation(keyid='i-"py', nonce="n-1", **base)
        with self.assertRaisesRegex(ValueError, "covered component is missing"):
            sign_presentation(keyid="i-py", nonce="n-1", **{**base, "headers": []})
        with self.assertRaisesRegex(ValueError, "both halves are mandatory"):
            sign_presentation(keyid="i-py", nonce="n-1",
                              **{**base, "instance_sign": lambda m: {"ed25519": self.key.sign(m)["ed25519"]}})


class TestMintDerivesTheLeaf(unittest.TestCase):
    CLAIMS = {"sub": "ainra:registrar-07:acme:bot@1.0.0", "capabilities": ["read:invoices", "pay:invoices"],
              "log": {"leaf": "x", "root": "y", "checkpoint": "z"}}

    def _mint(self, **kw):
        k = Key()
        args = dict(passport_claims_b64=_b64.encode(canon_bytes(self.CLAIMS)), instance_public=k.public(),
                    capabilities=["read:invoices"], audience="https://shop.example", now=NOW, iid="i-py",
                    control_sign=k.sign)
        return mint_instance_credential(**{**args, **kw}), k

    def test_the_leaf_is_the_claims_without_log(self):
        ic, k = self._mint()
        body = {key: v for key, v in self.CLAIMS.items() if key != "log"}
        self.assertEqual(ic["passport_leaf"], _b64.encode(leaf_hash(canon_bytes(body))))
        # The control key signed exactly the bytes a verifier recomputes.
        ed = k.ed.public_key()
        ed.verify(_b64.decode(ic["sig"]["ed25519"]), instance_signing_bytes(ic))

    def test_a_leaf_that_is_not_these_claims_is_refused(self):
        ic, _ = self._mint()
        self._mint(passport_leaf_b64=ic["passport_leaf"])  # the right one is accepted
        with self.assertRaisesRegex(ValueError, "not the leaf of these claims"):
            self._mint(passport_leaf_b64=_b64.encode(bytes(32)))

    def test_widening_is_still_refused(self):
        with self.assertRaisesRegex(ValueError, "must narrow"):
            self._mint(capabilities=["admin:all"])


if __name__ == "__main__":
    unittest.main()
