# SPDX-License-Identifier: Apache-2.0 OR MIT
"""D-079 in the Python gate: every decision about a named passport is signed, chained and checkable.

Real fixtures (a valid passport and a revoked one, captured from a live registrar), through the ASGI gate with a
decision log; then the log is checked with nothing but the gate's public key. WITNESS: drop the ``_record`` call on
the refusal path and ``test_refusals_and_admissions_are_recorded`` goes red; record the operator on a refusal and
``test_a_refusal_never_names_the_operator`` goes red; and the request digest is pinned to the core's bytes.
"""

from __future__ import annotations

import asyncio
import base64
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ainra import AinraGate, Verifier
from ainra.decision import DecisionLog, request_digest, verify_chain
from ainra.middleware import HEADER

ROOT = Path(__file__).resolve().parents[3]
FX = ROOT / "packages" / "middleware" / "test" / "fixtures"


def _fx(name):
    return json.loads((FX / name).read_text())


def _gate_with_log():
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    lines = []
    log = DecisionLog(pub, key.sign, lines.append, freshness="F2", audience="https://shop.example")
    directory, roots = _fx("directory.json"), _fx("roots.json")
    verifier = Verifier.from_directory(directory, roots["root_ed25519"], roots["root_slh"])
    now = _fx("meta.json")["now"]

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    return AinraGate(app, verifier, now, decisions=log), lines, pub


def _call(gate, bundle, path="/orders"):
    hdr = base64.urlsafe_b64encode(json.dumps(bundle).encode()).rstrip(b"=")
    scope = {"type": "http", "method": "GET", "path": path, "query_string": b"",
             "headers": [(b"host", b"shop.example"), (HEADER.encode(), hdr)]}
    out = {}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(m):
        if m["type"] == "http.response.start":
            out["status"] = m["status"]

    asyncio.run(gate(scope, receive, send))
    return out["status"]


class TestDecisionLog(unittest.TestCase):
    def test_the_request_digest_is_the_cores(self):
        self.assertEqual(request_digest("GET", "shop.example", "/orders?id=7"),
                         "tHlRA9FaC4JbQTLk_5luMTNLhNGamRFVfC1G1OQ7otQ")

    def test_refusals_and_admissions_are_recorded(self):
        gate, lines, pub = _gate_with_log()
        self.assertEqual(_call(gate, _fx("bundle-valid.json")), 200)
        self.assertEqual(_call(gate, _fx("bundle-revoked.json")), 403)
        self.assertEqual(_call(gate, _fx("bundle-valid.json"), "/refunds"), 200)
        self.assertEqual(len(lines), 3)
        self.assertEqual(verify_chain(lines, pub), {"ok": True, "count": 3})
        recs = [json.loads(x) for x in lines]
        self.assertEqual([r["verdict"] for r in recs], ["valid", "invalid", "valid"])
        self.assertEqual(recs[1]["reason"], "revoked")
        self.assertNotEqual(recs[0]["request"], recs[2]["request"])

    def test_a_refusal_never_names_the_operator(self):
        gate, lines, _ = _gate_with_log()
        _call(gate, _fx("bundle-revoked.json"))
        self.assertNotIn("operator", json.loads(lines[0]))

    def test_an_edited_record_is_found(self):
        gate, lines, pub = _gate_with_log()
        _call(gate, _fx("bundle-valid.json"))
        _call(gate, _fx("bundle-revoked.json"))
        edited = [lines[0], lines[1].replace('"reason":"revoked"', '"reason":"stale_status"')]
        self.assertEqual(verify_chain(edited, pub), {"ok": False, "index": 1, "problem": "signature"})

    def test_an_unnamed_request_is_decided_but_not_recorded(self):
        gate, lines, _ = _gate_with_log()
        self.assertEqual(_call(gate, {"claims": "AAAA"}), 403)
        self.assertEqual(lines, [])


if __name__ == "__main__":
    unittest.main()
