# SPDX-License-Identifier: Apache-2.0 OR MIT
"""D-078 in the Python gate: link mode. Real vectors from vectors/v1-link, served as a registrar would serve them;
the request's key is the caller's own verified key; the gate says who stands behind it."""

from __future__ import annotations

import asyncio
import base64
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ainra import AinraLinkGate, DecisionLog, Verifier
from ainra.decision import verify_chain

ROOT = Path(__file__).resolve().parents[3]


def _vec(name):
    return json.loads((ROOT / "vectors" / "v1-link" / f"{name}.json").read_text())


def _b64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _served(v):
    lk = v["link"]
    claims = json.loads(_b64(lk["claims"]))
    index = {"checkpoint": lk["checkpoint"], "checkpoint_sig": lk["checkpoint_sig"],
             "links": [{"thumbprint": claims["subject"]["thumbprint"], "claims": lk["claims"],
                        "registrar_sig": lk["registrar_sig"], "leaf_index": lk["leaf_index"],
                        "inclusion_proof": lk["inclusion_proof"]}]}
    status = {"uri": lk["status_uri"], "status_list_b64": lk["status_list"], "bit_len": lk["status_len"],
              "issued_at": lk["status_issued_at"], "sig_ed25519": lk["status_sig_ed25519"],
              "sig_mldsa65": lk["status_sig_mldsa65"]}
    return index, status


def _run(v, key, decisions=None, capability=None):
    verifier = Verifier.from_directory(v["directory"], v["roots"]["root_ed25519"], v["roots"]["root_slh"],
                                       freshness=v["freshness"])
    seen = {}

    async def app(scope, receive, send):
        seen["link"] = scope["ainra_link"]
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    gate = AinraLinkGate(app, verifier, lambda scope, headers: key, lambda: _served(v), v["now"],
                         capability=(lambda scope: capability) if capability else None, decisions=decisions)
    out = {}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(m):
        if m["type"] == "http.response.start":
            out["status"] = m["status"]
            out["reason"] = dict(m["headers"]).get(b"x-ainra-reason", b"").decode()

    asyncio.run(gate({"type": "http", "method": "GET", "path": "/orders", "query_string": b"",
                      "headers": [(b"host", b"shop.example")]}, receive, send))
    return out, seen


class TestLinkGate(unittest.TestCase):
    def test_a_linked_key_passes_and_names_the_operator(self):
        v = _vec("l01-valid")
        out, seen = _run(v, _b64(v["presented_key"]))
        self.assertEqual(out["status"], 200)
        self.assertEqual(seen["link"]["operator"], "acme")

    def test_revoked_out_of_scope_unlinked_and_unverified_are_refused_by_name(self):
        v = _vec("l05-link-revoked")
        self.assertEqual(_run(v, _b64(v["presented_key"]))[0]["reason"], "revoked")
        n = _vec("l13-outside-scope")
        self.assertEqual(_run(n, _b64(n["presented_key"]), capability=n["capability"])[0]["reason"], "ceiling_exceeded")
        ok = _vec("l01-valid")
        self.assertEqual(_run(ok, bytes([3]) * 32)[0]["reason"], "not_linked")
        self.assertEqual(_run(ok, None)[0]["reason"], "sig_invalid")

    def test_link_decisions_are_recorded_and_chained(self):
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        lines = []
        log = DecisionLog(pub, key.sign, lines.append)
        v = _vec("l01-valid")
        _run(v, _b64(v["presented_key"]), decisions=log)
        _run(v, bytes([3]) * 32, decisions=log)
        self.assertEqual(verify_chain(lines, pub), {"ok": True, "count": 2})
        a, b = (json.loads(x) for x in lines)
        self.assertEqual((a["kind"], a["operator"]), ("link", "acme"))
        self.assertEqual(b["reason"], "not_linked")
        self.assertNotIn("operator", b)


if __name__ == "__main__":
    unittest.main()
