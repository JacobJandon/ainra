# SPDX-License-Identifier: Apache-2.0 OR MIT
"""The ASGI gate: pass through on VALID, deny 403 fail-closed otherwise."""

from __future__ import annotations

import asyncio
import base64
import json
import unittest
from pathlib import Path

from ainra import AinraGate, Verifier
from ainra.middleware import HEADER

ROOT = Path(__file__).resolve().parents[3]
V1 = ROOT / "vectors" / "v1"


def _vec(name):
    return json.loads((V1 / f"{name}.json").read_text())


async def _call(gate, headers, body=b""):
    """Drive one HTTP request through an ASGI app; return (status, headers, body)."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/agent",
        "headers": [(k.encode("latin1"), v.encode("latin1")) for k, v in headers.items()],
    }
    sent = {"delivered": False}

    async def receive():
        if not sent["delivered"]:
            sent["delivered"] = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    out = {"status": None, "headers": {}, "body": b""}

    async def send(message):
        if message["type"] == "http.response.start":
            out["status"] = message["status"]
            out["headers"] = {
                k.decode("latin1").lower(): v.decode("latin1") for k, v in message["headers"]
            }
        elif message["type"] == "http.response.body":
            out["body"] += message.get("body", b"")

    await gate(scope, receive, send)
    return out


async def _ok_app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"served"})


class TestMiddleware(unittest.TestCase):
    def setUp(self):
        self.v = _vec("valid-0000")
        self.now = self.v["presentation"]["now"]
        self.verifier = Verifier(self.v["anchors"])

    def _gate(self):
        return AinraGate(_ok_app, self.verifier, now=self.now)

    def test_deny_without_passport(self):
        out = asyncio.run(_call(self._gate(), {}))
        self.assertEqual(out["status"], 403)
        self.assertIn("x-ainra-reason", out["headers"])
        self.assertEqual(out["body"], b'{"error":"forbidden","reason":"schema_violation"}')

    def test_deny_revoked(self):
        rv = _vec("revoked-0000")
        verifier = Verifier(rv["anchors"])
        gate = AinraGate(_ok_app, verifier, now=rv["presentation"]["now"])
        b64 = base64.urlsafe_b64encode(
            json.dumps(rv["presentation"]).encode()
        ).rstrip(b"=").decode()
        out = asyncio.run(_call(gate, {HEADER: b64}))
        self.assertEqual(out["status"], 403)
        self.assertEqual(out["headers"]["x-ainra-reason"], "revoked")

    def test_allow_with_valid_header(self):
        b64 = base64.urlsafe_b64encode(
            json.dumps(self.v["presentation"]).encode()
        ).rstrip(b"=").decode()
        out = asyncio.run(_call(self._gate(), {HEADER: b64}))
        self.assertEqual(out["status"], 200)
        self.assertEqual(out["body"], b"served")
        event = json.loads(out["headers"]["x-ainra-verdict"])
        self.assertEqual(event["status"], "valid")

    def test_allow_with_body_field(self):
        body = json.dumps({"ainra_passport": self.v["presentation"]}).encode()
        out = asyncio.run(_call(self._gate(), {"content-type": "application/json"}, body))
        self.assertEqual(out["status"], 200)


if __name__ == "__main__":
    unittest.main()
