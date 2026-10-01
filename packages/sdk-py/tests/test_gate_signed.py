# SPDX-License-Identifier: Apache-2.0 OR MIT
"""D-062 / D-065 in the Python gate: the request bound to the presentation, and send-once.

WITNESS — could these tests fail? The binding tests drive REAL signed requests from ``vectors/v1-presentation``
through the ASGI extraction in ``check_binding``: read the path without its query, drop the Host header, or lower-
case the method differently and ``test_a_real_signed_request_is_bound`` goes red while the corpus test in
``test_presentation.py`` stays green — the wiring is exactly what these cover. Store a bundle without verifying it
and ``test_a_bundle_that_does_not_verify_is_never_stored`` goes red.
"""

from __future__ import annotations

import asyncio
import base64
import json
import unittest
from pathlib import Path

from ainra import AinraGate, PresentationStore, Verifier, check_binding
from ainra.middleware import HEADER
from ainra.presentation import PRIME_PATH, presentation_ref

ROOT = Path(__file__).resolve().parents[3]
PV = ROOT / "vectors" / "v1-presentation"
V1 = ROOT / "vectors" / "v1"


def _pv(name):
    return json.loads((PV / f"{name}.json").read_text())


def _scope(v, path=None, method=None):
    """A presentation vector's request as an ASGI scope, the way a server hands it over."""
    r = v["request"]
    p = path or r["path"]
    raw, _, qs = p.partition("?")
    return {
        "type": "http",
        "method": method or r["method"],
        "path": raw,
        "raw_path": raw.encode("latin1"),
        "query_string": qs.encode("latin1"),
        "headers": [(b"host", r["authority"].encode("latin1"))]
        + [(k.encode("latin1"), val.encode("latin1")) for k, val in r["headers"]],
    }


def _body(v):
    b = v["request"]["body_b64u"]
    return base64.urlsafe_b64decode(b + "=" * (-len(b) % 4)) if b else b""


def _instance(v):
    return {"instance": {"iid": v["instance"]["iid"], "ikey": v["instance"]["ikey"]}}


class TestBinding(unittest.TestCase):
    def test_a_real_signed_request_is_bound(self):
        for name in ("p01-valid-get", "p02-valid-post-with-body"):
            v = _pv(name)
            with self.subTest(name):
                self.assertIsNone(check_binding(_scope(v), _body(v), _instance(v), v["now"]))

    def test_moved_altered_and_replayed_are_refused_by_name(self):
        v = _pv("p02-valid-post-with-body")
        self.assertEqual(check_binding(_scope(v, path="/admin/refunds"), _body(v), _instance(v), v["now"]),
                         "presentation_sig_invalid")
        self.assertEqual(check_binding(_scope(v, method="PUT"), _body(v), _instance(v), v["now"]),
                         "presentation_sig_invalid")
        self.assertEqual(check_binding(_scope(v), b'{"sku":"A-1","qty":200}', _instance(v), v["now"]),
                         "presentation_sig_invalid")
        self.assertEqual(check_binding(_scope(v), _body(v), _instance(v), v["now"], seen=lambda n: True),
                         "presentation_replayed")

    def test_another_signers_signature_is_left_to_its_own_verifier(self):
        # D-070, through the ASGI wiring: p35 arrives as separate header lines per signer, which only a gate that
        # joins a field's lines reads correctly; p38 is signed by the signature agent alone.
        for name in ("p34-beside-a-signature-agent", "p35-beside-a-signature-agent-own-lines",
                     "p36-ainra-member-first", "p44-signature-agent-covers-ainra"):
            v = _pv(name)
            with self.subTest(name):
                self.assertIsNone(check_binding(_scope(v), _body(v), _instance(v), v["now"]))
        v = _pv("p38-signature-agent-only")
        self.assertEqual(check_binding(_scope(v), _body(v), _instance(v), v["now"]), "presentation_unsigned")

    def test_no_instance_credential_means_nothing_to_check_a_signature_against(self):
        v = _pv("p01-valid-get")
        self.assertEqual(check_binding(_scope(v), b"", {}, v["now"]), "presentation_unsigned")


async def _call(gate, method="GET", path="/agent", headers=None, body=b""):
    scope = {"type": "http", "method": method, "path": path, "raw_path": path.encode(), "query_string": b"",
             "headers": [(k.encode("latin1"), val.encode("latin1")) for k, val in (headers or {}).items()]}
    done = {"d": False}

    async def receive():
        if not done["d"]:
            done["d"] = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    out = {"status": None, "headers": {}, "body": b""}

    async def send(m):
        if m["type"] == "http.response.start":
            out["status"] = m["status"]
            out["headers"] = {k.decode("latin1").lower(): val.decode("latin1") for k, val in m["headers"]}
        elif m["type"] == "http.response.body":
            out["body"] += m.get("body", b"")

    await gate(scope, receive, send)
    return out


async def _ok(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"served"})


class TestGate(unittest.TestCase):
    def setUp(self):
        self.v = json.loads((V1 / "valid-0000.json").read_text())
        self.now = self.v["presentation"]["now"]
        self.verifier = Verifier(self.v["anchors"], unauthenticated_status=True)  # a vector: its status is an input

    def test_require_signature_refuses_an_unsigned_request_by_name(self):
        gate = AinraGate(_ok, self.verifier, now=self.now, require_signature=True)
        b64 = base64.urlsafe_b64encode(json.dumps(self.v["presentation"]).encode()).rstrip(b"=").decode()
        out = asyncio.run(_call(gate, headers={HEADER: b64}))
        self.assertEqual(out["status"], 403)
        self.assertEqual(out["headers"]["x-ainra-reason"], "presentation_unsigned")
        self.assertEqual(json.loads(out["headers"]["x-ainra-verdict"])["status"], "valid",
                         "the credential is fine; the refusal is about the request")

    def test_send_once_then_name_the_bundle_by_its_digest(self):
        store = PresentationStore()
        gate = AinraGate(_ok, self.verifier, now=self.now, store=store)
        p = asyncio.run(_call(gate, method="POST", path=PRIME_PATH, body=json.dumps(self.v["presentation"]).encode()))
        self.assertEqual(p["status"], 201)
        ref = json.loads(p["body"])["ref"]
        self.assertEqual(ref, presentation_ref(self.v["presentation"]))
        self.assertEqual(asyncio.run(_call(gate, headers={HEADER: ref}))["status"], 200)

    def test_a_bundle_that_does_not_verify_is_never_stored(self):
        store = PresentationStore()
        gate = AinraGate(_ok, self.verifier, now=self.now, store=store)
        forged = dict(self.v["presentation"], status_list=self.v["presentation"]["status_list"][:-2] + "AA")
        p = asyncio.run(_call(gate, method="POST", path=PRIME_PATH, body=json.dumps(forged).encode()))
        self.assertEqual(p["status"], 403)
        out = asyncio.run(_call(gate, headers={HEADER: presentation_ref(forged)}))
        self.assertEqual(out["status"], 428)
        self.assertEqual(out["headers"]["x-ainra-reason"], "presentation_unknown")
        self.assertEqual(out["headers"]["link"], f'<{PRIME_PATH}>; rel="ainra-prime"')

    def test_a_field_sent_on_two_lines_is_one_field(self):
        # D-072: this gate kept only the LAST `x-ainra-passport` line, so a request carrying the header twice was
        # allowed here and refused by the Node and edge gates, which see the two lines joined. One rule everywhere:
        # the joined value is neither a digest reference nor a bundle.
        gate = AinraGate(_ok, self.verifier, now=self.now)
        b64 = base64.urlsafe_b64encode(json.dumps(self.v["presentation"]).encode()).rstrip(b"=").decode()
        self.assertEqual(asyncio.run(_call(gate, headers={HEADER: b64}))["status"], 200, "the control: once is fine")
        scope = {"type": "http", "method": "GET", "path": "/agent", "raw_path": b"/agent", "query_string": b"",
                 "headers": [(HEADER.encode(), b"not-a-presentation"), (HEADER.encode(), b64.encode())]}
        out = {"status": None, "headers": {}}

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(m):
            if m["type"] == "http.response.start":
                out["status"] = m["status"]
                out["headers"] = {k.decode().lower(): v.decode() for k, v in m["headers"]}

        asyncio.run(gate(scope, receive, send))
        self.assertEqual(out["status"], 403)
        self.assertEqual(out["headers"]["x-ainra-reason"], "schema_violation")

    def test_the_store_is_bounded_and_forgets(self):
        s = PresentationStore(max_entries=2)
        s.put("a", {"n": 1}, 10)
        s.put("b", {"n": 2}, 10)
        s.get("a", 0)
        s.put("c", {"n": 3}, 10)
        self.assertIsNone(s.get("b", 0), "the idlest goes first")
        self.assertIsNone(s.get("a", 10), "nothing outlives its expiry")


if __name__ == "__main__":
    unittest.main()
