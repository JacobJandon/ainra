# SPDX-License-Identifier: Apache-2.0 OR MIT
"""The Python column of `make link-parity`: each vectors/v1-link entry through the Python link gate, one JSON line
each ({"name", "status", "reason", "operator"}). Driven by tools/link-parity.mjs; not a test on its own."""
import asyncio, base64, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "packages", "sdk-py"))
from ainra import AinraLinkGate, Verifier  # noqa: E402

def b64(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def served(v):
    lk = v["link"]; c = json.loads(b64(lk["claims"]))
    return ({"checkpoint": lk["checkpoint"], "checkpoint_sig": lk["checkpoint_sig"],
             "links": [{"thumbprint": c["subject"]["thumbprint"], "claims": lk["claims"], "registrar_sig": lk["registrar_sig"],
                        "leaf_index": lk["leaf_index"], "inclusion_proof": lk["inclusion_proof"]}]},
            {"uri": lk.get("status_uri"), "status_list_b64": lk["status_list"], "bit_len": lk["status_len"],
             "issued_at": lk["status_issued_at"], "sig_ed25519": lk.get("status_sig_ed25519"), "sig_mldsa65": lk.get("status_sig_mldsa65")})

def run(v):
    verifier = Verifier.from_directory(v["directory"], v["roots"]["root_ed25519"], v["roots"]["root_slh"], freshness=v["freshness"])
    if verifier is None:
        return {"name": v["name"], "status": "no_gate", "reason": None, "operator": None}
    seen, out = {}, {}
    async def app(scope, receive, send):
        seen["op"] = scope["ainra_link"]["operator"]
        await send({"type": "http.response.start", "status": 200, "headers": []}); await send({"type": "http.response.body", "body": b""})
    cap = v.get("capability")
    gate = AinraLinkGate(app, verifier, lambda s, h: b64(v["presented_key"]), lambda: served(v), v["now"],
                         capability=(lambda s: cap) if cap else None)
    async def receive(): return {"type": "http.request", "body": b"", "more_body": False}
    async def send(m):
        if m["type"] == "http.response.start":
            out["status"] = m["status"]; out["reason"] = dict(m["headers"]).get(b"x-ainra-reason", b"").decode() or None
    asyncio.run(gate({"type": "http", "method": "GET", "path": "/", "query_string": b"", "headers": [(b"host", b"x.example")]}, receive, send))
    return {"name": v["name"], "status": out["status"], "reason": out["reason"], "operator": seen.get("op")}

d = sys.argv[1]
for f in sorted(x for x in os.listdir(d) if x.endswith(".json") and x != "manifest.json"):
    print(json.dumps(run(json.load(open(os.path.join(d, f))))))
