# SPDX-License-Identifier: Apache-2.0 OR MIT
"""An agent written in Python, end to end (D-071) — the journey `make identity-e2e` runs in TypeScript.

    1. the agent generates its own hybrid key; the secret never leaves this process
    2. it asks the registrar's public door for a passport, proving it holds that key
    3. it mints an instance credential for one running copy
    4. the running copy sends its bundle ONCE, then names it by digest
    5. it SIGNS each HTTP request with its instance key; a real gate lets it in
    6. the same request moved, unsigned or replayed is refused, each by name
    7. after revocation the gate refuses the passport

Usage:  python examples/agent.py http://127.0.0.1:<port>      (an origin from `node tools/gate-origin.mjs`)

It needs the wall-clock network (`make live-up`) and `cryptography` for the keys; everything AINRA-specific is the
public API of this package. Each step asserts the gate's status AND reason; step 5 is the positive control that makes
the refusals mean something. TEST-ROOT: this proves the mechanism, not that anyone outside has used it.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

from ainra import (canonicalize, mint_instance_credential, presentation_ref, prove_instance_possession,
                   sign_presentation)

REG = os.environ.get("AINRA_REGISTRAR", "http://127.0.0.1:4970")
AUD = os.environ.get("AINRA_AUDIENCE", "https://shop.example")
PRIME_PATH = "/.well-known/ainra-presentation"
bad = 0


def now() -> int:
    return int(time.time())


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def ok(msg: str) -> None:
    print(f"  ok    {msg}")


def fail(msg: str) -> None:
    global bad
    bad = 1
    print(f"  FAIL  {msg}", file=sys.stderr)


def step(msg: str) -> None:
    print(f"\n{msg}")


class HybridKey:
    """Ed25519 + ML-DSA-65, held by the caller. The SDK only ever sees `sign`, a callback."""

    def __init__(self) -> None:
        self._ed = ed25519.Ed25519PrivateKey.generate()
        self._ml = mldsa.MLDSA65PrivateKey.generate()

    def public(self) -> dict:
        raw = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {"ed25519": b64u(self._ed.public_key().public_bytes(*raw)),
                "mldsa65": b64u(self._ml.public_key().public_bytes(*raw))}

    def sign(self, msg: bytes) -> dict:
        return {"ed25519": b64u(self._ed.sign(msg)), "mldsa65": b64u(self._ml.sign(msg))}


def call(method: str, url: str, headers=None, body: bytes | None = None):
    """(status, x-ainra-reason, parsed JSON body or None). A refusal is an answer, not an exception. A 429 is
    "wait": the registrar's public door allows 30 writes a minute, so this waits its turn (up to 70 s)."""
    for attempt in range(15):
        req = urllib.request.Request(url, data=body, method=method, headers=dict(headers or {}))
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                status, hdrs, raw = r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            status, hdrs, raw = e.code, e.headers, e.read()
        if status != 429 or attempt == 14:
            break
        time.sleep(5)
    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = None
    return status, hdrs.get("x-ainra-reason"), parsed


def main(origin: str) -> int:
    authority = urllib.parse.urlsplit(origin).netloc
    try:
        _, _, accred = call("GET", f"{REG}/accreditation")
    except OSError:
        print(f"agent.py: no live registrar at {REG} — run `make live-up` first", file=sys.stderr)
        return 2

    step("1 · the agent generates its own hybrid key")
    holder, instance = HybridKey(), HybridKey()
    ok("generated locally · ed25519 + ml-dsa-65 · the secret never leaves this process")

    step("2 · the registrar's public door issues a passport bound to it")
    registrar = (accred or {}).get("id") or (accred or {}).get("registrar") or "registrar-07"
    spec = {"operator": "specimen", "lineage": "pyagent", "holder_key": holder.public()}
    st, _, _ = call("POST", f"{REG}/demo/issue", body=json.dumps(spec).encode())
    ok(f"a key WITHOUT a proof is refused ({st})") if st != 200 else fail("the door certified a key with no proof")
    proof = holder.sign(canonicalize(
        {"holder": holder.public(), "purpose": "ainra-holder-pop-v1", "registrar": registrar}).encode("utf-8"))
    st, _, issued = call("POST", f"{REG}/demo/issue", body=json.dumps({**spec, "holder_pop": proof}).encode())
    if st != 200:
        fail(f"issue failed: {st} {issued}")
        return 1
    sub = issued["sub"]
    carried = json.loads(issued["claims"])["keys"][0]
    ok(f"issued {sub} · carries the AGENT's key") if carried == holder.public() else fail("the passport carries another key")

    step("3 · the agent mints an instance credential for one running copy")
    present = f"{REG}/present?sub={urllib.parse.quote(sub)}&now="
    _, _, bundle = call("GET", present + str(now()))
    ic = mint_instance_credential(
        passport_claims_b64=bundle["claims"], instance_public=instance.public(), capabilities=["demo:specimen"],
        audience=AUD, now=now(), iid="i-" + secrets.token_hex(4), control_sign=holder.sign, lifetime_secs=900)
    ok(f"{ic['iid']} · {ic['exp'] - ic['nbf']}s · audience {ic['aud']} · minted with the passport key")

    def presentation(b=None) -> dict:
        pop = prove_instance_possession(audience=AUD, credential=ic, nonce="p-" + secrets.token_hex(6), now=now(),
                                        instance_sign=instance.sign)
        return {**(b or bundle), "instance": {**ic, "pop": pop}}

    step("4 · the running copy sends its bundle once")
    full = presentation()
    st, reason, primed = call("POST", origin + PRIME_PATH, {"content-type": "application/json"},
                              json.dumps(full).encode())
    ref = (primed or {}).get("ref")
    if st == 201 and ref == presentation_ref(full):
        ok(f"201 · named from now on by {ref[:22]}… — the digest this SDK computes for the same bundle")
    else:
        fail(f"priming: {st} {reason} · gate ref {ref} · ours {presentation_ref(full)}")
        return 1

    def send(method="GET", path="/orders", body=None, sign=True, wire_path=None, name=None):
        pop = presentation()["instance"]["pop"]
        headers = [("x-ainra-passport", name or ref), ("x-ainra-pop", b64u(json.dumps(pop).encode()))]
        if sign:
            headers += sign_presentation(
                method=method, authority=authority, path=path, headers=headers, body=body, keyid=ic["iid"],
                nonce="r-" + secrets.token_hex(6), created=now(), instance_sign=instance.sign)
        st, reason, _ = call(method, origin + (wire_path or path), headers, body)
        return st, reason, headers

    step("5 · the running copy signs each request; the real gate lets it in")
    st, reason, headers = send()
    size = sum(len(k) + len(v) + 4 for k, v in headers)
    ok(f"GET → 200 · request headers {size / 1024:.1f} KiB") if st == 200 else fail(f"signed GET: {st} {reason}")
    st, reason, _ = send(method="POST", body=b'{"sku":"A-1","qty":2}')
    ok("POST with a body → 200 · the body is covered by its digest") if st == 200 else fail(f"signed POST: {st} {reason}")

    step("6 · every way of misusing it is refused, by name")
    for label, want_status, want_reason, kw in [
        ("moved to another path", 403, "presentation_sig_invalid", {"wire_path": "/admin/refunds"}),
        ("unsigned", 403, "presentation_unsigned", {"sign": False}),
        ("a digest this gate was never sent", 428, "presentation_unknown",
         {"name": "sha-256=:" + base64.b64encode(bytes(32)).decode() + ":"}),
    ]:
        st, reason, _ = send(**kw)
        if (st, reason) == (want_status, want_reason):
            ok(f"{label} → {st} {reason}")
        else:
            fail(f"{label}: {st} {reason}")
    first, _, headers = send()
    again, reason, _ = call("GET", origin + "/orders", headers)
    if (first, again, reason) == (200, 403, "presentation_replayed"):
        ok(f"the identical request sent twice → 1st 200, 2nd 403 {reason}")
    else:
        fail(f"replay: {first} then {again} {reason}")

    step("7 · revoke the passport")
    st, _, body = call("POST", f"{REG}/demo/revoke", body=json.dumps({"sub": sub, "now": now()}).encode())
    if st != 200:
        fail(f"revoke failed: {st} {body}")
    _, _, fresh = call("GET", present + str(now()))
    st, reason, _ = call("POST", origin + PRIME_PATH, {"content-type": "application/json"},
                         json.dumps(presentation(fresh)).encode())
    if (st, reason) == (403, "revoked"):
        ok(f"sending the post-revocation bundle → 403 {reason} — a revoked credential is never stored")
    else:
        fail(f"priming after revoke: {st} {reason}")

    print("\nPYTHON-AGENT-E2E FAILED" if bad else
          "\nPYTHON-AGENT-E2E OK: an agent written in Python held its own key, got a passport for it, minted a "
          "credential for a running copy, signed its requests, and the gate let it in — then refused it moved, "
          "unsigned, replayed and revoked. TEST-ROOT.")
    return bad


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1].rstrip("/")))
