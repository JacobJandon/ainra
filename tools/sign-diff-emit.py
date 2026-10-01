# SPDX-License-Identifier: Apache-2.0 OR MIT
"""make sign-diff, the Python signer's half: sign fresh requests with a key that has never existed, and write each as a
presentation vector (the shape of vectors/v1-presentation) for the three verifiers to check. See tools/sign-diff.mjs.

Usage:  PYTHONPATH=packages/sdk-py python3 tools/sign-diff-emit.py <out-dir>
"""

from __future__ import annotations

import base64
import json
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

from ainra import sign_presentation

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
b64u = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")  # noqa: E731
ed, ml = ed25519.Ed25519PrivateKey.generate(), mldsa.MLDSA65PrivateKey.generate()
raw = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
ikey = {"ed25519": b64u(ed.public_key().public_bytes(*raw)), "mldsa65": b64u(ml.public_key().public_bytes(*raw))}
sign = lambda m: {"ed25519": b64u(ed.sign(m)), "mldsa65": b64u(ml.sign(m))}  # noqa: E731
now = int(time.time())
ref = "sha-256=:" + base64.b64encode(bytes(range(32))).decode("ascii") + ":"
other = [("signature-input", 'sig1=("@authority");created=1;expires=2;keyid="k";alg="ed25519";tag="web-bot-auth"'),
         ("signature", "sig1=:" + base64.b64encode(bytes(64)).decode("ascii") + ":")]

cases = [
    ("get", "GET", "/orders", None, []),
    ("post-with-body", "POST", "/orders", b'{"sku":"A-1","qty":2}', []),
    ("query-and-case", "get", "/Search?q=a%20b&page=2", None, []),
    ("beside-another-signer", "GET", "/orders", None, other),
]
for i, (name, method, path, body, prior) in enumerate(cases):
    headers = [("x-ainra-passport", ref), *prior]
    add = sign_presentation(method=method, authority="Shop.Example:8443", path=path, headers=headers, body=body,
                            keyid="i-signdiff", nonce=f"py-{i}", created=now, instance_sign=sign)
    names = {k for k, _ in add}
    final = [[k, v] for k, v in headers if k not in names] + [[k, v] for k, v in add]
    vector = {
        "name": f"py-{name}",
        "request": {"method": method, "authority": "Shop.Example:8443", "path": path, "headers": final,
                    "body_b64u": b64u(body) if body else None},
        "instance": {"iid": "i-signdiff", "ikey": ikey},
        "now": now, "max_age_secs": 300, "seen_nonces": [],
        "expect": {"created": now, "nonce": f"py-{i}", "ok": True},
    }
    (out / f"py-{name}.json").write_text(json.dumps(vector))
print(f"python signed {len(cases)} requests")
