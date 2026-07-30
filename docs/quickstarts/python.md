<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Python quickstart — verify in ~5 lines, gate a route

`ainra` (`packages/sdk-py`) is the independent Python verifier — the **fourth column** of the conformance differential
(`make diff`: core ↔ sdk ↔ cli ↔ py, agreeing byte-for-byte on every vector's verdict *and* reason). Verify-only,
offline, fail-closed, zero telemetry. Install editable from a checkout: `pip install -e packages/sdk-py` (needs
`cryptography>=44`).

## Verify in ~5 lines

You hold trust anchors (the root can be dark) and verify a presentation bundle **at your own clock** — there is no I/O.

```python
import json, base64
from ainra import Verifier

vec = json.load(open("vectors/v1/valid-0000.json"))
verifier = Verifier(vec["anchors"])                       # offline anchors; the root can be dark
v = verifier.verify(vec["presentation"], now=1500)
print("valid  :", v.valid, "| event:", json.dumps(v.event()))

rvk = json.load(open("vectors/v1/revoked-0000.json"))
rv = Verifier(rvk["anchors"]).verify(rvk["presentation"], rvk["presentation"]["now"])
print("revoked:", rv.valid, "| reason:", rv.reason)

# The verifier owns the clock: forward-dating past exp cannot dodge expiry.
exp = json.loads(base64.urlsafe_b64decode(vec["presentation"]["claims"] + "=="))["exp"]
print("at exp :", verifier.verify(vec["presentation"], exp).reason)
```

Real output (from the repo root):

```
valid  : True | event: {"status": "valid", "reason": null, "name": "ainra:registrar-01:acme:invoicing@1.0.0", "number": "did:ainra:registrar-01:acme:invoicing", "tier": "L1", "freshness_age_s": 10}
revoked: False | reason: revoked
at exp : expired
```

- **The verifier owns the clock.** `now` is *your* argument; any `now` inside the presentation is ignored, so a
  presenter cannot forward-date past `exp` to dodge expiry (the `at exp → expired` line above).
- `.verify()` **never raises** — any malformed bundle is a `Verdict(valid=False, reason=…)`, one of the 15 in
  [`reasons.json`](../reasons.json).
- `verdict.event()` is the M16 verdict event ([`PRESENTATION.md`](../PRESENTATION.md)): `status`, `reason`, `name`,
  `number` (the permanent version-less AINRA Number), `tier`, `freshness_age_s`.

## Gate a route, fail closed (ASGI)

`ainra.AinraGate` / `ainra_gate` is the framework-agnostic ASGI wedge (Starlette, FastAPI, Quart, any ASGI app). Every
gated request must carry a valid passport in the `x-ainra-passport` header or it is denied **403 + `x-ainra-reason`**;
on allow, the response carries the verdict event in `x-ainra-verdict`. Pure over the verifier — no network, no state.

```python
from ainra import Verifier, ainra_gate

verifier = Verifier.from_directory(directory, root_ed25519, root_slh)   # None if the directory isn't authentic
app.add_middleware(ainra_gate(verifier))                                # or: AinraGate(app, verifier)
```

Real output (allow on a valid bundle, deny on a revoked one, deny on a missing header):

```
allow  : 200 | x-ainra-verdict: {"status":"valid","reason":null,"name":"ainra:registrar-01:acme:invoicing@1.0.0","number":"did:ainra:registrar-01:acme:invoicing","tier":"L1","freshness_age_s":10}
deny   : 403 | x-ainra-reason: revoked
missing: 403 | x-ainra-reason: schema_violation
```

Fail-closed by default: a missing header, a garbage bundle, an un-anchored directory — all deny. **The independence
caveat is exact (D-041):** shared cryptographic *primitives* (pyca `cryptography` / OpenSSL for Ed25519 + ML-DSA-65,
OpenSSL `libcrypto` via `ctypes` for SLH-DSA-SHA2-128s, stdlib for SHA-256), **independent verification logic** — the
differential exercises the logic, not the primitives. Proven by `make diff` + the `packages/sdk-py` tests.

Next: prove your own implementation with the [conformance runner](conformance.md).
