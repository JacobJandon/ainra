<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Python quickstart — verify in ~5 lines, gate a route

`ainra` (`packages/sdk-py`) is the independent Python verifier — the **fourth column** of the conformance differential
(`make diff`: core ↔ sdk ↔ cli ↔ py, agreeing byte-for-byte on every vector's verdict *and* reason). Offline,
fail-closed, zero telemetry. It holds no keys: an agent written in Python signs through callbacks
([Be the agent](../../packages/sdk-py/README.md#be-the-agent-d-071)).

```sh
pip install ainra              # v0.4.0 from PyPI, published by trusted publishing with PEP 740 attestations
```

Or editable from a checkout, if you would rather read the source you are running:
`pip install -e packages/sdk-py` (needs `cryptography>=48`).

## Verify in ~5 lines

You hold a directory that both ceremony roots signed (the root can be dark) and verify a presentation bundle **at
your own clock** — there is no I/O.

```python
import json
from ainra import Verifier

S = "kits/verifier/sample-artifacts/"
load = lambda f: json.load(open(S + f))
directory, roots, now = load("directory.json"), load("roots.json"), load("meta.json")["now"]

# 1) Build a verifier from a directory that verifies against both ceremony roots (None if it does not).
verifier = Verifier.from_directory(directory, roots["root_ed25519"], roots["root_slh"])

# 2) Verify a bundle. The caller supplies `now`; there is no I/O.
verdict = verifier.verify(load("bundle-valid.json"), now)
print("valid :", verdict.valid, "| reason:", verdict.reason)
print("event :", json.dumps(verdict.event()))

# 3) A revoked lineage fails closed with a named reason.
rv = verifier.verify(load("bundle-revoked.json"), now)
print("revoked ->", rv.valid, "| reason:", rv.reason)

# 4) The verifier owns the clock and the status. An hour later the same bundle is stale; and a status list the
#    registrar did not sign is no status, so a revoked passport cannot bring its own all-clear.
print("an hour later ->", verifier.verify(load("bundle-valid.json"), now + 3600).reason)
forged = dict(load("bundle-revoked.json"), status_list=load("bundle-valid.json")["status_list"], status_issued_at=now)
print("forged status ->", verifier.verify(forged, now).reason)
```

Real output (from the repo root):

```
valid : True | reason: None
event : {"status": "valid", "reason": null, "name": "ainra:registrar-07:acme:invoicing@1.0.0", "number": "did:ainra:registrar-07:acme:invoicing", "tier": "L3", "freshness_age_s": 1}
revoked -> False | reason: revoked
an hour later -> stale_status
forged status -> stale_status
```

- **The verifier owns the clock, the freshness class and the status.** `now` is *your* argument, and the status list
  counts only if the registrar signed it: the last two lines above are the same bundle an hour later, and a revoked
  passport carrying a list of its own.
- `.verify()` **never raises** — any malformed bundle is a `Verdict(valid=False, reason=…)`, one of the 20 in
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

## A running copy (ADR-019)

```python
v = Verifier.from_directory(directory, roots["root_ed25519"], roots["root_slh"],
                            audience="https://api.example", freshness="F2")
v.verify(bundle, now)
```

Use `from_directory`. The plain `Verifier(anchors, …)` is for anchors you pin yourself, and since 0.5.0 it fails
closed (D-075): without each registrar's status key in the anchors, every passport is `stale_status`. To replay a
conformance vector, pass `unauthenticated_status=True` — never for anything that decides access.

The empty default is fail-closed: no audience, no instance credential accepted. Minting is
`mint_instance_credential` with a signing callback, run where the control key lives.
