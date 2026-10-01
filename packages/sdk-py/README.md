<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# ainra — Python verifier (independent implementation #4)

A verify-only, offline, fail-closed, zero-telemetry Python implementation of the
AINRA agent-passport verifier. It is written **independently** from the AINRA
specification (`docs/AINRA_I_The_Standard.md`, `docs/AINRA_Master_Technical_Specification_v1.md`)
and the CC0 conformance vectors — **not** transliterated from the Rust core or
the TypeScript SDK. It joins the conformance differential as a **fourth column**:
core ↔ sdk ↔ P0 ↔ **py**, agreeing byte-for-byte on every vector's verdict *and*
reason.

Why a fourth brain? If an independent reimplementation, built to the same
spec + vector reference, reaches the same verdict on every vector, that is
independent confirmation the standard is unambiguous and the reference is
correct. If it disagreed, we would have found something. It agrees on
**1153 passport + 17 delta + 9 directory** vectors.

## Install

```
pip install ainra                  # v0.4.0 from PyPI
pip install -e packages/sdk-py     # or editable, from a checkout
```

Published to PyPI by **trusted publishing** — no API token is involved at any
point. Each release carries PEP 740 attestations binding the artifact to the
GitHub Actions workflow that built it, so you can check where it came from
before you trust it.

Requires Python ≥ 3.10 and `cryptography` ≥ 48, which ships Ed25519 and ML-DSA-65. The floor is measured: 46 has
no ML-DSA module, and 47's wheels refuse ML-DSA-65. SLH-DSA-SHA2-128s, SHA-256, and zlib need no
extra dependency (see below).

## Quickstart

```python
import json, base64
from ainra import Verifier

vec = json.load(open("vectors/v1/valid-0000.json"))

# 1) Build an offline verifier from the trust anchors.
verifier = Verifier(vec["anchors"])

# 2) Verify a bundle. The caller supplies `now`; there is no I/O.
verdict = verifier.verify(vec["presentation"], now=1500)
print("valid :", verdict.valid, "| reason:", verdict.reason)
print("event :", json.dumps(verdict.event()))

# 3) A revoked lineage fails closed with a named reason.
rvk = json.load(open("vectors/v1/revoked-0000.json"))
rv = Verifier(rvk["anchors"]).verify(rvk["presentation"], rvk["presentation"]["now"])
print("revoked ->", rv.valid, "| reason:", rv.reason)

# 4) The verifier owns the clock: forward-dating past `exp` cannot dodge expiry.
exp = json.loads(base64.urlsafe_b64decode(vec["presentation"]["claims"] + "=="))["exp"]
print("at exp ->", verifier.verify(vec["presentation"], exp).reason)
```

Real output (run from the repo root):

```
valid : True | reason: None
event : {"status": "valid", "reason": null, "name": "ainra:registrar-01:acme:invoicing@1.0.0", "number": "did:ainra:registrar-01:acme:invoicing", "tier": "L1", "freshness_age_s": 10}
revoked -> False | reason: revoked
at exp -> expired
```

The verdict event is the M16 shape every AINRA surface emits
(`docs/PRESENTATION.md`): `status`, `reason`, `name`, `number` (the permanent
version-less AINRA Number), `tier`, `freshness_age_s`.

## ASGI middleware — gate a route, fail closed

Framework-agnostic (Starlette, FastAPI, Quart, any ASGI app). Every gated request
must carry a valid passport or it is denied **403 + `x-ainra-reason`**; on allow,
the response carries the verdict event in `x-ainra-verdict`.

```python
from ainra import Verifier, ainra_gate

verifier = Verifier.from_directory(directory, root_ed25519, root_slh)  # None if not authentic
app.add_middleware(ainra_gate(verifier))   # or: AinraGate(app, verifier)
```

The bundle is read from the `x-ainra-passport` header (base64url of canonical
JSON, or raw JSON for local testing), falling back to the JSON body field
`ainra_passport`. Verification never needs the body, so the header form is
streaming-safe.

## What it verifies

The frozen nine-step verify, first-failure-wins, mapping to the 20 frozen reasons
(`docs/reasons.json`): AINRA name grammar; canonical JSON (sorted keys, no spaces,
rejecting floats / non-ASCII keys / integers beyond 2⁵³); the strict base64url
decode gateway (D-029 — every external decode is a canonical round-trip, fail
closed); hybrid **Ed25519 + ML-DSA-65** (both signatures or `alg_downgrade`/`sig_invalid`);
the exact validity window (`nbf` inclusive, `exp` exclusive — no skew, no grace);
scope-ceiling and delegation narrowing; revocation-status freshness classes
(F1 ≤ 30 s · F2 ≤ 5 min · F3 ≤ 24 h, fail closed); logged-before-valid RFC 6962
inclusion to a signed checkpoint (root **SLH-DSA-SHA2-128s** or a scope-limited,
in-window, unrevoked delegate); the signed status delta / fresh-head classes; and
the dual-root-signed directory. Fail closed everywhere; `.verify` never raises.

## Cryptography — shared primitives, independent logic (state precisely, D-041)

The verification **logic** is independent; the cryptographic **primitives** are
shared, audited libraries — reimplementing a signature scheme would be less safe,
not more independent:

| Primitive | Sizes (confirmed) | Source |
|---|---|---|
| Ed25519 | 32 B key / 64 B sig | `cryptography` (pyca, wraps OpenSSL 3.5+) |
| ML-DSA-65 (FIPS 204) | 1952 B key / 3309 B sig | `cryptography` (pyca / OpenSSL 3.5+) |
| SLH-DSA-SHA2-128s (FIPS 205) | 32 B key / 7856 B sig | OpenSSL `libcrypto` via `ctypes` (EVP raw-public-key verify) — that primitive only |
| SHA-256 (RFC 6962 prefixes) | — | Python stdlib `hashlib` |

**The claim, precisely:** *shared cryptographic primitives (pyca `cryptography` /
OpenSSL 3.5+ for Ed25519 + ML-DSA-65; OpenSSL `libcrypto` via `ctypes` for
SLH-DSA-SHA2-128s; stdlib for SHA-256), with an independent verification logic —
the differential exercises the logic, not the primitives.* `cryptography` 49 does
not yet surface SLH-DSA, so it is reached from the same underlying OpenSSL
directly; if the OpenSSL SLH-DSA verify path is unavailable, that primitive fails
**closed** (returns `False`).

## Differential — the fourth column

`make diff` (or `node tools/diff-harness/run.mjs`) runs the Python verifier over
the whole corpus and asserts it agrees with the Rust core's recorded verdict on
every vector, including the `alg-downgrade-*`, `noncanon-*`, `boundary-*`,
`renewal-*` classes, plus delta and directory:

```
(A) verdict diff  core↔sdk : 1153/1153 agree
(B) canon 3-way  core↔sdk↔P0 : 10/10 byte-identical
(C) canon reject core↔sdk : 4/4 both refuse
(D) delta diff   core↔sdk : 17/17 agree
(E) directory diff core↔sdk : 9/9 agree
(F) verdict diff  core↔py : 1153/1153 agree
(F) delta diff   core↔py : 17/17 agree
(F) directory diff core↔py : 9/9 agree

DIFF OK: all implementations agree (core ↔ sdk ↔ P0 ↔ py)
```

## Tests

```
cd packages/sdk-py && PYTHONPATH=. python3 -m unittest discover -s tests
```

Covers the whole-corpus agreement (all 20 reasons reachable), the ~5-line
`Verifier` surface (valid / revoked / verifier-owns-the-clock), the ASGI gate
(allow on VALID, deny 403 fail-closed on missing/revoked), and the strict
base64url / canonical-JSON gateways. Zero telemetry, no network.

## License

Apache-2.0 OR MIT (dual). The conformance vectors are CC0 (`vectors/LICENSE`).

## Build it the documented way

```python
v = Verifier.from_directory(directory, roots["root_ed25519"], roots["root_slh"],
                            audience="https://api.example", freshness="F2")
```

`from_directory` authenticates the directory against both ceremony roots and carries the registrar's **status
key**, its **status URI**, and any **graduated-distrust cutoff** into the verifier — so revocations are
authenticated (D-020) and a distrusted registrar is refused (D-044).

The raw `Verifier(anchors, …)` constructor exists for callers embedding anchors they already trust. It **cannot**
authenticate revocations, because anchors supplied that way carry no status key. Use `from_directory` in
production; the difference is recorded in [`docs/POLICY-PARITY.md`](../../docs/POLICY-PARITY.md).

## Verify a running copy (ADR-019)

Same call; supply **your** audience when you build the verifier:

```python
v = Verifier.from_directory(directory, roots["root_ed25519"], roots["root_slh"],
                            audience="https://api.example")   # never taken from the bundle
v.verify(bundle, now)     # the instance layer is checked automatically when present
```

The default empty audience is fail-closed — a service that has not said who it is accepts no instance credential.

Minting lives on the operator's side and takes a signing callback, so no key material enters this package:
`mint_instance_credential`, `prove_instance_possession` (see "Be the agent" below).

## Signed requests and send-once (D-062, D-065)

`AinraGate` matches `@ainra/middleware`. Every option is off by default, so existing integrations behave as before:

```python
from ainra import AinraGate, PresentationStore
app = AinraGate(app, verifier, require_signature=True, seen_nonce=cache.seen, store=PresentationStore())
```

- `require_signature=True`: the request must be signed by the running copy's instance key (RFC 9421). Otherwise it
  is refused as `presentation_unsigned`, `presentation_sig_invalid`, `presentation_stale` or
  `presentation_replayed`.
- `store=`: a running copy `POST`s its bundle once to `/.well-known/ainra-presentation` (`201 {"ref"}`) and names it
  by digest after that. A digest the gate doesn't hold is `428 presentation_unknown`.
- The request-signature profile is the one `ainra-core` generates `vectors/v1-presentation` from, and this package
  agrees with it on every vector (`make diff`).

## Be the agent (D-071)

An agent written in Python can make the whole journey with this package. Keys stay with you: every function that
signs takes a callback, `bytes -> {"ed25519": <b64url>, "mldsa65": <b64url>}`.

```python
from ainra import mint_instance_credential, prove_instance_possession, sign_presentation, presentation_ref

# where the passport key lives (never in the container): a credential for one running copy
ic = mint_instance_credential(passport_claims_b64=bundle["claims"], instance_public=instance_public,
                              capabilities=["read:invoices"], audience="https://api.example",
                              now=now, iid="i-0f3a2b71", control_sign=passport_key_sign)

# inside the running copy: send the bundle once, then sign each request
pop = prove_instance_possession(audience="https://api.example", credential=ic, nonce=fresh(), now=now,
                                instance_sign=instance_key_sign)
full = {**bundle, "instance": {**ic, "pop": pop}}        # POST once to /.well-known/ainra-presentation
headers = [("x-ainra-passport", presentation_ref(full)), ("x-ainra-pop", b64url_json(pop))]
headers += sign_presentation(method="POST", authority="api.example", path="/orders", headers=headers, body=body,
                             keyid=ic["iid"], nonce=fresh(), created=now, instance_sign=instance_key_sign)
```

- `sign_presentation` returns the headers to set: `content-digest` when there is a body, `signature-input`,
  `signature`. It appends to another signer's fields (a signature agent's, D-070) and never overwrites them.
- A runnable agent, start to finish: [`examples/agent.py`](examples/agent.py). `make python-agent-e2e` runs it
  against the Node gate and the edge gate on the live network.
- `make sign-diff` holds this signer to the other implementations: what it signs, `ainra-core` and `@ainra/sdk`
  accept.
