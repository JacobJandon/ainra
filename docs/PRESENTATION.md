<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Presentation & the verdict event — one envelope, one shape

An agent presents its passport one way; every AINRA-aware surface reports the result one way. No new protocol —
this pins the two conventions so integrations line up.

## The request envelope

Present the passport bundle in a single request header:

| | |
|---|---|
| **Header** | `x-ainra-passport` |
| **Encoding** | the presentation bundle as **base64url of its canonical JSON** (raw JSON is also accepted for local testing) |
| **Size** | AINRA bundles are **tens of KB** (a measured sample is ~46 KB) — the post-quantum ML-DSA-65 key and signature dominate, and delegation chains add more. This is **over most default header limits** (nginx ~8 KB, many stacks 16 KB). So the header form suits small/edge cases; for the common case present the bundle in the request **body** field `ainra_passport` (same bytes, no header ceiling). Raise `large_client_header_buffers` only if you deliberately want it in the header. |
| **Streaming-safe** | the header is set once, before the body streams; verification never needs the body |

The middleware reads exactly this (`ainraGate` / `checkRequest`), defaulting to `x-ainra-passport` and falling back to
`req.body.ainra_passport`. Gate a path in ~5 lines:

```ts
import { ainraGate, Verifier } from "@ainra/middleware";
const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh)!;
app.use("/agent", ainraGate(verifier));   // every /agent request must carry a valid passport, or 403 fail-closed
```

## The verdict event

Every surface emits the same event when it reports a verdict. Fields, in this fixed order:

```json
{"status":"valid","reason":null,"name":"ainra:registrar-07:acme:invoicing@4.2.1","number":"did:ainra:registrar-07:acme:invoicing","tier":"L3","freshness_age_s":1}
```

| Field | Type | Meaning |
|---|---|---|
| `status` | `"valid"` \| `"invalid"` | the verdict |
| `reason` | named reason \| `null` | one of the 20 frozen reasons (see [`reasons.json`](reasons.json)); `null` when valid |
| `instance_iid` | string \| `null` | ADR-019 — the running copy's opaque instance id; `null` when a passport was presented directly |
| `instance_exp` | number \| `null` | ADR-019 — when that copy's credential expires. An operator watching these sees short numbers; a long one is a finding |
| `name` | string \| `null` | the full **versioned credential** name (`…@version`) |
| `number` | string \| `null` | the permanent **AINRA Number** — the version-less DID `did:ainra:reg:op:lineage`; identity is eternal, the credential is not |
| `tier` | `L0`…`L4` \| `null` | accreditation level (never a score) |
| `freshness_age_s` | integer \| `null` | age of the revocation info: `now − status_issued_at`, seconds |

`null` fields appear when the bundle can't be decoded (e.g. `schema_violation`) — the event is always well-formed.

### Where it's emitted

- **Middleware** — response header `x-ainra-verdict` on every request (allow and deny), and `req.ainra.event`.
- **MCP** — the `ainra_verify` tool returns `event`.
- **CLI** — `ainra events <registry.json>` prints one event line per record.

### Proven identical

`make presentation-diff` seeds a real registry and asserts the CLI (Rust), the middleware, and the MCP server
serialize every record's event **byte-for-byte identically**:

```
$ make presentation-diff
✓ one verdict-event shape: CLI ≡ SDK byte-identical over 13 records; middleware ≡ MCP ≡ SDK confirmed.
```


## The instance envelope (ADR-019 / D-047)

A running copy presents its passport bundle **plus** an `instance` object. Absent on a plain passport
presentation, so every pre-M28 bundle is byte-unchanged and still verifies.

```json
{
  "claims": "…", "issuer_sig": {…}, "…": "…the passport bundle, unchanged…",
  "audience": "https://api.example",
  "instance": {
    "sub": "ainra:registrar-07:acme:billing@1.0.0",
    "iid": "i-0f3a2b71",
    "ikey": { "ed25519": "…", "mldsa65": "…" },
    "nbf": 1776729600, "exp": 1776730500,
    "capabilities": ["read:invoices"],
    "aud": "https://api.example",
    "passport_leaf": "…",
    "sig": { "ed25519": "…", "mldsa65": "…" },
    "pop": { "aud": "https://api.example", "nonce": "…", "ts": 1776729600, "sig": {…} }
  }
}
```

**`audience` is not the presenter's to set.** It is on the wire so the conformance corpus can pin audience
cases deterministically — exactly as `now` and `revoked_delegates` are — and the GA `Verifier` **never reads
it**: `decodePresentation` takes the audience as an argument, and the verifier passes its own, which is a
constructor parameter defaulting to the empty string. A service that has not said who it is cannot be the
intended recipient of anything, so the default refuses every instance credential.

**Verify order.** The nine passport steps run first, unchanged; the instance rung is step 10. That ordering is
what makes revoking a passport kill every live copy under it *and* report `revoked` rather than an
instance-layer reason — the lineage failed, not the container, and the reason must send a debugging integrator
to the right place.
