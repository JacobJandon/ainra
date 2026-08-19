<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Middleware quickstart — gate a request path, fail closed

`@ainra/middleware` is the verifier wedge: a request either carries a passport that verifies, or it is denied with a
machine-readable reason. Pure over `@ainra/sdk` — no network, no state, no telemetry.

Connect/Express:

```js
import { ainraGate, Verifier } from "@ainra/middleware";
const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh);
app.use("/agent", ainraGate(verifier));   // every /agent request needs a valid passport, or 403 fail-closed
```

The passport arrives in the `x-ainra-passport` header (or `req.body.ainra_passport`) — see [PRESENTATION.md](../PRESENTATION.md).
On allow, `req.ainra` carries the result and the response gets an `x-ainra-verdict` event header. On deny, it's `403`
with `x-ainra-reason`.

Framework-agnostic (edge/fetch): `checkRequest(verifier, bundle, opts)`:

```js
import { Verifier, checkRequest, serializeVerdictEvent } from "@ainra/middleware";
const ok = checkRequest(verifier, validBundle, { now: () => NOW });
const no = checkRequest(verifier, revokedBundle, { now: () => NOW });
```

Real output:

```
allow: true · event: {"status":"valid","reason":null,"name":"ainra:registrar-07:acme:invoicing@1.0.0","number":"did:ainra:registrar-07:acme:invoicing","tier":"L3","freshness_age_s":1}
deny : false · reason: revoked
```

Fail-closed by default: a missing header, a garbage bundle, an unauthenticated status list — all deny. Proven by
`make wedge-test`.

## A running copy (ADR-019)

Build the verifier with your audience and the gate accepts instance credentials too. Refusals keep their own
reasons — `instance_expired`, `instance_scope_exceeds`, `instance_sig_invalid`, `instance_pop_invalid` — and a
revoked passport still reports `revoked`, because the lineage failed rather than the copy. `make instance-gate`
proves each one.
