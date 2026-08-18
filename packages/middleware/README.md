<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# @ainra/middleware

A fail-closed gate for requests made by AI agents. Five lines in front of your handler, and a request gets through
only if it carried a valid [AINRA](https://ainra.vercel.app/) passport.

**Offline. Fail-closed. Zero telemetry.** The check is local — no account with us, no per-request call, nothing that
can be down. A request with no passport, a revoked one, or one whose status cannot be freshly confirmed is refused
with a machine-readable reason.

```sh
npm install @ainra/middleware
```

## Connect / Express

```js
import express from "express";
import { Verifier, ainraGate } from "@ainra/middleware";

const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh);

const app = express();
app.use("/agent", ainraGate(verifier));      // every /agent request must carry a valid passport

app.post("/agent/order", (req, res) => {
  req.ainra;   // the GateResult: { allow, reason?, verdict, event }
});
```

The passport arrives in the `x-ainra-passport` header (raw JSON or base64url of it), or in `body.ainra_passport`.
On refusal the gate answers **403** with `{ error, reason }`. Every response — allowed or refused — carries
`x-ainra-verdict`, the canonical verdict event.

Options: `header` (default `x-ainra-passport`), `now` (your clock, for tests and fixed demo windows), and `onDeny`
for logging. It never receives secrets and never throws.

## Any other framework

`checkRequest` is the same decision without the Connect shape — hand it the bundle, get a result:

```js
import { checkRequest } from "@ainra/middleware";

const result = checkRequest(verifier, req.headers.get("x-ainra-passport"));
if (!result.allow) return new Response(result.reason, { status: 403 });
```

It accepts a decoded object or the base64url-of-JSON string a header carries, and returns
`{ allow, reason?, verdict, event }`. Anything that is not a bundle verifying `valid` — including a parse failure —
comes back `allow: false`.

## What "fail-closed" costs you

Nothing on the happy path, and it is the whole point on the unhappy one. When status freshness cannot be
established this gate refuses, rather than admitting the request and logging a warning. That is the behaviour you
want on the day a key is stolen, and it is the behaviour that becomes impossible to add later, once something
depends on the lenient path.

## Underneath

Verification is [`@ainra/sdk`](https://www.npmjs.com/package/@ainra/sdk) — one of four independent implementations
agreeing on 793 conformance vectors. This package adds only the request plumbing: header decoding, the 403, the
verdict event, and `req.ainra`.

Licensed Apache-2.0 OR MIT.
