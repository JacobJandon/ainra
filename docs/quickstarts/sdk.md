<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# SDK quickstart — verify in ~5 lines

`@ainra/sdk` is the real verifier — the code that agrees byte-for-byte in the conformance differential. It has no
network, no state, no telemetry. You hold a signed directory + root keys (the root can be dark), and verify bundles
against them at your own clock.

```js
import { Verifier } from "@ainra/sdk";
import { readFileSync } from "node:fs";
const j = (f) => JSON.parse(readFileSync("kits/verifier/sample-artifacts/" + f, "utf8"));
const roots = j("roots.json");
const verifier = Verifier.fromDirectoryB64(j("directory.json"), roots.root_ed25519, roots.root_slh);
console.log(verifier.verify(j("bundle-valid.json"), j("meta.json").now));     // → { verdict: 'valid' }
console.log(verifier.verify(j("bundle-revoked.json"), j("meta.json").now));   // → { verdict: 'invalid', reason: 'revoked' }
```

Real output:

```
valid  : {"verdict":"valid"}
revoked: {"verdict":"invalid","reason":"revoked"}
```

- `Verifier.fromDirectoryB64` returns `null` if the directory isn't anchored by the given roots (fail closed).
- `verify()` never throws — any malformed input is `{verdict:"invalid", reason:…}` (one of the 15 in [`reasons.json`](../reasons.json)).
- Build the [verdict event](../PRESENTATION.md) with `verdictEvent(bundle, verdict, now)` when you need `{name, number, tier, freshness_age_s}`.

Next: gate a whole request path with [the middleware](middleware.md).
