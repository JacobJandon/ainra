<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# SDK quickstart — verify in ~5 lines

`@ainra/sdk` is the real verifier — the code that agrees byte-for-byte in the conformance differential. It has no
network, no state, no telemetry. You hold a signed directory + root keys (the root can be dark), and verify bundles
against them at your own clock.

```sh
npm i @ainra/sdk            # published with Sigstore provenance
npm audit signatures        # optional: verify where it was built before you trust it
```

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
- `verify()` never throws — any malformed input is `{verdict:"invalid", reason:…}` (one of the 21 in [`reasons.json`](../reasons.json)).
- Build the [verdict event](../PRESENTATION.md) with `verdictEvent(bundle, verdict, now)` when you need `{name, number, tier, freshness_age_s}`.

Next: gate a whole request path with [the middleware](middleware.md).

## Your own policy: refuse someone, at once, by yourself (D-100)

A gate can refuse a registrar, a lineage or one exact passport, the moment it decides to, with nobody's permission.
It can also refuse a directory that has grown older than it allows (the defence against a host that withholds a
newer one). Both are off unless you set them, so a gate that works offline keeps working on the directory it holds.

```ts
const gate = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F2", false, "", {
  deny: ["registrar-07", "ainra:registrar-11:acme:invoicing", "ainra:registrar-11:globex:travel@2.0.0"],
  maxDirectoryAgeS: 92 * 86400, // optional: the published quarterly cadence
});
```

A deny entry is a registrar id, a lineage (every version), or an exact name with its version. The policy only ever
turns `valid` into `denied_by_policy`: a passport that already fails keeps its own reason, so a revocation is never
hidden behind yours. The same option exists in the Python package, in `@ainra/edge` (`policy`), in the MCP tool
`ainra_verify` (`policy`) and in `ainra verify-request` (`--deny`, `--max-directory-age`), all held to the same gate
vectors (`vectors/v1-gate`, g31–g37).

## A running copy, not the agent itself (ADR-019)

If the thing presenting is one *running copy* — a container, a worker — it should not hold the lineage's key. It
carries an **instance credential**: minted by the passport's control key outside the container, narrowed, ≤1 h,
bound to a key only that copy holds.

You change exactly one thing: tell the verifier who **you** are.

```js
const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F2", false,
  "https://api.example");           // your audience — never read from the bundle
verifier.verify(bundle, now);        // unchanged; the instance layer is step 10 when present
```

Run the whole shape: `node examples/instance-deployment.mjs`.
