<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# @ainra/edge — the AINRA gate at the edge

Most traffic gets decided at the CDN edge, so this gate runs there. It is a function from a standard `Request` to
a decision. It uses web-standard APIs only (`Request`, `Response`, `URL`, `atob`, WebAssembly: no Node `Buffer`, no
filesystem), so the same file runs in a Worker, in Deno and in Node's fetch server.

**The engine is `ainra-core` itself,** compiled to WebAssembly. It's the Rust verify path that generates the
conformance corpus, not a re-implementation. The package has no verification logic of its own. It holds only what
the core can't, because the core has no state:

- **The send-once store** (D-065): bundles sent to `/.well-known/ainra-presentation`, verified in full and named
  by digest.
- **The nonce cache:** each request nonce is used once, checked only after the signature holds (D-062).

Both are bounded and kept per isolate. Behind several isolates, pass shared ones.

```js
import { initAinra, createAinraEdgeGate } from "@ainra/edge";
import wasm from "@ainra/edge/wasm";             // wasm/ainra_wasm_bg.wasm
await initAinra(wasm);
const gate = await createAinraEdgeGate({
  directory, roots,                               // the published directory + the two ceremony root keys
  audience: "https://shop.example",               // who THIS service is (ADR-019), never taken from the request
});
export default {
  async fetch(request) {
    const g = await gate(request);
    return g.allow ? fetch(request) : g.response;  // 403 by name · 428 "send the bundle first" · 201 on send-once
  },
};
```

## Trust is the verifier's

- **The directory must verify against both ceremony roots** (FROST Ed25519 and SLH-DSA), once, when the gate is
  created. If it doesn't, the gate refuses to exist.
- **The freshness class is the gate's** (default `F2`, five minutes, the same as `@ainra/sdk`).
- **Revoked delegates come from the trusted directory.**

A presenter can't loosen any of these (D-068).

## Proof

- **`make edge-test`:** the WASM build answers every request-signature vector as the core recorded it. Every
  credential verdict equals what the independently written `@ainra/sdk` gives on the same bundle and clock. An `F3`
  bundle checked an hour later is `stale_status` under the gate's `F2`. Only verified bundles are stored.
- **`make edge-runtimes`:** the same checks under Deno, Bun, Node and inside the workerd runtime itself (the WASM
  loaded as a compiled module, like a deployed worker). A runtime that isn't installed is reported SKIPPED.
- **`make edge-e2e`:** the whole journey against the live registrar, served by this gate:
  - the agent's own key, a passport, an instance credential;
  - send-once 201;
  - a signed request allowed with 10.7 KiB of headers;
  - an unknown digest answered 428;
  - moved, unsigned and replayed requests refused by name;
  - a revoked credential refused at the door.
- **`make signature-agent-e2e`:** the same gate with a signature agent's signature on the same request (D-070). Each
  verifier reads its own label, in either order, and after revocation this gate refuses a request the operator
  signed. See [`docs/SIGNATURE-AGENTS.md`](../../docs/SIGNATURE-AGENTS.md).
