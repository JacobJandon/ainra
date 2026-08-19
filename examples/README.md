<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Examples

Tiny, complete, runnable integrations. Placeholder operators only; nothing leaves your machine. Build the packages
once (`make sdk-build wedge-build` and, for the MCP one, `cargo build --release -p ainra-cli-rs`), then:

| File | What it shows | Run |
|---|---|---|
| [`verify-5-lines.mjs`](verify-5-lines.mjs) | the minimal offline verify | `node examples/verify-5-lines.mjs` |
| [`verify-then-act.mjs`](verify-then-act.mjs) | verify, then act only if valid (refuse otherwise) | `node examples/verify-then-act.mjs` |
| [`gate-http-service.mjs`](gate-http-service.mjs) | an HTTP service gating a path on the middleware, fail closed | `node examples/gate-http-service.mjs` |
| [`instance-deployment.mjs`](instance-deployment.mjs) | **ADR-019** — the real deployment shape: control key with the operator, instance credential in the container, service verifying with its own audience | `node examples/instance-deployment.mjs` |
| [`mcp-lifecycle.mjs`](mcp-lifecycle.mjs) | the lifecycle through MCP tools: issue → check → revoke → check + verify | `node examples/mcp-lifecycle.mjs` |

Real output:

```
# gate-http-service.mjs
valid passport         → HTTP 200 · {"ok":true,"agent":"ainra:registrar-07:acme:invoicing@1.0.0","tier":"L3"}
no passport            → HTTP 403 · {"error":"denied","reason":"schema_violation"}
revoked passport       → HTTP 403 · {"error":"denied","reason":"revoked"}

# mcp-lifecycle.mjs
2. ainra_lookup: {…,"standing":"active"}
4. ainra_lookup: {…,"standing":"revoked"}
```

Bundles are presented in the request **body** (`ainra_passport`), not the header — AINRA bundles are tens of KB
(post-quantum key + signature). See [docs/PRESENTATION.md](../docs/PRESENTATION.md).
