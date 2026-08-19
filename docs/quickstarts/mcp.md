<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# MCP quickstart — give an agent AINRA as native tools

`@ainra/mcp` is a zero-dependency MCP server. It exposes six tools that wrap existing surfaces — no new protocol
semantics, zero telemetry. Read-only tools (`ainra_verify`, `ainra_lookup`, `ainra_status`) run freely; write tools
(`ainra_issue`, `ainra_renew`, `ainra_revoke`) require `confirm: true` and only ever touch a registrar you control.

## Zero steps, if your client reads project config

This repo ships **`.mcp.json`** at its root — a project-scoped MCP client opened in this repo picks the `ainra`
server up automatically. It defaults to the staging registrar (`http://127.0.0.1:4907`, from `make stage-up`);
export `AINRA_STAGE_ISSUE_TOKEN` (in `stage/.issue-token`) to enable the write tools.

## Three steps, anywhere else

1. **Build the SDK once** (the server wraps it): `make sdk-build`.
2. **Choose the target** (one field) — a local registrar dir *or* a live registrar/network you control:
   ```
   export AINRA_TARGET=genesis-out            # a local registrar dir (from `make genesis-local` or `ainra init`)
   # or:
   export AINRA_TARGET=http://127.0.0.1:4907  # a registrar daemon — full lifecycle; writes need AINRA_STAGE_ISSUE_TOKEN
   # or:
   export AINRA_TARGET=http://127.0.0.1:8091  # a public artifact server — read-only (lookup/status/verify)
   ```
3. **Register the server** in your MCP client's config as a stdio server. The shape every MCP client accepts:
   ```json
   {
     "mcpServers": {
       "ainra": {
         "command": "node",
         "args": ["packages/mcp/src/server.mjs"],
         "env": { "AINRA_TARGET": "http://127.0.0.1:4907" }
       }
     }
   }
   ```

That's it. The agent now sees the six tools. `ainra_verify` returns the real verdict + the named reason in plain
words; it is byte-identical to `@ainra/sdk` (proven by `make mcp-test`).

## A real session (live staging registrar)

```
status       → {"network":"staging","root":"test-root","registrar":"registrar-07","issued":4,"revoked":1,"write_auth":true}
lookup seed  → {"name":"ainra:registrar-07:acme:invoicing@4.2.1","tier":"L3","standing":"active","verdict":"valid"}
issue        → {"issued":"ainra:registrar-07:acme:agent-tour@1.0.0","tier":"L2"}
renew        → {"renewed":"…agent-tour@1.0.0","new_generation":"ainra:registrar-07:acme:agent-tour@1.0.1"}
revoke       → {"revoked":"…agent-tour@1.0.0","note":"fails closed everywhere within the freshness window"}
lookup again → {"standing":"revoked","verdict":"invalid","reason":"revoked"}
no-confirm   → ERROR: ainra_revoke is a WRITE operation … Re-call with `confirm: true`. Nothing was changed.
```

## The tools

| Tool | Kind | What it does |
|---|---|---|
| `ainra_verify` | read-only | Verify a presentation bundle → verdict + named reason (the real `@ainra/sdk`). |
| `ainra_lookup` | read-only | Resolve a name to its public record (tier, authority, standing). |
| `ainra_status` | read-only | The target's head: network/root label, counts, verification window. |
| `ainra_issue` | write · `confirm` | Issue a passport on a registrar you control. |
| `ainra_renew` | write · `confirm` | Reissue a lineage with a fresh window (ADR-017). |
| `ainra_revoke` | **destructive** · `confirm` | Set a lineage's revocation bit (fails closed everywhere). |

Write tools refuse without `confirm: true` and never target a registrar you don't hold keys for.

## Verify it yourself

```
$ make mcp-test
✔ ainra_verify ≡ @ainra/sdk over 107 sampled vectors (byte-identical)
✔ safety annotations: read-only vs destructive are marked correctly
✔ write tools fail closed without explicit confirm
```

## Verifying a running copy (ADR-019)

Pass your own `audience` to `ainra_verify`. It is never taken from the bundle, and omitting it refuses every
instance credential. The result carries an `instance` object whose `layer` says whether the *copy* or the
*lineage* failed — different problems, different fixes. Minting is deliberately not a tool: it needs a control
key, which belongs nowhere an agent can reach.
