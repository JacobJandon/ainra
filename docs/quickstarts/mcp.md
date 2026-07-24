<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# MCP quickstart — give an agent AINRA as native tools

`@ainra/mcp` is a zero-dependency MCP server. It exposes six tools that wrap existing surfaces — no new protocol
semantics, zero telemetry. Read-only tools (`ainra_verify`, `ainra_lookup`, `ainra_status`) run freely; write tools
(`ainra_issue`, `ainra_renew`, `ainra_revoke`) require `confirm: true` and only ever touch a registrar you control.

## Three steps

1. **Build the SDK once** (the server wraps it): `make sdk-build`.
2. **Choose the target** (one field) — a local registrar dir *or* a network you control:
   ```
   export AINRA_TARGET=genesis-out            # a local registrar dir (from `make genesis-local` or `ainra init`)
   # or:
   export AINRA_TARGET=http://127.0.0.1:8091  # a network (issue/renew/revoke need AINRA_STAGE_ISSUE_TOKEN)
   ```
3. **Register the server** in your MCP client's config as a stdio server. The shape every MCP client accepts:
   ```json
   {
     "mcpServers": {
       "ainra": {
         "command": "node",
         "args": ["packages/mcp/src/server.mjs"],
         "env": { "AINRA_TARGET": "genesis-out" }
       }
     }
   }
   ```

That's it. The agent now sees the six tools. `ainra_verify` returns the real verdict + the named reason in plain
words; it is byte-identical to `@ainra/sdk` (proven by `make mcp-test`).

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
