<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# @ainra/mcp

[AINRA](https://ainra.vercel.app/) as native agent tools. A zero-dependency MCP server that hands an assistant the
real verifier, the public record, and — only if you point it at a registrar you control — the ability to issue,
renew, and revoke.

> **Not published to a registry.** This package is run from the repository. See `packages/mcp/` in
> [github.com/JacobJandon/ainra](https://github.com/JacobJandon/ainra).

## Configure

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

`AINRA_TARGET` selects one thing and one thing only:

| Value | Means |
|---|---|
| `genesis-out` (default) | a **local** registrar directory — what `make genesis-local` or `ainra init` produced — driven through the CLI |
| `http://127.0.0.1:8091` | a running AINRA network you control (`make stage-up`) |

There is no hosted default and no fallback. If the target isn't reachable the tools say so and stop.

## Tools

**Read-only** — `ainra_verify` decides whether a presentation someone handed you verifies, and says why in plain
words. It takes the signed `directory` and the `roots` you trust (or fetches a URL target's own), checks the one
against the other, authenticates the status list against the registrar's status key, and uses **your** clock,
freshness class and audience. Nothing a presenter put in the bundle is believed. The result carries
`decision: "accept" | "refuse"` and the policy that decided.

> **In 0.4.1 this tool did not do that.** It replayed the bundle through the fixture-semantics verifier with the
> bundle's own clock, freshness class and status list, so a revoked or expired presenter could be reported `valid`
> (D-074). Upgrade. Replaying a conformance vector is still possible and is now a separate, labelled mode:
> `anchors` plus `fixture: true`, which returns `decision: null`.

`ainra_lookup` resolves a name to its public record; `ainra_status` reports the target's head — network, root label,
registrar count, freshness window.

**Write, and each requires an explicit `confirm: true`** — `ainra_issue`, `ainra_renew`, and `ainra_revoke`.
`ainra_revoke` is destructive: it fails a live credential closed everywhere inside the freshness window. An agent
cannot reach any of the three by accident, and none of them targets a registrar you do not hold the write token for.

## Zero telemetry

The only outbound calls this server makes are to the `AINRA_TARGET` you set. Nothing is reported anywhere, by
design and by inspection — it is a few hundred lines with no dependencies.

Licensed Apache-2.0 OR MIT.

### Verifying a running copy (ADR-019)

`ainra_verify` takes an optional **`audience`** — yours. It is never read from the bundle, and an empty audience
refuses every instance credential (fail-closed). The result gains an `instance` object that reports the layer
distinctly:

```json
{ "verdict": "invalid", "reason": "instance_expired",
  "instance": { "presented": true, "iid": "i-0794", "expires": 2600, "layer": "instance",
                "note": "the RUNNING COPY is not entitled — the passport may be fine; mint a fresh instance credential" } }
```

`layer` is `"instance"`, `"passport"` or `"ok"`, because the remedies differ: renew the copy, or stop trusting the
lineage. Minting is **not** an MCP tool — it needs a passport's control key, and that key belongs outside any
agent-reachable surface.
