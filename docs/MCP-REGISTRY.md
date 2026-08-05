<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# MCP registry — prepared, and honestly parked

**State: PARKED on two blockers, neither of them ours to remove today.** Everything that can be prepared is
prepared: `packages/mcp/server.json` is written and valid, and `packages/mcp/package.json` carries the `mcpName`
field the registry uses to verify ownership.

The registry is free, self-serve, needs no legal entity and no approval. It also hosts **metadata only** — the
package itself must live on a package registry first. That is blocker one.

## Blocker 1 — `@ainra/mcp` is not published

Verified against the public registry: `@ainra/mcp` returns *not found*. The registry entry would point at nothing.
This clears the moment the npm publish runs (`.github/workflows/publish.yml`), which is itself waiting on the
maintainer's credentials.

## Blocker 2 — the namespace, and why we are not taking the easy one

Two namespace routes:

| Route | Namespace | Verification |
|---|---|---|
| Account auth | `io.github.<user>/ainra` | sign in as that account |
| **DNS auth** | **`org.ainra/ainra`** | a TXT record on the domain |

The account route works today and reads as **one person's project**. For a neutral root that is the same optics
problem the organization move exists to fix (see [`ORG-MOVE.md`](ORG-MOVE.md)) — and a namespace is far harder to
change after adopters have wired it into configuration files.

**The domain does not resolve yet** (checked: `ainra.org` and `ainra.dev` both fail to connect), so the DNS route
is unavailable. Per the standing instruction, no domain is registered here.

**Decision: park rather than fall back.** Taking the personal namespace now would trade a permanent identifier for
a few weeks of listing, on the one project whose entire proposition is that it is not a personal project.

### When the domain exists — the exact record

```
Type   TXT
Name   _mcp-registry.<domain>          (some flows use the apex; the publisher prints which)
Value  <the token `mcp-publisher` prints>
TTL    300
```

Then:

```sh
npm install -g @modelcontextprotocol/mcp-publisher   # or the release binary
mcp-publisher login dns --domain <domain>            # prints the TXT value to add, then verifies
mcp-publisher publish                                # reads packages/mcp/server.json
```

Update `name` in `server.json` and `mcpName` in `packages/mcp/package.json` to the `org.<domain>/ainra` form in the
same commit — they must match, or ownership verification fails.

## What happens once it is live

- A curated directory **ingests the registry daily** — no separate submission, no extra task.
- Two further listings need a submission each and take about 25 minutes combined: a tool-level index (via its
  account-auth flow) and a large community list (fork → alphabetical entry → pull request).
- The tool-level index withholds distribution from servers whose inferred container build fails, so a working
  `Dockerfile` and a `LICENSE` are the real bar there, not the form.

## Caveats to carry into any listing

- **The registry is in preview** — its own documentation warns of breaking changes and data resets. Do not treat a
  listing as durable infrastructure.
- **Buy no placement.** Paid slots exist on at least one directory; a neutral root paying for ranking is exactly
  the thing it tells everyone else not to do.
- The upstream "servers" list in the protocol repository is **retired** in favour of the registry — the most common
  stale advice in MCP distribution guides. Do not submit there.
- The container catalog is **LATER**: it is a reasonable channel, but its licence gate accepts permissive licences
  and rejects copyleft, and every submission is human-reviewed. Revisit after the registry entry is live.
