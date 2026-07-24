<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# AINRA cookbook

The owner's manual. Each page is ≤ 1 screen and ends with real pasted output. Start with the two sixty-second paths,
then pick the surface you build on.

## The two sixty-second paths

| Do this | Command | What you get |
|---|---|---|
| **Verify** a credential | `make verify` | The real verifier's verdict on a valid + a revoked credential, with the named-reason legend. No account, no server. `[LOCAL TESTBED]`, or `[STAGING · TEST-ROOT]` with `AINRA_NET=…`. |
| **Issue** your first passport | `make issue-first` | A local registrar (kept in `./my-registrar`), one issued passport, verified — with plain-words narration. `[LOCAL TESTBED]` |

## Per-surface quickstarts

- [SDK](sdk.md) — verify in ~5 lines in your own service.
- [Middleware](middleware.md) — gate a request path, fail closed.
- [CLI](cli.md) — `ainra init / issue / verify / renew / revoke`.
- [MCP](mcp.md) — give an agent AINRA as native tools.
- [Console](console.md) — the open registrar console (issue/renew/revoke/list in a browser).

## For agents

An agent can onboard itself by fetching **[`/skills.md`](../../skills.md)** (alias `/agents.md`) — a deterministic,
executable-as-written instruction file.

## Honest status

This is a reference implementation with a **staging network on a TEST-ROOT**. The production root is born only at a
recorded genesis ceremony (a pending milestone). No trust migrates from staging. Everything here is real cryptography
over placeholder operators — never production, never a claim of usage.
