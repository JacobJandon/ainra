<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# kits/pilot: an AINRA gate in front of any service, in one command

For a design partner's first week. Nothing in their service changes: the pilot sits in front of it, refuses by name
what should not get in, forwards the rest with the operator named, and keeps a signed, hash-chained record of every
decision ([DECISION-RECORDS.md](../../docs/DECISION-RECORDS.md)).

```
node kits/pilot/pilot.mjs --upstream http://127.0.0.1:3000 --listen 127.0.0.1:8080 \
  --directory directory.json --roots roots.json \
  --mode link --registrar https://registrar.example --freshness F1 \
  --decisions decisions.jsonl --gate-key gate.key
```

| Mode | The request arrives with | What the pilot checks |
|---|---|---|
| `link` | a signature-agent signature (the Web Bot Auth profile) | an independent open-source verifier checks the signature against the operator's key directory; [AINRA Link](../../docs/LINKS.md) then says who stands behind the key, from the registrar's index and signed status list, cached inside the freshness class |
| `passport` | an AINRA presentation, signed per request by the agent's running copy (RFC 9421) | the standard `@ainra/middleware` gate, with send-once and single-use nonces |

Forwarded requests carry `x-ainra-operator` and `x-ainra-passport-name`; the presentation headers are stripped.
`GET /.well-known/ainra-decisions-head` returns the log's head digest and the gate's public key: publish it somewhere
you cannot quietly rewrite, and anyone can then check the log with `ainra verify-decisions --head`.

| Command | What it proves |
|---|---|
| `make pilot-e2e` (after `make live-up` and `make stage-up`; in `make live-drills`) | Link mode, live: a linked key's request reaches the upstream with the operator named; an unlinked key is refused `not_linked` and a revoked one `revoked` (after the 10-second status cache), neither reaching the upstream; the three decisions verify and the last is the published head. |

**Not yet drilled:** passport mode through the pilot. The gate it uses is the one the identity drills exercise, but this
wiring of it has no live test of its own yet.

This is a test root over http on 127.0.0.1. It proves the mechanism; it is not evidence that anyone runs it.
