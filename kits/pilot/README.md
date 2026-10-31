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
`GET /.well-known/ainra-decisions-head` returns the log's head digest, the gate's public key and the latest receipt.
With `--publish-head https://registrar.example` the pilot hands its signed head to that registrar's transparency log
every `--head-every` decisions (100) or `--head-seconds` (300), whichever comes first, and keeps the receipt in
`<decisions>.receipt.json`; anyone can then check the log with `ainra verify-decisions --receipt` and see a cut tail as
`truncated` ([D-081](../../docs/DECISION-RECORDS.md)). Records after the latest logged head are what it could still
lose, so the interval is that bound.

| Command | What it proves |
|---|---|
| `make pilot-e2e` (after `make live-up` and `make stage-up`; in `make live-drills`) | Both modes, live. **Link:** a linked key's request reaches the upstream with the operator named; an unlinked key is refused `not_linked` and a revoked one `revoked` (after the 10-second status cache), neither reaching the upstream. **Passport:** an agent with its own key and a passport for it sends its bundle once, then a signed request reaches the upstream with the operator named and no presentation headers; unsigned (`presentation_unsigned`), replayed (`presentation_replayed`) and post-revocation (`revoked`) requests are refused and never forwarded. Each pilot's decisions verify and the last is the published head. **Heads:** the passport-mode pilot logs its head at the registrar; the receipt verifies against the published directory, and with the last record cut the chain alone still holds while the receipt reads `truncated`. |

This is a test root over http on 127.0.0.1. It proves the mechanism; it is not evidence that anyone runs it.
