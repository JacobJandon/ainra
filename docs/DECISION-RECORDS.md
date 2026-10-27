<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Decision records: what a gate decided, provably

A gate that checks AINRA passports or links can keep a **decision log**: one small record per decision, signed by
the gate's own Ed25519 key and chained to the record before it. Anyone holding the gate's public key can check the
log end to end. An edited, deleted, reordered, inserted or re-dated record is found, and the check says which record
and why. Decision: [D-079](DECISIONS.md).

This answers what auditors and regulators ask of AI agents: who acted, under whose authority, and what the gate
knew when it let them in (see [REGULATION.md](REGULATION.md): AI Act Art. 12 logging, the IETF agent-identity
draft's "durable audit logs", the Financial Stability Board's "reconstruction of actions"). It is evidence for
whoever operates the gate; it does not make anyone compliant.

## One record

```json
{"at":1776729600,"checkpoint":{"origin":"ainra-log/registrar-07","root":"…","size":212},
 "gate":"<RFC 7638 thumbprint of the gate key>","kind":"passport","operator":"acme",
 "policy":{"audience":"https://shop.example","freshness":"F2"},"prev":"<SHA-256 of the previous line>",
 "request":"<SHA-256 of the request's signed components>","seq":41,"sig":"<Ed25519>",
 "status":{"issued_at":1776729599,"list":"<SHA-256 of the status list>","uri":"status://registrar-07/1"},
 "subject":"ainra:registrar-07:acme:invoicing@1.0.0","v":"ainra-decision-1","verdict":"valid"}
```

- **The field set is closed.** Every value is a name, a digest, a number or a word from a fixed vocabulary, so there
  is nowhere to put a request body, an address or an account. A record with any other field is refused.
- `kind` is `passport` or `link`. For a link, `subject` is the presented key's thumbprint and `passport` the passport
  it was attributed to.
- `reason`, present exactly on a refusal, is a frozen credential reason, a request-signature reason
  (`presentation_unsigned`, `presentation_sig_invalid`, `presentation_stale`, `presentation_replayed`), or, for a
  link, `not_linked`.
- `operator` appears only on a valid decision. On a refusal, the name in the claims is only the presenter's word.
- `request` is SHA-256 over the canonical `{authority, content_digest, method, path}`: what the request's signature
  covers, never its body.
- One record is one line of canonical JSON. `prev` is the SHA-256 of the previous line; the first record has
  `seq` 0 and an empty `prev`.

## Keeping a log

```js
import { createDecisionLog } from "@ainra/sdk";
import { ainraGate } from "@ainra/middleware";

const decisions = createDecisionLog({
  gatePublic, sign: (msg) => ed25519.sign(msg, gateSecret),
  append: (line) => fs.appendFileSync("decisions.jsonl", line + "\n"),
  freshness: "F2", audience: "https://shop.example",
  lastLine,                    // the file's last line, to continue after a restart
});
app.use("/agent", ainraGate(verifier, { decisions }));
// publish decisions.head() from time to time
```

Python has the same pieces in `ainra.decision` (`sign_decision`, `verify_chain`). A decision the gate cannot write is
logged as an error and does not change the decision.

## Checking a log

```
ainra verify-decisions decisions.jsonl --gate-key <base64url Ed25519 public key> [--head <digest>]
HOLDS 1204 record(s), ending at the published head
```

Per record, in this order: **schema**, **gate**, **signature**, **sequence**, **link**, **clock**. An edited record
therefore reads `signature`, and only records the gate really signed can read as deleted, reordered or re-dated.
`--after SEQ:AT:DIGEST` checks a segment that continues from a record already checked.

**The honest limit.** A chain cannot show what is missing after its end: cut the last records and what remains
still holds (`vectors/v1-decision/d17` pins this). The defence is a **head**: the gate publishes the digest of its
latest record from time to time, somewhere it cannot quietly rewrite, and the checker compares (`--head`). Without
that, a log proves what it contains, not that it is complete.

## Held to one corpus

[`vectors/v1-decision`](../vectors/v1-decision) holds 21 logs with the answer to each, including the limit above.
The Rust core, the TypeScript SDK and the Python package agree on all of them in `make diff`. Each check was removed
once from each implementation, and a vector went red every time.
