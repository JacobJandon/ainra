<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# AINRA Link: attribution and revocation for keys agents already have

An agent usually already signs its requests with a key: a signature-agent key, a workload key. That key can be revoked
only inside the system that issued it, and it says nothing about who is accountable for it. A **link** is a
registrar's signed, logged statement that one such key acts for one AINRA passport, with a bit in the registrar's
status list that anyone can check offline. Decision: [D-078](DECISIONS.md). Plan: [PLAN-M47](PLAN-M47.md).

**What a link does not do.** It does not make a request genuine. Your gate verifies the request's signature first,
with whatever protocol it already speaks; a link answers the next question: *who stands behind this key, and is that
still true?*

## The record

```json
{
  "v": "ainra-link-1",
  "registrar": "registrar-07",
  "passport": "ainra:registrar-07:acme:invoicing@1.0.0",
  "subject": { "kind": "jwk", "alg": "Ed25519", "thumbprint": "<RFC 7638 thumbprint, base64url>" },
  "scope": [],
  "nbf": 1775865600,
  "exp": 1778457600,
  "status": { "uri": "status://registrar-07/1", "idx": 5 },
  "passport_status": { "uri": "status://registrar-07/1", "idx": 3 },
  "pop": "<Ed25519 signature by the linked key>",
  "log": { "leaf": "<RFC 6962 leaf of the record without `log`>" }
}
```

- The registrar signs these exact canonical bytes with its hybrid key (Ed25519 and ML-DSA-65, both or invalid).
- `pop` is the linked key's own consent: an Ed25519 signature over the canonical
  `{"nbf", "passport", "purpose": "ainra-link-pop-1", "registrar", "thumbprint"}`. Nobody can link a key they do not
  hold.
- `scope` empty means "whatever the passport allows"; otherwise the link refuses any capability it does not name.
- Two bits: the link's own, and the passport's. Revoking the operator refuses every link it has.

## At the registrar

| Route | What it does |
|---|---|
| `POST /link` | Body `{passport, key, pop, scope?, nbf, exp}` (`key` is the base64url Ed25519 public key). Refused unless the key signed its consent, the passport is this registrar's and not revoked, and the link fits inside it: window inside the passport's, scope inside its capabilities. Bearer token, rate limited. |
| `GET /links` | The whole index. Each entry is registrar-signed and proven under one delegate-signed checkpoint. There is no lookup by key: you download the index, so nobody learns which key you asked about. |
| `POST /link/revoke` | Body `{thumbprint, kind, suspect_since?}`. `kind` is `link` (this key is retired), `operator` (the passport's lineage is suspended, so every link flips) or `compromise` (the key was stolen; `suspect_since` marks when its actions stopped being the operator's). Bearer token, rate limited. |
| `POST /demo/link`, `POST /demo/link/revoke` | The public demo door, for trying Link without a token: the same bodies, the same proof of control, but staging only, on the demo door's own rate limit, and only for demo specimens (passports from `POST /demo/issue`). A key cannot be linked to, and a link cannot be revoked from, any other passport through it. |

Three rules:

- **One link per key, ever.** A revoked key stays revoked; to rotate, link a new key and revoke the old one.
- **A `link` revocation can later become a `compromise`.** A compromise is never downgraded.
- **Everything is logged.** Each link and each revocation is appended to the registrar's transparency log, so the log
  alone says which keys were ever attributable and when that ended.

## At a gate

A gate holds a dual-root-signed directory, as it does for passports. For each request whose signature it has verified
with an Ed25519 key, it builds a `WireLink` from the index entry for that key, the index's checkpoint, and the
registrar's current signed status publication:

```js
import { Verifier } from "@ainra/sdk";
const gate = Verifier.fromDirectoryB64(directory, rootEd25519, rootSlh, "F1");
const r = gate.verifyLink(link, presentedKey, nowSecs, "read:invoices");
// { verdict: "valid", registrar, operator, passport, scope }  or  { verdict: "invalid", reason }
```

```python
from ainra import Verifier
gate = Verifier.from_directory(directory, root_ed25519, root_slh, freshness="F1")
r = gate.verify_link(link, presented_key, now, "read:invoices")
```

The order is fixed and the first failure wins:

1. schema (`schema_violation`, `name_malformed`);
2. the registrar is accredited (`unknown_registrar`);
3. the status publication is the registrar's: signed, under the directory's status URI, before anything is
   decompressed (`stale_status`);
4. the window, exactly (`not_yet_valid`, `expired`);
5. the registrar's hybrid signature (`alg_downgrade`, `sig_invalid`);
6. the key the gate verified is the linked key, and that key signed its consent (`sig_invalid`);
7. scope (`ceiling_exceeded`);
8. freshness, then the link's bit, then the passport's (`stale_status`, `revoked`);
9. logged before valid (`checkpoint_invalid`, `not_logged`, `registrar_distrusted`).

A key with no link at all is **not linked**: an outcome for the gate to act on, not a reason. A gate in link mode
refuses it.

### Ready-made gates and tools

| Where | What |
|---|---|
| Node (Express/Connect) | `ainraLinkGate(verifier, { verifiedKey, source, capability?, decisions? })` from `@ainra/middleware` |
| Python (ASGI) | `AinraLinkGate(app, verifier, verified_key, source, capability=..., decisions=...)` |
| Edge (WebAssembly) | `createAinraLinkCheck({ directory, roots, freshness })` from `@ainra/edge`, plus `linkFromIndex` |
| Command line | `ainra verify-link --link L --directory D --roots R --key K` prints ACCEPT with the operator, or REFUSE with the reason; `ainra link`, `ainra link-revoke` and `ainra links` run a local registrar's side |
| MCP | `ainra_verify_link`, read-only; takes a link, or the registrar's index and status publication |

`verifiedKey` (Python: `verified_key`) is yours: whatever already checks the request's signature hands over the key
it verified. `source` returns the registrar's index and signed status publication; cache them inside your freshness
class. Each gate records `link` decisions when given a decision log.

`make link-parity` serves every link vector to the Node, edge and Python gates as a registrar would, and requires the
same status, reason and operator from all three. CI runs it.

## Held to one corpus

[`vectors/v1-link`](../vectors/v1-link) has 36 vectors in gate form: the directory and roots, the link as a gate
receives it, the key the gate verified, and the gate's own clock, freshness class and capability. A valid answer names
the registrar, operator, passport and scope, so accepting for the wrong operator counts as a disagreement. The Rust
core, the TypeScript SDK and the Python package must agree on every one in `make diff`. Each check was removed once from
each implementation to confirm a vector goes red; the leaf-binding attack (`l22`) was rewritten after that exercise
showed its first version could not tell a verifier with the check from one without it.

## Live

`make link-e2e` (in `make live-drills`, which CI runs) does it at the real clock against a running registrar. An
operator's agents sign as signature agents with keys in its published directory. Two of three keys are linked, each
with its own consent. An origin reads every request twice: an independent open-source signature-agent verifier, then
AINRA Link from the downloaded index and signed status list.

| Step | Signature-agent reader | AINRA Link |
|---|---|---|
| Signed by a linked key | valid | valid, names the operator |
| Signed by the key nobody linked | valid | refused: not linked |
| Key A revoked | valid | A refused `revoked`; B still valid |
| A upgraded to `compromise` | valid | refused; downgrading back is refused |
| Operator suspended | valid | every key refused; the passport itself reads `revoked` |

The signature-agent reader accepts throughout because its profile has no revocation: its remedy is removing the key
from the directory, which reaches a verifier at its next cache refresh. That is the gap Link fills.

