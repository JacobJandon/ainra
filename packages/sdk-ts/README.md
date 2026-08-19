<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# @ainra/sdk

The verify-only TypeScript SDK for [AINRA](https://ainra.vercel.app/) — a neutral, non-profit root for AI-agent
identity. An agent carries a passport it can prove; you check it here, locally, in about a millisecond.

**Offline. Fail-closed. Zero telemetry.** No account, no API key, no call home — verification is a pure function of
the bundle you were handed and the trust anchors you already hold. If anything is missing, stale, malformed, or
merely ambiguous, the answer is `invalid` with a named reason. There is no "probably fine".

```sh
npm install @ainra/sdk
```

## Verify a presentation

```js
import { Verifier } from "@ainra/sdk";
import { readFileSync } from "node:fs";

const j = (f) => JSON.parse(readFileSync(f, "utf8"));
const roots = j("roots.json");

// Build a verifier from the dual-root-signed directory. `null` if the directory isn't authentic — check it.
const verifier = Verifier.fromDirectoryB64(j("directory.json"), roots.root_ed25519, roots.root_slh);

const verdict = verifier.verify(j("bundle.json"), Math.floor(Date.now() / 1000));
// { verdict: "valid" }  |  { verdict: "invalid", reason: "revoked" }
```

`reason` is one of fifteen frozen strings — `sig_invalid`, `alg_downgrade`, `expired`, `not_yet_valid`, `revoked`,
`mandate_revoked`, `chain_widening`, `chain_expired`, `not_logged`, `checkpoint_invalid`, `stale_status`,
`name_malformed`, `ceiling_exceeded`, `unknown_registrar`, `schema_violation`. A closed set, so you can branch on it
and it will not grow under you between minor versions.

## What it checks

Signature and hybrid-suite integrity (Ed25519 **and** ML-DSA-65 — one alone is `alg_downgrade`), the validity
window, authority-chain containment (a delegate can never widen its parent's scope), log inclusion against a signed
checkpoint (unlogged is not valid), and revocation freshness under the *verifier's* policy, never the presenter's.
The whole path is RFC and FIPS primitives over [`@noble`](https://www.npmjs.com/package/@noble/curves); there is no
vendor in it to remove.

## Also here

- `verify(presentation, anchors)` — the same decision without building a `Verifier`, when you already hold anchors.
- `canonicalize` — the deterministic sorted-key JSON encoder the whole system signs over.
- `verifyDelta` / `verifyFreshHead` — status-list deltas and the fresh-head replay defence.
- `verdictEvent` / `serializeVerdictEvent` — the one event shape every AINRA surface emits, so logs from the CLI,
  the middleware, and this SDK are identical.
- HTTP request gating lives in **[`@ainra/middleware`](https://www.npmjs.com/package/@ainra/middleware)**.

## Don't take our word for it

This SDK is one of **four independent implementations** — a Rust core, this one, a Node reference CLI, and a Python
verifier — which agree on all **1009** conformance vectors, verdict *and* reason. The corpus is CC0 and the runner is
language-agnostic, so you can build a fifth and check us:

```sh
git clone https://github.com/JacobJandon/ainra && cd ainra && make conformance
```

The root's honest status — including what has **not** happened yet — is at
[ainra.vercel.app](https://ainra.vercel.app/) and in the repository's `ROADMAP.md`.

Licensed Apache-2.0 OR MIT.

## Verify a running copy (ADR-019)

A **passport** identifies the agent. An **instance credential** identifies one *running copy* of it: minted by the
passport's control key (which never enters the container), narrowed, ≤1 h, and bound to a key only that copy holds.
Verification is automatic — if the bundle carries an `instance` object, the verifier checks it as step 10.

The only thing you must supply is **your own audience**:

```ts
const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F2", false,
  "https://api.example");           // ← YOUR audience. Never taken from the bundle.
verifier.verify(bundle, now);        // same call as before; the instance layer is checked when present
```

The empty-string default is **fail-closed**: a service that has not said who it is accepts no instance credential.

Four reasons are specific to this layer and are never collapsed into `expired` — `instance_expired`,
`instance_scope_exceeds`, `instance_sig_invalid`, `instance_pop_invalid`. A revoked *passport* still reports
`revoked`, because the lineage failed rather than the copy.

Minting is the operator's side (`mintInstanceCredential`, `proveInstancePossession`); signing is a callback, so no
key material enters this library. Full shape: [`docs/PRESENTATION.md`](../../docs/PRESENTATION.md) ·
runnable: [`examples/instance-deployment.mjs`](../../examples/instance-deployment.mjs).
