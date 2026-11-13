<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# @ainra/sdk

The verify-only TypeScript SDK for [AINRA](https://ainra.org/) — the identity layer of the internet for AI
agents, an open standard with a neutral, non-profit root. An agent carries a passport it can prove; you check it here, locally, in about a millisecond.

**Offline. Fail-closed. Zero telemetry.** No account, no API key, no call home — verification is a pure function of
the bundle you were handed and the trust anchors you already hold. If anything is missing, stale, malformed, or
merely ambiguous, the answer is `invalid` with a named reason. There is no "probably fine".

```sh
npm install @ainra/sdk
npm audit signatures    # optional: check the Sigstore provenance before you trust it
```

## Verify a presentation

Try it in an empty folder with the test network's sample files (a valid passport, the same one revoked, and the
directory and root keys they verify against):

```sh
npm i @ainra/sdk
for f in roots.json directory.json bundle-valid.json bundle-revoked.json meta.json; do
  curl -sLO https://github.com/JacobJandon/ainra/raw/main/kits/verifier/sample-artifacts/$f
done
```

```js
// verify.mjs — run with: node verify.mjs
import { Verifier } from "@ainra/sdk";
import { readFileSync } from "node:fs";

const j = (f) => JSON.parse(readFileSync(f, "utf8"));
const roots = j("roots.json");

// Build a verifier from the dual-root-signed directory. `null` if the directory isn't authentic — check it.
const verifier = Verifier.fromDirectoryB64(j("directory.json"), roots.root_ed25519, roots.root_slh);

// The samples were signed for one moment, kept in meta.json. With today's clock they answer `stale_status`, because
// their status list is from that day: the check working. For a live passport, pass Math.floor(Date.now() / 1000).
const now = j("meta.json").now;
console.log(verifier.verify(j("bundle-valid.json"), now));    // { verdict: 'valid' }
console.log(verifier.verify(j("bundle-revoked.json"), now));  // { verdict: 'invalid', reason: 'revoked' }
```

`reason` is one of the frozen strings in the `Reason` type this package exports. The same list, with a plain-words
gloss for each, is [`docs/reasons.json`](https://github.com/JacobJandon/ainra/blob/main/docs/reasons.json) in the
repository, and `make reasons-check` fails the build if that file and this type ever differ. A closed set, so you can
branch on it. So far every new reason has arrived in a minor release, never in a patch.

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

## Never go back to an older directory

Both ceremony roots signed every old directory too, so a signature check alone cannot refuse a replayed one — and an
old directory may still accredit a registrar the root has withdrawn, or miss a delegate it has revoked. If you refresh
the directory, keep a holder; it remembers the highest epoch it accepted and refuses anything older:

```js
import { createDirectoryHolder } from "@ainra/sdk";
const holder = createDirectoryHolder({ rootEd25519, rootSlh, minEpoch: savedFloor });
const v = holder.verifier(fetchedDirectory);   // a Verifier, or { ok: false, refusal: "rollback" | "unauthentic" }
saveFloor(holder.floor());                      // persisting it across restarts is yours to do
```

`verifyDirectoryAtLeast(directory, rootEd25519, rootSlh, minEpoch)` is the one-shot form. Held to
`vectors/v1-directory-epoch` with the Rust core and the Python package.

`verifyLogCheckpoint(directory, rootEd25519, rootSlh, checkpoint, checkpointSig, now)` answers which accredited
registrar's log signed a checkpoint, or `null` — what a witness, or anyone counting witnesses, checks before a
cosignature means anything.

## Replaying the test vectors is a different import

```ts
import { Verifier } from "@ainra/sdk";                 // decides whether to trust a presenter
import { runVector } from "@ainra/sdk/conformance";    // replays a test vector; decides nothing
```

`runVector` believes a vector's own clock, freshness class and status list: that is what lets the corpus pin every
reason, and it is why it must never be used to decide trust (D-074). The corpus runners live in
`@ainra/sdk/conformance` only: since 0.7.0 the package root no longer exports them (0.6.0 kept them there,
deprecated).
`Verifier.verify` takes a `PresentedBundle`: the fields a vector uses to pin policy are typed as ignored.

## Don't take our word for it

This SDK is one of **four independent implementations**: a Rust core, this one, a Node reference CLI, and a Python
verifier. Three of them (the Rust core, this SDK and the Python verifier) agree on all **1169** conformance vectors,
verdict *and* reason (`make diff`); the CLI is held to them on canonical encoding. The corpus is CC0 and the runner
is language-agnostic, so you can build a fifth and check us:

```sh
git clone https://github.com/JacobJandon/ainra && cd ainra && make conformance
```

The root's honest status — including what has **not** happened yet — is at
[ainra.org](https://ainra.org/) and in the repository's `ROADMAP.md`.

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
