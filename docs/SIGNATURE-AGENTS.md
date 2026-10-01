<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Signature agents and AINRA: one request, two readers

If you already sign your agents' requests as a **signature agent**, you can keep doing exactly that and add an AINRA
signature beside it. This applies to the Web Bot Auth profile of RFC 9421: Ed25519 keys published at
`/.well-known/http-message-signatures-directory`, and `tag="web-bot-auth"`. Each verifier reads its own signature
and ignores the other. Nothing about your existing setup changes (D-070).

## What each signature says

| | The signature agent's (`sig1`) | AINRA's (`ainra`) |
|---|---|---|
| **Who signs** | the operator's key, from its directory | one running copy's instance key, under a passport |
| **What it binds** | `@authority` and its `signature-agent` member, plus whatever else the operator covers | method, authority, path, body digest, and the presentation |
| **What a verifier learns** | "this operator signed a request for this site" | "this running copy of this passport signed this exact request, and the passport is not revoked" |
| **Revocation** | none in the profile: the operator removes the key, and each verifier sees that on its next directory refresh | the passport's status bit, checked on every request; a status snapshot counts only within the verifier's freshness class (F2 ≤ 5 min by default) |

## Sign with both

The order doesn't matter. Each signer adds its own member to `signature-input` and `signature`, and neither
overwrites the other. `signPresentation` in `@ainra/sdk` appends to whatever the request already carries:

```ts
// 1. the operator signs as it always has (any RFC 9421 signature-agent library), adding sig1 to the fields
// 2. the running copy appends its own member
Object.assign(headers, await signPresentation({
  req: { method, authority, path, headers }, keyid: credential.iid, nonce, created: now, instanceSign,
}));
// signature-input: sig1=("@authority" "signature-agent";key="sig1");…;tag="web-bot-auth", ainra=("@method" …)
```

`signPresentation` refuses a request that already has an `ainra` member, or only half of another signature. It
won't overwrite either.

## Verify both

Each verifier verifies only its own label. The AINRA gates (`@ainra/middleware`, `@ainra/edge`, the Python
`AinraGate`) read only `ainra`:

- **Only the operator signed:** AINRA answers `presentation_unsigned`.
- **The operator's signature is broken:** AINRA's answer doesn't change.

To require both, run both verifiers. The order of the two checks is up to the site's own policy.

## Optional: the operator covers AINRA's signature

An operator that signs after the running copy can cover AINRA's signature. Section 5.2.2 of the profile requires
it to cover the union:

- `"signature-input";key="ainra"`
- `"signature";key="ainra"`
- every component AINRA covered.

This is evidence that AINRA's signature was present on that message. AINRA doesn't need it and doesn't read it.

## What AINRA doesn't do

It doesn't verify, interpret or vouch for the operator's signature, and it doesn't check the shape of other
members' contents. It only checks that the fields split cleanly into members, so it can find its own.

## Proof

- **`make signature-agent-check` (offline, in CI).**
  - An independent open-source signature-agent verifier, pinned in `kits/signature-agent`, verifies the operator's
    signature in every conformance vector that carries one.
  - AINRA's answer on the same request stays the recorded one.
  - Negative control: one byte flipped in each operator signature, and every one is refused.
- **`make signature-agent-e2e` (needs `make live-up`).** Both signatures on live requests, read by both verifiers,
  through the Node middleware and the edge gate.
  - After the passport is revoked, a request the operator signed is refused by AINRA as `revoked`, while the
    operator's signature still verifies.
  - The operator's key, once withdrawn, keeps verifying until the directory is fetched again.

Test root only. The drill serves the directory over http on 127.0.0.1; in deployment the profile requires https.
