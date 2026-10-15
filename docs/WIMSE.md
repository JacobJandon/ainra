<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# AINRA beneath WIMSE (D-076)

The IETF's agent-identity work is built on workload identity. `draft-ietf-wimse-aims` (agent identity, Informational,
-00, September 2026) takes two WIMSE drafts as its building blocks:

- **`draft-ietf-wimse-workload-creds`** (-02): a short-lived *Workload Identity Token* (WIT). It is a JWT with
  `typ: wit+jwt`. Its `sub` names the workload (`wimse://<trust domain>/<path>`) and `cnf.jwk` binds the workload's key.
- **`draft-ietf-wimse-http-signature`** (-07): the workload signs each HTTP request with RFC 9421, using the tag
  `wimse-workload-to-workload`.

Two things are left open there. AINRA supplies both.

| WIMSE says | AINRA supplies |
|---|---|
| Each trust domain must be bound to its authorized issuer keys "via a secure out-of-band mechanism". It does not say which. | The passport. Its key is certified by an accredited registrar and recorded in a public log. A verifier checks both offline. |
| No revocation. "A short expiration is the primary mitigation." | The registrar-signed status list. A revoked passport is refused within the verifier's freshness class (F1: 30 s), whatever its tokens say. |

## The mapping

| AINRA | WIMSE |
|---|---|
| passport `ainra:registrar-07:acme:invoicing@1.0.0` | trust domain `invoicing.acme.registrar-07.ainra.org` |
| the passport's key (`keys[0]`, the one ADR-019 signs instance credentials with) | the trust domain's authorized WIT issuer key |
| one running copy, `i-0f3a2b71` | workload `wimse://invoicing.acme.registrar-07.ainra.org/i-0f3a2b71` |
| the copy's own key | `cnf.jwk` in its WIT |

AINRA labels are already DNS host labels (1–63 characters of `[a-z0-9-]`, never starting or ending with a hyphen).
So every passport name gives a valid trust domain, and nobody has to register one.

## Use it

On the side that holds the passport key, mint a WIT for each running copy. Never do this inside the container:

```js
import { mintWit } from "@ainra/sdk";
const wit = await mintWit({
  passportClaimsB64: bundle.claims, iid: "i-0f3a2b71", instanceEd25519Public, now,
  controlSignEd25519: (msg) => signWithThePassportKey(msg),   // the Ed25519 half of it
});
```

In the running copy, sign each request:

```js
import { signWimseRequest } from "@ainra/sdk";
const headers = await signWimseRequest({
  req: { method, authority, path, headers: { "content-type": "application/json" }, body },
  wit, audience: "https://ledger.example/entries", nonce, created: now,
  instanceSignEd25519: (msg) => signWithTheCopysKey(msg),
});
// sets Workload-Identity-Token, Signature-Input, Signature (and Content-Digest when there is a body)
```

A service that speaks WIMSE and has never heard of AINRA accepts this request. It needs this trust domain's issuer key,
which is the passport's key. An AINRA-aware service also verifies the passport:

```js
import { Verifier, verifyWimseRequest } from "@ainra/sdk";
const verifier = Verifier.fromDirectoryB64(directory, rootEd25519, rootSlh, "F1", false, AUDIENCE);
const r = verifyWimseRequest({ req, verifier, bundle, audience: AUDIENCE, now, seenNonce });
// { ok: true, sub: "wimse://…/i-0f3a2b71", nonce } or { ok: false, reason: "revoked" | "stale_status" | … }
```

The checks run in this order:

1. **The passport.** Registrar signature, log inclusion and the authenticated status list are checked under the
   verifier's own clock and freshness class. A revoked passport stops here.
2. **The WIT.** It must be `wit+jwt` and EdDSA, signed by the passport's key. Its `sub` must be inside the passport's
   trust domain. It must be unexpired and at most an hour long. Its `cnf.jwk` must be an EdDSA Ed25519 key.
3. **The request signature.** It is found by its tag, and a second tagged signature is refused. It must cover
   `@method`, `@path` and `@query`, plus every listed header that is present. `wimse-aud` must equal this service.
   It must expire within minutes and must not carry `keyid` or `alg`. The `Content-Digest` must match the body.
4. **The nonce.** It is checked last, and only once everything above holds.

Refusals reuse AINRA's existing reason names: `presentation_*` for the request, and `instance_sig_invalid` and
`instance_expired` for the WIT. Another signer's signature on the same request is left to its own verifier (D-070).

The bundle reaches the service the usual way: sent once, then named by its digest (D-065).

## What is proven, and how

| | Command | What it proves |
|---|---|---|
| Unit | `cd packages/sdk-ts && npm test` | The positive case, plus one refusal for each check. The passport step uses the real gate corpus: g02, a revoked passport, is refused `revoked` although its WIT and signature are perfect. |
| Interop (CI) | `make wimse-check` | Both directions, against independent open-source JOSE and RFC 9421 libraries pinned in `kits/wimse/package-lock.json`. Their verifier accepts AINRA's tokens and signatures, and AINRA accepts theirs. `--negative` tampers with each one, and every tampered request must be refused. |
| Live | `make wimse-e2e` (after `make live-up`; also part of `make live-drills`) | At the real clock, a WIMSE-only verifier and AINRA read the same requests. After revocation, AINRA refuses the copy's current passport at once and its old all-clear snapshot after 30 s. The WIMSE-only verifier keeps accepting until the WIT expires, up to an hour. |

## Said plainly

- **Ed25519 only at this layer.** WIMSE's JOSE world has no hybrid post-quantum signature, so the WIT and the request
  signature use the Ed25519 half of the passport's hybrid key. The passport chain beneath stays hybrid. The AINRA
  instance credential (ADR-019) remains the post-quantum path for running copies.
- **The old snapshot.** A copy that keeps presenting its pre-revocation status list is refused once that list is older
  than the verifier's freshness class. Choose F1 for hot paths. This is the bound AINRA has always stated.
- **The drafts move.** This follows workload-creds -02 and http-signature -07. Response signing (`wimse-sign-response`)
  and transaction tokens are not implemented.
- **TEST-ROOT.** It proves the mechanism. It is not evidence that anyone deploys it.
