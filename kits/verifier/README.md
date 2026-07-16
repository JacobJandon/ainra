<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# AINRA External Verifier Kit

Become **independent verifier #N**. In under 10 minutes, on your own machine, you prove — using **only the published
`@ainra/sdk`** — that AINRA's core promise holds: a genuine agent passport verifies with the **root offline**, a
revoked one is rejected, and a *forged* all-clear status can't un-revoke it. You emit a **signed attestation** we can
count as evidence **without trusting your word**.

This kit imports nothing but `@ainra/sdk` (its public `Verifier`) and Node built-ins. No internal AINRA crates, no
network calls (when run against local artifacts), **no telemetry**.

## Quickstart (≤ 10 min)

Requires Node 18+ (built-in `crypto`, `zlib`). From this directory:

```sh
npm install          # installs @ainra/sdk (see the note below for the published package)
node verify-kit.mjs  # runs against the bundled sample-artifacts/ and writes verifier-attestation.json
```

You'll see three checks, all of which must pass:

```
✓ genuine passport (root dark) → valid
✓ revoked passport             → invalid:revoked
✓ forged all-clear status      → invalid:stale_status
✓ wrote a signed attestation → verifier-attestation.json
```

Then send us `verifier-attestation.json`. We (or anyone) confirm it without trusting you:

```sh
node check-attestation.mjs --attestation verifier-attestation.json
# → ATTESTATION VALID — genuine external-verifier result
```

### Installing the published SDK
The bundled `package.json` uses a local path dependency so the kit runs inside this repo. As a stranger, replace it
with the published package and reinstall:

```json
"dependencies": { "@ainra/sdk": "^0.1.0" }
```

## What the three checks mean
- **Genuine, root dark** — the verifier holds only the signed **directory** + the two **root public keys** (never a
  root secret). It verifies a real passport → `valid`. This is the §29 "outsider verifies from public artifacts".
- **Revoked** — the same passport after revocation → `invalid` with reason `revoked` (the status list, authenticated
  against the registrar's key, has its bit set).
- **Forged all-clear** — we take the revoked bundle and rewrite its status bitmap to "nobody revoked", re-stamped
  fresh, *without* re-signing. A conformant verifier rejects it → `invalid:stale_status`. If your SDK returned
  `valid` here, that would be a revocation bypass — the kit fails loudly and writes no attestation.

## Running against a LIVE registrar (the real external run)
Point the kit at any directory holding a registrar's published `directory.json` + `roots.json` + a `bundle-*.json`
(e.g. output of `make genesis-local`, or fetched from a registrar's `/present` + a mirror's directory), and pass the
current time:

```sh
node verify-kit.mjs --artifacts /path/to/artifacts --now $(date +%s) --out my-attestation.json
```

## The attestation (what we collect)
`verifier-attestation.json` is a JSON `{body, sig_ed25519_b64}` where `body` records: your **Ed25519 public key**,
the **SHA-256 of every artifact** you verified, your **verdicts**, the **SDK version**, and a **timestamp**;
`check-attestation.mjs` verifies the signature under your key, recomputes the artifact hashes against the canonical
published set, and confirms the verdicts. Three independent strangers producing three valid attestations from three
machines satisfies the §29 "≥3 external verifiers" bar — with no trust in any of them.

See **SECURITY.md** for how to run this isolated.
