<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# AINRA External Verifier Kit

Become **independent verifier #N**. In under 10 minutes, on your own machine, you prove — using **only the published
`@ainra/sdk`** — that AINRA's core promise holds: a genuine agent passport verifies with the **root offline**, a
revoked one is rejected, and a *forged* all-clear status can't un-revoke it. You emit a **signed attestation** we can
count as evidence **without trusting your word**.

This kit imports nothing but `@ainra/sdk` (its public `Verifier`) and Node built-ins. No internal AINRA crates, no
network calls (when run against local artifacts), **no telemetry**.

## Quickstart (≤ 10 min)

Requires Node 18+ (built-in `crypto`, `zlib`). First, **ask the maintainer for a `CHALLENGE`** — a single-use nonce
they issue to you personally (e.g. `a1b2c3…`). Your attestation is bound to it, so it can't be pre-manufactured or
replayed. From this directory:

```sh
npm install                              # installs @ainra/sdk (see the note below for the published package)
node verify-kit.mjs --challenge <NONCE>  # verifies the bundled sample-artifacts/ and writes verifier-attestation.json
```

You'll see three checks, all of which must pass:

```
✓ genuine passport (root dark) → valid
✓ revoked passport             → invalid:revoked
✓ forged all-clear status      → invalid:stale_status
✓ wrote a signed attestation → verifier-attestation.json
```

Then send us `verifier-attestation.json`. We (or anyone) confirm it **without trusting you** — the maintainer re-runs
the check with the *same* nonce they issued:

```sh
node check-attestation.mjs --attestation verifier-attestation.json --challenge <NONCE>
# → ATTESTATION VALID — genuine external-verifier result
```

**What the attestation proves — and doesn't.** A valid attestation proves a party holding key *K* ran the real
`@ainra/sdk` against the *complete* canonical corpus and answered the nonce we issued: **execution + freshness +
tamper-evidence**. A fresh keypair is free, so the cryptography alone is *not* Sybil-proof — it can't prove you're a
distinct person. Operator distinctness is established **out of band**: we issue **one** challenge per separately-vetted
party. See **SECURITY.md** and `GENESIS-CHECKLIST.md §3`.

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
node verify-kit.mjs --artifacts /path/to/artifacts --now $(date +%s) --challenge <NONCE> --out my-attestation.json
```

## The attestation (what we collect)
`verifier-attestation.json` is a JSON `{body, sig_ed25519_b64}` where `body` records: the **challenge** we issued you,
your **Ed25519 public key**, the **SHA-256 of every artifact** you verified, your **verdicts**, the **SDK version**,
and a **timestamp**. The Ed25519 signature covers the **whole body** (recursive canonical JSON — nested objects
included). `check-attestation.mjs` verifies that signature under your key, confirms the challenge is the exact nonce we
issued, requires **every** artifact in the canonical set to be present and byte-matching (an empty or partial corpus
fails closed), rejects any extra artifact, and confirms the verdicts. Three separately-vetted strangers producing
three challenge-bound attestations from three machines satisfies the §29 "≥3 external verifiers" bar — with no trust in
any of them (distinctness comes from the one-challenge-per-party issuance, not the crypto).

See **SECURITY.md** for how to run this isolated.
