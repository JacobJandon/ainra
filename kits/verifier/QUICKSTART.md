<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Become external verifier #N — 10-minute quickstart

You will independently confirm that AINRA's core promise holds — a genuine passport verifies with the **root offline**,
a revoked one is rejected, a forged all-clear can't un-revoke it — and then verify a **fresh challenge** only you were
given, proving you *actually ran* a verifier. You send back one signed file. **No data leaves your machine**; you talk
to no one but the maintainer who hands you a challenge.

## 0. Prerequisites (2 min)
- **Node 18+** (built-in `crypto`, `zlib` — nothing else).
- The **`@ainra/sdk`** package (the only dependency). Inside this repo it's wired to the local build; as an outsider,
  set `"@ainra/sdk": "^0.1.0"` in `kits/verifier/package.json` and `npm install`.

## 1. Get a challenge from the maintainer (1 min)
Ask the AINRA maintainers to **mint you a challenge**. They send you a folder — call it `challenge/` — containing
`challenge.json`, `directory.json`, `roots.json`, and several `bundle-*.json`. They keep a private *answer key* you
never see. (One challenge is minted per verifier; that's what makes your attestation count as a *distinct* one.)

> Why a challenge and not just "verify the samples"? The bundled samples are public and their correct verdicts are
> public — reporting them proves agreement, not that you ran anything. The challenge bundles were revoked (or not) by a
> **secret coin flip**, so the only way to report the right answers is to actually verify. See `SECURITY.md`.

## 2. Run one command (2 min)
From the repo root:

```sh
make verify-as-external CHALLENGE=/path/to/challenge
```

(or directly: `node kits/verifier/verify-kit.mjs --challenge <NONCE> --challenge-dir /path/to/challenge`). You'll see
the three sample checks pass, then a verdict printed for each fresh bundle, then:

```
✓ wrote a signed EXECUTION-BOUND attestation → verifier-attestation.json
```

## 3. Send back `verifier-attestation.json` (1 min)
That one file is all that leaves your machine. It contains your public key, the artifact hashes, your verdicts, and a
signature — no private data. The maintainer confirms it **without trusting you**:

```sh
node kits/verifier/check-attestation.mjs --attestation verifier-attestation.json --challenge <NONCE> --secret <answer-key>
# → ATTESTATION VALID (EXECUTION-BOUND) — correctly verified K fresh bundles whose answers we never published
```

## Try the whole loop yourself first (optional)
Want to see both sides end-to-end before you're issued a real challenge? This stands up a throwaway registrar, mints a
challenge, verifies it, and collects the attestation — all locally:

```sh
make verifier-kit-smoke
```

## What a pass proves — and what it doesn't (read this)
A valid **execution-bound** attestation proves a party holding your key, answering the challenge you were issued,
**correctly verified `K` fresh bundles whose answers were never published** — i.e. you actually *performed* AINRA
verification (not merely asserted public constants). It does **not** prove you ran our exact `@ainra/sdk` *binary* (a
conformant reimplementation would also pass) and it is **not** Sybil-proof (a fresh key is free). Your *distinctness*
as an operator is established out of band — the maintainer mints **one** challenge per separately-vetted person. This
is the honest scope from `DECISIONS.md` D-024; nobody should claim more from it.

Stuck? See **TROUBLESHOOTING.md**. Running it isolated? See **SECURITY.md**.
