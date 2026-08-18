<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# AINRA External Verifier Kit

> **`@ainra/sdk` is not published to a registry yet.** The published-SDK route below will fail with
> `E404` until it is. Use the in-repo route (`git clone` + `make verifier-kit-smoke`), which needs no
> registry at all. Publishing is prepared and parked on the maintainer's credentials — see
> [docs/_archive/plans/PLAN-M26.md](../../docs/_archive/plans/PLAN-M26.md) § PARKED.

Become **independent verifier #N**. In under 10 minutes, on your own machine, you prove — using **only the published
`@ainra/sdk`** — that AINRA's core promise holds: a genuine agent passport verifies with the **root offline**, a
revoked one is rejected, and a *forged* all-clear status can't un-revoke it. Then you verify a **fresh challenge
corpus** the maintainer minted for you, and emit a **signed attestation** we can count as evidence **without trusting
your word** — and, critically, **that a party who never ran a verifier cannot fabricate**.

This kit imports nothing but `@ainra/sdk` (its public `Verifier`) and Node built-ins. No internal AINRA crates, no
network calls (when run against local artifacts), **no telemetry**.

## Same afternoon: the conformance programme

If you're wrapping your own AINRA verifier (not just running `@ainra/sdk`), the challenge attestation here is the same
motion as **self-attesting conformance**. The [conformance programme](../../docs/conformance/PROGRAMME.md) publishes the
full corpus + a language-agnostic runner: point it at your implementation, get a signed, re-runnable report, and anyone
can re-check it — *no root certifies anyone*. Running conformance and returning a challenge attestation is a single
documented afternoon: same signing mechanism (`ssh-keygen -Y`), same "trust the re-run, not a badge" principle. Start
with `make conformance` and `tools/conformance/CONTRACT.md`.

## Why a "challenge corpus" (and not just a nonce)

The three sample checks below run against a **static, published** corpus whose correct verdicts are public. So an
attestation that merely reports them proves *agreement*, not *execution*: anyone who knows the public answers could
assert them without running anything. (An earlier version of this kit over-claimed here — see `DECISIONS.md` D-024.)

To make the attestation actually require verification, the maintainer hands you a **fresh challenge corpus**: `K`
bundles whose revocation state is a **secret coin flip**, minted just for your challenge and **never published**. You
verify each one root-dark and report your verdicts. You can only report the correct set **by verifying** — a party who
guesses succeeds with probability `2^-K`. The maintainer checks your verdicts against a **private answer key** you
never see.

## Quickstart (≤ 10 min)

Requires Node 18+ (built-in `crypto`, `zlib`). The maintainer sends you **(1)** a single-use challenge **nonce**, and
**(2)** a `challenge/` directory (`directory.json`, `roots.json`, `challenge.json`, and `K` `bundle-*.json`). From this
directory:

```sh
npm install                                                          # installs @ainra/sdk (see the note below)
node verify-kit.mjs --challenge <NONCE> --challenge-dir /path/to/challenge
```

You'll see the three sample checks, then the execution binding — verdicts on the fresh bundles:

```
✓ genuine passport (root dark) → valid
✓ revoked passport             → invalid:revoked
✓ forged all-clear status      → invalid:stale_status
execution binding — verifying 8 FRESH challenge bundles root-dark (nonce …):
  · bundle-0.json → valid
  · bundle-1.json → invalid:revoked
  …
✓ wrote a signed EXECUTION-BOUND attestation → verifier-attestation.json
```

Then send us `verifier-attestation.json`. We confirm it **without trusting you** — the decisive gate is that your
fresh-bundle verdicts match the private answer key:

```sh
node check-attestation.mjs --attestation verifier-attestation.json --challenge <NONCE> --secret <answer-key.json>
# → ATTESTATION VALID (EXECUTION-BOUND) — correctly verified K fresh bundles whose answers we never published
```

`--secret` is **required** — without the answer key, execution cannot be checked and the collector refuses to certify
(fail closed). Running `verify-kit.mjs` **without** `--challenge-dir` produces a *conformance-only* attestation that is
explicitly marked non-counting.

**What a pass proves — and doesn't.** It proves a party holding key *K*, answering the challenge we issued, **correctly
verified `K` fresh bundles whose answers we never published** — i.e. they **actually performed AINRA verification**
(not merely asserted public constants). It does **not** prove they used our exact `@ainra/sdk` *binary* vs. a
conformant reimplementation, and a fresh keypair is free so it is **not** Sybil-proof. Operator distinctness is
established **out of band**: we mint **one** challenge per separately-vetted party. See **SECURITY.md** and
`GENESIS-CHECKLIST.md §3`.

### Installing the published SDK
The bundled `package.json` uses a local path dependency so the kit runs inside this repo. As a stranger, replace it
with the published package and reinstall:

```json
"dependencies": { "@ainra/sdk": "^0.3.3" }
```

## What the three sample checks mean
- **Genuine, root dark** — the verifier holds only the signed **directory** + the two **root public keys** (never a
  root secret). It verifies a real passport → `valid`. This is the §29 "outsider verifies from public artifacts".
- **Revoked** — the same passport after revocation → `invalid` with reason `revoked` (the status list, authenticated
  against the registrar's key, has its bit set).
- **Forged all-clear** — we take the revoked bundle and rewrite its status bitmap to "nobody revoked", re-stamped
  fresh, *without* re-signing. A conformant verifier rejects it → `invalid:stale_status`. If your SDK returned
  `valid` here, that would be a revocation bypass — the kit fails loudly and writes no attestation.

These are a **demonstration** of the core promise; the fresh challenge corpus is what makes your attestation *evidence*.

## For maintainers: minting a challenge
`mint-challenge.mjs` is the maintainer's side (it needs a running `registrar-box`; `tools/verifier-kit-smoke.sh` shows
the full flow):

```sh
node mint-challenge.mjs --registrar <url> --now <unix> --count 8 --out ./challenge --secret ./answer-key.json --nonce <NONCE>
```

It issues `K` fresh lineages, revokes a **secret** random subset, records the ground-truth verdicts (with the real SDK)
into `answer-key.json` (**keep private**), and writes the public `./challenge` you hand the verifier. Use a `K` large
enough that `2^-K` is negligible for your bar (8 → 1/256; 16 → 1/65536).

## The attestation (what we collect)
`verifier-attestation.json` is `{body, sig_ed25519_b64}` whose `body` records: the **challenge** nonce, an
`execution_bound` flag, your **Ed25519 public key**, the SHA-256 of the sample corpus, your sample **verdicts**, and —
the evidence — the **hashes of the fresh challenge corpus** and your **per-bundle verdicts** on it. The signature
covers the **whole body** (recursive canonical JSON — nested objects included). `check-attestation.mjs` verifies the
signature, confirms the challenge matches the answer key, requires the sample corpus complete + byte-matching, and —
decisively — requires the challenge corpus byte-identical to what we minted **and every fresh-bundle verdict to equal
the private answer key**. `K` separately-vetted strangers producing `K` execution-bound attestations from `K` machines
satisfies the §29 "≥3 external verifiers" bar — with no trust in any of them, and no way to fake having verified.

See **SECURITY.md** for how to run this isolated.
