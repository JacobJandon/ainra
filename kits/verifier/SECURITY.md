<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Running the Verifier Kit safely

The whole point of AINRA is *verify, don't trust* — including not having to trust this kit or its authors. Here is
how to run it in isolation and confirm it behaves.

## It is offline and silent by design
- Run against local `--artifacts` and the kit makes **zero network calls** — it reads files, calls the SDK, writes
  one attestation. There is **no telemetry, no phone-home**, in the kit or in `@ainra/sdk` (verify: `grep -rIn
  "fetch\|http\|net\|telemetry\|analytics" verify-kit.mjs check-attestation.mjs` finds nothing).
- The only time the kit touches the network is if *you* pass a remote `--artifacts`/URL to fetch a live registrar's
  published files — that's your choice, over plain HTTPS, to a host you pick.

## Run it isolated
- Use a throwaway container or VM with no inbound ports and only outbound HTTPS if you fetch live artifacts:
  ```sh
  # example: a disposable container, no secrets mounted (NONCE = the challenge the maintainer issued you)
  docker run --rm -v "$PWD":/kit -w /kit node:22-alpine sh -c 'npm install && node verify-kit.mjs --challenge <NONCE>'
  ```
- Nothing here needs root, secrets, or your real identity. The signing key is a **fresh throwaway** Ed25519 key
  generated per run; if you want a stable verifier identity across runs, keep your key material outside the container
  and adapt the kit to load it — never commit it.

## Verify what you install
- Pin `@ainra/sdk` to a known version and check its integrity (`npm install` records a lockfile hash). The SDK's
  behaviour is itself checkable: it is byte-differential-tested against the Rust core over the public CC0 vectors
  (`make diff` in the main repo), so "does my SDK agree with the spec" is answerable without trusting us.

## What a valid result proves (and doesn't)
- A passing **execution-bound** run (`--challenge-dir` + the maintainer's `--secret` answer key) proves that a party
  holding key *K*, answering the challenge we issued, **correctly verified `K` fresh bundles whose revocation state we
  never published** — i.e. they actually *performed* AINRA verification, root dark. Because the answers were a secret
  coin flip, a party who did not verify must guess all `K` (success `2^-K`). It does **not** ask you to trust our
  infrastructure: the challenge corpus is hashed into your attestation and we re-check it against exactly what we minted.
- Precise limits, stated plainly (an earlier version of this kit over-claimed "the cryptography enforces execution" —
  corrected, see the main repo `DECISIONS.md` D-024):
  - It does **not** prove you ran our exact `@ainra/sdk` *binary* — a conformant reimplementation that computes the
    correct verdicts would also pass. What it proves is that *some* correct AINRA verification was performed on inputs
    you could not have precomputed. (Binding the specific binary would need TEE/ZK attestation — out of scope here.)
  - It does **not** prove you are a *distinct* person. A fresh Ed25519 key is free, so the crypto cannot be Sybil-proof.
    Distinctness is out of band: the maintainer mints **one** challenge per separately-vetted party.
  - A *conformance-only* attestation (no `--challenge-dir`) proves only agreement on the public sample verdicts and is
    explicitly marked non-counting; the collector refuses to certify it, and refuses to certify at all without `--secret`.
- If any check fails, the kit exits nonzero and writes **no** attestation. A failure is a finding — please report it
  (see the main repo's `SECURITY.md`).

## Reporting
Security issues in AINRA go to the process in the repository root `SECURITY.md`. Fail-closed is the posture: if you
can make a revoked or forged passport verify VALID, that is a critical bug and we want it.
