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
  # example: a disposable container, no secrets mounted
  docker run --rm -v "$PWD":/kit -w /kit node:22-alpine sh -c 'npm install && node verify-kit.mjs'
  ```
- Nothing here needs root, secrets, or your real identity. The signing key is a **fresh throwaway** Ed25519 key
  generated per run; if you want a stable verifier identity across runs, keep your key material outside the container
  and adapt the kit to load it — never commit it.

## Verify what you install
- Pin `@ainra/sdk` to a known version and check its integrity (`npm install` records a lockfile hash). The SDK's
  behaviour is itself checkable: it is byte-differential-tested against the Rust core over the public CC0 vectors
  (`make diff` in the main repo), so "does my SDK agree with the spec" is answerable without trusting us.

## What a valid result proves (and doesn't)
- A passing run proves *your* SDK, on *your* machine, produced the conformant verdicts on the given artifacts —
  root dark. It does **not** ask you to trust our infrastructure: the artifacts are hashed into your attestation, and
  we re-check those hashes against the canonical published corpus when we collect it.
- If any check fails, the kit exits nonzero and writes **no** attestation. A failure is a finding — please report it
  (see the main repo's `SECURITY.md`).

## Reporting
Security issues in AINRA go to the process in the repository root `SECURITY.md`. Fail-closed is the posture: if you
can make a revoked or forged passport verify VALID, that is a critical bug and we want it.
