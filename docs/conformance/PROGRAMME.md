<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# The AINRA conformance programme

**We don't certify implementations — we make certification unnecessary.**

AINRA is a neutral revocation + conformance layer. A neutral layer that also acted as the *authority* on who is
conformant would not be neutral: it would gatekeep. So the root does the opposite of gatekeeping. It publishes two
things — the **conformance corpus** (`vectors/v1` + `vectors/v1-delta` + `vectors/v1-directory`, CC0) and a
**language-agnostic runner** (`tools/conformance/`) — and certifies no one. Anyone points the runner at their own
implementation and proves conformance *themselves*; anyone else re-runs it and checks. Trust the re-run, not a badge.

This is the same shape as the rest of AINRA: verification is offline and re-derivable, never an appeal to our
authority. A release is trusted because it rebuilds byte-for-byte from source, not because we signed it. An
implementation is conformant because the corpus says so on *your* machine, not because we blessed it.

## The three roles

| role | what they do | what they trust |
|---|---|---|
| **the root** (us) | publish the corpus + the runner; run it on our own reference impls in CI | nothing — it's all re-derivable |
| **an implementer** | run the runner against their impl; **self-attest** their result with **their own** key | their own signature + the runner |
| **anyone else** | re-run the runner against that impl; check the signature + that the result reproduces | the re-run, not the implementer, not us |

No badge implies a root endorsement, because none exists. The truthful thing an implementer may claim is exactly:
**"self-attested conformant, re-runnable"** — meaning *I ran the published corpus against my implementation, it passed,
I signed the result with my key, and anyone can reproduce that in an afternoon.* We never say "AINRA-certified".

## The contract

The full contract is `tools/conformance/CONTRACT.md`. In one paragraph: your implementation is an executable; the runner
invokes it once per corpus part with the **kind** (`passport` | `delta` | `directory`) as the last argument, streams
that part's vectors to **stdin** as JSON Lines (one published vector per line), and reads one `<name>\t<result-json>`
line per vector from **stdout**:

| kind | result JSON |
|---|---|
| `passport` | `{"verdict":"valid"}` or `{"verdict":"invalid","reason":"<reason>"}` |
| `delta` | `{"accept":true}` or `{"accept":false,"reason":"<reason>"}` |
| `directory` | `{"accept":true,"registrars":<n>}` or `{"accept":false}` |

No files, no network — everything is on stdin. This is the shape every AINRA surface already emits
(`docs/PRESENTATION.md`), so an existing verifier needs only a thin wrapper (see `tools/conformance/adapters/`).

## Run it

```sh
node tools/conformance/run.mjs --impl "<your command>" --name <your-impl> --version <ver> --out report.json
```

The runner drives the **full** corpus, records the **corpus hash** (a `sha256` pinning the exact vector set — a
partial/empty corpus fails the count guard and can never pass vacuously), and writes a machine-readable JSON report:
pass/fail per vector, `expected` vs `got` for every divergence, totals. Exit 0 iff the run is clean. The reference
implementations show it green both ways:

```sh
make conformance    # Rust core, TS SDK, Python all pass CLEAN; a broken impl FAILS with named divergences
```

## Attest your result

An attestation is a small **signed statement** binding `{implementation name+version, corpus_hash, report_hash,
result, date}`, signed with **your own** SSH key (`ssh-keygen -Y` — the exact mechanism as AINRA release signing,
D-042, but *your* key, never the root's). Generate one from a clean report:

```sh
ssh-keygen -t ed25519 -f my-conformance-key            # your key; keep the private half offline
node tools/conformance/attest.mjs generate \
     --report report.json --key my-conformance-key --identity you@example.org --out attestation.json
# writes attestation.json, attestation.json.sig, and attestation.json.allowed_signers (publish these three)
```

Publish `attestation.json`, its `.sig`, and your public key (`allowed_signers` line). That's the whole claim:
"self-attested conformant, re-runnable". There is nothing to send us and nothing for us to approve.

## Re-check someone else's attestation

You do **not** trust the implementer and you do **not** trust us. With their attestation + their public key + a way to
run their implementation:

```sh
node tools/conformance/attest.mjs verify \
     --attestation attestation.json --allowed-signers attestation.json.allowed_signers \
     --identity you@example.org --impl "<their command>" [--report their-report.json]
```

`verify` (1) checks the signature (the implementer's key, over the exact statement bytes — a tampered statement or a
forged signature is rejected), (2) optionally confirms their report artifact matches the signed `report_hash`, and
(3) **re-runs the runner** against the named implementation and confirms the fresh `corpus_hash` and `result` match
what was signed. Step 3 is the substance: the claim is accepted because it *reproduced on your machine over the same
corpus*, not because of who signed it. If it doesn't reproduce, it's rejected — fail closed.

## Why this is honest, not a loophole

- **Nothing vacuous passes.** The corpus hash + the count guard mean a stubbed or trimmed corpus is a different corpus,
  visibly, and below-minimum counts fail closed.
- **The tool can fail.** `make conformance` runs a *deliberately broken* implementation and asserts the runner catches
  it with named divergences. A conformance tool that cannot fail is theatre; this one demonstrably fails on nonconformance.
- **No authority is manufactured.** We publish inputs and a runner. Every conclusion — "this impl is conformant" — is
  something you compute, and re-compute, without us.

Because running the corpus and returning a signed attestation is a single documented afternoon, the same motion is the
one an external verifier makes for the genesis Definition-of-Done challenge (`kits/verifier/`, `outreach/`): run
conformance, sign the result, hand it back. Same runner, same signing mechanism, same "trust the re-run" principle.
