<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Conformance quickstart — prove your own implementation conformant

The root does **not** certify implementations — it makes certification unnecessary. It publishes the **conformance
corpus** (`vectors/`, CC0) and a **language-agnostic runner**
(`tools/conformance/`), and certifies no one. You point the runner at your own verifier, prove conformance
*yourself*, and anyone else re-runs it and checks. **Trust the re-run, not a badge.** The full doctrine + the three
roles (root / implementer / re-checker) are in [`docs/conformance/PROGRAMME.md`](../conformance/PROGRAMME.md).

## The runner contract (one paragraph)

Your implementation is an executable. The runner invokes it once per corpus part with the **kind**
as the last argument, streams that part's vectors to **stdin** as JSON Lines (one
published vector per line), and reads one `<name>\t<result-json>` line per vector from **stdout** — no files, no
network. This is the shape every AINRA surface already emits, so an existing verifier needs only a thin wrapper
(see `tools/conformance/adapters/`). The full contract is
[`tools/conformance/CONTRACT.md`](../../tools/conformance/CONTRACT.md):

| kind | result JSON |
|---|---|
| `passport` | `{"verdict":"valid"}` or `{"verdict":"invalid","reason":"<reason>"}` |
| `delta` | `{"accept":true}` or `{"accept":false,"reason":"<reason>"}` |
| `directory` | `{"accept":true,"registrars":<n>}` or `{"accept":false}` |
| `presentation`, `gate`, `link`, `decision`, `directory-epoch` | the shape that corpus records in `expect` ([CONTRACT.md](../../tools/conformance/CONTRACT.md)) |

Those last five are profile **`full`** (the default): what a gate decides, including status only if the registrar
signed it. Profile **`core`** (`--profile core`) is the first three, contract v1; it is still a valid claim, but a
verifier that believes the presenter's status passes it (D-072, D-084), so it is not the claim a gate needs.

## Run it, then attest it

```sh
node tools/conformance/run.mjs --impl "<your command>" --name <your-impl> --version <ver> --out report.json
```

The runner drives the profile's corpora (`full` by default, `--profile core` for v1's three), pins the exact vector set with a `corpus_hash` (a trimmed or empty corpus fails
the count guard and can never pass vacuously), and writes a machine-readable report — pass/fail per vector, `expected`
vs `got` for every divergence, totals. Then **self-attest** by signing the result with **your own** SSH key
(`ssh-keygen -Y` — the same mechanism as AINRA release signing, but *your* key, never the root's). The only truthful
claim is *"self-attested conformant, re-runnable"*, never "AINRA-certified"; anyone re-runs the corpus and checks, and
the substance is the re-run, not who signed.

`make conformance` proves the whole loop **both ways** — the three in-repo impls pass clean, a deliberately broken one
is caught with named divergences, and the self-attestation round-trips:

```
clean adapters (must PASS, full corpus, 0 divergences):
  ainra-core       passport 1169/1169  delta 17/17  directory 9/9  divergences=0  → PASS
  ainra-sdk-ts     passport 1169/1169  delta 17/17  directory 9/9  divergences=0  → PASS
  ainra-sdk-py     passport 1169/1169  delta 17/17  directory 9/9  divergences=0  → PASS
broken adapter (must FAIL with named divergences):
    ✓ broken adapter correctly FAILED — 66 named divergence(s)
  ✓ conformance OK — runner passes the 3 real impls clean, catches the broken one, attestation round-trips.
```

A conformance tool that cannot fail is theatre; this one demonstrably fails on nonconformance. Because running the
corpus and signing the result is a single documented afternoon, it is the **same motion** an external verifier makes
for the genesis Definition-of-Done challenge ([`kits/verifier/`](../../kits/verifier/)): run conformance, sign, hand
it back.
