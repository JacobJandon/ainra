<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Operator runbook — onboard a real external verifier

This is the **maintainer's** side of the highest-leverage pending DoD row: *≥3 independent external verifiers*
(`GENESIS-CHECKLIST.md` §3). You mint a challenge, hand it to a vetted person, and check what they send back — never
trusting their word. Three distinct passes turns that row ✅ on `make genesis-status`.

> Prove the whole loop first, on dry-run parties, with nothing real: `make verifier-operator-drill`.

## One verifier, from cold

**0. Stand up (or point at) the registrar** whose root the party will verify — the live one, or `make genesis-local`
for a rehearsal. You need its `--registrar` URL and a `--now`.

**1. Mint a challenge for the party** (use a stable id, e.g. their handle):

```sh
node kits/verifier/mint-challenge.mjs --registrar <url> --now $(date +%s) --count 8 --party alice
```

This writes, under the **gitignored** `ops-verifier/alice/`:
- `challenge/` — the PUBLIC corpus (directory, roots, `challenge.json`, 8 fresh bundles) to send them;
- `answer-key.json` — the **PRIVATE** answer key. **Never send it, never commit it** (`ops-verifier/` is gitignored;
  the challenge you send contains no answers). Use `--count 16` if you want a smaller forge probability (2⁻¹⁶).

**2. Send them two things:** the `ops-verifier/alice/challenge/` folder (a zip is fine) and the one-pager
[`outreach/EXTERNAL-VERIFIER-CALL.md`](../../outreach/EXTERNAL-VERIFIER-CALL.md). Nothing else.

**3. They run one command** (with only the published `@ainra/sdk`) and send back `verifier-attestation.json`:

```sh
make verify-as-external CHALLENGE=<the folder you sent>
```

**4. Check it — without trusting them** — and write durable evidence:

```sh
node kits/verifier/check-attestation.mjs --attestation <their-file> \
  --challenge <the nonce from ops-verifier/alice/challenge/challenge.json> \
  --secret ops-verifier/alice/answer-key.json --party alice
# → ATTESTATION VALID (EXECUTION-BOUND) … → wrote evidence/verifier/alice.json
```

The decisive gate: their verdicts on your fresh, **never-published** bundles must match your private answer key. A
hand-authored, wrong-key, replayed, or conformance-only attestation is **rejected with a clear reason and writes no
evidence**. On success it writes `evidence/verifier/alice.json` — which carries the attestation + your verdict + a
*hash* of the answer key, **never the key itself**.

**5. Watch the board increment:**

```sh
make genesis-status     # the "≥3 external verifiers" row counts distinct valid evidence files
```

Repeat for three separately-vetted people → the row goes ✅.

## What three passes prove — and don't (verbatim, D-024)

> A valid execution-bound attestation proves a party holding key *K*, answering the challenge you issued, **correctly
> verified `K` fresh bundles whose answers were never published** — i.e. they actually *performed* AINRA verification
> (not merely asserted public constants). It does **not** prove they ran your exact `@ainra/sdk` *binary* (a conformant
> reimplementation would also pass) and it is **not** Sybil-proof (a fresh key is free). Their *distinctness* as an
> operator is established out of band — you mint **one** challenge per separately-vetted person.

So: the crypto enforces *execution + freshness*; **you** enforce *distinctness* by vetting who gets each challenge.
Record who got which challenge out of band. Do not count the same person twice, and do not count `verifier-operator-drill`
dry-run parties — they are labelled `dryrun-*` for exactly that reason.
