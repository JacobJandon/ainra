<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Becoming a registrar: the path, one page

For an organisation that already vets companies and issues credentials. A registrar issues agent passports to its own
customers, who may move to another registrar with their history. The root accredits registrars and never issues one
([the Standard](../AINRA_I_The_Standard.md), §0.5 and Part I §1). Run everything from a clone of this repository.

## 1. Run a registrar: issue, renew, revoke

On your own machine. No root is involved: the registrar checks its passports against its own keys, and nothing it
issues is valid anywhere else. A new directory and an unused id leave any registrar you made before untouched.

```sh
DIR=my-registrar-42 ID=registrar-42 make issue-first    # a new registrar and one passport, verified
ainra=./target/release/ainra
$ainra renew my-registrar-42 ainra:registrar-42:acme:assistant@1.0.0 --version 1.0.1
$ainra revoke my-registrar-42 ainra:registrar-42:acme:assistant@1.0.1
$ainra list my-registrar-42
```

```
issued ainra:registrar-42:acme:assistant@1.0.0
reissued ainra:registrar-42:acme:assistant@1.0.1 (renewal of ainra:registrar-42:acme:assistant@1.0.0)
revoked ainra:registrar-42:acme:assistant@1.0.1 — signed delta seq 0 → 1
ainra:registrar-42:acme:assistant@1.0.0      L2    A2    0     revoked  INVALID (revoked)
ainra:registrar-42:acme:assistant@1.0.1      L2    A2    0     revoked  INVALID (revoked)
```

Real output, trimmed. Revocation covers the whole lineage, so the passport the renewal replaced is refused too. It
cannot be undone: to run this section again, delete `my-registrar-42` first.

## 2. The checks the root runs before it accredits

Accreditation starts as a request signed with your registrar's own keys. The checks are code; run them yourself:

```sh
$ainra accredit my-registrar-42 > accreditation.json    # your public keys, as the directory would list them
$ainra directory request ACCREDIT --registrar my-registrar-42 --filed-at $(date +%s) --test-root --out acc.json
$ainra directory check-request acc.json --accreditation accreditation.json \
  --directory site/net/directory.json --roots site/net/roots.json    # against the published test directory
```

```
REFUSED [prerequisites] ACCREDIT of a new registrar lacks the Standard §3 prerequisite(s), each as a named file and its SHA-256: the signed identical agreement, the independence attestation, the funded competitor monitor, the audit with its date
```

No request passes that yet: there is no agreement to sign before a legal entity exists. The full list of checks is
[ACCREDITATION-CHECKS.md](../ACCREDITATION-CHECKS.md). In short: the request is for the test root; a new registrar's
keys are complete, match what it serves at `/accreditation` and each sign the request; and four documents are named by
SHA-256 (the identical agreement, an independence attestation, a funded monitor of a competitor, a dated audit).

Not built yet: the live checks of your endpoints. They will use the compliance probe (`kits/probe`), which
`make probe-drill` proves against one honest and five dishonest local registrars. Once a root exists, a request that
passes goes into a public proposal that only a ceremony signs. `make sign-epoch-rehearsal` runs that on a test root.

## 3. The fees, as they stand

- **Per lineage:** at most USD 0.10 a year, paid by the registrar to the root. It may only stay flat or fall
  ([D-077](../DECISIONS.md), accepted 2026-11-06).
- **Accreditation:** a flat fee, identical for every registrar. **Its amount is not set.**
- Checking a passport is free, and an unpaid fee never changes a verdict (D-094, item 15). Nothing is charged until a
  root exists.

## 4. What is true today

- **A test network:** two placeholder registrars, `registrar-07` and `registrar-11`, run by the project under a test
  root. No trust moves from it to a production root.
- **No organisation accredited, no production root, no ceremony date,** and no custodian named
  ([GOVERNANCE.md](../../GOVERNANCE.md)).
- **No legal entity,** so there is no agreement to sign, and its text is not written yet. Its terms so far are what the
  Standard §3 asks of every registrar and D-094 items 10 and 11 (a probe term; a 30-day cure window).

## 5. How to say you are interested

Write to [info@ainra.org](mailto:info@ainra.org): which organisation you are and where it is registered, what you
already verify about a company before you issue it a credential, and a contact for the reply. A reply is not an
accreditation, and nothing on this page commits you or the project.
