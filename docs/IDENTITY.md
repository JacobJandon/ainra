<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Agent identity, in five parts

One word — *identity* — is doing five different jobs in this field, and mixing them is why two projects can both
say "we do agent identity" and mean almost nothing in common. This page separates the five, says plainly which one
AINRA provides at which distance, and ends each part with the command that shows it working. Nothing here has to be
taken on faith; every claim below is something you can run.

---

## 1 · A passport the agent carries

The agent presents **one signed document**, and the document is self-contained: name, lineage, version, operator,
tier, key, and the log position proving it was recorded before it was valid. It is an SD-JWT verifiable credential,
so a holder may disclose one field without revealing the rest.

The name is the address of the identity:

```
ainra:{registrar}:{operator}:{lineage}@{version}
```

The **lineage** is the permanent part — soulbound, non-transferable, the anchor of all history. It is the agent
across every version, every re-issue, and every change of owner; a genuine ownership transfer is a *logged event*
that resets assurance evidence while preserving the record. The **version** is re-certified on material change.

```sh
ainra issue "ainra:registrar-07:acme-corp:invoicing@4.2.1" --operator "Acme Corp" --tier L2
```

---

## 2 · The agent's own identity — not the developer's, not the user's

This is the part most often skipped, and the one that changes what is possible.

In most deployments today an agent acts on **borrowed** identity: the developer's API key, or the signed-in user's
session. Both make the agent itself invisible. You cannot revoke the agent without revoking the human. You cannot
tell two agents of the same developer apart. And when an agent misbehaves, the only name attached to the act is a
person's.

An AINRA passport belongs to the agent:

- the **lineage** is the agent's own and cannot be sold or transferred;
- the **operator** is a *field on* the passport, not the identity itself — the company answers for the agent
  without being the agent;
- the **human** behind it is proven in **zero-knowledge** (authority class A1, backed by a signed consent
  mandate), so accountability exists while the person's data never transits or rests at the root.

That last point is not a configuration choice. *Holds no personal data* is one of the six constitutional
prohibitions in [GOVERNANCE-AMENDMENT.md](../GOVERNANCE-AMENDMENT.md): what is never collected cannot be leaked,
subpoenaed, or sold.

---

## 3 · Attestation, not a lookup

Nothing in AINRA is believed because a server said so.

- Every credential is **signed**, and the registrar's signature chains to the root.
- Signatures are **hybrid Ed25519 + ML-DSA-65, both-or-invalid** — a classical break and a quantum break each
  have to happen before a forgery verifies.
- Presentation rides **HTTP message signatures**: the request signature names the passport key, so the credential
  travels as a proof rather than as a secret to be replayed.
- Verification runs **on the verifier's own machine**. There is no "is this agent real?" endpoint to call, by
  design — the facts that change (the status list, the fresh head, the delta stream) are *signed artifacts you
  fetch and check*, not questions you ask a service that could lie, stall, or disappear.

```sh
ainra verify ainra:registrar-07:acme-corp:invoicing@4.2.1
# change one byte of the passport → INVALID  sig_invalid
```

---

## 4 · A short-lived credential for each running copy

The passport identifies the agent. It does not identify the **container**. A copy running in production carries an
**instance credential**, minted by the passport's control key — which never enters the container (ADR-019 / D-047):

- **≤ 1 hour**, enforced at *verify*, not only at issuance;
- **capabilities narrow only** — always a subset of the passport's;
- **bound to one audience** and **holder-bound by proof-of-possession**, so a captured credential is not a bearer
  token: presented to a different audience it fails with `instance_pop_invalid`;
- **hybrid, with no speed exception** — the rung closest to the workload is not the place to save microseconds;
- **not logged**, but bound to the passport's already-logged leaf, so nothing can be minted for a passport that
  was never recorded, and a container start never becomes a log append;
- **revoking the passport kills every live instance.**

Stated plainly, and in the module doc so nobody has to infer it: this does **not** make a compromised container
harmless. An attacker with live access acts as the agent until the credential expires. It makes that compromise
*bounded in time, bounded in scope, and killable from outside* — three things it was not.

```sh
ainra instance issue AP-5FDC-E4 --aud https://shop.example --caps read:orders --ttl 900
ainra instance verify i-bc5dbeed --aud https://shop.example     # VALID
ainra instance verify i-bc5dbeed --aud https://bank.example     # instance_pop_invalid
```

---

## 5 · An immutable record

Every accreditation, issuance and revocation lands in a **hash-chained transparency log**, and a credential is not
valid until it is logged — *logged-before-valid*, the inverse of a system where the record is written afterwards
and can be quietly adjusted. Each entry carries the hash of the entry before it, and the head is witness-cosigned.

```sh
ainra log verify
# edit any line of $AINRA_HOME/log/log.jsonl → "log broken at seq N: hash mismatch"
```

The record shows **what exists, never what agents did**. It is a registry, not a surveillance trail: you can prove
that a passport was issued, narrowed, re-issued or revoked, and you can prove *when* — and there is nothing in it
about what any agent went on to do.

---

## Two distances

Workload identity and agent identity are both real, both necessary, and not substitutes for one another. They
answer different questions at different distances.

| The question | Answered by | Scope |
|---|---|---|
| *Which process is this, inside my own network?* | workload identity in your own mesh | one trust domain, one operator, your infrastructure |
| *Whose agent is this, and is it still allowed?* | the AINRA passport | between organizations that share no infrastructure |

Workload identity is excellent, and it stops at the boundary of whatever issues it: a credential minted by your
mesh means nothing to a company that does not run your mesh. AINRA begins exactly where that ends — a stranger,
with none of your infrastructure and no prior relationship, verifies your agent offline in milliseconds and gets a
fact rather than an opinion.

Part 4 is deliberately the *same shape* as mesh workload identity — short-lived, audience-bound, narrow — so the
two compose instead of competing: your mesh proves which process is speaking inside your walls, and the instance
credential proves, to everyone outside them, which agent that process is a copy of.

---

## What this is not

- **Not a guardrail.** It never judges what an agent says or does. What an agent is permitted to attempt is the
  operator's policy; AINRA makes the identity behind the attempt provable.
- **Not a score.** The root returns facts, never ratings — a root that judges is no longer neutral infrastructure.
- **Not permission to exist.** An agent may exist unregistered; the root records, it does not license being.
- **Not a directory you must query.** There is no lookup service in the hot path, so there is nothing to rate-limit
  you, meter you, or watch who you verify.
- **Not a holder of personal data.**

---

## See all five at once

```sh
make demo
```

The lifecycle by hand — init, accredit, issue, verify, instance issue/present/verify, revoke, log verify — is in
[the quickstarts](quickstarts/) and [`skills.md`](../skills.md). The shape of the system is in
[AINRA_I_The_Standard.md](AINRA_I_The_Standard.md); the reasoning behind part 4 is
[D-047 and D-049 in DECISIONS.md](DECISIONS.md).
