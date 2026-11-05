<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Trade-offs, checked against the code

A common summary of AINRA lists three strengths and three costs. This page checks each one against the
specification, the code and the drills, says which parts are true, and corrects the parts that are not. Written
2026-11-05.

| The summary says | Verdict | What is true |
|---|---|---|
| **Instant off-switch.** The operator revokes the passport centrally, freezing all API access globally. | **Partly wrong** | Not central, not instant everywhere — see 1. |
| **Trustless verification.** Third parties verify the passport offline, instantly. | **True** | Offline, local, in well under a millisecond — see 2. |
| **Accountability.** Actions tie to a verified operator (KYB). | **True, by tier** | From the tiers that require it — see 3. |
| **Single point of failure.** If the registry is down, fail-closed stops the agent completely. | **Partly true, and bounded** | Measured — see 4. |
| **Operational overhead.** Keys and constant "heartbeat" checks add latency and complexity. | **Mostly wrong** | No per-request call — see 5. |
| **Privacy constraints.** Lineage and operator are public, so stealth operation is hard. | **True for lineage, by design; partly wrong for the operator** | See 6. |

## 1. The off-switch

- **Who revokes.** "Only the issuer, the principal, or due process can revoke" (the charter's *Death* rule,
  `site/docs.html#charter`). The
  root revokes no agent; it issues nothing. A revocation is one bit set in the issuing registrar's signed status
  list.
- **How fast.** Publication took under 60 s in a local drill (`make soak-smoke`). After that, each verifier refuses
  once its own copy of the list shows the bit — within its freshness class: 30 s (F1), 5 min (F2, the SDK's
  default) or a day (F3). An unsigned push can make a verifier fetch sooner (MTS ADR-018); it is never trusted.
- **Corrected 2026-11-05 (D-092).** The Standard §9 promised a "global SLO of <60 seconds issue-to-rejection" and
  the charter said every revocation is "honored everywhere in under a minute". That holds for verifiers at the strict
  class (F1), not for the SDK's default (F2, 5 min). The texts now say so; the default stays F2, because F1 would
  make every agent refresh its status every 30 s — the overhead in 5.
- **What it stops.** Acceptance by verifiers. It does not reach into the agent's process; a verifier that does not
  check is not stopped by anything.

## 2. Offline verification

True as stated, with the precise version: the chain, both signatures and the log proof verify locally, with no call
to the root or the registrar, and a full verification is measured in [BENCHMARKS.md](BENCHMARKS.md) (held by
`make bench-gate`). The one input that ages is the status list — see 4. Verification with every AINRA service
unreachable is drilled in [drills/ROOT-DARK.md](drills/ROOT-DARK.md).

## 3. Accountability

True for the tiers that require an accountable operator: the operator is proven to an accredited registrar, which
keeps that evidence; the root never sees it. L0 "grants existence, not consequence" (MTS §7) — an L0 passport is a
name, not a vouched-for company, and verifiers set their own tier floor.

## 4. When the network goes dark

Measured, not argued: [drills/REGISTRAR-DARK.md](drills/REGISTRAR-DARK.md), held by `make outage-drill` (and
`--negative`, which plants four failures and requires each to be caught).

- **The root dark:** no effect on verification ([drills/ROOT-DARK.md](drills/ROOT-DARK.md)).
- **One registrar's status signer dark:** only that registrar's agents are affected, and only once their last signed
  status is older than each verifier's class — 30 s, 300 s or a day. Then `stale_status`.
- **A revoked passport never passes** during an outage. That is the reason for failing closed: if verifiers accepted
  stale data, knocking a status host offline would bring revoked agents back.
- **Mirrors** can serve the signed lists (they cannot forge them), which helps reach; only the registrar's delegate
  can sign a newer one.
- **Not built:** a standby status signer per registrar, so an outage is a failover rather than a wait. The target is
  in MTS §20; it belongs in the plan as an operations item.

## 5. Overhead

- **No heartbeat per request.** A verifier refreshes a registrar's status list on its class's schedule, not per
  call; the agent sends its passport once per session and names it by digest after that (D-065).
- **Per request:** the running copy signs the request (RFC 9421) with its own short-lived key, and the verifier
  checks that signature locally.
- **Keys:** the lineage key is the operator's to hold; renewal is ACME-style, designed to be invisible, with overlap
  issuance (MTS ADR-017) — scheduling it is deployment, not protocol.
- **What remains real:** onboarding with a registrar, holding the lineage key safely, and running the SDK or
  middleware. That is the cost of being checkable at all.

## 6. Privacy

- **Lineage: public and linkable, by design.** Every verifier sees every claim ([LEAK-LEDGER.md](LEAK-LEDGER.md)),
  and an agent's name is in every presentation, so its activity is linkable across verifiers (MTS §11: "agents are
  accountable"). The ZK study weighed unlinkable presentations and refused them for agents
  ([ZK-STUDY.md](ZK-STUDY.md), Z2). Running a "stealth" agent that verifiers cannot recognise again is
  deliberately not offered.
- **The operator need not be a public company name.** MTS §11: the operator field is "an org identifier or a
  registrar-assigned handle"; the KYB evidence behind it stays with the registrar.
- **People are private.** No personal data at the root; a human principal reaches verifiers only as a digest
  (D-066).
- **Status checks** reveal whose list a verifier fetched, not which agent; a network-wide file closes that for
  verifiers that fetch (D-091).
