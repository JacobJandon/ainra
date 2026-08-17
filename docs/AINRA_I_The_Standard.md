# AINRA — THE STANDARD
## Agent Identity & Naming Registry Authority · Master Specification v5.1 · July 2026
*Document I of III. Public. Supersedes and consolidates all prior specification versions (v1–v5.0) and the one-pager. This document names no third party anywhere; every example uses placeholder registrars by constitutional rule. Category, stated once: **the identity layer for autonomous AI**. Canonical description of AINRA's role in it, used verbatim everywhere: "The neutral root of AI agent identity." (38 characters.) v5.1 changes: root cryptography reissued for assumption diversity (Part I, key architecture); delegated online signing named honestly; no semantic changes elsewhere.*

---

# PART 0 — PRINCIPLES (NORMATIVE, CONSTITUTIONAL)

**0.1 The problem, stated once.** The majority of internet traffic is automated; machine identities outnumber humans roughly 80:1 inside enterprises; most organizations cannot see their agent-to-agent traffic; and every major platform, network, and directory has shipped its own agent identity that no other system can verify. A legitimate agent cannot prove itself away from home; a malicious one banned in one place walks into the next; nothing stops a compromised fleet everywhere at once; and past one hop of delegation, no deployed protocol proves who authorized what. The missing piece is a root — the one component nobody can build alone.

**0.2 The solution, stated once.** One open standard and one deliberately thin non-profit root that does four jobs and is constitutionally barred from all others: run the **namespace**, **accredit** independent registrars, anchor the **root of trust**, and operate the **revocation fabric and transparency logs**. Everything else — issuing, verifying evidence, serving customers, judging behavior, making decisions — lives at the edge, with registrars, operators, principals, and verifiers.

**0.3 The Separation Principle.** The root must never issue; the issuer must never be privileged; the explorer must never judge. Trust in a center is proportional to how little the center does. Whatever *can* live at the edge, does; the one thing that cannot during bootstrap (issuance) is pushed into a firewalled, sunset-reviewed **independent organization** the root can never own, fund, staff, or instruct.

**0.4 The Neutrality Gradient.** Declared honestly, in three grades. **AINRA is absolutely neutral** — no policy, interface, default, ranking, or *example* features any real registrar; all illustrations use placeholders (`registrar-07`, `chain-open-01`). **The canonical explorer is neutral by construction** — read-only over public data, mechanically ordered, proof-attached, structurally incapable of editorializing. **The first registrar is arm's-length, honestly not neutral** — it is an issuer with prices and customers; its obligations appear in Part IV.

**0.5 The Registry–Registrar Model.** The root operates the authoritative registry; accredited registrars are the sole retail interface. (i) Operators obtain passports only from registrars — the root never transacts with an operator. (ii) Every registrar issuance is *atomically* a registration in the root registry: authoritative name record and sealed log entry at the root; customer relationship, verification evidence, and service at the registrar. (iii) Lineages **transfer between registrars** with history and log continuity intact — names belong to the namespace, never to a registrar. (iv) Registrars operate under one identical contract and one uniform, published, capped fee schedule. (v) The passport document carries registry-record data only; operational state (mandate balances, running instances, local credentials) lives at the edge, outside the document and outside the root.

**0.6 The Open-Standard Principle.** The specification is freely implementable — no license, fee, or permission. Reference implementations are open-source under permissive licenses (Apache-2.0). Any current player — payment network, enterprise directory, edge provider, chain, identity vendor — may adopt, implement, mirror, or fork it today. The root stewards the standard; it does not own it; the standard survives the root.

**0.7 The Scale Invariant (I1).** Root load is independent of the number of agents. The root talks only to registrars and publishes only keys, rules, status data, and logs; registrars handle lineages and versions; running instances use short-lived credentials minted locally under the passport; verification happens at the edge against cached material. A trillion agents leave the center's load flat.

**0.8 Login → decision.** The historical trust boundary was the login: one human, one prompt, one yes. Agents act continuously at machine volume, so the boundary moves to the decision — every action, evaluated in context. Division of labor: **the root standardizes every input to the decision** (identity, chain, authority, ceilings, live status — cached, offline-capable, freshness-classed); **the decision itself always belongs to the verifier.** The root never decides.

---

# PART I — THE ROOT (AINRA)

## 1. The Charter — six prohibitions
Amendable only by supermajority within *every* constituency after twelve months of public comment:
1. **Issues no passports.** Accreditation only; never retail.
2. **Computes no scores.** Facts and proofs; judgment belongs to verifiers. Others may build scoring atop the public record — the root never does.
3. **Processes no payments.** Fees are invoiced flat charges, never per-transaction, never in-band.
4. **Holds no personal data.** Human backing is proven in zero-knowledge; PII never transits or rests at the root.
5. **Never gates L0 existence.** Permissionless registration is a guaranteed right; consequence is earned tier by tier.
6. **Features no registrar, ever.** No policy, interface, default, ranking, or published example names, promotes, pre-selects, or visually features any registrar — including any affiliated one.

**Article S — Structural Separation.** S1: the root holds no equity in, and receives no revenue share from, any registrar or explorer. S2: no shared staff, systems, offices, or credentials with any registrar. S3: any affiliated registrar receives zero non-public access of any kind. S4: board interlocks target zero and are published. S5: the affiliated registrar is sunset-reviewed on a fixed public cadence until indistinguishable from competitors. S6: all inter-body dealings are published (Part IV interface table). S7: **example neutrality** — all root-published examples, schemas, demos, documentation, and interface defaults use neutral placeholder registrars; the affiliated registrar may never appear in them; canonical-explorer registrar listings are ordered mechanically (time, name, or volume — labeled), never curated.

## 2. Namespace
Grammar: `ainra:{registrar}:{operator}:{lineage}@{version}` — lowercase alphanumerics and hyphens; version is semver (1–3 numeric fields). Every `ainra:` name is a DID underneath (method `did:ainra`), resolvable by standard tooling. Resolution returns the signed passport document; names point, registrars serve. The **lineage** is the permanent identity — soulbound, non-transferable, the anchor of all history; a genuine ownership transfer is a *logged event* that resets assurance evidence while preserving the historical record. The **version** is re-certified on every material change (model, permissions, operator), so old trust never silently covers new behavior.

## 3. Accreditation
The root publishes one rulebook and one contract, identical for all registrar classes: **licensed issuers** (regulated-market lane, L3–L4), **enterprise directories** (mint a passport when an internal agent crosses the boundary; internal actor chains feed the authority chain), and **permissionless chains** (on-chain registries whose entries auto-map to L0–L1; transfers logged, assurance reset). Obligations: uniform verification standards per tier; evidence retention at the registrar (never at the root); mandatory funding of one transparency monitor watching a *competitor*; annual audit; breach disclosure ≤72h. Enforcement ladder: finding → remediation window → suspension of new issuance → **wholesale de-accreditation** (registrar certificate revoked; its passports enter a grace window for supervised transfer to other registrars — customers are never punished for their registrar's sins). Fees: capped, cents-scale per lineage-year plus flat accreditation; the cap may only *fall* as volume grows (Part V economics).

## 4. Root of trust
Root keys are **threshold keys (5-of-9)** held by custodians spanning ≥5 jurisdictions and ≥3 institution types (civil-society, academic, industry, public-interest technical, archival), used only in public, recorded **key ceremonies**, with a quorum-activated standby in escrow. The classical root is a **FROST threshold Ed25519 key (RFC 9591)** — it emits standard signatures, so any stock verifier validates the root without special code. Its post-quantum counterpart is deliberately **hash-based (SLH-DSA-SHA2-128s, FIPS 205)** rather than lattice-based: agent and registrar keys are lattice-signed (**hybrid Ed25519 + ML-DSA-65**, both signatures mandatory), and the anchor that must survive to re-certify successor algorithms must not share the assumption it would be recovering from. Sub-minute freshness signals are signed by **delegated online keys** — quarterly-certified by the root, scope-limited to freshness duties only, so the true root stays offline and any compromise is bounded to one quarter. Published rotation and algorithm-migration procedures govern all of it. Verifiers cache the root set and registrar certificates; every verification is local and offline-capable in milliseconds.

## 5. The passport
An SD-JWT verifiable credential; selective disclosure by field. Canonical schema (illustrative values; placeholder registrar by S7):
```json
{
  "type": "agent-passport", "v": 1, "serial": "AP-8F2E-C41",
  "ainra_name": "ainra:registrar-07:acme-corp:invoicing@4.2.1",
  "lineage": "invoicing", "version": "4.2.1",
  "operator": { "name": "Acme Corp", "kyb": true, "jurisdiction": "US-DE" },
  "registrar": "registrar-07",
  "authority": { "class": "A1", "proof": "zk:commitment:…", "act_chain_ref": "…" },
  "tier": "L3",
  "validity": { "issued": "2026-04-11", "expires": "2027-04-11", "renewable": true },
  "key": { "alg": "Ed25519+ML-DSA-65", "pub": "…", "fp": "9C41:8F2E:AA07:D356" },
  "history": { "soulbound": true, "reputation_pointers": ["…"] },
  "log": { "seq": 2, "hash": "…" },
  "registrar_sig": "…", "registrar_cert": { "…chains to root…" }
}
```
Registry-record fields only; mandates and fleets live outside the document (0.5.v). Presentation rides **HTTP message signatures**: the request signature names the passport key, so the credential travels inside ordinary web traffic. Instance credentials: running copies carry minutes-scale credentials minted locally under the passport, bound to the connection (mTLS) — a stolen token expires before it matters (I1).

## 6. Authority classes
Every passport declares who stands behind it; delegation may only narrow; chains stay provable to their anchor at any depth from the credential alone.
- **A1 — Human-delegated.** A verified person, proven via zero-knowledge commitment: accountability exists while privacy stays intact. Backed by a signed **consent mandate**.
- **A2 — Organization-delegated.** A verified legal entity; the mandate is an organizational authorization resolving to responsible officers via the registrar of record.
- **A3 — Agent-delegated.** Another passported agent is principal. Every hop dual-signed (delegator + delegatee), scopes strictly narrowing, depth capped (default 3), the full chain verifiable to its ultimate A1/A2 anchor — closing the field's known multi-hop gap.
- **A4 — Autonomous.** Self-directed, declared truthfully. Requirements: reachable governance endpoint; dead-man renewal timer; and, to rise above the lowest tiers, an accountability substitute — bond, insurance, or steward of record. Verifiers choose how much A4 to accept; honest existence is always guaranteed.

**Consent mandates** (the authority instrument): grant → attenuate → exercise → review → revoke. A signed permission slip from the principal — scopes, time limits, spend ceilings, revocation address — which downstream delegation can only narrow. Revoking a mandate recalls its entire subtree, everywhere, within the revocation SLO. The **trust graph** — the log-derivable map of delegation edges (never behavior) — gives the ecosystem structure with privacy intact; expired-mandate orphans surface globally.

## 7. Assurance tiers
| Tier | Requirements | Typical consequence granted by verifiers |
|---|---|---|
| **L0 Declared** | Valid keypair + logged registration + revocation endpoint. Permissionless by charter. | Sandbox, attributed crawl |
| **L1 Anchored** | + verified domain control or established wallet history | Rate-limited APIs, low-value micropayments |
| **L2 Operated** | + KYB-verified operator, declared model lineage, soulbound lineage | Standard commerce, B2B data exchange |
| **L3 Backed** | + zero-knowledge principal + liability-insurance attestation | Consumer-scale payments, contract execution |
| **L4 Regulated** | + sector license, independent audit, third-party work validation | High-value autonomy, critical infrastructure |
The root labels; every verifier sets its own floor. Five levels; you set the floor.

## 8. Verification protocol (normative sequence)
1 **Present** — signed request names the passport key. 2 **Chain** — passport → registrar cert → root set; plus authority chain to anchor; cached keys, milliseconds, offline-capable. 3 **Status** — fresh revocation proof (freshness class by tier: L3–L4 require proofs ≤5 min; high-assurance actions demand a fresh proof so a blocked feed **fails closed**) + log-inclusion proof. 4 **Decide** — verifier policy: tier floor, accepted classes, required scopes, fail mode. Reference CLI exit codes: 0 valid / 1 invalid; `--json` for machines.

## 9. Revocation fabric & transparency logs
One compressed, signed status structure every verifier mirrors; push channels propagate deltas with a **global SLO of <60 seconds** issue-to-rejection. Revocation scopes: a version (kills its entire fleet), a lineage, a mandate subtree, or a registrar (wholesale). Every event — registration, issuance, re-certification, transfer, mandate grant/revoke, accreditation action — is sealed **before validity** in append-only, hash-chained Merkle logs whose checkpoints are cosigned by **independent witnesses**; anyone may run a monitor; registrars must fund one watching a competitor; the logs are mirrorable and the whole system forkable, so history cannot be rewritten and the root cannot quietly lie. "Logged before valid" is load-bearing: unlogged is invalid.

## 10. Threat model (condensed register)
Root-key compromise → threshold + standby + ceremony-only use. Registrar fraud → audits, monitors, wholesale de-accreditation with customer grace. Impersonation → key-in-signature binding + mTLS instance creds. Replay/theft → minutes-TTL local credentials. Delegation laundering → dual-signed narrowing chains, depth caps. Sybil floods → L0 grants existence, not consequence. Revocation suppression → freshness classes fail closed. Log fork/rewrite → witness cosigning, open monitors. Jurisdictional coercion → custodian spread; namespace censorship is structurally impossible below quorum. Privacy attack → no PII at root; zk principals; selective disclosure; graph shows structure, never behavior. Capture of governance → constituency supermajorities, 12-month comment, public everything. Price abuse → charter fee caps that only fall. Explorer manipulation → independence + client-side verification. Metaphor-imported failure modes (registrar race-to-bottom, registry price creep, public-record privacy conflict) → uniform tier standards + falling caps + zero-PII design, respectively. Successor standard emerges → managed-migration clause (Part V.4). Root institutional failure → fork-readiness drills; the standard outlives the institution.

---

# PART II — THE PUBLIC RECORD & EXPLORERS

The record — every passport, registrar, checkpoint, revocation — is public, witness-cosigned, and shows **what exists, never what agents did**. Independent explorers render it; **the root operates no explorer and funds none** — explorers are separately governed and sustain themselves through grants and donations, never listing fees or root budget. Explorer requirements (any implementation claiming conformance): facts, never scores; no rankings, ads, or promotion; mechanical ordering, labeled; structurally identical registrar pages; every fact one click from its cryptographic proof; client-side verification available ("don't trust, verify"); open-source and mirrorable. Search grammar: free text plus typed prefixes `name: lineage: operator: registrar: log: witness: tier: class:`, grouped by object type, ordered by recency, zero personalization. Freshness SLOs: log-to-page <30 s; revocation-to-page <5 s. Root→explorer interface: public endpoints only, identical to what any mirror receives — no funding, staffing, instruction, emphasis, or private channel.

---

# PART III — INTEROP PROFILES (GENERIC)

How existing layers plug in without replacement — keep what you built, gain everyone else: **payment networks** keep tokens and checkout; key-directory lookups resolve through the root; gain cross-network recognition and the shared switch. **Runtime identity/control planes** keep gateways and per-action policy; consume the record as the standardized input to every decision; gain cross-boundary trust. **Edge/bot defense** keeps signature checks; mirrors the root directory behind them; gains operator/tier/status behind every signature — a welcome lane. **Enterprise identity** keeps internal directories; mints a passport at boundary-crossing; internal chains feed the authority chain. **On-chain registries** keep permissionless registration; entries auto-map to L0–L1; transfers logged; gain off-chain acceptance. **Merchants/APIs**: one verify middleware plus a tier floor — an afternoon. **Insurers/auditors** read passports, chains, logs — attributable history, the raw material for pricing agents. **Regulators** recognize tiers and classes and read the same public logs as anyone — oversight without operating anything or holding anyone's data.

---

# PART IV — THE FIRST REGISTRAR (ARM'S-LENGTH)

**Meridian** exists to prove the flows and seed the market, under posture declared honestly: an issuer, therefore not neutral, therefore kept **outside, visible, and equal-footed.** Obligations: (i) identical public rules, fees, audits, timelines as every registrar; (ii) zero non-public access; (iii) never appears in root examples, defaults, or interfaces (Charter 6, S7); permitted distinctions are "first" and "reference," both expiring; its materials may carry the standard attribution mark — **"Built on the AINRA open standard"** — available to every registrar identically, direction strictly one-way (registrars reference the standard; the root displays no one's mark); (iv) conflicts register, interlocks (target zero), and inter-body payments published annually; (v) open-sources its full registrar stack ("registrar-in-a-box") to seed competitors; (vi) recurring **sunset review** until ordinary — continue as one-of-many, spin fully out, or wind down. Scope: L1–L3 only; the licensed L4 lane belongs to regulated registrars. Mechanically it is a registrar in the full Part 0.5 sense: every issuance registers into the root; every customer may leave with history intact.

**Inter-body interface table (all published):** Root→registrars: rulebook, contract, fees, audits — identical for all; never leads, capital, or preview access. Root→explorers: public endpoints only. Registrar↔explorer: none beyond public data. Any exception: none permitted; exceptions are the scandal.

---

# PART V — GOVERNANCE, ECONOMICS, ROADMAP

**1. Bodies.** AINRA is constituted as an **international, member-governed, non-profit federation** — the same organizational species that gave sport, aviation, and the internet their neutral coordinating bodies: legitimacy flows *from* the members, the rules bind only those who join, and the federation itself never competes with them (it fields no team). Membership classes span the whole ecosystem: **issuer members** (accredited registrars of every class), **attestor members** (principal-proof providers), **verifier members** (edges, gateways, merchants, control planes), **resolution and data members**, **witness members**, and **public-interest members** — each class a constituency in the assembly, which elects the board under charter constraints; membership dues are the capped per-lineage fees of §2, identical within class. Custodians (keys) and witnesses (logs) remain structurally separate from board and assembly alike. Everything material is public: statutes, minutes, budgets, audits, fee schedules, and ceremonies (recorded). Existing identity systems join as members through the door that fits their function — an issuer's credentials upgrade in place to passports, an attestor's proof becomes a first-class field available through every registrar, a verifier consumes the record — so federation replaces the quadratic cost of pairwise integrations with a single membership.

**2. Economics — position, not profit.** Revenue = capped per-lineage-year fees (cents-scale) + flat accreditation + grants. The design intent is a **position where value must pass without being taxed**: every agent interaction of consequence resolves a verification; every verification chains to the root; the root's cut is deliberately negligible — cheap enough that removing it costs more than keeping it. Worked shape: at 10M lineages × $0.10 = $1M/yr (lean root sustained); at 100M, the charter's falling cap *reduces* the fee; at 1B, the fee approaches archival cost. Anti-creep is constitutional because the toll position, not the toll, is the asset.

**3. Status line (honest, live).** ROOT: PRE-CEREMONY (operator-run FROST 5-of-9 + SLH-DSA genesis root minted; the recorded public ceremony pending) · LOGS SEALED: 0 · WITNESSES: RECRUITING · SPEC: PUBLIC (this document) · REFERENCE CLI: v0.3.0 WORKING (real hybrid Ed25519 + ML-DSA-65 chain verification, signed revocation, hash-chained checkpointed log; labeled limits: local witness keys pending independent witnesses, poll-based status pending push fabric). Every public number is a cited external figure or a shipped artifact; an honest zero beats a decorated maybe.

**4. Roadmap, planned to the end.** **Prove** (now): external verifier trials against pre-registered gates; venue filing of this standard as community submission/Internet-Draft with the CLI as conformance suite. **Anchor**: institutional co-conveners; charter ratification; first public 5-of-9 ceremony sealing log #1; two registrar classes issuing live; one revocation propagated worldwide, watchably. **Endure**: the long middle — adoption plateaus and pressure met with pre-decided responses (Document II obstacle ledger), principles fixed, pace flexible. **Disappear** (the goal): verification as boring as the clock — everywhere, invisible, with a public record behind it. **Ω — beyond the institution**: generational key-succession ceremonies; fork-readiness drills; and a **managed-migration clause** — if a demonstrably better successor standard achieves legitimate multistakeholder adoption, the root's final duty is an orderly migration of the namespace and record into it. The standard outlives the institution; that is planned, not feared.

---

*Everything above composes from open standards proven at internet scale — signed messages, selective-disclosure credentials, resolvable identifiers, witnessed append-only logs, threshold ceremonies, compressed status proofs. Proven parts; new assembly; and a charter that keeps the center small forever.*
