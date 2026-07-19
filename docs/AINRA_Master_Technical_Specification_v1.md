# AINRA — Master Technical Specification v1.0
**09 July 2026 · Production-grade specification for the working prototype ("Genesis") and its migration path**
**Engineering companion specification** to the public Standard. Names only technologies and standards bodies (RFCs, FIPS, IETF/NIST/FIDO work) — never commercial third parties, per Charter rule S7, which also mandates placeholder registrars only (e.g. `registrar-07`) in every example and test fixture. No invented data: figures are either measured in-environment (marked **[measured]**), verified against published standards (marked with RFC/FIPS), carried from July-2026 field research, or explicitly marked **[estimate]**.

**Provenance.** Consolidates: the public Standard v5.0, July-2026 field research, Doctrine, P0 CLI v0.1.0 (shipped, tamper-tested), P1 Prototype Specification (09 Jul 2026), and all prior drafts. Where this document contradicts an earlier one, **this document wins and the change is logged below**.

---

## Adversarial Review Ledger (what was challenged, what happened)

Per the brief, every prior decision was treated as a hypothesis. Outcomes:

| # | Prior decision challenged | Verdict | Result |
|---|---|---|---|
| 1 | Root PQ key = ML-DSA-65 (ceremony-Shamir) | **OVERTURNED** | Root PQ = **SLH-DSA-SHA2-128s**. The anchor must not share failure assumptions with the leaves (registrars/lineages are lattice-based; a lattice break must not kill the root that would re-certify their replacement suites). Hash-based = most conservative assumption set; industry PKI guidance explicitly recommends SLH-DSA for long-lived offline roots; RFC 9909 (Dec 2025) provides the X.509 algorithm identifiers our bridge profile needs. Cost measured and acceptable: sign 4.4 s in JS **[measured]** — root signs rarely; verify 5.4 ms; pk 32 B; sig 7.9 KB on rare, cached artifacts. ADR-001. |
| 2 | "Fresh status head signed by threshold root every 30 s" | **OVERTURNED (self-contradiction)** | A 5-of-9 human-custodian quorum cannot sign every 30 s. Fixed with **delegated online signing keys**: quarterly-certified, scope-limited (`fresh-head`, `delta-countersign`, `daily-checkpoint`), hybrid (2-of-3 FROST-Ed25519 among ops nodes + online ML-DSA-65), 7-day fresh-head key validity, blast radius ≤ one quarter. The trust ledger gains an honest row instead of hiding an impossible one. ADR-002. |
| 3 | Build our own Sunlight-style tile log | **OVERTURNED** | **Tessera** (tile-native, C2SP `tlog-tiles` compliant, GA, from the team with a decade of production transparency logs) is strictly better than bespoke. We write glue, not a log. Witnessing joins the **operating witness ecosystem** (witness-network.org onboarding; omniwitness/litewitness software; ArmoredWitness-class hardware as P2) instead of inventing one. ADR-005. |
| 4 | Revocation delta push via WebSub | **OVERTURNED** | WebSub adds a hub dependency for nothing. Long-poll + Server-Sent Events with ETag semantics. Boring wins. ADR-007. |
| 5 | "No blockchain anywhere" | **REFINED after steelman** | Root on-chain stays rejected (capture economics, §13). But checkpoint **anchoring to a public chain as one optional witness class** (OpenTimestamps-style) is cheap, adds an unkillable public timestamp, and never enters the verify path. Accepted as witness-class plugin. ADR-006. |
| 6 | Semaphore zk plugin presented as clean | **CORRECTED (honesty)** | Groth16 requires a trusted setup — a trust assumption that was missing from the ledger. Added as ledger row 9; plugin labeled demonstration-grade; BBS (no trusted setup; IETF track; not PQ) and PQ anonymous credentials tracked in §31. ADR-011. |
| 7 | Registrar datastore = Postgres | **RELAXED** | Log is the source of truth; the DB is a rebuildable index. SQLite+Litestream for small registrars, Postgres for large. Lowers the barrier to running a registrar — decentralization through cheapness. ADR-013. |
| 8 | Hybrid Ed25519+ML-DSA-65 for registrars/lineages; SD-JWT VC; logged-before-valid; consensus-free witnessed logs; RFC 9421 presentation; SPIFFE instances; did:ainra+did:web; Rust/Go/TS split; fee-capped economics | **HELD** | Survived challenge; justifications strengthened with 2026 evidence (RFC 9901 published; TSL draft-21; FN-DSA still not final — expected no earlier than late 2026, confirming its rejection). |
| 9 | Economics "fees cover the root" | **CORRECTED (honesty)** | At the fee cap, fees alone sustain the root only at ≥ ~5 M lineages **[estimate]**. Until then: capped founding-member dues + public-interest grants. Stated plainly in §22 instead of implied away. |

---

## 1. Executive Summary

AINRA is a neutral root of AI-agent identity: a namespace (`ainra:registrar:operator:lineage@version`), an accreditation regime (the root **accredits registrars; it never issues**), and four root functions — **accredit · anchor · revoke · log** — delivered as boring, verifiable infrastructure. The design goal is not novelty; it is **capture-resistance**: every artifact mirrorable, every claim verifiable offline, every trust assumption enumerated with a removal milestone, and the whole system forkable from public data (the fork drill is a *feature*, exercised quarterly).

Architecture in one paragraph: a **5-of-9 FROST threshold Ed25519** root (emits standard RFC 8032 signatures — verifiers cannot even tell it is thresholdized) paired with a **SLH-DSA-SHA2-128s ceremony root** for post-quantum diversity; **SD-JWT VC passports** (RFC 9901 base) with selective disclosure and an X.509 bridge; **Tessera tile logs** with C2SP checkpoints cosigned by independent witnesses ("logged-before-valid"); **Token Status List** revocation (10 M lineages ≈ 21.2 KB gzipped **[measured]**) with delta streams and a 30-s signed fresh head from delegated, quarterly-certified online keys; **RFC 9421** presentation binding and **SPIFFE**-style instance identity; verification is local, offline-capable, and free.

Everything security-relevant is either an RFC/FIPS, a GA open-source component with production history, or ≤ 1 kLoC of our own glue under a fuzz/property/differential test program with hard CI gates. Prototype exit = the **Genesis testbed** (§29): recorded ceremony, two registrar classes live, ≥3 external verifiers, revocation p95 < 60 s across three regions for 14 days, an injected log fork caught by witnesses (not by us), and an outsider forking the root from public artifacts alone.

## 2. Problem Definition

Agents now transact, negotiate, and act at machine speed; every serious counterparty asks the same three questions — *who is behind this agent, what is it allowed to do, is it still trusted right now* — and today each platform answers them with a proprietary registry. The July-2026 field position (Campaign §6): payment networks shipped agent tokens; a KYA-token cluster is accepted by most major bot-management vendors; a credit bureau now sells agent *scores* on top of it; a CA markets an "AI Agent Passport"; chain-native registries grew two orders of magnitude in a year; the EU's machine-marking obligations bite on 2 Aug 2026. The identity layer is being built — as N² pairwise integrations and as proto-roots that bundle identity with scoring, payments, or a vendor.
The gap AINRA fills: a **facts-only, vendor-neutral root** — standardized *inputs* to trust decisions (identity, authority class, capability ceiling, revocation status, log inclusion), never the decision itself, never a score, never a price. Doctrine: **login is ours; decision is the verifier's.**

## 3. System Requirements (functional)

| ID | Requirement | Acceptance |
|---|---|---|
| F1 | Namespace + DID form (`did:ainra:`), parser/resolver round-trip | 100 % on vector set |
| F2 | Passport: authority class A1–A4, tier L0–L4, capabilities, scope ceiling, hybrid keys, status ref, log ref, act_chain, mandates root, transfer history | Schema-validated; every field verified |
| F3 | Logged-before-valid | Unlogged credential rejected (T-L3) |
| F4 | Revocation < 60 s global; mandate revoke kills subtree | p95 < 60 s ×3 regions; T-R4 |
| F5 | Delegation only narrows (∩ scopes, ≤ expiry), O(depth) verify | Property P-2: 10⁶ chains, zero widenings |
| F6 | Registrar transfer with continuous history | Log trail unbroken across transfer |
| F7 | Explorer renders and verifies from public data only | Runs against a mirror with root dark |
| F8 | Fee schedule = root-signed object, monotonically non-increasing | Conformance test §28 |
| F9 | Full offline verification (F3 freshness class) | Air-gapped verify passes |

## 4. Non-Functional Requirements

| ID | Requirement | Target |
|---|---|---|
| N1 | Independence | Kill any single vendor → verify path unaffected (drill) |
| N2 | Decentralization | Threshold root; witnessed logs; byte-mirrorable artifacts |
| N3 | Vendor neutrality | Verify path = RFCs + OSI-licensed deps only (§24 audit) |
| N4 | Trust minimization | Every assumption in §12 ledger with removal milestone |
| N5 | Security program | §28 gates green per release |
| N6 | Mechanical neutrality | S7 linter; mechanical ordering; quarterly fork drill |
| N7 | Privacy | No PII in root structures; herd-private status; local verification (no phone-home) |
| N8 | PQ posture | Hybrid mandatory where root/registrar sign; assumption diversity at root |
| N9 | Laptop-runnable | `make genesis-local` boots full stack on one machine |
| N10 | Cost | Root marginal cost ≈ static hosting; I1: 10 M lineages × $0.10 ceiling |
| N11 | Maintainability | ≤ 1 kLoC bespoke security-critical code; two-maintainer rule; reproducible builds |
| N12 | Upgradeability | Algorithm agility via root-signed policy objects; deprecation windows ≥ 180 days |

## 5. Competitive Landscape Analysis (condensed, by pattern — no commercial third parties named)

**Clusters.** (a) *Payment-adjacent KYA*: token-based agent auth accepted across major bot managers; bureau scoring layered on top; the flagship I-D explicitly disclaims defining agent identity "in its entirety" — our interoperability door. (b) *CA/PKI*: an incumbent markets an agent passport with DNS-anchored policy records — root-aspirant via existing DNS trust. (c) *Chain-native*: agent registries at 10⁵ scale; composite identity+wallet platforms. (d) *Platform IdPs*: enterprise agent IDs inside existing directories. (e) *Proof-of-personhood*: zk human-delegation at 10⁷-user scale → maps to our A1. (f) *Venues*: NIST CAISI agent-standards initiative; FIDO agentic-auth WG; IETF drafts (ANS; KYA/pay profiles). **Posture:** align and profile, never re-implement; the root federates the clusters that today integrate pairwise.

**Lessons from successes.** Certificate Transparency: verify-don't-trust + append-only logs work at internet scale, but **gossip never shipped — witness cosigning is the deployed fix** → we start witnessed. ACME/free-certs: **zero price + automation beats incumbents** → issuance ≤ cents, one-command registrar. SPF/DKIM/DMARC: **record-pattern adoption** (publish a record, verifiers check it) → our directory/status objects are dumb fetchable records. SPIFFE: workload identity via short-lived attested certs → our instance layer.
**Lessons from failures.** A federated login system died when its **centralized fallback + sponsor exit** killed it → AINRA must survive sponsor death: mirrors, fork drill, nonprofit. A social-proof identity startup died by **acquisition** → assets legally unownable (charter), conformance vectors CC0. EV badges died when **UIs removed them** → never bet on indicator real estate; sell verifiable facts to machines, not badges to humans. OCSP failed on **privacy + liveness** → herd-private status lists, offline classes. DNSSEC's decades-long crawl: **ceremony complexity and ossified middleboxes tax adoption** → one ceremony a quarter, plain HTTPS transport, no new wire protocols.

## 6. Technology Landscape Research (what was evaluated)

Signatures: Ed25519 ✓, P-256 ✗ (no gain), RSA-3072 ✗ (size/speed), ML-DSA-44/65/87 (✓65 at leaf layer), **FN-DSA/Falcon ✗ for now — not a final FIPS; final expected no earlier than late 2026; FP-implementation hazard**, SLH-DSA-128s/f ✓ (root; break-glass), XMSS/LMS ✗ (stateful hazard SLH-DSA exists to fix), BLS ✗ (assumption + PQ dead-end). Threshold: FROST RFC 9591 ✓ (ZF Rust w/ DKG+refresh+repair; Go; noble), ROAST ✓ wrapper, CGGMP21 ✗, threshold-PQ ✗ (research: TALUS/Trilithium — tracked §31). Credentials: SD-JWT VC ✓ (base RFC 9901 published; VC draft-16), W3C VC-LD ✗ (canonicalization surface), mdoc ✗ P1 (CBOR/COSE burden; future profile), X.509 ✓ as bridge (RFC 9909 gives SLH-DSA OIDs). Logs: **Tessera ✓ (GA, tile-native)**, Sunlight (informed design) , Trillian ✗ (ops weight), Rekor ✗ (domain coupling), Sigsum ◐ (minimalism informs witness policy). Witnessing: C2SP tlog-witness ✓; omniwitness/litewitness ✓; witness-network.org onboarding ✓; ArmoredWitness hardware → P2. Revocation: IETF Token Status List draft-21 ✓, CRLite cascades ◐ (>10⁸ scale future), OCSP ✗, short-lived-only ✗. Transport/presentation: RFC 9421 ✓, DPoP-style KB-JWT ✓ (RFC 9901), mTLS/SPIFFE ✓. Consensus: none ✓; CometBFT/raft/L1s/DAGs ✗ for root (§13). Storage/distribution: HTTPS+rsync ✓, torrent ◐ optional, IPFS ◐ optional transport only (gateway centralization irony). DBs: SQLite+Litestream ✓ small, Postgres ✓ large — never in verify path. zk: Groth16/Semaphore ◐ demo (trusted setup — ledgered), BBS ◐ tracked, STARKs → research. Languages: Rust ✓ core, Go ✓ (log/witness ecosystem reuse only), TypeScript ✓ SDK, Node P0 ✓ retained as independent differential implementation. Time: signed heads + skew bounds now; Roughtime P2.

## 7. Architectural Decision Records

Format: Problem → Alternatives → Decision → Why → Failure modes & mitigations → Status.

**ADR-001 Root signature suite — REVISED.** *Problem:* one key must anchor everything for decades. *Alternatives:* single Ed25519; hybrid Ed25519+ML-DSA-65 (prior); Ed25519+SLH-DSA; PQ-only. *Decision:* **FROST-Ed25519 5-of-9 (RFC 9591) + SLH-DSA-SHA2-128s ceremony root.** *Why:* (i) FROST emits standard RFC 8032 signatures — universal verifiability, threshold invisible to verifiers; (ii) **assumption diversity**: leaves are lattice-based (ML-DSA); if lattices fall, a hash-based root survives to re-certify successor suites — the recovery root must not share the failure mode it recovers from; (iii) hash-based = most conservative, stateless (no XMSS state hazard); (iv) PKI-migration guidance explicitly recommends SLH-DSA for long-lived offline roots; (v) X.509/CMS integration standardized (RFC 9909, RFC 9814). *Measured:* 128s keygen 668 ms, sign 4 368 ms (JS floor; root signs ~dozens of artifacts/quarter), verify 5.4 ms, **pk 32 B** (composite root pubkey = 64 B total), sig 7 856 B on rare cached artifacts; tamper-rejection asserted **[measured]**. *Failure modes:* ceremony compromise during PQ signing (mitigated: air-gap, ephemeral OS, recording, ADR-002 keeps online use away from it); SHA-2 collapse (break-glass: SHAKE variant + suite policy object, §14). *Status:* REVISED, evidence-grounded.

**ADR-002 Delegated online signing — NEW.** *Problem:* fresh-heads every 30 s and delta countersigns cannot come from a human-custodian threshold; prior spec hand-waved a "pre-authorized window." *Alternatives:* longer fresh-head TTL (weakens F1 class); root online (unacceptable); delegate keys. *Decision:* **quarterly-certified delegate**: Ed25519 as 2-of-3 FROST among geographically separate ops nodes + one online ML-DSA-65 key; scope-limited by certificate (`fresh-head`,`delta-countersign`,`checkpoint-daily`); fresh-head key validity 7 days (auto-rolled), delegate cert ≤ 92 days; certified at ceremony by both root components. *Why:* keeps the true root offline, bounds blast radius to ≤ one quarter (typ. ≤ 7 days for the hottest key), honest ledger row. *Failure modes:* delegate compromise → root-signed revocation of delegate cert (published in directory + log; verifiers reject in ≤ fresh-head TTL); ops-node collusion (2-of-3) → detectable via log/witnesses, quarterly rotation. *Status:* NEW.

**ADR-003 Leaf suite — HELD.** Registrar + lineage (L2+): **hybrid Ed25519 + ML-DSA-65, both mandatory** (downgrade = INVALID, T-C2). L0/L1 instance keys Ed25519-only (short-lived). *Why:* measured costs fine (sign 12.7 ms, verify 3.1 ms, sig 3 309 B, exact FIPS 204 sizes ⇒ conformant impl **[measured]**); cat-3 margin at the layer that signs constantly; ML-DSA-44 rejected (thin margin for multi-decade lineages), -87 rejected (size, no need given hybrid).

**ADR-004 Credential format — HELD.** **SD-JWT VC** (`vct: ainra/passport/v1`; base = RFC 9901) + KB-JWT holder binding + **X.509 bridge profile** (passport hash + lineage in extension; SLH-DSA/ML-DSA OIDs per RFC 9909/RFC 9814 line). VC-LD rejected (canonicalization attack/fragility surface); mdoc deferred. *Draft risk:* SD-JWT VC is draft-16 — pinned via `vct` versioning; base RFC is done; migration is claim-name-level, not cryptographic.

**ADR-005 Transparency log — REVISED.** *Decision:* **Tessera** tile log (C2SP `tlog-tiles`), one shard per registrar prefix, C2SP checkpoint format, **join the operating witness ecosystem** (witness-network.org application; independent operators run omniwitness or litewitness; ≥3 at Genesis incl. charter's competitor-funded seats), root/delegate countersigns shard checkpoints into the top checkpoint. Tiles served as immutable static files (any mirror/CDN/laptop). *Why:* battle-tested library over bespoke; static tiles make availability capture-proof; witnesses are an existing community, not our invention. *Failure modes:* split view → k-witness quorum in verifier policy (default 2-of-3) makes equivocation require log+2-witness collusion, tested by injected-fork drill T-L5; witness churn → network onboarding + litewitness's near-zero ops cost.

**ADR-006 No blockchain root; chain as optional witness — REFINED.** On-chain root rejected: tokenholder governance = plutocratic capture; fee volatility taxes I1; verifier chain-dependence violates N1/N3; PQ posture of chains outside our control. What a chain provides (ordering, non-equivocation) witnesses provide at ~zero cost. **Accepted:** OpenTimestamps-style checkpoint anchoring as *one witness class* — extra public evidence, never required by verifiers. Permissionless lane = **ERC-8004 mapping profile** via gateway registrar (lane demand evidenced by 10⁵ registry growth in 2026).

**ADR-007 Revocation fabric — HELD, transport simplified.** **Token Status List (draft-21)** bulk layer (1 bit/lineage; measured at I1: 10 M lineages, 0.1 % revoked → **21.2 KB gz**, empty 1 245 B **[measured]**; herd privacy inherent) + signed **delta stream** via HTTP long-poll/SSE with ETag (WebSub dropped — hub dependency) + **fresh head** (delegate-signed status hash, max-age 30 s). Freshness classes: F1 fresh-head mandatory (payments-grade), F2 ≤ 5 min, F3 ≤ 24 h offline — **all fail closed**. CRLite kept as >10⁸ optimization; OCSP rejected (privacy+liveness).

**ADR-008 Logged-before-valid, strict — HELD.** No SCT-style promises (CT's promise mechanism was its weak point; gossip never deployed). Issuance: write leaf → 1 s batch → inclusion proof → release credential. Cost: ~1–2 s issuance latency. Accepted: issuance is rare; verification is hot.

**ADR-009 Consensus-free — HELD.** Single-writer per shard + witness non-equivocation + root countersign. BFT/validator sets rejected: a validator set is a **governance capture surface** and an ops tax; CT-style witnessed logs are the proven pattern at internet scale. CAP stance: verify = AP with *bounded, fail-closed staleness*; issuance = CP per shard (a shard writer down ⇒ that registrar pauses issuance; others unaffected).

**ADR-010 Languages — HELD with guardrail.** Rust `ainra-core` (all consensus-critical verify/issue logic; cargo-fuzz; C FFI). Go strictly for Tessera/witness glue (**reuse-only rule**: no novel security logic in Go). TypeScript SDK for web/Node. **P0 Node CLI retained as the independent second implementation** for differential testing (§28) — plurality is a feature, not waste.

**ADR-011 A1 principal proofs — REVISED for honesty.** `principal_proof` = pluggable attestor interface `{type, attestor, ref, proof?}`; root stores attestation facts, never identity data. P1 ships the interface + **one Semaphore-class zk plugin explicitly labeled demonstration-grade: Groth16 trusted setup is now trust-ledger row 9.** External PoH ecosystems integrate as attestor members (proofs consumed opaquely). BBS (no trusted setup; not PQ) and PQ anonymous credentials tracked (§31).

**ADR-012 Distribution — HELD.** Plain HTTPS + rsync for tiles/lists/directory; torrent optional for bulk; IPFS optional transport only (its gateway reality would re-centralize the thing it decentralizes). Two independent static hosts + open community mirroring; mirrors verified by content, not channel (root key pinned in SDK).

**ADR-013 Registrar datastore — REVISED.** SQLite + Litestream (small registrars) / Postgres (large). The **log is the source of truth; the DB is a rebuildable index** (rebuild tool ships). Never in the verify path. Lowers registrar cost floor → more registrars → decentralization through cheapness.

**ADR-014 Resolution — HELD.** Root-signed **registrar directory** (small JSON, mirrored like tiles) + `did:ainra` thin resolver + `did:web` mapping for stock DID tooling. DNSSEC anchoring deferred to P2 (adds a trust root before it removes one). Root-operated live resolution rejected (root must be safe to be dark).

**ADR-015 Observability — NEW (explicit).** Self-hosted Prometheus + Grafana + Loki for root ops and registrar-in-a-box (optional). **Zero telemetry in every shipped component** — verification never phones home (N7). Public status page rendered from witnessed checkpoints, not from us.

**ADR-016 Time — NEW (explicit).** Freshness decisions use signed timestamps inside heads/checkpoints with ±30 s skew tolerance; verifier clock sanity-check against last witnessed checkpoint; Roughtime-class source at P2. Ledger row 7. *Scope note (ADR-017):* the skew tolerance is a freshness-layer rule; the passport validity window is compared **exactly** (`nbf ≤ now < exp`) — a skewed window would be a fail-open grace period.

**ADR-017 Validity & renewal — NEW: identity eternal, credentials bounded, renewal invisible.** *Problem:* how long should a passport live? *Alternatives:* infinite passports (identity documents, not certificates); Web-PKI-style ever-shorter certificates; long-lived credentials with automatic renewal. *Decision:* **the identity (lineage + AINRA Number) is permanent; the passport CREDENTIAL defaults to 366 days**; delegated certs stay ≤ 92 d (ADR-002); instance credentials minutes–hours; freshness seconds. **Renewal is ACME-style and invisible**: reissue at T−30 d, **overlap issuance** (both generations verify as the same lineage in good standing until the old `exp` — no grace period after it: expiry is expiry), and a logged **REISSUE** whose body carries **`prev_leaf`** — the RFC 6962 leaf hash of the predecessor's credential body — so renewals are walkable through the transparency log as one unbroken chain, and a wrong/missing/superseded link is refused at issuance, fail closed. **L3+ passports may never outlive the audit behind their tier** (`exp` ≤ the tier audit's own expiry; evidence stays registrar-side per Standard §4 — the wire format is unchanged). *Why infinite passports are REJECTED:* (i) expiry is the status list's garbage collector — without it revocation state grows monotonically forever; (ii) crypto agility — a bounded lifetime is the natural suite-migration point (a 2035 lattice break must not grandfather 2026 credentials); (iii) claim staleness / ghost agents — an eternal credential asserts facts (operator, audit, insurance) nobody has re-checked, and abandoned agents stay "trusted" forever; (iv) verifier fragmentation — if lifetimes are policy, every verifier invents its own cutoff and the shared meaning of VALID decays. *Why long validity is affordable here:* revocation **fails closed in <60 s** (F1 fresh heads + deltas + push) — the opposite of Web PKI, whose shrinking certificates compensate for revocation that fails open. Short certs are what you need when revocation doesn't work; ours does, so the credential can be boring and the switch does the work. Renewal scheduling (the T−30 d rhythm) is deployment, not protocol.

## 8. Complete System Architecture

**Components.** C1 Root signer (FROST coordinator + 9 custodian clients; SLH-DSA ceremony module; **offline by default**) · C2 Log layer (Tessera writer per shard + static tiles) · C3 Witnesses (≥3 independent; omniwitness/litewitness; optional chain-anchor witness) · C4 Status distributor (TSL builder, delta stream, fresh-head via ADR-002 delegate) · C5 Registrar-in-a-box (issuer API, datastore, key mgmt, TSL segment, transfer engine) · C6 Verifier middleware (Rust lib; TS SDK; reverse-proxy filter) · C7 Explorer (static, client-verifying) · C8 Agent SDK (keys, presentation, act_chain, mandates) · C9 Conformance harness (P0 CLI + vector runner).

**Key hierarchy.**
```
ROOT  = FROST-Ed25519 5-of-9  ⊕  SLH-DSA-SHA2-128s (ceremony)
 ├─ signs: registrar certs · directory · policy objects · quarterly top checkpoints · DELEGATE certs
 ├─ DELEGATE (online): 2-of-3 FROST-Ed25519 (ops) ⊕ ML-DSA-65 — fresh-heads · delta countersigns · daily checkpoints (≤92-day cert)
 ├─ REGISTRAR keys (hybrid Ed25519+ML-DSA-65, HSM-recommended)
 │    └─ LINEAGE keys (hybrid at L2+) → INSTANCE keys (SPIFFE-style, short-lived Ed25519)
 └─ WITNESS keys (independent, ecosystem-standard)
Mandates: PRINCIPAL → lineage → sub-lineage… (dual-signed links, ∩-narrowing, log-referenced, subtree-revocable)
```

**Verify hot path** (local, offline-capable): ① resolve registrar via signed directory → ② verify **both** signatures (hybrid; chain to root) → ③ status per freshness class (fresh-head / TSL+deltas) → ④ log inclusion: leaf → tile path → checkpoint (root/delegate sig + ≥k witness cosigs). Any failure ⇒ INVALID with machine-readable reason code.

## 9. Threat Model

Adversaries: malicious registrar; malicious log operator (us, in the adversary's chair); minority custodian coalition (≤4); compromised delegate/ops node; network MITM; malicious mirror; squatter/impersonator; coercive vendor or state actor targeting infrastructure; quantum-capable future adversary. **Non-goals stated honestly:** we do not claim resistance to a global adversary coercing ≥5 custodians across jurisdictions, nor to endpoint compromise of a verifier's own machine.

| Threat (register ID) | Property at risk | Primary control | Test |
|---|---|---|---|
| Forged passport | Integrity | Hybrid sig + chain to root | T-C1/2, fuzz |
| Downgrade to single alg | Integrity | Both-sigs-mandatory | T-C2 |
| Unlogged issuance | Transparency | Logged-before-valid | T-L3 |
| Log split view | Consistency | k-witness quorum | T-L5 fork drill |
| Stale/blocked revocation | Freshness | Fail-closed classes + deltas + fresh-head | T-R1..3 |
| Scope widening in chains | Authorization | ∩-narrowing invariant | P-2 (10⁶ chains) |
| Replay of presentation | Authenticity | RFC 9421 nonce+created, 5-min window, nonce cache | T-P3 |
| Registrar key theft | Containment | Root revokes registrar cert; blast-radius report from log | T-K2 |
| Delegate key theft | Containment | ≤7-day fresh-head key; cert revocation | T-K6 (new) |
| Custodian share loss/theft | Root safety | 5-of-9 + refresh/repair (ZF FROST) | T-K3 |
| Mirror poisoning | Availability/led-astray | Content-addressed verification; key-pinned SDK | T-M1 |
| Squatting/impersonation | Naming | Registrar-scoped namespace + dispute policy (governance) | vectors |
| Quantum break (lattice) | Long-term | SLH-DSA root re-certifies successor suites | agility drill §30 |

## 10. Security Architecture

Defense-in-depth: (1) **Cryptographic** — hybrid mandatory, assumption-diverse root, alg-agility policy objects with ≥180-day windows, break-glass suite pre-named (SLH-DSA-SHAKE variant). (2) **Key management** — root offline (air-gapped ceremony machines, ephemeral OS with published hashes, recorded); delegate keys in HSM-backed ops nodes (two vendors, deliberately different — no HSM monoculture); registrar HSM recommended profile; instance keys short-lived. (3) **Software** — Rust core; reuse-only rule for Go; ≤1 kLoC bespoke security logic; two-maintainer review; reproducible builds; SLSA-3 pipeline; Sigstore signing **plus** an independent offline dual-maintainer SHA-256 manifest (no single trust root over our own releases). (4) **Operational** — signing policy objects define exactly what each key may sign (enforced in signer software and checked by witnesses' policy linter); quarterly ceremonies; incident response with public postmortems; standby quorum (sealed second share set, activation = published policy event). (5) **Assurance** — §28 program with hard gates; external crypto/protocol audit before Genesis→production (§30); public bug bounty at P2.

## 11. Privacy Architecture

Data minimization table: root structures contain **agent lineage IDs, org-level operator handles, capability metadata, hashes** — no natural-person data; policy: operator field MUST be an org identifier or registrar-assigned handle. Registrar-side KYB/KYC (if their market requires it) stays registrar-side with **crypto-shredding** (per-record keys; erasure = key destruction) — satisfying GDPR erasure without breaking append-only logs (logs hold commitments, not personal data). **Verification is local: no phone-home, no per-verify beacon to us or anyone.** Status lists are herd-private by construction (bulk bitstring — a verifier's fetch reveals nothing about which agent it checks). Selective disclosure (SD-JWT) lets an agent prove tier+capability without revealing full act_chain. **Deliberate trade-off, stated:** lineage IDs are stable ⇒ agent activity is linkable *by design* — agents are accountable; **principals are private** (A1 proofs reveal personhood/authority, not identity). Explorer shows registry facts only.

## 12. Decentralization Analysis & Trust Ledger

**Minimum-collusion sets [analysis].** Safety (forge root-signed artifact): ≥5 custodians (classical) — and ceremony compromise additionally required to forge PQ-verified artifacts. Consistency (hide a revocation / split view): log writer + ≥k witnesses (default policy 2) colluding, detectable by any other witness/mirror. Liveness (verification): **1 surviving mirror + cached directory** — root, registrars, and we ourselves can all be dark and verification at F2/F3 continues; F1 fails closed as designed. Censorship (refuse accreditation): constrained by published criteria + appeal + credible fork (quarterly-drilled) — exit power disciplines the root.

**Trust ledger (complete; a missing row = a bug):**
| # | You trust | For | P1 mitigation | Removal milestone |
|---|---|---|---|---|
| 1 | 5-of-9 custodians | non-collusion | jurisdiction spread; public ceremony; refresh | 7-of-13 across member orgs (P2) |
| 2 | Witness set | ≥1 honest (k for policy) | independent + competitor-funded; ecosystem onboarding | permissionless witness policy (P2) |
| 3 | Ceremony env | PQ seed secrecy | air-gap, ephemeral OS, recording | threshold-PQ when production-grade (§31) |
| 4 | Delegate ops (2-of-3) | scope compliance ≤1 quarter | scope-limited certs; 7-day hot key; witnessed | shorter certs + HSM attestation (P2) |
| 5 | Registrars | correct issuance | accreditation; everything logged; differential audit | bonds/slashing policy (P2); cross-registrar checks |
| 6 | Our release pipeline | binary integrity | SLSA-3; Sigstore + independent manifest; reproducible | ≥2 external reproducing builders (M7 gate) |
| 7 | Time | freshness windows | signed heads; ±30 s bounds; checkpoint sanity | Roughtime-class (P2) |
| 8 | DNS/TLS at first fetch | bootstrap only | pinned root key in SDK; content-verified thereafter | DNSSEC anchor (P2) |
| 9 | Groth16 setup (A1 demo plugin) | zk soundness | labeled demo-grade; interface-isolated | BBS / PQ-anon-creds plugin (§31) |
| 10 | Attestors | principal_proof truth | accredited; attestations logged | zk-verified attestor class growth |

## 13. Consensus and Trust Model

No consensus protocol. Total order *within a shard* = single sequencer; **non-equivocation** = witness cosigning (the deployed, CT-proven answer; gossip's failure is the cautionary tale); *cross-shard* = root/delegate countersigned top checkpoint. Why not BFT/L1: a validator set is a standing political body — the exact capture surface this design exists to avoid — plus fee/ops taxes and verifier lock-in. Trust is **explicit and enumerated** (§12) rather than laundered through "decentralization theater." Verifier trust policy is client-side and configurable (k witnesses, freshness class), Sigsum-style.

## 14. Cryptographic Design

| Layer | Classical | Post-quantum | Notes |
|---|---|---|---|
| Root | FROST-Ed25519 5-of-9 (RFC 9591 → RFC 8032 sigs) | SLH-DSA-SHA2-128s (FIPS 205) | pk 32+32 B; PQ sig 7 856 B **[measured]**; assumption-diverse |
| Delegate | FROST-Ed25519 2-of-3 | ML-DSA-65 | scope-limited, ≤92 d |
| Registrar/Lineage | Ed25519 | ML-DSA-65 (FIPS 204) | both mandatory; sig 64+3 309 B **[measured]** |
| Instance (L0/L1) | Ed25519 | — | short-lived, SPIFFE-style |
| Hash | SHA-256 (RFC 6962 prefixes) | — | ecosystem/witness compat; SHAKE migration path in policy object |
Downgrade rule: absence of any mandated signature ⇒ INVALID. Agility: root-signed **suite policy objects** name current + successor suites and deprecation windows (≥180 d); break-glass path pre-published. All randomness: OS CSPRNG; ceremonies add custodian-XOR entropy. KDFs/HKDF per RFC 5869 where derivation needed. No bespoke primitives anywhere.

## 15. Data Model (normative sketches)

**Passport (SD-JWT VC):** `vct, iss(did:ainra:registrar-07), sub(name), nbf/exp, authority{class∈A1..A4, principal_proof{type,attestor,ref,proof?}}, tier∈L0..L4, capabilities[], scope_ceiling, keys[]{Ed25519, ML-DSA-65}, cnf, status{status_list{idx,uri}}, log{leaf,root,checkpoint}, act_chain[](link hashes), mandates_root, transfer_history[]`. SD-able: capabilities detail, act_chain, proof metadata. Forbidden: PII, scores, prices. ~660 B JSON; ~4.1 KB hybrid-signed **[measured]**.
**Delegation link:** `{parent_sub, child_sub, granted⊆parent, exp≤parent, sig_parent, sig_child, log_leaf}`.
**Mandate:** `{principal_ref, subject_sub, scope, constraints{amount,count,window}, exp, revocation_idx}`; grant and revoke both first-class, subtree-indexed.
**Directory entry:** `{registrar_id, class, endpoints[], keys, status, accredited_at, cert_ref}` — whole directory root-signed.
**TSL delta:** `{list_uri, idx[], new_status, seq, ts, sig_registrar, countersig_delegate}`.
**Checkpoint:** C2SP body (origin, size, root hash) + log sig + witness cosig lines (+ optional chain-anchor proof).

## 16. API Specification (JSON/HTTPS; verify path fully static-capable)

Registrar C5: `POST /issue` (→202 leaf → 200 credential+proof), `POST /revoke`, `POST /transfer-out|in`, `GET /lineage/{name}`, `GET /status-list/{n}`, `GET /deltas?since=` (long-poll/SSE, ETag). Log C2: `GET /checkpoint`, `GET /tile/{L}/{idx}`, `GET /log/entries?…` (tiles suffice; proofs derivable client-side). Root static: `GET /directory.json`, `GET /fresh-head`, `GET /policy/*`. Witness C3: C2SP tlog-witness `add-checkpoint`. Errors: RFC 9457 problem+json with stable `reason` codes matching the INVALID vocabulary in Appendix vectors. Versioning: URI-versioned (`/v1/`), additive-only within a major.

## 17. Network Topology

```
[custodians ×9, air-gapped]──(ceremony only)──▶ signed artifacts
[ops nodes ×3: delegate FROST + status distributor + Tessera writers]──▶
   ├── static host A (tiles/lists/directory)   ├── static host B (independent)
   └── community mirrors (rsync/HTTPS, open)  ──▶ verifiers everywhere (local verify)
[witness 1..n, independent networks] ◀── checkpoints ──▶ cosigs → distributor & mirrors
[registrar-07..n, self-hosted] ──leaves──▶ their shard writer
```
Ports/protocols: HTTPS only externally; mTLS(SPIFFE) between our internal components; witnesses reachable via bastion pattern where operators prefer (litebastion-style). No inbound requirement on verifiers ever.

## 18. Infrastructure Design

Deliberately hostable by a small nonprofit: 3 modest VMs (ops nodes, different providers/regions) + 2 independent static hosts + custodian hardware. **No Kubernetes requirement** — static binaries under systemd; containers offered, never required. Everything rebuildable from the public artifacts + sealed keys (infra-as-code in repo; secrets never in repo). Providers chosen pairwise-diverse (N1 drill kills any one). Community mirrors invited from day one; mirror correctness is cryptographic, not contractual.

## 19. Scalability Strategy

Horizontal by construction: **shard-per-registrar** logs (adding registrars adds capacity — decentralization *is* the scaling plan); TSL segments per registrar; tiles are cache-perfect static content (CDN-able without trust). Measured floors (JS, single-thread — conservative): Merkle 100 k leaves/519 ms; verify crypto ≈5 ms/passport ⇒ ~200/s/core even in JS, ×10–100 native **[measured]**; TSL at I1 = 21.2 KB. Growth table [estimate]: 10 k lineages (Genesis) → 1 M (tens of registrars, no arch change) → 10 M (I1: unchanged verify path; status build ≤5 s; log shards ~dozens). Bottleneck watchlist: delta fan-out (mitigate: tiered relays, mirrors can relay), directory size (mitigate: paginated, still root-signed).

## 20. Reliability & Disaster Recovery

| Path | RTO | RPO | Mechanism |
|---|---|---|---|
| Verification | ~0 (mirrors + cache) | n/a | static artifacts; F-classes fail closed |
| Status freshness (F1) | ≤ delegate failover (min) | 0 | 2-of-3 delegate; hot standby head signer |
| Issuance (per shard) | ≤ 4 h | 0 | log = source of truth; writer redeploy; DB rebuild tool |
| Root functions | next ceremony / emergency ceremony ≤ 7 d | 0 | standby quorum (sealed shares) activation runbook |
Runbooks (repo `/runbooks`): delegate compromise; registrar compromise; witness loss; mirror poisoning; emergency ceremony; standby-quorum activation; regional partition. Chaos suite (§28) exercises each quarterly. Backups: sealed key material per custodian policy; everything else is public by design — **the DR plan for public data is the mirrors**.

## 21. Performance Targets & Benchmarks

| Metric | Measured (JS floor) | P1 target (native) |
|---|---|---|
| Ed25519 sign / verify | 0.544 / 1.924 ms | ≤0.05 / ≤0.15 ms |
| ML-DSA-65 sign / verify | 12.72 / 3.13 ms | ≤2 / ≤0.5 ms |
| SLH-DSA-128s sign / verify | 4 368 / 5.4 ms | ≤1 000 / ≤1 ms (root-rare) |
| Full passport verify (all 4 steps, warm cache) | — | ≥200/s/core; p99 ≤10 ms |
| Log append→inclusion | — | ≤2 s (1 s batches) |
| Revocation propagation | — | p95 <60 s ×3 regions (F4) |
| TSL build @10 M | — | ≤5 s |
| Fresh-head cadence | — | 30 s, jitter ≤5 s |
All **[measured]** rows from Appendix-grade runs 09 Jul 2026 (Node 22, single thread); native targets are gates in CI perf jobs, not hopes.

## 22. Cost Analysis **[all estimates unless noted]**

Root opex/yr: static hosting ≈ $1.2–3.6 k; 3 VMs ≈ $2–5 k; ceremonies (2×/yr, hw+travel) ≈ $20–40 k; external audit (annualized) ≈ $60–120 k; legal/entity/standards participation ≈ $30–80 k; witness honoraria optional ≈ $0–7 k. Infrastructure is deliberately trivial; **people dominate** (3–5 engineers). Revenue at fee cap: 100 k lineages → $10 k/yr; 1 M → $100 k; 10 M (I1) → $1 M — **fees alone sustain the root only ≥ ~5 M lineages**. Bridge (honest): capped founding-member dues (federation model; e.g., 10–20 seats × $25–50 k) + public-interest grants; **no equity, no tokens, no data monetization — charter-prohibited.** Unit economics at I1: root marginal cost per lineage ≈ $0.001–0.01 vs $0.10 ceiling → headroom funds audits/witness program, and the fee-cap object can *ratchet down* (F8).

## 23. Build vs Buy (OSS-reuse)

| Capability | Decision | Rationale |
|---|---|---|
| Threshold signing | Reuse ZF FROST (Rust) | audited, DKG+refresh+repair |
| PQ primitives | Reuse RustCrypto ml-dsa / FIPS-track libs; noble (TS) | audited families; sizes verified **[measured]** |
| Tile log | Reuse Tessera | GA; decade of operator lineage |
| Witnessing | Join ecosystem (omniwitness/litewitness/network) | operating network > invented one |
| SD-JWT VC | Reuse existing libs + our profile | multiple impls exist |
| Token Status List | Thin bespoke (≤300 LoC) over draft-21 | libs immature — flagged dependency risk |
| Core verify/issue | **Build** (`ainra-core`) | this *is* the product; ≤1 kLoC critical |
| Registrar box, resolver, explorer, SDKs | Build (thin) | glue over the above |
| Anything SaaS in verify path | Never | N1/N3 |

## 24. Dependency Analysis

BOM (verify-path): @noble/{curves,hashes,post-quantum} (MIT, audited); ed25519-dalek + RustCrypto ml-dsa (MIT/Apache); ZF frost-ed25519 (MIT/Apache, audited); Tessera + tlog-tiles/note (Apache-2.0); zlib; that's it — **no copyleft in SDK path, no proprietary anywhere**. Registrar-side adds SQLite/Postgres/Litestream (public-domain/PostgreSQL/Apache). Supply chain: lockfiles; `cargo vet`/`cargo audit` + npm provenance; SLSA-3; reproducible builds diffed by ≥2 external builders (M7 gate); Sigstore + independent dual-maintainer offline manifest. **Flagged risks:** litewitness = effectively single-maintainer (mitigation: omniwitness parallel-supported); TSL libraries immature (mitigation: our thin impl + vectors upstreamed); SD-JWT VC draft churn (pinned vct). Update policy: quarterly dep review; security patches ≤72 h with reproducible rebuild.

## 25. Risk Register

| # | Risk | L×I | Trigger | Mitigation / owner |
|---|---|---|---|---|
| 1 | Adoption fails (root conferred to no one) | M×H | no external conferral by the gate dates | pivot ladder (authorship-only → verifier-middleware → honest archive); tech stays useful as a conformance suite |
| 2 | Proto-root with scores entrenches first | M×H | a scoring incumbent reaches root scale first | interop posture: accept their tokens as inputs; facts-vs-scores positioning |
| 3 | SD-JWT VC churn | M×L | draft-17+ breaking | vct pin; claim-level migration |
| 4 | Threshold-PQ never matures | M×M | §31 watch | ceremony cadence acceptable indefinitely; SLH root unaffected |
| 5 | Witness recruitment <3 | L×H | M6 | network onboarding + funded seats + litewitness cheapness |
| 6 | Custodian coercion/loss | L×H | — | 9 seats/≥5 jurisdictions; refresh/repair; standby quorum |
| 7 | Delegate compromise | M×M | monitoring | ADR-002 bounds; revocation drill T-K6 |
| 8 | Spec ambiguity → impl divergence | M×M | differential CI | 3-impl differential is the trap (release-blocking) |
| 9 | Funding gap pre-5M lineages | H×M | §22 | dues+grants bridge; costs deliberately tiny |
| 10 | Solo-founder bus factor | M×H | — | everything public/mirrorable; two-maintainer rule; §30 handover artifacts |
| 11 | Legal attack on neutrality (antitrust/liability) | L×M | — | facts-only outputs; published criteria; counsel review at P2 |
| 12 | Quantum timeline surprise | L×H | NIST advisories | hybrid now; SLH root; agility drill §30 |

## 26. Regulatory & Compliance Considerations

**EU AI Act Art. 50** transparency/machine-readable marking obligations apply from **2 Aug 2026** — AINRA provides standardized identity inputs that help deployers meet marking/disclosure duties; we make **no compliance-guarantee claims** (positioning rule). **eIDAS 2 / EUDI**: SD-JWT VC alignment keeps passports wallet-ecosystem-compatible. **GDPR**: §11 analysis — root holds no natural-person data; registrar-side crypto-shredding reconciles erasure with append-only logs; DPIA template ships with registrar-in-a-box. **DORA/financial verifiers**: our offline-verify + multi-mirror design maps cleanly to ICT-resilience expectations (documentation pack at P2). **NIST CAISI**: track the agent-standards initiative; submit profile alignment (Campaign phase-0). **Export/import**: standard published-crypto exemptions apply; note import-notification regimes (e.g., France) in distribution docs. **Liability posture**: the root publishes verifiable facts and accreditation status only — no scores, no fitness-for-purpose representations; registrar agreements allocate issuance liability to issuers.

## 27. Implementation Roadmap (12 weeks to Genesis)

M1 (wk1–2) `ainra-core` skeleton, schemas, vectors v1, CI+fuzz scaffolding · M2 (wk3–4) Tessera shard deployment + checkpoint pipeline + witness onboarding applications filed · M3 (wk5–6) TSL + deltas + delegate signer (ADR-002) + registrar-in-a-box α · M4 (wk7) FROST integration end-to-end + **public rehearsal ceremony** · M5 (wk8–9) verifier middleware + TS SDK + explorer on live testbed; ≥3 external verifier candidates engaged · M6 (wk10) adversarial program green; injected-fork drill with real witnesses · M7 (wk11) reproducible builds ×2 external builders; mirrors live; docs freeze · M8 (wk12) **Genesis ceremony** + 14-day measured soak → §29 DoD review. Dependencies: witness onboarding (start M2, longest external lead); custodian recruitment (start now).

## 28. Validation & Testing Strategy

**Fuzzing:** cargo-fuzz (SD-JWT/JWT parser structure-aware, tile/proof parser, TSL codec, chain evaluator) + Jazzer.js on SDK — **72 CPU-h/release, zero crashes/UB**, corpus versioned. **Property tests:** P-1 verify∘sign=VALID; P-2 no chain ever widens scope/extends expiry (10⁶ random chains); P-3 revoked-link ⇒ subtree INVALID; P-4 TSL round-trip bit-exact; P-5 canonical encoding stability. **Differential:** Rust core vs P0 Node CLI vs TS SDK on the 10 k-vector corpus — **100 % verdict agreement or the release blocks.** **Fault injection:** log equivocation → witness alarm ≤1 interval; tile corruption → clean failure; revoke-vs-verify races; root-dark drill (F1 fails closed, F2/F3 unaffected). **Key drills:** lineage rotate <5 min; registrar cert revocation + auto blast-radius report; custodian share refresh/repair; malicious FROST participant excluded via ROAST; delegate revocation (T-K6). **Red team scripts:** out-of-ceiling issuance; downgrade; replay; squat; stale-mirror; 4-custodian unauthorized-sign attempt (must fail cryptographically, visibly). **Load/chaos:** targets of §21; witness loss; partitions; ±10 min skew. **Neutrality conformance:** quarterly fork drill (scripted + third-party); S7 linter (CI greps fixtures for real names); mechanical-ordering test; vendor-kill drill; fee-cap monotonicity test. **Formal (stretch, M8+):** Tamarin/ProVerif model of presentation binding/replay. **Gates:** all above + BOM/license audit + SAST + secret-scan + reproducible-build match + two-maintainer sign-off.

## 29. Prototype Specification — Genesis testbed (Definition of Done)

☐ Recorded 5-of-9 FROST DKG + SLH-DSA ceremony (≥3 people, ≥5 machines, ≥5 jurisdictions' custodians; transcript hash published) ☐ Delegate certified and rotating ☐ 2 registrar classes issuing (org-tier box + permissionless-lane ERC-8004 gateway) ☐ ≥3 external verifiers passing conformance (≥1 not written by us) ☐ Revocation p95 <60 s, 3 regions, 14 days continuous ☐ ≥3 independent witnesses; injected fork **caught by them** ☐ Outsider fork drill from public artifacts ☐ Differential parity 100 % ☐ Fuzz budget met ☐ Trust ledger §12 externally reviewed ☐ `make genesis-local` on a clean laptop ☐ ≥2 non-us mirrors byte-verified. (Supersedes the P1 doc's DoD only via ADR-001/002/005 deltas; everything else carries.)

## 30. Production Migration Plan (Genesis → production root)

Custodians 5-of-9 → **7-of-13 across member organizations**; delegate certs shortened + HSM attestation; registrar HSM profile mandatory ≥L3 issuers; **DNSSEC anchor** added (belt on braces, ledger row 8 retired); **permissionless witness policy** + hardware witnesses (ArmoredWitness-class) — ledger row 2 retired; two independent security audits (different firms/jurisdictions) with published reports; public bug bounty; annual **algorithm-agility drill** (rotate a suite end-to-end in staging); transparency report cadence (ceremonies, incidents, fee object history); governance handover per federation statutes (founding table ratifies suite policy + fee object); production SLOs promoted from §21 with public dashboards rendered from witnessed data.

## 31. Future Research Areas

Threshold post-quantum signing (TALUS/Trilithium line) to retire ledger row 3 · PQ anonymous credentials / BBS-family for A1 without trusted setup (retire row 9) · STARK-based privacy-preserving inclusion queries (verify membership without revealing which lineage) · aggregate/compressed witness cosignatures · Roughtime deployment (retire row 7) · dedicated AINRA hardware witness · CRLite-cascade status at >10⁸ · mdoc/CWT profile for wallet ecosystems · formal verification of the full verify state machine · registrar bond/slashing economics design.

---
**Appendix — measurement record (09 Jul 2026, Node 22, single thread, conservative floors):** Ed25519 0.544/1.924 ms sign/verify, 32/64 B · ML-DSA-65 12.72/3.13 ms, pk 1 952 / sk 4 032 / sig 3 309 B (exact FIPS 204) · SLH-DSA-SHA2-128s keygen 668 ms, sign 4 368 ms, verify 5.4 ms, pk 32 B, sig 7 856 B; 128f sign 245 ms, sig 17 088 B · hybrid leaf sig 3 373 B · Merkle 100 k/519 ms; 1 M-proof 640 B · TSL 10 M: 1 221 KB→21.2 KB gz (0.1 % revoked), empty 1 245 B · passport 660 B / ≈4.1 KB signed · tamper-rejection asserted true for all three schemes. **Standards register:** FROST RFC 9591 · SD-JWT **RFC 9901** · SD-JWT VC draft-16 · Token Status List draft-21 · HTTP Message Signatures RFC 9421 · FIPS 204/205 final · SLH-DSA X.509 **RFC 9909**, CMS RFC 9814 · FN-DSA not final (≥ late 2026) · Tessera GA · C2SP checkpoint/tlog-tiles/tlog-witness · witness-network.org onboarding live.
*End. Build order: M1. First public event: the rehearsal ceremony.*
