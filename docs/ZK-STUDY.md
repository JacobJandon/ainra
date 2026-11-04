<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# AINRA and zero-knowledge proofs: a study

Date: 2026-11-04. Status: a study and a recommendation, not a decision. Repo state read: `13b0509` plus the work
that became D-089 ("A1 means a checked principal proof"). The operational texts it found wrong (`docs/IDENTITY.md`,
the A1 and L3 explanations on the site and in `apps/landing`) were corrected the same day; the normative ones wait
for the amendment D-090 proposes.

Rules this document keeps:
- Every outside fact has a URL.
- Every fact about AINRA names the repo file it comes from, and was checked against code, not only docs.
- **UNCONFIRMED** marks anything not checked against a primary source.
- Most performance numbers come from the people who built the system. Read them as "the authors report".
- No company or commercial product is named (S7). Systems are named by role, or by the standard, RFC, draft or
  research paper that defines them. Sources stay as URLs.
- Decision numbers: **D-090** (claims match the code, and a leak ledger) and **D-091** (one network-wide status file)
  are recorded in `docs/DECISIONS.md` as PROPOSED; the operator rules on both.

---

## Summary

1. **AINRA already solves most of what it promises without zero-knowledge.** Verification is offline. Status lists are
   fetched whole, or carried by the agent. Everything is logged before it is valid. The root holds no personal data.
   None of this needs ZK, and ZK would not make any of it stronger.

   **Post-quantum coverage is partial, and the repo should say so.** Passports, delegation hops, status lists and the
   registrar half of each status delta are hybrid Ed25519 + ML-DSA-65, both-or-invalid
   (`crates/ainra-core/src/crypto.rs` `verify_hybrid`). The directory is signed by both ceremony roots, FROST Ed25519
   and SLH-DSA (`directory.rs`). But the **online freshness and witness layer is classical**: fresh heads
   (`status.rs` `FreshHead.sig_delegate`), delegate-mode checkpoints (`checkpoint.rs`, `sig_ed25519`), the delegate
   half of each delta, and witness cosignatures (`kits/witness/README.md`, `GET /key` returns an Ed25519 key) are all
   Ed25519 only. Delegate certificates are SLH-DSA, so a quantum attacker cannot mint a delegate, but one who breaks
   a delegate's Ed25519 key could forge heads and checkpoints inside that certificate's window (≤ 92 days). What
   exactly that enables against a verifier is not analysed (UNCONFIRMED).

2. **Four things the repo says about privacy or delegation are not true of the code today.** These matter more than
   any ZK plan.
   - **The passport is not an SD-JWT, and there is no selective disclosure.** The docs call it "an SD-JWT verifiable
     credential, so a holder may disclose one field without revealing the rest" (`docs/IDENTITY.md` §1). The wire
     object is plain JSON: base64url claims plus a separate `{ed25519, mldsa65}` signature object
     (`docs/WIRE-FORMAT-PRIMER.md` §1). There is no JWS header, no `alg`, no `typ`, no compact serialization, no salted
     disclosures and no KB-JWT. Every field is always shown.
   - **"Human backing is proven in zero-knowledge" is not something AINRA does.** No ZK proof is checked anywhere in
     AINRA's code. The A1 path is `kits/personhood` (D-066): it reads an on-chain registry and puts a SHA-256 digest
     of the evidence on the wire. Since D-089 the registrar refuses A1 unless a pluggable checker accepts the
     evidence, which makes A1 real, but still not zero-knowledge on AINRA's side.
   - **The trust ledger lists a ZK plugin that does not exist.** MTS §12 row 9 covers a "Groth16 setup (A1 demo
     plugin)". No Groth16 or group-membership proof code exists in `crates packages kits services apps tools`. Its
     planned replacement, "BBS / PQ-anon-creds", includes BBS, which is not post-quantum.
   - **The delegation depth cap is claimed but not enforced.** Standard §6 (A3) says "depth capped (default 3)" and
     §10 lists "depth caps" as a defence. No implementation enforces a hop limit (`chain.rs`, `verify.rs`,
     `packages/sdk-ts/src`, `services`).

3. **The real privacy leak is in who fetches what, and it is narrow.** By default the agent brings its own signed
   status list inside the bundle (`WIRE-FORMAT-PRIMER.md` §1), and in currency mode its fresh head too (D-086;
   `packages/sdk-ts/src/index.ts` `fresh_head`). The registrar then learns only that its agent refreshed. The leak
   appears only when a verifier fetches a registrar's list itself. `heads.json` from `tools/publish-static.mjs`
   already covers every registrar in one file, but the list files it points to (`<registrar>/status-list.json`,
   `sha256/<digest>`) are per registrar, so the host learns which registrar's agents that verifier checks. No SDK
   fetches status today; the fix is a network-wide file for whoever does fetch, with no new signing key.

4. **ZK would add something real in only a few places, and none of them belongs in the root or the frozen core
   today.** The places:
   - checking a delegation chain without seeing it;
   - letting the registrar check facts about the human principal, such as age or residence from a government wallet
     credential (verifiers would still see only a digest);
   - later, unlinkable revocation for principals.

   Every one is research-grade or classical-only. Every one conflicts with at least one of: hybrid post-quantum
   signatures, header-size limits, the four-implementation rule, or simple published rules.

5. **Recommendation (ranked; full list in §4).**
   - **Now:** (1) correct every privacy and delegation claim by the normative amendment path, and gate the words so
     they cannot drift back; (2) make privacy measurable with a leak ledger and its witness, `make leak-ledger`
     (D-090); (3) publish one network-wide, unsigned, content-addressed status file for verifiers that fetch
     (D-091); (4) decide the depth cap: correct the text now, enforce later only by its own decision; (5) write down
     what the classical online layer exposes to a quantum attacker.
   - **Watch:** hash-based ZK over ML-DSA, and a registrar-side ZK principal checker behind `AINRA_PRINCIPAL_CHECKER`.
   - **Refuse:** ZK in the root, BBS, pairing or trusted-setup proofs in the core, unlinkable agent passports, and
     any "model proven" claim.

---

## 1. Zero-knowledge in plain words

**The one-sentence version.** A zero-knowledge proof lets you convince someone a statement is true without showing
them the data that makes it true.

**An everyday picture.** You want to prove you know the combination to a locked box without telling anyone the
combination. You take the box behind a curtain, open it, and bring out the note your friend locked inside that
morning. Your friend is convinced you can open it and still does not know the combination. A ZK proof does this
with mathematics instead of a curtain. It also works when the verifier is a stranger on another continent who
checks the proof alone, later, offline.

**What a proof proves.** Always a precise statement of the form "I know hidden data X such that a public check C(X)
passes". Examples:
- "I hold a document signed by an accredited registrar, its tier is at least L2, and it is not revoked." The hidden
  data is the document and its signature. The check is "signature valid, tier ≥ L2, status bit = 0".
- "I am one of the people in this registered set." The hidden data is which one.

The check C is written as a **circuit**, a program in a restricted form that the proof system can reason about.

**Three properties every proof system claims:**
- **Complete:** a true statement can always be proven.
- **Sound:** a false one cannot, except with negligible probability.
- **Zero-knowledge:** the proof reveals nothing beyond "the statement is true".

**Words that get mixed up:**
- **Selective disclosure:** show some signed fields, hide the rest. Signed salted hashes do this, with no ZK needed
  ([RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html)).
- **Unlinkability:** two showings of the same credential cannot be tied together. Salted hashes cannot give this,
  because the same signature appears every time. RFC 9901 §10.1 says so, and the EU wallet Architecture and Reference
  Framework says the "only viable mitigation is to adopt Zero-Knowledge Proofs"
  ([IETF 124 CFRG slides, quoting ARF 2.4.0](https://datatracker.ietf.org/meeting/124/materials/slides-124-cfrg-longfellow-zk-01)).
- **Predicate:** proving something *about* a field, such as "age ≥ 18", without the field itself. This needs a real
  ZK proof.
- **Trusted setup:** some proof systems (Groth16, used by most on-chain group-membership schemes) need secret
  parameters made once in a ceremony. Whoever keeps those secrets can forge proofs.
- **Transparent:** no trusted setup. Hash-based systems such as Ligero, STARKs and Aurora are transparent.
- **Post-quantum:** proofs built only on hash functions are plausibly safe against quantum computers. Proofs built on
  pairings or elliptic curves (Groth16, BBS, Curve Trees) are not.

**What ZK cannot do.** This is the part people skip.
- **It proves the circuit, not the world.** If the statement is "the registry says a human backs this wallet", the
  proof is only as good as the registry. If the statement is "this output came from weights with hash H", something
  outside the proof still has to say what H is.
- **It does not make a weak signature strong.** A post-quantum proof about an ECDSA signature still falls when ECDSA
  falls.
- **A circuit bug is a forgery bug.** The circuit is new code that decides validity, and it is much harder to review
  than an ordinary verifier. Reviews of a proof *scheme* do not cover the circuits written on top of it. For the
  best-reviewed system in this study (the CFRG hash-based draft below), two reviews report "No issues raised wrt to
  the ZK scheme", one done and one reported as forthcoming
  ([IETF 124 CFRG slides](https://datatracker.ietf.org/meeting/124/materials/slides-124-cfrg-longfellow-zk-01)). Its
  formal proofs cover a mathematical model, not the code, with one zero-knowledge (privacy) property still unproven:
  "full V2 joint-view zero knowledge remains open"; "These results do not constitute source-level verification of
  the Rust or C++ implementation" ([the system's repository](https://github.com/google/longfellow-zk)).
- **It costs something.** Proofs are kilobytes to megabytes, proving takes milliseconds to minutes, and every
  verifier needs the same circuit and parameters.

---

## 2. The state of the art (sourced)

### 2.1 Credentials: selective disclosure and anonymous credentials

| Scheme | Unlinkable across showings | Proof size | Post-quantum | Standards status (Nov 2026) | Deployed |
|---|---|---|---|---|---|
| SD-JWT ([RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html)) | No; only one-time batches help | small | Yes if signed with ML-DSA (RFC 9901 §9.1 leaves the algorithm open) | RFC, Proposed Standard, Nov 2025 ([datatracker](https://datatracker.ietf.org/doc/rfc9901/)). SD-JWT VC -23 is in IESG evaluation with a DISCUSS, on the 5 Nov 2026 telechat ([datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)) | EU wallet PID format ([ETSI TR 119 476-1](https://www.etsi.org/deliver/etsi_tr/119400_119499/11947601/01.03.01_60/tr_11947601v010301p.pdf)) |
| ISO mdoc | No | small | No (ECDSA) | ISO/IEC 18013-5/-7 | Mass deployment in phone wallets ([press report](https://techcrunch.com/2025/04/29/google-wallet-to-add-support-for-digital-ids-in-more-states)) |
| Hash-based ZK over an existing ECDSA credential (`draft-irtf-cfrg-longfellow`) | Yes | ~300 KB for 60+ attributes ([independent comparison](https://eid-privacy.github.io/wp0/2025/11/28/crescent-longfellow-showdown.html)); 357–362 KB in a third-party wrapper ([wrapper](https://github.com/Alik-eth/zk-eidas), unaudited) | Proof system plausibly yes; the ECDSA statement inside it is not | CFRG Active RG Document -00, Informational ([datatracker](https://datatracker.ietf.org/doc/draft-irtf-cfrg-longfellow/)). Independent second implementation ([repository](https://github.com/abetterinternet/zk-cred-longfellow)) | Phone-wallet age checks ([IETF 124 slides](https://datatracker.ietf.org/meeting/124/materials/slides-124-dispatch-longfellow-zero-knowledge-credentials-00)). For **age verification only**, the EU portal's own summary says "Zero-Knowledge Proof is now defined as the mandatory presentation mechanism, with plain mDoc presentation as fallback" ([ageverification.dev](https://ageverification.dev)); the wording in the underlying spec is UNCONFIRMED, and it is not an EUDI PID rule |
| Same, over an ML-DSA signature | Yes | **not published** | Yes (our analysis) | none; a benchmark only: ML-DSA-44 proof of possession, 858 ms to prove on a 2024 laptop processor ([IETF 126 slides](https://datatracker.ietf.org/meeting/126/materials/slides-126-cfrg-longfellow-zk-00)). **The benchmark hides only the signature**: its statement is "Exists (r,s) such that Verify_Internal(pk=(Ahat,t1,tr) sig, mu) = 1", with the public key and `mu` public. Hiding the issuer key (set membership) and hashing hidden claims into `mu` in-circuit (SHAKE-256) are not included; their cost is UNCONFIRMED | none |
| Groth16 over existing credentials (research system, [ePrint 2024/2013](https://eprint.iacr.org/2024/2013)) | Yes | 1–40 KB; sources disagree ([comparison](https://eid-privacy.github.io/wp0/2025/11/28/crescent-longfellow-showdown.html), [EUDI TS4](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts4-zkp.md)) | No (pairings, trusted setup) | none | none found |
| Folding-based ZK over existing credentials (2026 research system) | Yes | 108 kB, 92 ms prove ([paper](https://www.microsoft.com/en-us/research/wp-content/uploads/2026/05/Vega_Low-Latency-Zero-Knowledge-Proofs-over-Existing-Credentials.pdf)) | A rival's authors say no ([IETF 126 slides](https://datatracker.ietf.org/meeting/126/materials/slides-126-cfrg-longfellow-zk-00)); not independently checked | research | none |
| BBS (`draft-irtf-cfrg-bbs-signatures`) | Yes | 80 B signature, 272 + 32·U B proof (U = hidden fields; our arithmetic from [draft -12](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-12.html) §3.5.4, §7.2; **not re-checked against -14**) | Forgery no; privacy everlasting (§6.9) | CFRG -14 (29 Oct 2026), Active RG Document, Informational, not an RFC; no RG last call shown on the datatracker ([datatracker](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)); W3C `bbs-2023` is a Candidate Recommendation Draft with features at risk ([W3C](https://www.w3.org/TR/vc-di-bbs/)) | No large wallet found (UNCONFIRMED absence) |
| CL-signature credentials (the AnonCreds specification) | Yes | multi-KB (UNCONFIRMED) | No | AnonCreds community spec ([spec](https://github.com/hyperledger/anoncreds-spec)) | A national wallet ([source](https://docs.yivi.app/blog/2026-id-cards-driver-licenses)) |
| Lattice anonymous credentials | Yes | tens of KB to 899 KB ([ePrint 2023/560](https://eprint.iacr.org/2023/560), [ePrint 2026/1649](https://eprint.iacr.org/2026/1649)) | Yes | none | none |

**What this adds up to.**
- No standardised post-quantum anonymous credential exists.
- The practical post-quantum route has two layers: the issuer signs with ML-DSA, and the holder proves possession
  with a hash-based ZK proof. It exists only as a benchmark for ML-DSA-44 that hides the signature alone. There is no
  spec and no proof-size figure. AINRA uses ML-DSA-65 (pure ML-DSA, empty context string, deterministic signing;
  `crates/ainra-core/src/crypto.rs` `MLDSA_CTX`), so the -44 numbers do not carry over.
- The EU and the large phone-wallet vendors prefer not to deploy new elliptic-curve schemes. Device binding and legacy
  support "rule out schemes such as the BBS family" (the CFRG hash-based draft's authors,
  [IETF 126 slides](https://datatracker.ietf.org/meeting/126/materials/slides-126-cfrg-longfellow-zk-00)).
- ISO/IEC 27565 (ZK privacy guidance) is reported as published in 2026; the ISO page refused our request, so the
  date is UNCONFIRMED ([ISO](https://www.iso.org/standard/80398.html); secondary: ETSI TR 119 476-1 above).

### 2.2 Status, revocation and logs

- **Bulk lists won.** The largest public certificate authority ended OCSP "primarily because it represents a
  considerable risk to privacy on the Internet" ([Dec 2024](https://letsencrypt.org/2024/12/05/ending-ocsp/)); its
  end-of-life post of 6 Aug 2025 says the same in the past tense
  ([Aug 2025](https://letsencrypt.org/2025/08/06/ocsp-service-has-reached-end-of-life)). A major browser checks every
  Web PKI revocation locally: "an average of 300 kB of revocation data per day", a 4 MB snapshot every 45 days plus
  deltas ([browser engineering blog](https://hacks.mozilla.org/2025/08/crlite-fast-private-and-comprehensive-certificate-revocation-checking-in-firefox/)).
  The underlying paper reports a 6.7 MB package and 26.8 kB per 6-hour delta
  ([ePrint 2025/610](https://eprint.iacr.org/2025/610)); a "every 22 days" figure seen elsewhere is UNCONFIRMED.
- **IETF Token Status List** -21 is in the RFC Editor queue, Proposed Standard, no RFC number yet
  ([datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)). It concedes that the issuer can
  infer verifier activity "from request metadata such as IP address".
- **W3C Bitstring Status List** (Recommendation, 15 May 2025) sets a 131,072-entry minimum for herd privacy
  ([W3C REC](https://www.w3.org/TR/vc-bitstring-status-list/)). The EU's blockchain services infrastructure calls
  direct issuer fetches "not recommended"
  ([EBSI](https://hub.ebsi.eu/vc-framework/credential-status-framework/strategies)).
- **Holder-carried status** (the holder carries a short-lived "still valid" note, so the verifier contacts nobody) is
  an individual IETF draft
  ([draft-demarco-oauth-status-assertions-00](https://ftp.belnet.be/mirror/ftp.ietf.org/internet-drafts/draft-demarco-oauth-status-assertions-00.html)).
  AINRA already does the equivalent: the agent carries its registrar-signed list (§3.2 item 6).
- **ZK non-revocation (accumulators).** Every mature option is pre-quantum:
  - AnonCreds tails files ([reference server](https://www.github.com/bcgov/indy-tails-server));
  - ALLOSAUR ([ePrint 2022/1362](https://eprint.iacr.org/2022/1362));
  - Curve Trees ([ePrint 2022/756](https://eprint.iacr.org/2022/756));
  - the EU wallet signed-pair and accumulator designs, where "no construction dominates in every aspect"
    ([ePrint 2026/1824](https://eprint.iacr.org/2026/1824)).

  The one post-quantum accumulator is a research paper ([ePrint 2025/1099](https://eprint.iacr.org/2025/1099)).
- **Private lookups (PIR/PSM) and relays (Oblivious HTTP, [RFC 9458](https://www.rfc-editor.org/rfc/rfc9458.html))**
  all need a live server at verify time, so they are not offline.
- **Key transparency** is mature and has no post-quantum option.
  - Deployed at three large messaging services, one with a public third-party auditor
    ([1](https://engineering.fb.com/2023/04/13/security/whatsapp-key-transparency/),
    [auditor](https://blog.cloudflare.com/key-transparency),
    [2](https://security.apple.com/blog/imessage-contact-key-verification/),
    [3, launched 11 Aug 2026](https://signal.org/blog/automatic-key-verification/)).
  - The IETF protocol draft (-06) defines only P-256 and Ed25519 suites with ECVRF
    ([datatracker](https://datatracker.ietf.org/doc/draft-ietf-keytrans-protocol/)). The architecture draft is on
    the 3 Dec 2026 telechat ([datatracker](https://datatracker.ietf.org/doc/draft-ietf-keytrans-architecture/)).
  - We found no post-quantum key transparency system. **AINRA is no exception for its online layer**: its fresh
    heads, delegate checkpoints and witness cosignatures are Ed25519 too (Summary item 1). This is not an advantage
    AINRA can claim.

### 2.3 ZK for AI models and agents

- **Proving a model produced an output (zkML) works in research, for small models only.**
  - 13B parameters in under 15 min, proofs under 200 kB ([CCS 2024, arXiv 2404.16109](https://arxiv.org/abs/2404.16109));
    the token count is UNCONFIRMED.
  - A small (under 1.5B-parameter) open language model in under 25 s
    ([USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/qu-zkgpt)).
  - The same model class at 512 tokens in 7.6 min on a 24-core CPU, 10.7 MiB proofs
    ([a zkML library](https://github.com/Lagrange-Labs/deep-prove)).
  - 0.30 s per token on the same model class ([ePrint 2026/199](https://eprint.iacr.org/2026/199)).
  - There is no published proof for a frontier-size model.
  - Proofs cover a quantized copy of the model, not the floating-point model that runs.
- **Proving which model it was is a signing job.** ZK can bind an output to a weights commitment
  ([a zkML library's docs](https://docs.ezkl.xyz/visibility_what_is_private)). Only a publisher's signature can say
  what that commitment *is* ([an open model-signing specification, v1.0](https://blog.sigstore.dev/model-transparency-v1.0)).
- **Proving an agent followed a policy** is at the prototype stage:
  - [ePrint 2026/199](https://eprint.iacr.org/2026/199);
  - [NeurIPS 2026](https://neurips.cc/virtual/2026/173090);
  - an open-source prototype ([repository](https://github.com/dvelton/agentproof)).

  These prove that a logged action sequence meets formal rules. They cannot prove the log is complete. A 2026 paper
  argues signed tool receipts are far cheaper ([arXiv 2603.10060](https://arxiv.org/html/2603.10060)).
- **ZK proof-of-personhood for agents is in beta or on testnets:**
  - A chain proof-of-personhood registry with an agent toolkit ([docs](https://docs.world.org/agents)). The live docs
    still call the toolkit "Beta" and say registry lookup "always resolves against the canonical" deployment on the
    registry's own chain. The toolkit's repo is archived and deprecated as of 20 Oct 2026, with no successor named
    ([repository](https://github.com/worldcoin/agentkit)); only that archived README names a relay on another chain
    for gasless registration. Reports that the toolkit moved into a newer version of the registry's identity
    protocol are UNCONFIRMED.
  - Two personhood-bound agent ID services: one on a testnet
    ([docs](https://docs.celo.org/build-on-celo/build-with-ai/self-agent-id)), one that calls the link "permanent"
    ([site](https://billions.network/kya)).

  The registry's own proofs use Groth16 over BN254 pairings, which are not post-quantum
  ([crate docs](https://docs.rs/world-id-proof/0.5.4/world_id_proof/nullifier)). The curves used by the other two
  services are UNCONFIRMED. None has expiry or one-bit revocation, as we read them; D-066 found the registry
  contract has "no revoke, no unregister and no expiry".
- **ERC-8004** is a Draft and has no agent-identity revocation ([EIP-8004](https://eips.ethereum.org/EIPS/eip-8004)).
- **TEE attestation is the practical alternative for verifiable inference.**
  - Under 5–9% average overhead on current data-centre GPUs in confidential mode
    ([arXiv 2409.03992](https://arxiv.org/html/2409.03992v4)).
  - A 2025 memory-interposer attack used a sub-$1,000 DDR5 interposer to pull attestation keys from patched CPU
    confidential-computing TEEs of both major server CPU vendors
    ([press report](https://securityweek.com/new-attack-targets-ddr5-memory-to-steal-keys-from-intel-and-amd-tees)).

---

## 3. Does AINRA solve verifiability and privacy in AI?

Short answer: **AINRA solves one specific, important slice: who an agent is, who answers for it, whether it is still
allowed, and proof that the record was not rewritten. It solves this without ZK and without an online authority.**
It does not solve what an agent did, whether its model is what it claims, or whether its outputs are true. On privacy
it keeps the human behind the agent away from the root and from verifiers (not from the registrar), and it
deliberately makes the agent itself linkable.

### 3.1 What AINRA already solves without ZK

| Property | How | Where in the repo |
|---|---|---|
| A stranger can verify an agent offline, with no call to the root or anyone else | Directory, status, checkpoint and inclusion proof travel as signed artefacts; the core has no clock and no network | `crates/ainra-core/src/verify.rs` (nine fixed steps); `docs/IDENTITY.md` §3; `docs/CLAIMS.md` `cap.offline` (gate `make verify`, root-dark against committed artefacts) |
| Forging a passport, hop, status list or directory needs both a classical and a quantum break | Hybrid Ed25519 + ML-DSA-65, both-or-invalid, on passports, hops, status lists and the registrar half of deltas; the directory is signed by FROST Ed25519 and SLH-DSA | `crates/ainra-core/src/crypto.rs` `verify_hybrid`; `status.rs` `StatusDelta.sig_registrar`; `directory.rs`; `cap.hybrid` (`make cli-check`). **Limit:** the online freshness and witness layer is classical (fresh heads, delegate checkpoints, delegate countersignatures, witness cosignatures are Ed25519; `status.rs`, `checkpoint.rs`, `kits/witness/README.md`). A quantum break of a delegate key, inside its ≤ 92-day certificate window, could forge heads; what that enables is not analysed (UNCONFIRMED) |
| The record cannot be quietly changed | Logged before valid; RFC 6962 inclusion; witnessed checkpoints | `docs/IDENTITY.md` §5; `cap.logged-before-valid`; `crates/ainra-core/src/merkle.rs`, `checkpoint.rs`. Honest limit: witness operators = **0** (`docs/CLAIMS.md` `witness.operators`), so the split-view guarantee is not yet in force |
| Revocation reaches every verifier without per-credential queries | Whole signed Token Status List, 1 bit per lineage; 21.2 KB gzipped at 10 M lineages and **0.1 % revoked** (MTS ADR-007 and appendix, measured). Size grows with the revocation rate (§3.3 Z3) | `crates/ainra-core/src/status.rs`; MTS ADR-007; `docs/ONLINE-VERIFICATION.md` |
| A stolen running copy is bounded | ≤ 1 h instance credentials, audience- and holder-bound, killed by passport revocation | `docs/IDENTITY.md` §4; `crates/ainra-core/src/instance.rs`; `cap.instance-bounded` |
| The root holds no personal data | Charter P4; passport schema refuses PII keys recursively | `GOVERNANCE-AMENDMENT.md` (P4); `crates/ainra-core/src/passport.rs` `FORBIDDEN_KEYS` |
| The human behind an A1 agent stays private **from the root and from verifiers** | The registrar holds the evidence; the wire carries a SHA-256 digest. Each binding names one agent key, so two agents of the same human get different digests. **Limits:** the registrar holds the wallet and can link every agent of one human; the wallet-to-human mapping is public on the chain registry itself (`lookup(address) → uint256`) | D-066; D-089; `kits/personhood` |
| A1 means something was checked | Since D-089 the registrar refuses A1 with no checker configured, refuses evidence the checker rejects, and writes only the proof the checker derived | D-089; `services/ainra-services/src/registrar_principal.rs`; `services/ainra-services/tests/a1_principal_door.rs`; `kits/personhood` `check-stdin` |
| No online service is designed to become an authority | Static artefacts first; the hosted verifier is designed to sign receipts, keep aggregates only, and refuse lookup or listing. **Designed and gated locally (`make online-verifier-check`); not deployed** ("They are not in force today: nothing is deployed"); aggregate-only logging is a policy | D-079; `docs/ONLINE-VERIFICATION.md` |
| What gates decided is tamper-evident without collecting decisions centrally | Gate-signed decision chain; the registrar sees a head digest only | D-079, D-081; `crates/ainra-core/src/decision.rs` |
| Delegation laundering is caught | Dual-signed, narrowing, logged hops. **No depth limit is enforced** (§3.2 item 4) | `crates/ainra-core/src/chain.rs`; D-009, D-012 |

**Verifiability in AI, honestly scoped:** AINRA makes the *identity and accountability input* to a decision
verifiable. That is the part every other agent-identity system in §2.3 either lacks (revocation, expiry) or provides
only within one platform. It is a real contribution and it needs no ZK.

### 3.2 What AINRA does not solve

**Claims the repo makes that the code does not back. Fix these first.**

1. **The passport is not an SD-JWT, and there is no selective disclosure.**
   - What the code does: the issuer hybrid-signs the canonical JSON of the *entire* claim set (`verify.rs` step 4,
     `crypto::verify_hybrid(&reg.issuer_key, pres.claims, …)`; `WIRE-FORMAT-PRIMER.md` §1 and §3). The wire object is
     plain JSON (base64url claims plus a `{ed25519, mldsa65}` signature object), not a JWT: no JWS header, no `alg`,
     no `typ`, no compact serialization. A search finds no `sd+jwt` or `dc+sd-jwt` type anywhere; the only JWT in the
     repo is the status-list compatibility copy. There are no `_sd` digests, no disclosures and no KB-JWT in
     `crates`, `packages/sdk-ts/src`, `packages/sdk-py/ainra` or `services`. The passport reuses some JWT and SD-JWT
     VC claim names (`vct`, `iss`, `sub`, `nbf`, `exp`, `cnf`, `status`). Holder binding is the RFC 9421 presentation
     signature (D-062), not a KB-JWT.
   - Consequence: every verifier sees the operator label, capabilities, scope ceiling, every delegation hop (names
     and grants), mandates and transfer history. `docs/CLAIMS.md` states that a capability cannot be claimed without
     a gate, and this claim has none.
   - **Every text that makes the claim** (checked by grep, 2026-11-04):
     - `docs/IDENTITY.md` §1 (line 14);
     - Standard §5 (line 50: "An SD-JWT verifiable credential; selective disclosure by field"), §10 (line 95:
       "selective disclosure"), closing line 131 ("selective-disclosure credentials");
     - MTS line 31 (opening summary: "SD-JWT VC passport … with selective disclosure"), §11 (line 165: "Selective
       disclosure (SD-JWT) lets an agent prove tier+capability without revealing full act_chain"), §15 (line 202:
       "Passport (SD-JWT VC)" and the "SD-able" list);
     - **MTS ADR-004** (line 92: "SD-JWT VC … + KB-JWT holder binding + X.509 bridge profile — HELD"; neither the
       KB-JWT nor the X.509 bridge exists in `crates`, `packages/sdk-ts/src` or `services`);
     - the site copies `site/standard.md` and `site/AINRA_I_The_Standard.md`, and `site/docs.html`;
     - `apps/landing/index.html` lines 455 ("SD-JWT VC" and "ZK PROOFS" in the standards strip) and 736 ("SD-JWT
       VERIFIABLE CREDENTIALS … Selective disclosure means the agent proves exactly the fields…").
2. **"Proven in zero-knowledge" is not something AINRA does.**
   - AINRA checks no ZK proof anywhere. `kits/personhood` reads a registry with `eth_call` pinned to a block and
     checks an EIP-191 wallet signature that binds the registrar and the agent key (D-066). Any ZK happened earlier,
     inside the registry's own system.
   - The registrar now requires a checked principal proof through `AINRA_PRINCIPAL_CHECKER` (D-089). No checker
     configured means A1 is refused by name, never downgraded.
   - D-066 records that the positive binding path was never proven live.
   - The registry's toolkit repo is archived and deprecated. The contract and the live docs still point at the same
     chain D-066 configured, so nothing needs re-choosing (§4 item 6).
   - **Spec says a structured proof; code has a string.** MTS ADR-011 (line 106) and §15 describe
     `principal_proof = {type, attestor, ref, proof?}`. The code has `principal_proof: String` inside a
     `deny_unknown_fields` struct (`passport.rs` line 56). Adding type or attestor metadata later is a wire change.
   - The constitutional rule P4 ("holds no personal data", `GOVERNANCE-AMENDMENT.md`) still holds, because the root
     sees only a digest. What is wrong is the *mechanism* sentence, not the prohibition.
   - **Every text that makes the claim:** Standard §1 P4 gloss (line 34), §6 A1 (line 71), §7 L3 row (line 84,
     "+ zero-knowledge principal"), §10 (line 95, "zk principals"); `docs/IDENTITY.md` §2 (line 47); MTS §11
     ("A1 proofs reveal personhood/authority, not identity"); the site copies of the Standard;
     `site/foundation.html` lines 784, 802; `site/verify.html` lines 624, 678, 824, 842; `apps/landing/index.html`
     lines 590, 614, 739 ("ZERO-KNOWLEDGE PROOFS"), 818, 1145, 1164.
3. **Trust ledger row 9** (MTS §12, line 182) describes a Groth16 demo plugin that is not in the code (MTS line 20
   and ADR-011 also describe it). Its removal path names "BBS / PQ-anon-creds" (also MTS §31, line 318). BBS is not
   post-quantum ([draft -12 §6.9](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-12.html)), so it
   cannot be a removal path in a hybrid post-quantum design.
4. **The delegation depth cap is not built.** Standard §6 A3 (line 73): "depth capped (default 3)"; §10 (line 95):
   "dual-signed narrowing chains, depth caps". No hop limit exists in `crates/ainra-core/src/chain.rs`, `verify.rs`,
   `packages/sdk-ts/src` or `services`. A chain of any length that narrows and is dual-signed and logged verifies
   today.

**Gaps that are real but by design, or out of scope:**

5. **Agents are linkable on purpose.** The name `ainra:{registrar}:{operator}:{lineage}@{version}` is in every
   presentation (`crates/ainra-core/src/name.rs`). The verdict event and decision records carry it
   (`docs/PRESENTATION.md`, D-079). MTS §11 calls this a deliberate trade-off: "agents are accountable; principals
   are private". We agree with it.
6. **Fetch metadata on the verifier-fetches path.** By default the presenter carries the registrar-signed status
   list (`status_list`, `status_len`, `status_issued_at`, `freshness`; `WIRE-FORMAT-PRIMER.md` §1) with its hybrid
   status signature (`index.ts` `status_sig_ed25519`, `status_sig_mldsa65`). In currency mode it also carries a fresh
   head (D-086; `packages/sdk-ts/src/index.ts` lines 915, 1141); outside currency mode the fresh head is optional.
   The registrar then learns only that its agent refreshed, never who verified. This is the holder-carried pattern
   of §2.2, already built.

   A verifier that fetches for itself does leak. Examples: a gate wanting a head newer than the one the presenter
   brought (the D-086 c03 limit), a mirror consumer, a `/v1/events` subscriber, or the MCP tool. `heads.json` is
   already network-wide (`tools/publish-static.mjs` takes repeated `--registrar` flags and writes one file holding
   `registrars: {id → digests}`). The leak is the follow-up fetch of `<registrar>/status-list.json` or
   `sha256/<digest>`, which names the registrar. So the host learns which registrar's agents this verifier deals with.

   No SDK fetches status today: `packages/sdk-ts/src`, `packages/sdk-py/ainra` and `packages/middleware/src` contain
   no fetch of status or heads. The only fetching package is `packages/mcp/src/tools.mjs`, and it fetches
   `directory.json` and `roots.json`.

   Three texts are true about the agent and silent about the registrar: `docs/SETTLERS.md` line 310 ("AINRA has no
   minimum list size and does not need one"), MTS §11 ("a verifier's fetch reveals nothing about which agent it
   checks") and `docs/ONLINE-VERIFICATION.md` line 26 ("a fetch says nothing about which agent is being checked").
7. **What agents did.** The record "shows what exists, never what agents did" (`docs/IDENTITY.md` §5). Gate decision
   records (D-079) are local to each gate. Nothing proves an action was right, authorised in substance, or complete.
8. **Model identity.** Standard §7 (line 83) requires "declared model lineage" for L2. The passport has no field for
   it (`passport.rs`, `deny_unknown_fields`). We found no place it is carried, so where L2 model lineage is recorded
   is UNCONFIRMED.
9. **Proving the verifier ran unmodified code.** D-024 says binding the binary "needs TEE/ZK, out of scope". That is
   still true.
10. **Who the hosted verifier would see.** As designed, `POST /v1/verify` receives the whole passport, and "don't log
    it" is a policy, not cryptography (D-079, `docs/ONLINE-VERIFICATION.md`). It is not deployed. The answer stays the
    existing one: run the verifier locally.

### 3.3 Where ZK would genuinely add something

Each candidate lists what it would give, its cost, whether it is post-quantum, how mature it is, and its conflicts
with AINRA's rules. The rules, from the repo:
- **R-PQ:** hybrid both-or-invalid (`docs/CRYPTO-AGILITY.md`).
- **R-OFF:** offline, root-dark verification (`cap.offline`).
- **R-WIRE:** frozen, hash-pinned wire format (`docs/FREEZE.sha256`, `GOVERNANCE.md`); changes need a decision
  record and a new corpus.
- **R-SIMPLE:** simple published rules; four independent implementations must agree on the corpus (`GOVERNANCE.md`,
  `make diff`).
- **R-ROOT:** no online root and no root console (D-034, P1–P6).

**Z1. "Accredited at ≥ L2", without revealing registrar, operator or lineage.**
- *Gives:* a verifier learns a tier floor and "not revoked" and nothing else.
- *Cost:* the circuit must prove, inside ZK:
  - an issuer hybrid signature (ML-DSA-65 **and** Ed25519) under *some* key in the directory, which is a
    set-membership proof over the directory;
  - the leaf hash and RFC 6962 inclusion under a checkpoint whose signature is either checked in-circuit or shared
    network-wide;
  - the status bit and the status list's own hybrid signature;
  - the validity window.

  No one has published costs for this combination. The only post-quantum data point is ML-DSA-44 proof of
  possession, 858 ms to prove, and that benchmark hides only the signature: the public key and `mu` are public
  ([IETF 126](https://datatracker.ietf.org/meeting/126/materials/slides-126-cfrg-longfellow-zk-00)). Set membership
  over issuer keys, in-circuit SHAKE-256 over hidden claims, ML-DSA-65, Ed25519 and SLH-DSA in-circuit costs are all
  UNCONFIRMED. Proofs from comparable systems are hundreds of KB.
- *PQ:* possible only with a hash-based proof system, and only if both halves of the hybrid are proven.
- *Maturity:* none.
- *Conflicts:*
  - It **breaks accountability**, which is the product. A verifier that cannot see the registrar cannot apply
    graduated distrust (D-044), cannot name the agent in a decision record (D-079), and cannot tell two agents
    apart.
  - It conflicts with R-WIRE, because it needs a new presentation type and the `sub` name carries the registrar
    itself.
  - It conflicts with R-SIMPLE, because four implementations of a circuit verifier are not realistic.
  - It conflicts with header limits. Bundles are already ~62 KB (`docs/PRESENTATION.md`, measured by
    `make identity-e2e`), and a fresh proof per request cannot use send-once-by-digest (D-065), since unlinkability
    means each proof is new.
- **Verdict: refuse for agents.** It may make sense one day for principals.

**Z2. Unlinkable presentations.**
- *Gives:* two verifiers cannot tell they saw the same agent.
- *Cost, PQ, maturity:* as Z1, plus a fresh proof every time.
- *Conflicts:* it contradicts the named passport and MTS §11's stated trade-off.
- **Verdict: refuse for agents.** Accountability needs linkage. For principals, D-066's per-agent binding already
  stops verifiers linking a principal across agents through the digest. It does not stop the registrar, which holds
  the wallet, and it does not hide the wallet's registration on the public chain registry.

**Z3. Status checks that do not reveal which credential.**
- *Gives:* the status host learns nothing about which credential is checked.
- *Reality:* AINRA already gets this from whole-list download, or better, from the agent carrying its own list. The
  verifier knows which credential, but it has the name anyway. The residual leak (§3.2 item 6) is *which registrar*,
  and a network-wide file closes it without ZK (§4 item 3).
- *Size, honestly:* 21.2 KB at 10 M lineages and 0.1 % revoked (MTS appendix, measured; 1,221 KB raw). Compressed
  size grows with the revocation rate. The information-theoretic floor at 1 % revoked is about 100 KB for 10 M bits
  (binary entropy of 0.01 ≈ 0.081 bits per bit), and zlib will land above that; **not measured**. The wire carries
  it as base64url, about +33 %. At F1 (30 s) a whole-list refresh is about 2,880 downloads a day. So a self-fetching
  F1 verifier should take signed deltas (`status.rs` `StatusDelta`, scope `delta-countersign`), not the whole file
  every 30 s.
- *Accumulators:* not post-quantum when mature, and post-quantum only in research
  ([ePrint 2025/1099](https://eprint.iacr.org/2025/1099)). They add holder state and online witness updates.
- **Verdict: refuse ZK here; do the network-wide file (§4 item 3), and measure it at 1 % revoked.**

**Z4. Checking a delegation chain without seeing it.**
- *Gives:* "this agent's authority descends, through N dual-signed, narrowing, logged hops, from an A1/A2 anchor",
  without revealing who delegated to whom. (The Standard's cap of 3 hops is not enforced today, §3.2 item 4.) The
  delegation graph is business-relationship data, and today every verifier sees all of it.
- *Cost:* per hop, two hybrid signatures (Ed25519 and ML-DSA-65 for each party) plus a narrowing check plus an
  inclusion proof, all in-circuit, with the party keys hidden. For 3 hops that is 6 ML-DSA-65 and 6 Ed25519
  verifications, plus key set membership and in-circuit hashing that no benchmark covers. Unbenchmarked; our estimate
  is seconds of proving and hundreds of KB.
- *PQ:* only hash-based.
- *Maturity:* none.
- *Conflicts:* R-WIRE (new presentation type), R-SIMPLE, header size.
- *Cheaper non-ZK partial:* real salted-hash selective disclosure (RFC 9901) for fields a verifier does not need
  to *check*, such as `transfer_history`. It needs a new `vct` and a corpus, because today's passport is not an
  SD-JWT at all. It does not help with the chain, which the verifier must check.
- **Verdict: the strongest agent-side ZK use case. Watch it.** It becomes worth a design once a hash-based ML-DSA-65
  proof with hidden keys has a spec and published sizes, and once the depth cap is settled.

**Z5. Facts about the human principal, checked by the registrar.**
- *Gives:* an A1 passport whose registrar has checked, for example, "adult, EU resident" from a government wallet
  credential, without the registrar seeing the person's data. **Verifiers still check no ZK proof.** They see the
  same opaque `principal_proof` digest as today and trust the registrar's check.
- *How it fits:* it would be one more checker behind `AINRA_PRINCIPAL_CHECKER` (D-089), the interface
  `kits/personhood check-stdin` already uses: `{registrar, holder, evidence}` in, `{ok, principal_proof}` or
  `{ok:false, reason}` out. No new mechanism. Its output must fit the opaque `principal_proof: String`; any
  structured proof (`{type, attestor, ref, proof?}` as ADR-011 describes) means a new `vct` and corpus.
- *Cost:* paid at the registrar, once at issuance. An independent comparison reports 1.17 s to prove and 0.68 s to
  verify on a 2021 mid-range phone, about 300 KB, for more than 60 attributes
  ([comparison](https://eid-privacy.github.io/wp0/2025/11/28/crescent-longfellow-showdown.html)). Verifiers pay
  nothing.
- *PQ:* the proof system plausibly yes; the ECDSA credential underneath no. That is acceptable as registrar-side
  evidence, outside the hybrid core, which is how D-066 already treats its upstream registry.
- *Maturity:* deployed in phone wallets for age checks. The EU makes ZK the mandatory presentation for **age
  verification only**, per the portal's summary ([ageverification.dev](https://ageverification.dev)); the underlying
  spec wording is UNCONFIRMED. The draft (`draft-irtf-cfrg-longfellow`) is a CFRG RG document, Informational, with an
  independent second implementation ([repository](https://github.com/abetterinternet/zk-cred-longfellow)). A
  registrar would have to act as a wallet relying party; the EU relying-party registration requirements are
  UNCONFIRMED.
- *Conflicts:* none with R-WIRE, R-OFF, R-ROOT or R-SIMPLE, because it lives in a kit behind the checker interface.
  It would let a registrar use a government-backed credential instead of one chain's registry.
- *What it would let the Standard say:* "Human backing is checked by the registrar, from a zero-knowledge proof
  where one is used; verifiers and the root receive a digest."
- **Verdict: the most plausible first real ZK in the AINRA ecosystem. Build it only when a registrar asks** (§4).

**Z6. Proofs about model identity (zkML).**
- *Gives:* "this output came from weights with commitment H".
- *Cost:* small models only, seconds to minutes, MB proofs (§2.3).
- *PQ:* depends on the system; many wrap in BN254 ([arXiv 2512.10020](https://arxiv.org/html/2512.10020)).
- *Maturity:* research.
- *Conflicts:* checking or ranking model claims at the root would be judging (P2). zkML is also irrelevant to
  frontier models today.
- *The honest hook:* the missing L2 "declared model lineage" (§3.2 item 8) could become a registrar-signed **model
  commitment** (a weights hash or a model-signing digest). A later zkML proof or TEE quote would then have something
  to point at. Two ways to carry it:
  - a new `vct` with a new field, which breaks R-WIRE because `deny_unknown_fields` makes old verifiers refuse it;
  - better, a separate registrar-signed record bound to the passport, the way D-078's Link binds a key. That needs
    no change to the frozen passport.
- **Verdict: watch.** The commitment hook is a design note for when L2 model lineage is specified, not now.

**Z7. Proving that the verifier or gate ran unmodified code.**
- *Gives:* closes the gap D-024 names.
- *Cost:* zkVM proofs of a full verifier run, which is far beyond practical. A TEE is the realistic tool.
- **Verdict: refuse ZK; record TEE as the path if it is ever needed.**

---

## 4. Ranked recommendation

### Now (cheap, no ZK, closes real gaps), in order

1. **Make every privacy and delegation claim match the code** (part of D-090).
   - The full list of texts is in §3.2 items 1–4. The corrected sentences:
     - "The passport is a hybrid-signed JSON credential that reuses some JWT and SD-JWT VC claim names. It is not a
       JWT. There is no field-level disclosure today; every claim is shown."
     - "Holder binding is the RFC 9421 presentation signature (D-062)." ADR-004 drops "KB-JWT holder binding" and
       "X.509 bridge profile", or marks them as not built.
     - "Human backing is checked by the registrar (D-089); the root and verifiers receive a digest." L3's
       "+ zero-knowledge principal" becomes "+ checked principal proof".
     - Ledger row 9 becomes "the upstream personhood registry's proof system: trusted setup and pairings, not PQ;
       evidence held at the registrar". BBS comes off the removal path (row 9 and MTS §31). ADR-011 records that
       `principal_proof` is an opaque string digest today, and that a structured form is a wire change.
     - The depth cap: "depth capped (default 3)" becomes "depth is not capped today" until item 4 decides otherwise.
   - **Process.** `docs/IDENTITY.md`, the site and `apps/landing` are operational text: ordinary change. The Standard
     and the MTS are **normative** (`GOVERNANCE-AMENDMENT.md` §2). They change by the normative path: an ADR, a
     D-record, and a dated entry in `docs/AMENDMENTS.md` written *before* the change lands, approved by the operator
     with a public record (operator-run era, §3); then `make freeze` in the same commit. `make amendment-check` must
     pass. The site copies of the Standard follow in the same commit.
   - **Keep it from drifting back.** Add a `make doctrine` rule (`tools/doctrine-check.mjs`), with its negative
     control in `tools/doctrine-negative.sh`, that fails on "zero-knowledge", "zk principal", "selective disclosure",
     "SD-JWT verifiable credential" and "KB-JWT" anywhere in tracked docs, site and apps, except in an allow-list of
     lines that say these are *not* done or are future work.
2. **Build the leak ledger and its witness** (D-090, §4.4). It is the measurement that every later privacy change,
   ZK or not, has to move.
3. **Close the fetch leak with one network-wide status file** (D-091).
   - `tools/publish-static.mjs` already gathers every registrar's list in one run and writes one network-wide
     `heads.json`. Add one more output: an **unsigned, content-addressed** file that concatenates every registrar's
     signed list and its current fresh head. Any mirror can assemble it, and the verifier checks each embedded
     signature as today. **No new key**: a signature over the whole would need either an online root (against
     R-ROOT) or a new online signer and a new trust-ledger row.
   - There is no SDK self-fetch path to change. Whoever fetches (a gate operator, a mirror consumer, the MCP tool)
     should read the network file. Pin that with a gate on any fetch path added later.
   - At F1, a self-fetching verifier takes signed deltas, not the whole file every 30 s (Z3). Measure the file at
     1 % revoked before calling it cheap.
   - Then a host learns only "this address verifies AINRA passports".
   - Correct the herd-privacy sentences in `docs/SETTLERS.md` (line 310), MTS §11 and `docs/ONLINE-VERIFICATION.md`
     (line 26) to cover fetches. MTS §11 is normative, so it rides the item 1 amendment.
4. **Decide the depth cap.** Enforcing it changes what verifies, in four implementations, and needs new vectors and a
   named refusal: either an existing reason or a new one, and a new one touches the frozen 20 (R-WIRE, R-SIMPLE).
   Correcting the text (item 1) is cheap and honest now. Enforcement, if wanted, is its own decision record with a
   corpus.
5. **Write down what the classical online layer exposes.** Fresh heads, delegate checkpoints, delegate
   countersignatures and witness cosignatures are Ed25519 only. Record, as an honest limit, what an attacker who
   breaks one delegate's Ed25519 key inside its ≤ 92-day window could make a verifier accept (replayed or forged
   currency, a forged checkpoint), and what still stops them (hybrid passport and list signatures, the SLH-DSA
   delegate certificate, revoked delegates in the directory). Mark the answer UNCONFIRMED until a drill shows it.
   Do not claim post-quantum heads. The true statement is: "AINRA's directory is signed by FROST Ed25519 and SLH-DSA,
   and its delegate certificates by SLH-DSA. Its online heads, delegate checkpoints and witness cosignatures use
   Ed25519, like the key-transparency suites."
6. **Re-run `make personhood-live`** to confirm the registry contract still answers. There is no need to pick a
   different chain: the live docs still resolve against the deployment D-066 configured. Record the result in D-066.
   Lower priority than items 1–5.
7. **Keep inclusion proofs inside the bundle,** as they are today (`WIRE-FORMAT-PRIMER.md` §1), and say so as a
   privacy property: verifiers never fetch log tiles, so they never reveal tile positions.
8. **Update the Token Status List citation** ("draft-21", MTS ADR-007) when it gets an RFC number
   ([datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)).

### Watch (named triggers, revisit when one fires)

| Item | Trigger that reopens it |
|---|---|
| Hash-based ZK over ML-DSA (Z4, and later Z1/Z2 for principals) | A spec or circuit for ML-DSA-65 *and* Ed25519, **with hidden public keys and hidden messages**, with published proof size and verify time, plus a second implementation |
| Registrar-side ZK principal checker (Z5), behind `AINRA_PRINCIPAL_CHECKER` | A registrar asks for A1 from government wallet credentials, or the `draft-irtf-cfrg-longfellow` documents reach RG last call |
| Post-quantum online layer (heads, delegate checkpoints, witness cosignatures) | The item 5 analysis shows a forgery that matters, or a post-quantum signature fits the 30 s freshness budget and witness formats |
| Post-quantum accumulator for principal revocation | [ePrint 2025/1099](https://eprint.iacr.org/2025/1099) or a successor gets an independent implementation and a public audit |
| Real SD-JWT disclosures for non-checked fields | SD-JWT VC becomes an RFC ([datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)) *and* a verifier or registrar names a field it needs hidden |
| Model commitment record (Z6 hook) | L2 "declared model lineage" gets specified, or a model-signing format becomes a standard verifiers ask for |
| zkML | A published ZK inference proof above 13B parameters, or an unwrapped (no BN254) post-quantum system |
| Privacy Pass ARC (rate-limited anonymous tokens) | An agent-specific profile appears ([draft](https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-arc-crypto-01)) |

### Refuse (and say why in the decision record)

- **Any ZK in the root.** The root anchors, revokes and logs. It does not issue or check evidence (P1, P4, D-034).
- **BBS anywhere in the hybrid path.** It is not post-quantum, not an RFC, needs a new issuer curve, and the large
  phone-wallet vendors rule it out for device binding (§2.1).
- **Pairing-based or trusted-setup proofs (Groth16 and the systems built on it) in the core verify path.** They would
  be the one non-post-quantum link in the passport path, and their setup secret would be a new trust-ledger row.
- **Unlinkable or anonymous agent passports (Z1, Z2 for agents).** They contradict accountability, the named passport
  and graduated distrust.
- **Online privacy machinery in the verify path** (PIR, Oblivious HTTP, hosted lookups). These break offline
  verification. Agent-carried lists, a network-wide file and signed deltas cover the need.
- **Any claim that AINRA proves a model, its outputs, or an agent's reasoning.** Nothing in §2.3 supports it, and the
  root never judges (P2).

### 4.4 The first experiment: a leak ledger, as a decision record and a witness

The idea: before anyone argues for ZK, **measure what each party learns today, pin it as a fact, and make every
future privacy change, ZK or not, say which line it moves.** This fits the repo's habits:
- a claim needs a gate (`docs/CLAIMS.md`);
- every new gate names a witness and has a negative control;
- honest limits are pinned as vectors (D-081, D-086 c03).

**D-090 (placeholder number) — What each party learns from a verification, measured; and the privacy claims
corrected (PROPOSED)**

*Problem:* the docs claim selective disclosure, an SD-JWT format, zero-knowledge principals and a delegation depth
cap that the code does not have (§3.2 items 1–4). Nothing measures what a verification reveals, and to whom, so
privacy claims can drift from the code without any gate going red.

*Decision:*
- **A leak ledger.** A generated file, `docs/LEAK-LEDGER.md`, from `tools/leak-ledger.mjs`. For each party (root,
  registrar, status host or mirror, log host, gate or verifier, hosted verifier as designed, network observer) it
  lists exactly what that party receives during the lifecycle: issue → prime (D-065) → present → verify → currency
  re-check (D-086) → revoke → re-verify. The root row reads "nothing: root-dark", and points at `cap.offline` rather
  than a new measurement, because the root runs no server to instrument.
- **The witness, `make leak-ledger`.** It runs that lifecycle against local registrar, mirror and gate processes
  instrumented to record every request and every decoded field they receive. It compares the result to a committed
  expected file (`evidence/leak-ledger.expected.json`) and fails on any difference.
- **Three pinned facts,** each with a negative control that must turn the gate red:
  1. *The verifier makes no network requests.* The verifier process makes zero network requests during
     verification of a carried bundle (same property as `cap.offline`, here measured on the gate process). Control:
     add a fetch to the verify path; the gate goes red.
  2. *No field-level disclosure exists.* Two cases: removing `transfer_history` (a defaulted field) from the claims
     refuses `sig_invalid` at step 4; removing `tier` (a required field) refuses `schema_violation` at step 1
     (`passport.rs`: required fields have no serde default). The gate's received-fields row lists every claim.
     Control: add a field to the claims without updating the expected file; the verifier row changes and the gate
     goes red.
  3. *Per-registrar fetch is visible.* On the verifier-self-fetch path the mirror's row shows the registrar segment.
     This row is the known leak, recorded so D-091 must change it. Control: point the self-fetch at the network file
     without updating the expected file; the gate must go red. After D-091 the expected row says "network file", and
     a per-registrar fetch turns the gate red.
- **Claims registry.** Add `cap.privacy-ledger` (gate `make leak-ledger`) to `tools/claims.mjs`.
- **Claim corrections.** §4 item 1: the operational texts by ordinary change; the Standard and MTS by the normative
  path (ADR + this D-record + a `docs/AMENDMENTS.md` entry before the change, then `make freeze` in the same commit,
  `make amendment-check` passing). Plus the `make doctrine` word rule and its negative control.
- **Rule for later.** Any future privacy proposal, ZK included, must name the ledger rows it changes and ship the new
  expected file. A proposal that moves no row is not a privacy change.

*Not changed:* the wire format, the 20 frozen reasons, every corpus. P1–P6 are untouched. P4 holds; only the sentence
describing its mechanism is corrected.

*Cost:* one tool, one expected file, one make target, one doctrine rule, plus text edits and one amendment record.
It uses only processes the repo already runs (`make identity-e2e`, `tools/publish-static.mjs`, `services/verify`).

*Honest limit:* the ledger shows what AINRA's own components receive. It cannot see what a third-party CDN or network
logs beyond the request itself. It says so in its header.

**Then D-091 (placeholder)** (network-wide unsigned status file, deltas at F1) is the first change measured by the
ledger. **The first real ZK work** would be Z5 as a registrar checker (`kits/zk-principal`, shaped like
`kits/personhood` and plugged in through `AINRA_PRINCIPAL_CHECKER`: evidence at the registrar, a digest on the wire,
every refusal named), started only when its watch trigger fires. Its record would have to show the ledger rows it
changes. Expected: the registrar row goes from "a wallet address and a pseudonymous human id from a public chain
registry" to "a predicate result only". The verifier row does not change.

---

## 5. Open questions for the operator

1. **Is the agent meant to be linkable forever?** The repo says yes (MTS §11), and this study agrees. Anonymous
   agents would be a different product, and would collide with accountability, D-044 and D-079.
2. **Is field-level disclosure wanted at all?** If not, delete the claim (cheap, honest). If yes, the cheap form
   (RFC 9901 salted hashes) means a real SD-JWT, a new `vct` and a corpus. It can only hide fields the verifier does
   not check.
3. **Should the delegation depth cap be enforced, or the claim deleted?** Enforcing it is a verify-rule change in
   four implementations.
4. **Does a registrar need ZK principal evidence (Z5) soon?** If no registrar is asking, it stays on the watch list.
5. **Should L2 "declared model lineage" be specified?** That decides whether the model-commitment hook (Z6) is ever
   needed.
