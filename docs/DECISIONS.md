# DECISIONS — conflicts, ambiguities, and resolutions
Rule (brief §8): where two docs conflict, the **Master Technical Specification (MTS) wins**; where the spec is ambiguous, choose the **safer/stricter** reading. Every entry is a decision the code depends on.

## D-001 — Passport field set: MTS/brief SD-JWT-VC set wins over the Standard's illustrative JSON
- **Conflict.** *Standard §5* shows an illustrative passport with fields `serial, ainra_name, lineage, version, operator{name,kyb,jurisdiction}, registrar, authority{class,proof,act_chain_ref}, tier, validity{issued,expires,renewable}, key{alg,pub,fp}, history{soulbound,reputation_pointers}, log{seq,hash}, registrar_sig, registrar_cert`. *MTS §15 + brief §2* specify the SD-JWT-VC claim set: `vct, iss, sub, nbf, exp, authority{class, principal_proof{type,attestor,ref,proof?}}, tier, capabilities[], scope_ceiling, keys[]{Ed25519, ML-DSA-65}, cnf, status{status_list{idx,uri}}, log{leaf,root,checkpoint}, act_chain[], mandates_root, transfer_history[]`.
- **Resolution.** MTS wins. `ainra-core` implements the **MTS/brief SD-JWT-VC field set** as normative. The Standard's JSON is treated as an earlier illustrative rendering; its `serial`/`registrar_sig`/`key.fp`/`history` fields are NOT core claims. `vct = "ainra/passport/v1"`.

## D-002 — `operator` is an org handle, never PII; the Standard's "Acme Corp" is non-conformant
- **Conflict/violation.** Standard §5's example uses `operator.name = "Acme Corp"` (a real-ish company name + `jurisdiction`), which violates Charter S7 (placeholder-only) and MTS §11 (operator MUST be an org identifier / registrar-assigned handle, no natural-person data).
- **Resolution (stricter).** `operator` is a single lowercase name-grammar label (e.g. `acme`, `globex`), part of `sub`. No `operator.name`/`kyb`/`jurisdiction` object in the core passport. Parser **rejects** any PII-shaped field (keys matching `email|phone|ssn|dob|address|full_name|given_name|family_name`) and the literal fields `score`/`price` anywhere → `schema_violation`. Fixtures use `acme`, `globex`, `initech`-style placeholders under registrars `registrar-01..99`.

## D-003 — Canonical encoder = deterministic sorted-key minimal JSON (matches the P0 CLI); frozen + golden-file tested
- **Ambiguity.** MTS §3/§14 says "JWS over the canonical UTF-8 serialization" and "one canonical encoder in core, golden-file tested; TS must byte-match" but does not pin a canonical-JSON scheme (JCS/RFC 8785 vs simple sorted-key).
- **Resolution.** Adopt the **sorted-key, no-whitespace JSON** scheme the P0 cli-node already uses (recursively sort object keys, `JSON.stringify` scalars, no spaces). Reasons: (a) it lets ainra-core, sdk-ts, and cli-node byte-match without editing P0 (brief forbids editing P0); (b) it is simple, total, and golden-file pinnable. Documented precisely in `ainra-core::canon`. If MTS later pins RFC 8785 JCS, migrate behind the `vct` version. This is the M1 canonical form.

## D-004 — Reason strings are FROZEN
- The 15 INVALID reasons (brief §2) are the exact machine strings the CC0 vectors reference. Frozen as a closed enum with `serde(rename)` to the exact strings: `sig_invalid, alg_downgrade, expired, not_yet_valid, revoked, mandate_revoked, chain_widening, chain_expired, not_logged, checkpoint_invalid, stale_status, name_malformed, ceiling_exceeded, unknown_registrar, schema_violation`.

## D-005 — M1 crypto: hybrid mandatory; SLH-DSA verify + labeled TEST-ROOT signer; NO FROST
- Ed25519 + ML-DSA-65 both mandatory at registrar/lineage (downgrade ⇒ `alg_downgrade`). SLH-DSA-SHA2-128s: **verify side + a test signer** clearly labeled `TEST-ROOT` for fixtures (brief §3). FROST 5-of-9 is **not** implemented in M1 — core only ever sees a standard Ed25519 signature; the root single-key stand-in is labeled `TEST-ROOT`. Exact FIPS sizes are asserted as conformance tests; any deviation = broken dependency (brief §3), not a code change.

## D-006 — Crypto crate versions pinned at first resolve; sizes are the real conformance gate
- MTS §3 names `RustCrypto ml-dsa` (FIPS 204) + `slh-dsa` (FIPS 205); both are `0.0.x` pre-releases with evolving APIs. We pin whatever resolves cleanly and lock `Cargo.lock`; the **size-conformance asserts** (32/64; 1952/4032/3309; 32/7856) are the load-bearing check that the dependency is a conformant FIPS impl.
- **Resolved (build succeeded, `crypto.rs` size asserts pass):** `ed25519-dalek 2.2.0`, `ml-dsa 0.0.4`, `slh-dsa 0.0.3`, `signature 2.2.0`, `sha2 0.10.9`, `base64ct 1.8.3`, `flate2 1.1.9`.
- **ml-dsa/slh-dsa feature note.** `ml-dsa 0.0.4` and `slh-dsa 0.0.3` gate a `pkcs8`-only import (`BitStringRef`) behind their `alloc` feature while the enclosing impl is gated on `alloc` alone — so `default-features=false, features=["alloc"]` fails to compile (`E0433`). We therefore take their **default feature set** (`alloc + pkcs8`), which compiles cleanly. This pulls in `pkcs8` DER encoding we do not use; it is dead weight, not a behavioral change, and does not add I/O or network. Revisit if a later release fixes the gate.

## D-007 — `did:web` mapping + FROST + Tessera + witnesses = M2+ (M1 does `did:ainra` parse only)
- M1 implements `did:ainra` parse/format round-trip only. `did:web` mapping (MTS ADR-014), Tessera/logd, witnessd, statusd, registrar-box are M2/M3 scaffolds that **compile and return a typed `NotImplemented`** — listed in STATUS.md. Nothing fake is presented as real (brief §0).

## D-008 — Merkle = RFC 6962 exactly; in-crate test log is for fixtures only
- SHA-256 with domain-separation prefixes `0x00` (leaf) / `0x01` (interior). M1 ships a **minimal in-crate test log writer** so vectors can carry real inclusion proofs to a real signed checkpoint (logged-before-valid holds even though the production log is M2 Tessera). The checkpoint is signed by the labeled `TEST-ROOT` / delegate stand-in.

## D-009 — Delegatee counter-signature + dynamic post-issue mandates = M2; M1 authenticates what it evaluates
Arising from the M1 adversarial review (findings #2 spec-compliance, #3 delegation). Two deliberate, recorded scopings:
- **Delegation hop signatures.** MTS §15's delegation link is `{parent_sub, child_sub, granted, exp, sig_parent, sig_child, log_leaf}`; Standard §6 (A3) requires every hop *dual-signed* (delegator **and** delegatee). M1's `ActLink` carries the **delegator (parent) hybrid signature + monotone ∩-narrowing only**. The core safety invariant — *authority may only ever shrink* — is fully enforced by the parent signature + narrowing (`chain_widening`/`chain_expired`). The delegatee **counter-signature** (`sig_child`, proving the delegatee consented) and the per-hop **`log_leaf`** (hop-level transparency) are additive anti-laundering controls, deferred to M2 with the log/witness stack (D-007). Recorded, not silently omitted — see STATUS.md.
- **Mandate subtree revocation.** The review confirmed a bypass: a **presenter-supplied** mandate path let a caller drop a revoked ancestor. **Fixed in M1** by moving the operative mandate path INTO the issuer-signed passport (`Passport::mandates`) — the issuer signature (verify step 4) authenticates it, so the presenter cannot omit an ancestor. The presenter supplies only the **revocation set** (a trusted verifier input, exactly like the status list). Dynamic **post-issue** mandate graphs with per-node RFC 6962 inclusion proofs to `mandates_root` (AP2-style, where mandates are minted after the passport) are M2; `mandates_root` remains in the schema as that future commitment.

## D-010 — Canonical encoder rejects cross-language-divergent inputs (M1 review finding #1/#5)
The canonical JSON must byte-match across Rust (`serde_json` BTreeMap / UTF-8) and the P0 cli-node JS (`Object.keys().sort()` / UTF-16, `JSON.stringify`). Three input classes would diverge and are therefore **rejected** (`Error::Canon`, mapped to `schema_violation`), the stricter reading (brief §8): floats; **non-ASCII object keys** (JS sorts by UTF-16 code units, serde_json by UTF-8 bytes — they disagree for astral-plane keys); and **integers outside `±(2^53−1)`** (JS `Number` cannot represent them exactly). The AINRA schema uses only ASCII keys, JS-safe integers, strings, booleans, and null, so no conformant credential is rejected — this only removes an unenforced "keys are ASCII" premise and keeps P-5 total.

---
# M2 decisions

## D-011 — M2 delivered the D-009 deferrals + the checkpoint/witness pipeline; production storage stays Tessera
M2 closes the two D-009 scopings and stands up the transparency pipeline:
- **Dual-signed hops (D-009 → done).** `ActLink` now carries `sig_child_ed25519`/`sig_child_mldsa65` (the delegatee counter-signature) and `log_leaf`. `chain::verify_hop_sig` verifies BOTH parties over the same canonical hop bytes (both-signatures-or-invalid per party); `verify` step 9 additionally requires each hop's `log_leaf` to prove RFC 6962 inclusion under the checkpoint (logged-before-valid for delegation events). Party keys are supplied one per PARTY (hops + 1), and structural linkage (`from[i+1]==to[i]`, `last.to==sub`) is enforced at the schema gate.
- **Dynamic mandates (D-009 → done).** When a passport commits `mandates_root` (+ `mandates_size`), the presenter supplies the path plus one RFC 6962 inclusion proof per node; each node's `{id,parent}` is hashed into its leaf, so an ancestor cannot be silently re-rooted. Static (in-passport) and dynamic modes are mutually exclusive.
- **Delegate signer (ADR-002).** `checkpoint.rs` gains `DelegateCert` (root-SLH-signed, scope-limited, ≤ 92-day) + `CheckpointSig::{Root,Delegate}`; `verify_sig_mode` accepts either. Every delegate-path failure (bad cert sig, outside window, wrong scope, wrong delegate key) is fail-closed `checkpoint_invalid`.
- **Consistency proofs.** `merkle.rs` gains RFC 6962 §2.1.2 consistency-proof gen/verify — the witness's core primitive.
- **Services (`ainra-services`).** `logd` (persistent append-only log + delegate-signed checkpoints + inclusion/consistency proofs), `witnessd` (cosigns append-only growth, refuses forks), `statusd` (signed TSL publisher). **All security math is `ainra-core`'s** (MTS ADR-010 reuse-only). **Production `logd` swaps its fsync'd file store for Tessera's tiles** — proofs are byte-identical because the tree math is the same core code; Tessera changes *storage*, not *semantics*. FROST-threshold root/witness signing (M4) and witness-network onboarding are later; the single-key stand-ins are verification-identical (RFC 8032).

## D-012 — Dual-hop signing input is the SAME canonical bytes for both parties + the log leaf
A hop is signed over `canonical({from,to,granted,exp})` (signature fields excluded). The delegator and delegatee sign the **identical** bytes, and `log_leaf = hash_leaf(those bytes)`, so the transparency log anchors exactly what both parties agreed to — no third representation to diverge. Reason ordering on a hop is fixed (delegator downgrade→verify, then delegatee) so the failure reason is deterministic across implementations.

## D-013 — Dynamic (post-issue) mandates are M3; M2 supports the sound STATIC path only (revised after the M2 review)
The M2 review (finding #1/#4, CONFIRMED high) showed the first-cut dynamic-mandate design was **fail-open**: because a post-issue mandate is minted after the passport, the passport commits only `mandates_root`/`mandates_size` — there is no committed *operative* mandate id — so a presenter could supply an **empty or unrelated non-revoked path** and still pass the mandate step, dropping a revoked ancestor entirely. Committing `parent` in each leaf stops *re-rooting* a presented path but cannot force the operative path to be presented at all. Soundly binding the operative mandate to a specific credential/action needs the **AP2 mandate-object model** (a signed mandate naming the agent + the authorized action), which is genuinely M3. **Decision:** dynamic mandates are deferred to M3. The M2 verifier keeps the fully-sound STATIC in-passport path (D-009) and **fails closed on any `mandates_root`/`mandates_size`** (`schema_violation`) — reserved fields, explicitly rejected, never silently honoured. Better to reject a mode we cannot yet evaluate soundly than ship a revocation bypass.

## D-014 — did:web mapping keeps the registrar id in the path (ADR-014)
`did:ainra:{reg}:{op}:{lin}` ↔ `did:web:{domain}:ainra:{reg}:{op}:{lin}`. The registrar id stays in the DID path (not only in the domain), so the mapping inverts without consulting the registrar directory, and the `ainra` marker segment prevents a look-alike `did:web` from half-parsing as AINRA. Pure string transform; resolution (fetching the domain's DID document) stays caller-side — `ainra-core` still performs no I/O (N7).

## D-015 — Signed status delta = both-signatures + single-step monotonic; two failure planes, two reasons (M3)
The delta stream (spec §202, ADR-007) carries `{uri, from_seq, seq, ts, idx[], new_status, sig_registrar, countersig_delegate}`. **Decision:** a delta is authorized by BOTH the registrar's hybrid key AND a root-certified online delegate (scope `delta-countersign`, ADR-002) — both-or-invalid, fail closed — and advances the head by **exactly one** (`seq == from_seq + 1`, `seq != 0`, indices strictly ascending). The two failure planes surface **distinct** reasons so the verdict is deterministic across implementations: a delegate-chain failure (forged/expired/wrong-scope cert, bad countersig) → `checkpoint_invalid` (the same trust boundary as a checkpoint signature); a structural or registrar-signature failure (gap, wrong base, out-of-range index, bad hybrid sig) → `stale_status` (the head cannot be advanced from trusted material → status unavailable → fail closed to stale, never valid). `apply` bounds-checks every index **before** mutating (no half-apply) and re-verifies head linkage; it trusts the bytes only after `verify` has run (documented, so a caller can verify once + apply a batch). The codec stays a faithful *general* Token Status List delta (`new_status` either way); AINRA registrar **policy** is revoke-only (monotonic) and pushes `new_status = true`.

## D-016 — Fresh head binds the head identity, not the bits; F1 is the 30-second heartbeat (M3)
`FreshHead {uri, seq, ts, status_hash, sig_delegate}` (ADR-007) carries no status bits — only the **SHA-256 identity** of the head (`head_hash` = SHA-256 over the same canonical `{bit_len, status_list, uri}` a full publication commits to, so a fresh head and a full list name the *same* head). **Decision:** `verify` authenticates the head's *identity + recency* (delegate cert scope `fresh-head` → delegate signature → freshness, F1 ≤ 30 s), and the caller MUST separately confirm the list it holds hashes to `status_hash` (`binds()`). A valid fresh head for a list you don't have is **not** a pass for that list. Freshness fails closed on future-dated `ts` (a clock/forgery anomaly is stale, never trusted). This closes the withheld-list/stream window without putting the (large) bits on the hot 30-second path.

## D-017 — registrar-box deterministic reload = seed-regenerated keys + replayed deltas; the daemon is not a security oracle (M3)
The CLI's registrar-box persists a **master seed** + the record set + the emitted delta log; `load` regenerates **byte-identical** issuer/root/delegate keys from that seed (so stored records — signed by the original keys — still verify), rebuilds the log tree from the durable `entries.log`, and **replays** the stored deltas to restore the status bits + head sequence without re-signing. A snapshot with `seed = 0` (the HTTP daemon's externally-seeded, single-process instance) is explicitly **non-reloadable** — `load` refuses it rather than regenerate the wrong keys. **Decision + boundary:** the registrar-box and its daemon make **no** security decision of their own — every verdict is `ainra_core::verify::verify`'s, every delta is the core codec's; the services only sequence, persist, and serve. The checkpoint a credential anchors to is delegate-signed with a ≤ 92-day cert (ADR-002), so the prototype's demonstrated verification timeline sits **inside one delegate-cert window**; cert rotation + checkpoint re-anchoring across windows is M4 operational work (the credential's own 1-year validity is independent).

## D-018 — FROST 5-of-9 threshold Ed25519 root lives OUTSIDE the verify path; it is verification-identical to single-key Ed25519 (M4)
The root's Ed25519 component is a **FROST 5-of-9 threshold** key (audited ZF `frost-ed25519` 3.0, RFC 9591), DKG'd among 9 custodians so the group secret is never assembled in one place (`crates/ainra-ceremony/src/frost.rs`, real 3-round DKG + 2-round threshold signing). **Decision:** FROST is a *signing-side* concern only — a 5-of-9 aggregated signature is a **standard RFC 8032 Ed25519 signature**, so `ainra-core` verifies it with plain `crypto::ed25519_verify` and **never links against FROST** (N7 preserved; ainra-core has no threshold code). Proven by test: a 5-of-9 signature verifies through `ainra_core::crypto::ed25519_verify`, a 4-of-9 quorum cannot produce a valid signature, and a verifier cannot tell the key is thresholdized. This vindicates the M1–M3 stand-in note (D-005/D-011): the labeled single-key `TestRootSlh`/`TestDelegate` fixtures were always verification-identical to the real threshold path, and M4 wires the real path in the ceremony while the corpus/verifier are unchanged. **Boundary honestly stated:** real custodian entropy, a public recorded ceremony with ≥5 jurisdictions, and FROST *witness* thresholding remain M8/external — the rehearsal is deterministic (labeled TEST seed) and single-host.

## D-019 — The registrar directory is dual-root-signed (FROST-Ed25519 + SLH-DSA, both-or-invalid); delegate revocation is a fingerprint published in it (M4)
"Accredit registrars" becomes a concrete object: `directory::Directory` maps registrar id → its hybrid issuer key + its log-checkpoint SLH root, carries the epoch/issued_at and the **revoked-delegate fingerprint list**, and is signed by BOTH ceremony roots over one canonical body. **Decision:** `Directory::accredit(root_ed, root_slh)` requires **both** signatures to verify AND the entries to be **strictly sorted + unique** (no shadow/duplicate accreditation); any failure — a single bad signature, a malformed key, an unsorted/duplicate entry, a tampered field — yields `unknown_registrar` (with no authentic directory, no registrar is known; fail closed). It returns the `TrustAnchors` a verifier feeds to `verify::verify` PLUS the revoked-delegate set — so trust anchors are no longer hand-built; they are *derived from a signed artifact*. **Delegate revocation** (ADR-002 "delegate compromise → root-signed revocation published in the directory"): a delegate cert's identity is `fingerprint() = SHA-256(canonical signing bytes)` — it names exactly one cert (this delegate key + window + scopes), so **rotating** the same key mints a *different* fingerprint (revoking the old cert does not touch the rotation). `verify::verify` gains a `revoked_delegates` input (obtained from the accredited directory); after a checkpoint's delegate signature verifies, a revoked fingerprint makes it `checkpoint_invalid` — fail closed, even though the cert's own signature + window still verify (the online key is dead network-wide). This is the M4 answer to D-017's deferred "cert rotation across windows": revocation + rotation now have a real, tested mechanism (the `make ceremony` drill shows one minted passport go VALID → `checkpoint_invalid` on revocation → VALID again on rotation, all through the full 9-step verify). Both semantics are cross-checked core↔sdk-ts (24 delegate-revocation passport vectors + 8 directory vectors; diff phases A/E).

## D-020 — The verifier wedge lives OUTSIDE the verify path; the verifier owns the clock + revocation, never the presenter (M5)
The Execution Playbook makes verification the wedge (free, local, offline, ~5-line integration). **Decision:** M5 ships this as *packaging only* — the SDK GA `Verifier` and `@ainra/middleware` are pure over the unchanged `ainra-core::verify` (the verify path is static and never changes; Playbook §4). Two security hardenings distinguish the GA `Verifier` from the raw `verify`, both about **who supplies the trusted inputs**: (1) the verifier uses **its own clock** (`now` is a caller argument; the presentation's own `now` field is ignored), so a presenter cannot backdate/forward-date to dodge expiry or freshness; (2) the revoked-delegate set comes **only from the dual-root-signed directory** (`Verifier.fromDirectory` → anchors + revocations), so a presenter cannot un-revoke its own delegate by omitting it from the bundle. `fromDirectory` returns `null` (no verifier) unless the directory is authentic (both root sigs + sorted/unique/ASCII entries), and `.verify` **never throws** — any structurally-broken bundle is an `invalid` Verdict, never a crash and never a wrong `valid` (a gate that 500s is not fail-closed; a gate that allows-on-error is a breach). The middleware `ainraGate` denies (403 + `x-ainra-reason`) on the absence of a passport and on any deny path, never calling `next()`. The registrar's `/present` bundle is exactly the conformance corpus's `presentation` block, so the SDK and the vectors share one decode path and the differential is unchanged (684/684).

**Amended (post-review, pulled forward from M6): the presented status list is now AUTHENTICATED, closing a revocation bypass.** The M5 adversarial review found the original wedge trusted the bundle's status list verbatim — a presenter could forge an all-clear bitmap + a fresh `issued_at` and make a *revoked* passport verify VALID. A bypassable gate is "fake" by our own doctrine, so the M6-planned publisher signature was pulled into M5. The registrar now publishes its **Token Status List signing hybrid key in the dual-root-signed directory** (`DirectoryEntry.status_ed25519/status_mldsa65`, part of the signed body → tamper-proof), and the `/present` bundle carries the **signed publication** (`status_uri` + `status_sig_ed25519/mldsa65` over the canonical `{bit_len, issued_at, status_list, uri}`, mirroring the Rust `StatusSigning`). The GA `Verifier` authenticates the status list against that directory key — with a **triple URI binding** (the passport's claimed status URI = the bundle's signed URI = the directory's published URI, so no other registrar's list can be spliced in) — *before* core verify trusts a single revocation bit; any failure fails closed to `stale_status`. An accredited registrar with no status key cannot have its revocations authenticated, so its passports also fail closed. **This lives in the GA `Verifier` layer, NOT in the frozen 9-step `verify`** (which still receives status bits as an input, exactly like `now`/revocations) — so the verify path and the 684/684 + directory 9/9 differential are unchanged; the authentication scales by *addition*, as the standing rule requires. Three further review hardenings shipped with it: the `Verifier` ignores the bundle's `mandate_revocations` and its advertised freshness class (both verifier-sourced — a presenter can neither drop a revocation nor downgrade freshness); `unpackStatus`/`StatusList::decode` bound the declared length (`MAX_STATUS_BITS = 2^24`) and cap the inflate output in *both* implementations (no zlib-bomb OOM); and anchor/freshness lookups use null-prototype maps + `Object.hasOwn` (the grammar-valid label `constructor` can no longer masquerade as an anchor, and a `__proto__` freshness label can no longer defeat the freshness gate). The bypass is proven closed end-to-end by `tools/testbed.sh` step 4b (forge modes `clear`/`strip`/`swap-uri` → all INVALID).

**Second adversarial pass (workflow, 5 invariants × attack→verify→synthesize): forgery bypass CONFIRMED closed; two residual holes found and addressed.** (1) *HIGH — pre-auth memory-amplification DoS.* `unpackStatus` expanded the list to a JS `boolean[]` (~180× the packed bytes → ~360 MB from a 2 KB blob at the `2^24` cap, which slipped the strict `>` bound), and it ran *before* authentication — an unauthenticated 27 KB request could OOM-abort the verifier process on a small-heap deploy (uncatchable, past the `try/catch`). Fixed two ways: the list is now kept **packed** (`Uint8Array`, ≤ 2 MiB at the cap; bits read on demand via `statusBit`), and `Verifier.verify` **authenticates the status signature over the compressed bytes BEFORE decompressing** — an unauthenticated presenter fails the cheap signature check and the inflate never runs. Regression: `revocation-auth.test.mjs` rejects an at-cap inflating bundle in < 200 ms (17 ms measured), no OOM. (2) *LOW — genuine superseded-snapshot replay within the freshness window.* The status list is a stapled, registrar-signed *snapshot*; the verifier proves its signature + age but not its *currency*, so a holder can replay a genuine pre-revocation snapshot until it ages out of the class (F1 ≤30 s · F2 ≤5 min · F3 ≤24 h) — the same replay-within-validity OCSP stapling has. This is inherent to an offline stapled model and was mis-described; the `Verifier` docstring now says "forge" (not "replay"), states the latency honestly, and points hot paths at F1. Sub-window currency (binding the delegate-signed **fresh head** / monotonic head sequence — machinery already in the SDK, `verifyFreshHead`/`headHash`, wired only into the delta corpus today) is the **M6** hardening. Regression `revocation-auth.test.mjs` pins the window: a genuine snapshot is VALID within F1 and fails closed (`stale_status`) past it.

## D-021 — A witness QUORUM (k-of-N) certifies the log head; fresh-head currency mode closes genuine-snapshot replay (M6)
Two M6 additions, both OUTSIDE the frozen verify path (differential unchanged: 684/684 + directory 9/9).

**(A) The fork catch is a QUORUM's, not one operator's.** M2 gave one `Witness` that refuses an equivocating fork; trusting one witness is trusting one operator. M6 adds `WitnessQuorum` (N independently-keyed witnesses + a threshold k) and a verifiable `QuorumCertificate` (`(witness_pubkey, cosignature)` pairs). A relying party holding the witness roster counts only cosignatures that are **cryptographically valid, from roster keys, distinct, and over the exact checkpoint** (`valid_cosigns` is fail-closed — a certificate cannot be padded with junk/non-roster/duplicate cosigns); the head is certified iff ≥ k count. **k is the RELYING PARTY's policy, never the certificate's** — `certified(cp, roster, k)` takes the RP's threshold as an argument and the certificate carries no threshold field of its own. *(This is the fix for the M6 adversarial-review HIGH: the first cut stored `threshold` inside the certificate and compared against `self.threshold`; because a certificate is an attacker-authorable, third-party-transmittable artifact, an equivocating log could author one with `threshold = 0` and "certify" a fork with zero cosignatures, or `threshold = 1` to downgrade a configured k=3 to one traitor. Removing the field and taking k from the relying party closes it; `certified` also refuses a nonsensical k = 0. Regression `fork_drill.rs`: a zero-cosign fork and a one-traitor fork both fail to certify under the RP's k=3.)* **Security property:** once the quorum certifies the honest head at size N, an equivocating fork at size N is refused by every honest witness that already cosigned N, so the fork gathers cosignatures only from adversarial/partitioned witnesses — it can reach quorum only if ≥ k witnesses are adversarial. Stated as the trust boundary: **`f < k` ⇒ no fork can be certified while the honest head still can.** Proven in `tests/fork_drill.rs` (N=5, k=3: honest head certified with 5 cosigns; fork gets 0 → not certified; f=2<3 traitors still can't certify, f=3 is the boundary) and shown by `make drill`. Scope: the quorum is demonstrated in-process with real independent keys + real cosignatures; the witness-network *transport* (gossip/HTTP) is deployment work (M7+), not a security gap — the catch is real and tested.

**(B) Fresh-head currency mode — closes the M5 review's replay LOW, honestly.** The default verifier trusts a genuine registrar-signed status *snapshot* within its freshness window (replay-within-validity, D-020). M6 adds an **opt-in `currency` mode** to the GA `Verifier`: the `/present` bundle now carries the registrar's delegate-signed **fresh head** + its cert; a currency verifier **requires** it (an absent one can't downgrade), **verifies** it (cert → the registrar's log root, delegate signature, F1 recency), **binds** it to the presented list by **head-hash** (the fresh head must name the exact list), and enforces a **monotonic `seq`** — once this verifier has observed a newer head (from any presentation, or an out-of-band poll), a replayed superseded snapshot (lower seq) is rejected (`stale_status`). **Honest limit (documented, not oversold):** the monotonic-seq check closes replay only for a verifier that *observes* the head advance; a purely passive verifier only ever shown the stale head still relies on the F1 (≤30 s) window. This is the inherent limit of offline stapled verification. Currency mode is stateful (a per-uri max seq) and strictly opt-in — the default stateless wedge is unchanged. Lives in the GA `Verifier` layer, not the frozen verify (parity preserved). Regressions in `revocation-auth.test.mjs`: a genuine current bundle → VALID; a replayed pre-revocation snapshot after the verifier observed the revocation → `stale_status`; a stripped fresh head → fail closed; a fresh head that doesn't name the presented list → fail closed; the default verifier ignores the fresh head.

## D-022 — Reproducibility is proven by a CLEAN rebuild into a fresh tree; mirrors byte-verify against the manifest, fail-closed (M7)
M7 makes the published spec artifacts (the CC0 vectors + the sample book) verifiable by anyone, with the **source** as the trust root — not our word, not a mirror.

**`make repro` proves byte-for-byte reproducibility by a CLEAN rebuild.** It builds the whole artifact set from source into a fresh empty temp tree **twice** (non-destructively — the committed tree is never touched) and asserts **committed == clean-rebuild-1 == clean-rebuild-2**, comparing *sets* (path + SHA-256), then writes `MANIFEST.sha256`. The generators are deterministic (seeded `ChaCha20Rng`; sample dates derive from fixed claim values, never wall-clock), and the toolchain is locked (Rust `1.96` via `rust-toolchain.toml`, `Cargo.lock`, Node built-ins only) — see `REPRODUCIBILITY.md`. Deliberately **excluded** from byte-identity (documented, not faked): the `tsc` SDK `dist/` (verified for *behaviour* by the 684/17/9 differential, not byte-hash, so the corpus isn't coupled to a compiler release) and timing-derived `BENCHMARKS.md`.

**Mirrors byte-verify against the manifest, fail-closed.** A mirror is any host serving the set; `make verify-mirror MIRROR=<dir>` recomputes every listed file's hash and exits 0 iff **byte-identical, none missing, none extra**. A relying party verifies any mirror using a manifest it trusts (reproducible from source via `make repro`), so a mirror's honesty is checkable **without trusting the mirror or us**. The normative docs (The Standard, the MTS, DESIGN) are frozen (`make check-freeze` fails on drift).

**M7 adversarial review (5-invariant workflow) found the machinery could report success while the property was false — 4 distinct real defects, all fixed:**
- **HIGH — `repro.sh` laundered non-generated bytes.** The first cut regenerated *in place* and derived its file list from the committed tree, so a committed **orphan/planted** file (that no generator produces) survived all passes byte-identical → "repro OK" and got enshrined into `MANIFEST.sha256` and served by mirrors. **Fixed:** rebuild into a fresh empty temp tree and compare sets — an orphan (committed-only) or a missing file (rebuild-only) now fails the proof. (`render-samples.mjs` gained `AINRA_SAMPLES_OUT/DATA` overrides so the rebuild is non-destructive.)
- **HIGH — `mirror-verify` extra-file check excluded by BASENAME** (`! -name MANIFEST.sha256`), so a mirror could smuggle an unlisted file named `MANIFEST.sha256` in any subdirectory. **Fixed:** exclude only the top-level `./MANIFEST.sha256` by full path.
- **MEDIUM — the extras check ignored symlinks** (`find -type f`), so a mirror could serve unlisted content via symlinks. **Fixed:** extras now include symlinks (`-o -type l`), and a manifest-listed path served as a symlink is rejected.
- **MEDIUM — `mirror-verify` skipped the last manifest entry** when the manifest had no trailing newline (`while read` returns nonzero at EOF), a fail-open on the final artifact. **Fixed:** `while read … || [ -n "$want" ]`. Also hardened `mirror.sh`'s `rm -rf "$OUT"` to refuse empty/absolute/`..`/repo paths.

All four exploits (planted orphan, subdir-`MANIFEST.sha256`, symlink, newline-stripped manifest) are now caught; `freeze.sh` was reviewed sound.

## D-023 — `make genesis-local` boots the whole stack on one laptop; the DoD marks external items honestly (M8)
M8 is the capstone (MTS §29 / N9): **one command stands up the entire AINRA world on one machine**, all real, and writes a transcript. `tools/genesis-local.sh` composes every layer — a dual-root ceremony (FROST 5-of-9 + SLH-DSA) over **two registrar classes** → each issues a passport *logged-before-valid* → a stranger's **5-line SDK verifies with the root DARK** (only the directory + roots) → revoke → re-verify **INVALID** → a forged all-clear status **INVALID** → an injected log fork **caught by the witness quorum, not us** → `transcript.json` (roots, registrars, every verdict, a SHA-256 of every artifact). Every verdict is the real tool's exit code, never narration; any wrong outcome exits nonzero. `docs/DOD.md` is the §29 checklist marked **✓ laptop-provable** vs **external/pending** (the ≥3 independent operators, the p95 < 60 s ×3-region ×14-day soak, the recorded in-person ceremony — real-world items code cannot fake).

**M8 adversarial review (workflow, 3 lenses: no-false-success / verdicts-are-real / DoD-honesty) found 3 real issues, all fixed:**
- **HIGH — "two registrar classes" was one keypair under two names.** The `registrar-box` bin seeded its RNG from a *hardcoded constant* independent of the `id`, so both daemons derived byte-identical issuer/log/status keys — `directory.json` listed the same issuer key twice. **Fixed:** the seed is now **id-derived** (FNV-1a over the id), so distinct registrars are cryptographically distinct (verified: two different issuer keys in `directory.json`); the library `RegistrarBox` is unchanged, so all other tests hold.
- **MEDIUM — a stale daemon could silently serve the run.** Ports were hardcoded and the daemons launched with stderr swallowed, so a leftover daemon on those ports would answer while the freshly-built binary died on `EADDRINUSE` unseen — a false green masking a regression. **Fixed:** a **pre-flight** check refuses to run if the ports already answer, and a **post-launch liveness** check (`kill -0` on the fresh child, stderr kept) fails loudly if the just-built daemon did not start.
- **MEDIUM — the DoD overclaimed the in-process witnesses.** The "fork caught by witnesses ✓" row read as a flat ✓, but the 5 witnesses run in one process (real independent *keys*, not independent *operators*). **Fixed:** the row is now "✓ (in-process) / external (independent operators)", matching the M6 D-021 transport scoping.

Everything re-verified green after the fixes: `make genesis-local` boots (distinct registrars, revoke+forge fail closed, fork caught), `wedge-test` 18/18 (frozen fixtures unaffected), `testbed` OK.

## D-024 — M9: committed + CI-gated + executable by strangers; the external DoD events get machinery, never faked results
The engineering ladder (M1–M8) is complete; M9 makes it shippable and lets third parties run the pending real-world §29 events without us in the room.

**Git scoped to the project, secrets excluded.** The working tree's git root was `$HOME`; M9 initializes a **fresh repository rooted at `ainra/`** (confirmed via `git rev-parse --show-toplevel`) so the project is self-contained. A strict `.gitignore` (written and dry-run-verified BEFORE the first `git add`) excludes `target/`, `node_modules/`, all `dist/`, generated run-outputs (`genesis-out/`, `*-out/`, `build/`), and — importantly — **all key material**: the generated `apps/registrar-explorer/data/` (which holds TEST registrar reload-seeds), plus `*.secret`/`*.key`/`*.pem`/`.env*`. Committed in **milestone-mapped conventional commits**, dual-license Apache-2.0 OR MIT with **CC0** vectors (`LICENSE-CC0`). **Acceptance (the real Task-0 gate): a fresh `git clone` runs `make test && make diff && make genesis-local` green** — nothing depends on an uncommitted file.

**CI runs every gate on push** (`.github/workflows/ci.yml`, toolchains pinned to Rust 1.96): the existing fmt/clippy/test(release)/vectors + differential + wedge + neutrality/N7/license/fuzz, **plus** an `integration` job (`make drill`/`testbed`/`genesis-local`) and a `reproducibility` job (`make repro` + a `verify-mirror` tamper regression). The release-test trap is encoded in a comment (debug stack-overflows the crypto-heavy test).

**Kits make the three external events executable + self-verifying (nothing fake).** Each pending DoD item gets machinery a stranger runs on their own infra, producing evidence we collect **without trusting their word**: (a) **verifier kit** — verify root-dark + reject revoked/forged using ONLY the published `@ainra/sdk`, emitting a signed `verifier-attestation.json` whose signature + artifact hashes + verdicts we re-check; (b) **ceremony kit** — the real 5-of-9 air-gapped RUNBOOK (one clearly-marked real-secret step) + a `ceremony-dry-run` that rehearses the commit-reveal choreography with **TEST-ROOT** material and has an independent witness recompute the transcript hash, failing loud on a skipped step; (c) **soak harness** — measures real revocation-propagation p50/95/99 from ≥3 vantage points into an **append-only hash-chained** log + a **signed** report, with the SLO **computed from the data** (never a hardcoded latency) and **fail-closed** on a miss. **Deliberately NOT done (honest):** no real 14-day soak, no scheduled ceremony, no invented external-verifier results — only the machinery + smoke proofs.

**Witness transport closes D-021 to deployable.** `witnessd` already served `/consider`; M9 adds a minimal std::net HTTP **client** to `ainra-services::http` and a `witness-quorum-drill` relying party that fetches cosignatures from N separate `witnessd` over HTTP and refuses an injected fork (`make drill-networked`). **k stays the relying party's argument** — the certificate carries no threshold to lower (regression added). *Found + fixed while building (same class as the M8 registrar bug): `witnessd` seeded every instance from a constant → identical witness keys; the seed is now address-derived so a quorum has cryptographically distinct keys.*

**N7 preserved.** Any developer-demand/traction metric is **opt-in, count-only, documented, off by default, and lives only in the kit/tutorial layer** — never in `ainra-core` or a shipped SDK. The ordered "declare done" runbook is `GENESIS-CHECKLIST.md`; the honest ✓-vs-⏳ picture is `docs/DOD.md`.

**M9 adversarial review (kit lenses: fail-open / signature-coverage / evidence-forgeability) found the evidence-collection machinery could accept a fabricated result — 8 real defects across the verifier/soak/ceremony kits, all fixed and each with a negative test that now fails closed:**
- **CRITICAL — verifier `check-attestation.mjs` was fail-open on the corpus.** It iterated `body.artifacts_sha256` and passed if every *listed* hash matched — so an attestation with an **empty** map (attacker never ran the SDK) satisfied it vacuously. **Fixed:** a `REQUIRED` set (`directory/roots/bundle-valid/bundle-revoked`) must **all** be present and byte-matching, and any *extra* artifact is rejected. Negative test: an empty-corpus attestation signed with a fresh key is now REJECTED.
- **HIGH — the signature covered almost nothing (canonical-JSON footgun).** All four kit tools signed `JSON.stringify(obj, Object.keys(obj).sort())` — an **array replacer acts as a recursive allowlist** that drops every *nested* key, so the `slo{}`, `overall{}`, `per_vantage{}`, and `verdicts{}` objects were outside the signed preimage and could be edited freely. **Fixed:** a single recursive `canonicalJSON` in `verify-kit`, `check-attestation`, `soak`, `verify-log`, `operator`, `witness` — the signature now covers the whole body, nested objects included.
- **HIGH — self-signed attestations proved nothing (no freshness/binding).** Both the verifier and soak reports were signed with an **ephemeral** key the runner generates, so an attestation could be pre-manufactured or replayed and "3 verifiers" could be one person three times. **Fixed:** the collector issues a **single-use `--challenge` nonce out of band**; `verify-kit`/`soak` stamp it into the body *and* the log's `soak-start`, and `check-attestation`/`verify-log` **require** the exact pinned nonce (no default). Honest scope written into the kits: crypto proves **execution + freshness + tamper-evidence**, *not* Sybil-resistance — distinctness is the one-challenge-per-vetted-party issuance (SECURITY.md, GENESIS-CHECKLIST §3).
- **HIGH — soak `verify-log.mjs` trusted the report's own SLO threshold.** It recomputed the p95 but compared it to `body.slo.revocation_p95_sec` *from the report*, so a runner could re-sign a `PASS` over a breaching log by lowering its own threshold. **Fixed:** the verifier **pins `--slo-p95-sec` itself** and requires both that the recomputed p95 passes OUR pin **and** that the report's own claim matches. Negative test: a re-signed PASS report over a 999 s-latency log is now REJECTED.
- **MEDIUM — soak trailing-drop.** `log_head_hash == tip` alone didn't catch dropping the last measurement lines and re-signing (the chain stays valid up to the new tip). **Fixed:** `verify-log` also requires the log's `measure`-row count to equal `body.measurements`.
- **HIGH — ceremony `witness.mjs` counted files, not custodians.** Quorum was `readdir().filter(operator-\d+).length === required` with **no `operator_id`↔filename binding and no distinct-key check**, so a no-show could be papered over by `cp operator-1.json operator-5.json` (still N files). **Fixed:** each `operator-K.json` must claim `operator_id K`, all custodian public keys must be **distinct**, and the count of distinct verified keys must itself meet the threshold. Negative test: a copied part over a no-show is now REJECTED (slot-id + key collision).
- **MEDIUM — ceremony `operator.mjs`/`witness.mjs` shared the array-replacer footgun** (bodies are currently all-scalar, so no active break, but a latent one). **Fixed:** both use the recursive `canonicalJSON`.

All four kit smokes re-run green after the fixes, each now including the adversarial negative case: `verifier-kit-smoke` (genuine VALID + empty-corpus + wrong-challenge rejected), `soak-smoke` (genuine PASS + breaching-run re-sign rejected), `ceremony-dry-run` (genuine PASS + skipped-custodian + copied-part rejected), `drill-networked` (fork refused; unchanged this pass). **Meta-lesson, consistent with M7/M8: the machinery that *collects proof* is itself attack surface — an evidence checker that fails open is worse than none, because it manufactures false confidence. Every kit now fails closed and states plainly what it does and does not prove.**

**M9 review — ROUND 2 (adversarial re-verification of the round-1 fixes; ultracode workflow `wckqz2man`, 6 attack lenses → per-finding refute-or-confirm). Two of the round-1 fixes were themselves defeatable — 5 confirmed findings collapsing to 2 real root causes, both now fixed with reproduced end-to-end exploits and regression tests. This round found that round-1's own framing over-claimed, and corrects it:**
- **CRITICAL — the ceremony distinct-key check compared RAW base64 STRINGS.** Round 1 keyed the `seenKeys` dedup on `pubkey_spki_b64` verbatim. But `Buffer.from(s,"base64")` is lenient: dropping the `=` padding (or adding whitespace) yields a *different string* that decodes to the *identical* key. A verifier agent reproduced **3 physical keys certified as a full 5-of-5 quorum** by aliasing two of them — defeating the very "copied-part" defence round 1 added. **Fixed:** the distinct-key identity is now the **canonical key** (decode → re-export DER → hex), computed once and reused for the signature check, failing closed on an unparseable key. New negative test in `ceremony-dry-run.sh`: a base64-padding alias of an existing key is rejected.
- **HIGH (×4, one root cause) — the verifier attestation proved *agreement on public data*, not *execution*; and round-1's docs falsely claimed it proved execution.** Every field `check-attestation.mjs` inspected was public (SHA-256 of the *published* corpus), a documented constant (the three verdicts), the issued nonce, or the party's own free key. A verifier agent hand-authored a passing attestation with `sdk:"i-never-imported-it"` — **accepted, exit 0, "ran the real SDK"** — without ever loading the SDK. The round-1 challenge nonce only bought freshness/non-replay, never execution; claiming otherwise (`SECURITY.md` "the cryptography enforces execution") was an overclaim of the same kind this whole review exists to catch. **Fixed properly — execution is now actually bound:** `mint-challenge.mjs` (maintainer) issues a **fresh challenge corpus** of `K` bundles with a **secret coin-flip** revocation each, records ground-truth verdicts (via the real SDK) into a **private answer key**, and publishes only the bundles; `verify-kit.mjs --challenge-dir` verifies them root-dark and signs its per-bundle verdicts into the attestation; `check-attestation.mjs --secret` (now **required**) certifies only if those verdicts match the answer key over a byte-identical corpus. A party who did not verify must guess all `K` (2^-K; smoke uses K=8). Docs corrected to the **honest** scope: this proves *actual verification was performed on un-precomputable inputs* — **not** the exact binary (a conformant reimplementation would also pass; binding the binary needs TEE/ZK, out of scope), and **not** Sybil-resistance (distinctness stays the one-challenge-per-vetted-party issuance). New `verifier-kit-smoke.sh` regressions: the exact hand-authored/conformance-only forgery, a wrong-answer guesser, a replay, and an answer-key-less call all fail closed.
- One finding was correctly **REFUTED** by an independent verifier (a zero-padded `operator-0N.json` filename that the loop never reads — it fails *closed*, not open, so it is not a bypass; noted, no change).

Both root causes were reproduced against the real code before fixing and re-proven closed after. **Deeper meta-lesson: the round-1 hardening was itself over-confident — a "challenge nonce" that only proves freshness was documented as proving execution. Adversarially re-reviewing your own fixes (not just the original code) is what caught it. The kit now binds execution to inputs the party cannot precompute, and every doc states the exact, narrow thing a pass proves.**

## D-025 — M10: publish-ready (private material out of history, brand-clean, licensed) + the DoD kits made stranger-completable
M10 adds **no protocol**. It makes the repo safe to open to the world and turns the three "machinery ready" DoD kits into events a stranger can complete unattended (Tasks 2–5, tracked in `docs/PLAN-M10.md`). This decision records Task 1 (the publish gate), the one item that is genuinely one-way.

**The publish audit (`docs/PUBLISH-AUDIT.md`) ran over the FULL 24-commit history, not just the tree** — a secret or private doc in an early commit is public even if deleted later. Findings:
- **Secrets: none.** `gitleaks` over all commits returned 672 hits, **all false positives** — high-entropy base64 of PUBLIC key fields (`log_root_key`, `issuer_key.{ed25519,mldsa65}`) in the CC0 vectors. No `*.secret`/`*.key`/`*.pem`/seed value was ever committed; private material is runtime-only and gitignored. `.gitleaks.toml` allowlists exactly the CC0-vector/sample public-artifact paths (so a real secret **anywhere else** still trips), and CI now runs gitleaks over full history.
- **Private strategy material WAS in history — the one-way call.** Three self-labeled-PRIVATE / strategy-GTM docs (`AINRA_Master_Plan_v1.md` — which itself says *"third-party names appear here but NEVER in public materials"* and named ~35 companies as targets/foils — plus `AINRA_Launch_Readiness_Plan.md` and the GTM-merge `PLAN.md`) and the 14 MB legacy `_archive/` (old Node prototype + research, 210 brand hits) were committed. **The owner chose Option A (surgical rewrite + relocate).** The four paths were copied to the sibling `../ainra-private/` (kept privately) and excised from ALL commits with `git filter-repo --invert-paths`; the milestone-mapped 24-commit history is otherwise intact (the `_archive`-only commit became empty and was pruned). Verified: zero references/objects remain, tree brand-clean, and a fresh clone still passes every gate.
- **The MTS is kept, not relocated** — the code cites `MTS §…` throughout and it names only technologies/standards (no commercial brands). Its internal framing was scrubbed: header "Internal engineering document" → "Engineering companion specification"; `Campaign §`/field-sweep provenance → "July-2026 field research"; two Risk-Register rows de-GTM'd. The public normative doc remains `AINRA_I_The_Standard.md`.

**Neutrality is now enforced on everything public, not just fixtures.** `tools/s7-lint.mjs` gained a second pass over docs / kit READMEs / `.github` / front-door files / **all commit messages**, using a *curated* `tools/s7-brand-denylist.txt` of unambiguous commercial/foil brands. A key subtlety, logged so it is not "simplified" away later: the existing fixture denylist lists common consumer words (`windows`, `chrome`, `apple`, `meta`, `oracle`) to catch product **impersonation in fixtures** — running *that* list over prose floods false positives (`deprecation windows`, `minimal chrome`, `-apple-system`, `meta.json`). So prose gets its own list restricted to tokens that only ever appear as a brand; standards bodies (IETF/NIST/FIDO/W3C/RFC) and this repo's own attribution trailers (Anthropic/Claude) are deliberately excluded. Both passes are green.

**Licensing is inventoried + honest.** `THIRD-PARTY.md` lists all 115 transitive Rust crates (from `cargo metadata`, authoritative) + the Node deps: every one is OSI-permissive; no copyleft is forced (the two `…OR LGPL` crates are `r-efi`, off the verify path, taken under MIT/Apache; `unicode-ident`'s `Unicode-3.0` is permissive). The verify-path direct deps are enumerated (dalek BSD-3, RustCrypto ML-DSA/SLH-DSA/SHA-2, noble MIT). SPDX headers now cover every source file (`license-check.mjs` green; the one missing `apps/cli-node/bin/ainra.js` fixed).

**`make preflight` is the "clone it and it works" promise** — one command runs build+test, differential, `genesis-local`, the verifier/ceremony/soak/witness smokes, S7, license, and repro from a cold clone and prints a green/red board (expected output in the README). `make audit` gates the publish checks (S7 + license + gitleaks). Where anything was ambiguous the stricter reading won (e.g. `PLAN.md` was *relocated*, not partially sanitized). Nothing was published — the repo is prepared to the point where the owner presses the button.

## D-026 — M11: public-operational (CI on host, release hygiene, operator loop, durability); no new protocol
M11 turns "green on my laptop" into "green on the host and operable by strangers." No protocol change. Key decisions:

**Reproducibility stays a PR gate, in its own parallel job (not moved to nightly-only).** `make repro` is ~6 min (331 s locally): rebuild the 729-file spec artifact set from source into a fresh temp tree twice and assert `committed == rebuild`. The tension is PR-CI speed vs. catching a reproducibility regression before merge. **Decision: keep it on every push/PR** in a dedicated `reproducibility` job with `timeout-minutes: 30`. Rationale: CI jobs run in **parallel**, so the fast gates (fmt/clippy/`test`) still report in ~2–3 min regardless; a repro job that only ran nightly would let a determinism-breaking change merge and be discovered hours later against an unrelated commit — reproducibility is a core N-property (N2/N11), too central to defer. GitHub Actions is free for public repos, so the minutes are not a constraint. A **nightly `schedule` run** of the whole workflow is added on top, to catch upstream/toolchain drift with no commits. (Stricter reading: never weaken a gate to save time — parallelize instead.)

**CI mirrors `make audit` exactly.** A dedicated `audit` job runs the *same* `make audit` a contributor runs locally (S7 fixtures+prose+every-commit-message, license headers, gitleaks over full history with `fetch-depth: 0`), so neutrality/secret/license parity is one command in both places and the redundant standalone gitleaks job was folded in. The `hygiene` job keeps the non-audit checks (status/DOD lockstep, docs-freeze, N7 no-network, npm-audit). Every job gained `timeout-minutes` (hang guard) and the workflow gained `concurrency` cancel-in-progress + least-privilege `permissions: contents: read`.

**Toolchains pinned explicitly:** Rust **1.96** (`rust-toolchain.toml` channel + `dtolnay/rust-toolchain@1.96` in every Rust job — they agree), Node **22** in CI; documented in `TOOLCHAIN.md` with `make doctor` to check a newcomer's environment before they waste an hour. The release-test trap (debug stack-overflow on the crypto-heavy test) is encoded inline in CI + Makefile + README.

**The CI badge is a single edit.** `<owner>` appears only in the README badge (a repo-wide find/replace resolves it); the exact pre-push checklist (set owner, enable Actions, tag `v0.1.0`, confirm first run green + badge resolves) is in `docs/PUBLISH-AUDIT.md`.

**Release hygiene = reproducibility's public counterpart.** `make release` refuses a dirty tree or a red preflight, re-checks `MANIFEST.sha256`, builds the reference CLI artifact, and prints a signable checksum manifest; `CHANGELOG.md` maps releases to the milestone ladder + D-0xx and **publicly owns the fixed security bugs** (CRITICAL revocation-bypass fail-open, base64-alias quorum forgery, attestation-proves-execution overclaim) — owning fixed bugs is doctrine.

**Operator loop for real external verifiers** (the highest-leverage ⏳ row): `mint-challenge.mjs` writes each party's private answer key under a gitignored per-party path (asserted ignored); `check-attestation.mjs` emits a durable `evidence/verifier/<party>.json` the board reads and refuses hand-authored/wrong-key attestations; `kits/verifier/OPERATOR.md` is the cold onboarding runbook. Proven on 3 clearly-labelled dry-run parties (NOT counted as real) — the board reads 3 distinct evidence files, a forgery is rejected.

**Docs-vs-reality lockstep extended.** `status-consistency.mjs` already pinned the README/STATUS status line; it now also fails if the genesis board's ✅/⏳ counts drift from `docs/DOD.md` — one enforced source of truth for "what's done."

## D-027 — M12 (ADR-017): identity eternal, credentials bounded, renewal invisible

**The MTS gains ADR-017 and M12 implements it end-to-end.** Infinite passports are rejected for the ADR's four
reasons (status-list GC, crypto agility, ghost agents/claim staleness, verifier fragmentation); the lineage + AINRA
Number remain permanent; long validity is affordable **because revocation fails closed <60 s** — the opposite trade
from Web PKI's shrinking certificates. (The MTS is a frozen doc: `docs/FREEZE.sha256` re-recorded with the edit.)

**One duration ladder, one home.** `ainra_core::consts`: `PASSPORT_VALIDITY_DEFAULT_SECS` (366 d),
`RENEWAL_LEAD_SECS` (30 d), `DELEGATE_CERT_MAX_SECS` (92 d — moved here, `checkpoint` re-exports it),
`INSTANCE_CRED_DEFAULT_SECS` (1 h, explicitly RESERVED — instance-cred machinery is future work; the constant only
pins the ADR's ceiling so later code cannot invent its own number). Every magic 365-day epoch pair in the repo
(registrar-box bin, CLI seed, scale-proof, sample, ceremony bin, P0 `plusDays(365)`) now derives from the constant;
the registrar's and ceremony's 90-day delegate-cert choices gained compile-time asserts against the 92 d cap; the
TS SDK exports mirrored constants + a `renewalDue(exp, now)` scheduling hint.

**Window semantics pinned exactly — no skew, no grace.** The verifier's `nbf ≤ now < exp` comparison was already
strict and fail-closed in all implementations with `not_yet_valid`/`expired` vectors at ±50 s; what was missing was
the BOUNDARY. New `boundary-*` vector families pin `now == nbf → VALID` (inclusive), `now == exp → expired`
(exclusive), `now == exp−1 → VALID`, `now == nbf−1 → not_yet_valid`, and the ADR-016 scope note now says in the MTS
what the code always did: the ±30 s skew tolerance is a freshness-layer rule and NEVER applies to the passport
window (a skewed window would be a fail-open grace period, which ADR-017 forbids).

**REISSUE is a first-class operation, distinct from ROTATE (key rotation).** A renewal mints the same lineage with
a FRESH `[now, now+366 d]` window, a NEW status index, and a new top-level signed claim **`prev_leaf`** — the
RFC 6962 leaf hash of the predecessor's credential body. `prev_leaf` is deliberately NOT inside the `log` object:
the `log` back-reference is stripped from the pre-log body, and the continuity link must be part of what the log
commits, so renewals are walkable through the log as one unbroken chain (proven by test: three generations walk
back g3→g2→g1→∅). Schema, all implementations: present ⇒ must strictly decode to 32 bytes, else
`schema_violation` (an unwalkable link that LOOKS like a renewal is refused, never ignored —
`renewal-invalid-prevleaf-*` vectors). **Issuance-side consistency is ACME-style:** the caller claims which
credential it renews; the registrar validates the claim against its recorded lineage continuity head BEFORE
anything is logged — wrong, missing, or superseded-generation (fork) links are `ReissueContinuity`, fail closed,
and the log is untouched (asserted). **Overlap:** the displaced generation is kept (persisted `superseded` set) and
keeps verifying until its own `exp` — that IS the overlap; at `exp` it fails closed `expired` while the new one
continues (`renewal-*-overlap/-expired/-survives` vectors, differential-checked). **No grace period exists
anywhere.** Two deliberate exclusions, stated honestly: (1) a delegated (chained) passport is NOT auto-renewable —
the delegation parties' consent signatures are theirs to give, not the registrar's to re-mint; renewal of a
delegation is a re-delegation (explicit error); (2) the HTTP daemon exposes no reissue endpoint yet — the CLI
(`ainra renew <dir> <sub> [--version V] [--dry-run]`) is the M12 surface, and its help says the T−30 d lead is a
deployment cadence, not protocol.

**Revocation stays lineage-wide across generations — renewal must never be a revocation bypass.** The status list
is one bit per LINEAGE (MTS §16), so `revoke` now flips the named record's bit AND every other unexpired
generation of the same lineage (superseded or version-bumped). Without this, revoking a freshly-renewed lineage
would leave its predecessor verifying for up to 30 days. Test-proven: reissue → revoke → BOTH generations
`revoked`.

**The L3+ audit cap: "audited" means audited recently.** `IssueSpec` gains optional `AuditEvidence {reference,
expires}` — held REGISTRAR-side (Standard §4: evidence never at the root), so the wire format is unchanged and no
verifier change is needed. `issue`/`reissue` refuse L3/L4 without it (`AuditRequired`) or when the requested `exp`
exceeds the audit's own expiry (`AuditStale` — the error names both timestamps and says why). The same request at
L2 issues without evidence (tested); an L3 renewal under an aged audit is refused until the audit itself renews
(tested). Fixture lineages at L3+ carry deterministic placeholder evidence expiring exactly at the window's end.

Corpus: 684 → **735** passport vectors (24 boundary + 27 renewal), all three implementations agree 735/735; the
existing 684 are byte-identical (purely additive). `MANIFEST.sha256` re-derived via the sanctioned `make repro`
clean-rebuild. No existing test weakened; the DoD table is unchanged (no new real-world rows).

## D-028 — Status-list garbage collection: DEFERRED with the math on the table (ADR-017 trap i)

ADR-017 names expiry as the status list's garbage collector; the standard pattern is cohort/epoch-sharded lists
(issuances in an epoch share a status URI; once every credential in a cohort has expired the whole list retires).
**M12 decides: defer the sharding machinery, keep the wire forward-compatible, write the thresholds down.**

- **Size is not the constraint.** Measured (MTS §16/§21): 10 M lineages at 0.1 % revoked → **21.2 KB gzipped**
  (empty list 1 245 B). A single list at I1 scale is bytes, not megabytes.
- **Index burn is the real ceiling.** Indices are never reused; with 366 d renewal each live lineage burns ~1 index
  per year (renewal allocates a new index; the old one dies with its credential's expiry — that IS the GC working,
  it just reclaims *meaning*, not list positions yet). A `MAX_STATUS_BITS = 2^24` segment therefore supports
  ~16.7 M lineage-years; at I1 (10 M lineages) that is under two years of steady state. **Sharding becomes
  necessary when a registrar shard's cumulative issuance approaches 2^24.** The testbed default capacity is 4096 —
  three orders of magnitude of headroom before any of this binds.
- **The wire format already carries the cohort discriminator: the status list URI itself.** `StatusRef` is
  deliberately unchanged (`{idx, uri}`, deny-unknown in both implementations): a registrar rotates cohorts by
  issuing new epochs under a NEW `uri`; verifiers already fetch/verify per-credential URIs. The additive change
  lives in the **directory** (an entry must be able to list current + prior epoch status URIs so the GA verifier's
  triple URI binding accepts every live cohort) — that directory extension + the retire-a-dead-cohort test are the
  deferred work, and nothing about the credential format blocks them.
- **`StatusFull` stays a terminal, honest error** rather than silently rolling over — a rollover without the
  directory-side epoch machinery would break the triple binding and could be abused to shed revocation state.

Deferral is the honest choice at testbed scale; the trap is neither built speculatively nor silently ignored.

### M12 adversarial review — 6 attack-dimension reviewers, findings triaged + hardened (D-027 addendum)

M12 got the standard adversarial pass (continuity/forks, revocation completeness, schema differential, window
boundaries, the audit cap, vector soundness). The refute-verify phase was cut short by an account spend limit, so
the raw findings were triaged by hand against the code; the real ones were fixed and regression-tested, and the
corpus grew 735 → **737** to pin the two cross-implementation gaps:

- **Differential (HIGH) — non-canonical `prev_leaf` was fail-open in the SDK.** Rust decodes with base64ct
  (strict, unpadded), which rejects a 43-char base64url string with nonzero trailing bits; Node's `Buffer.from`
  silently accepted it as 32 bytes, so the SDK would VALID a credential Rust rejects. Fixed: the SDK now requires a
  canonical round-trip (`b64uEncode(decode(s)) === s`). Vector `renewal-invalid-prevleaf-0003` pins it; both now
  agree `schema_violation`.
- **Differential (MEDIUM) — `"prev_leaf": null`.** Rust's `Option<String>` maps null → None (a first issuance);
  the SDK rejected null at the schema gate. Fixed: the SDK treats null identically to a missing field. Vector
  `renewal-null-prevleaf-0000` (signed with null in the body) pins it VALID in both.
- **Revocation durability (HIGH/edge) — an expired generation could be reissued into a clean status index.**
  `revoke` already flips every *unexpired* generation of a lineage (so no live credential escapes), but a lapsed
  generation could still be reissued. Closed by the ADR-017 rule that **renewal is for a credential in good
  standing**: `reissue` now refuses an expired (`now ≥ old.exp`) or revoked generation — renewal happens at T−30 d,
  before expiry; a lapsed credential requires fresh issuance. Test `expired_credential_cannot_be_renewed`.
- **Overflow (MEDIUM) — `now + 366 d`.** A hostile `now` near `u64::MAX` would wrap to `exp < nbf`. `reissue` now
  uses `checked_add` (fail closed); the CLI uses `saturating_add`.
- **Name-key integrity (LOW) — composite `operator:lineage` key.** An operator/lineage carrying a `:`/`@` could
  desync the continuity/revocation key. `issue` now validates the constructed subject with `AinraName::parse`
  (test `tier_vocabulary_is_closed`… covers the sibling closed-vocabulary gate for tier/authority strings).
- **Honesty (LOW) — `ainra renew --dry-run`** now evaluates the real guards (revoked / expired / chained / L3+
  audit) and reports refusal instead of always printing "would reissue".

Refuted / by-design (documented, not changed): the reissue caller supplies `now` (consistent with the whole
system's no-clock N7 design — the GA verifier uses its OWN clock); `issue()` of a genuinely new version is the
deliberate re-accreditation path (distinct from mechanical reissue); `build_renewal_pair`'s shared post-append
checkpoint is a sound modeling choice (each generation's leaf is genuinely committed, inclusion proofs verify).

## D-029 — M12.1: canonical-encoding sweep — one strict base64url gateway, differential-locked

The base64 fail-open class appeared twice (M9 ceremony custodian dedup on raw wire strings; M12 non-canonical
`prev_leaf`). M12.1 closes the class at every base64url ingestion point and adds a differential vector class so a
regression is caught, not re-discovered.

**Core was already canonical-strict** — every decode routes through `b64::decode` = base64ct `Base64UrlUnpadded`,
which rejects non-canonical trailing bits, padding, whitespace, and standard-alphabet (`+`/`/`) swaps. Locked by a
new unit test (`b64::decoder_is_canonical_only`). No core change was needed; there is no hex ingestion.

**The SDK now routes EVERY external base64url decode through one strict gateway.** `strictB64u` gained the canonical
round-trip (`b64uEncode(decode(s)) === s`) that mirrors base64ct exactly — Node's `Buffer.from(_, "base64")` is
lenient (it silently drops nonzero trailing bits and non-alphabet chars), which was the fail-open. A new `dec(s,
reason)` wraps it and fails closed. All ~30 lenient `b64uDecode` call sites were replaced: the claims-internal
verify-path fields carry the reason core uses at that field's decode (hop signatures → `alg_downgrade`, `log.leaf`
and hop `log_leaf` → `not_logged`), and the presentation/boundary decodes (issuer sig, chain keys, status list,
checkpoint, inclusion proofs, anchors, directory, delegate certs, fresh heads) fail closed to `schema_violation`.
The raw `b64uDecode` now survives only INSIDE the gateway. Locked by a new SDK unit test (`test/canonical.test.mjs`)
whose exhaustive last-char sweep confirms the SDK accepts exactly the 16 canonical values (≡ 0 mod 4) — identical to
base64ct.

**Differential vector class.** For the claims-internal decoded fields (the ones the verify path itself decodes; the
reference `run()` decodes presentation fields out-of-band, so those are the trusted boundary, covered by the unit
tests), a non-canonical encoding is signed INTO the credential body (via `build_mut`, so the issuer signature is
valid and the field's OWN decode is what fails) and BOTH implementations must reject identically:
`noncanon-logleaf-{trailingbits,whitespace,padding}` (→ `not_logged`), `noncanon-hopsig-{whitespace,padding}` (→
`alg_downgrade`), and `renewal-invalid-prevleaf-*` now spanning trailing-bits, padding, whitespace, and
standard-alphabet swaps (→ `schema_violation`). Corpus 737 → **745**; the 3-way differential agrees **745/745**.

**P0** ingests base64 at exactly one point — a *standard, padded* signature in its own demo passport format (PEM
keys, calendar-date validity), a different wire format from the base64url conformance corpus. P0 participates in the
differential only for canonical-JSON (B) and canon-rejection (C), never verdict (A), so it is outside the base64url
canonicalization class; forcing base64url-strictness on a standard-base64 field would be incorrect. Documented, not
changed.

Independent re-verification of the two M12 differentials this milestone was asked to confirm (before the sweep): two
adversarial refuters built 202- and 151-input batteries through both real implementations and found **zero
divergences**; both accept exactly the 16 canonical last-chars. No frozen doc changed (freeze stays valid). DoD
table unchanged.

## D-030 — M14 (partial): AINRAscan is a real client-verifying app; the SDK runs in the browser

The AINRAscan landing was a polished shell with hardcoded specimen data. It is now a **real explorer** rendering
real pipeline data and recomputing every verdict in the browser — the "verify it yourself" promise made literal.

**The real `@ainra/sdk` bundled for the browser (no reimplementation).** `packages/sdk-ts/browser/` esbuild-bundles
`src/index.ts` into one self-contained ESM: `@noble/*` inlined, `Buffer` shimmed, and the single Node dependency
`node:zlib.inflateSync` aliased to a shim over **`fflate.unzlibSync`** (the matching ZLIB-wrapped decoder —
`fflate.inflateSync` is raw RFC-1951 and was the first-try bug). Zero external requests. **Proven equivalent:** the
browser bundle reproduces core's verdict on all **745** vectors and all **13** seeded records — the browser runs the
exact code that anchors the differential. esbuild + fflate are build-time devDeps; they don't affect the `tsc` build
or the differential.

**Real data, every lifecycle state.** `seed.rs` gained an ADR-017 `renew` field; `make ainrascan` seeds a real
network (real hybrid signing / RFC 6962 inclusion / signed status deltas) including a renewal chain (`prev_leaf`),
self-checked by the core verifier. Data + bundle are derived (gitignored); `ainrascan/index.html` is committed.

**Two independent client-side checks, honest labels.** On click the app runs the full 9-step SDK verify AND an
independent RFC 6962 recompute in the page's own JS (SHA-256 leaf from the canonical body → walk the audit path →
equals the signed checkpoint root). Persistent `STAGING NETWORK · TEST-ROOT` banner (machine + human readable),
independence colophon + oath, mechanical ordering, zero telemetry, self-contained. Placeholder operators only.

**Scope discipline.** This is the client half: it does NOT deploy a network (no containers / multi-region / domain /
CDN), does not touch DoD rows, publishes nothing, and claims no usage. The deployment half remains a separate
milestone needing an operator's hosts. See PLAN-M14.

## D-031 — M14: the public artifact contract (the interface the world reads)

The only globally-distributed AINRA surface is static files; scale is a CDN configuration of them, not a protocol
problem (measured in `docs/SCALE.md`). `docs/ARTIFACT-CONTRACT.md` specifies the URL scheme + HTTP behaviour;
`tools/artifact-server.mjs` implements it (a production deploy fronts the same paths with a real CDN):

- **Immutable vs mutable is by PATH**, decided by the server from the URL (`…/checkpoints/`, `…/tiles/`,
  `.immutable.` → `Cache-Control: max-age=1y, immutable`; else `max-age=5, must-revalidate` + a strong ETag). Two
  cache rules keyed on path prefix — a CDN needs no per-object config.
- **CORS `*` on every response** (+ OPTIONS preflight, `Access-Control-Expose-Headers: ETag, X-AINRA-Network,
  X-AINRA-Root`). Browser client-verification dies without it, and the read path has nothing to protect (a
  transparency log is world-readable).
- **Every artifact + page carries the banner** `X-AINRA-Network: staging` / `X-AINRA-Root: test-root` (machine +
  human readable). Asserted live by `make stage-smoke`.
- Reference server measured at **~8000 req/s (immutable) / ~5000 req/s (mutable)** on one laptop Node process, 0
  failures — before any CDN.

## D-032 — M14: staging is a different trust domain from production (key separation)

What goes online now is a **staging network on a TEST-ROOT**, not production. The production root is born only at
the recorded 5-of-9 genesis ceremony (a pending DoD row). This is deliberate and load-bearing (`docs/SECURITY-STAGING.md`):

- **Different root, different keys, labeled everywhere.** No staging key, directory, or credential is trusted by a
  production verifier. Owning the entire staging network — even the write token — teaches an attacker nothing about
  the ceremony-born root, and tampered public data fails closed at every verifier by signature/inclusion. The
  staging `/directory.json` states in its own `note` field that the production directory is dual-root-**signed** at
  genesis; staging publishes real accreditations, unsigned-by-a-root, on purpose.
- **Write path guarded** (the only new attack surface): bearer-token auth (`AINRA_STAGE_ISSUE_TOKEN`, never in an
  image/repo — compose reads `deploy/.env`) + a coarse rate limit (30/60s) + the existing 1 MiB body cap. The read
  path stays open (public data). Proven: `make stage-smoke` step 4, unauth `POST /issue` → 401.
- This is standard infrastructure practice — staging before mainnet — and it is what lets real crypto go online
  *now* without faking the production root. `make stage-up|status|smoke|down` runs the whole network on one host;
  `deploy/` containers + the 3-host layout are the multi-region path (operator supplies hosts/domains).

**Honest scope (M14).** This milestone builds and runs the staging network + the artifact contract + the scale
measurements + AINRAscan-on-staging, all labeled TEST-ROOT. It advances the *machinery* for two pending DoD rows —
witness recruitment (deploy/witness-quickstart.md: an outsider witnesses staging in <10 min) and the 14-day/3-region
soak (the 3-host deployment IS the soak platform; docs/runbooks/soak.md is the human's start procedure). It does
NOT start the 14-day clock, run the ceremony, register a domain, publish a repo, or claim any usage — adoption is
earned by the humans running those rows. The DoD table is untouched and unfaked.

## D-033 — M15: production cutover is config, not a fork (staging↔production parity, data-driven banner)

Genesis brings production up as the **same reviewed staging deployment** with four axes changed — name, banner env,
volumes, and key source (the ceremony root chain vs staging's dev first-boot keys). A fifth difference is a fork,
and a fork is where a "production" deploy silently drifts from what was tested. So parity is **pinned by
`make config-diff`** (tools/config-diff.mjs): it masks the four allowed axes and asserts the two compose files are
otherwise byte-identical, failing closed (with the diverging lines) otherwise — proven by a negative test (a rogue
port change is caught). A divergence may be introduced only with a written D-0xx waiver.

The STAGING-vs-PRODUCTION display is **data-driven, not code-forked**: the artifact server emits
`X-AINRA-Network`/`X-AINRA-Root` from `AINRA_NETWORK`/`AINRA_ROOT` (set by the deploy profile from the real signing
root); AINRAscan and the services read them and label themselves accordingly. One codebase is honest as either
network — on genesis day AINRAscan flips to PRODUCTION by key-detection, showing honest near-zeros becoming real
entries (its empty-state design), never a hardcoded claim. **Nothing trusted migrates from staging** (different
root, keys, domains, volumes; the banner says which you are reading). docs/genesis-day/CUTOVER.md holds the DNS
checklist + the `v1.0.0-genesis` release/freeze/re-tag discipline.

## D-034 — M16: the open registrar console is neutral open-core (the reference never advantages anyone)

Registrar-in-a-box serves a minimal web console at `GET /console` (issue / renew / revoke / list with live verdicts,
the ADR-017 fleet expiry horizon, and delegation/mandate views). It is deliberately **unbranded and neutral**: no
company styling, no pricing, no accounts beyond the registrar's own operator write-token (kept in memory, never
stored). This is a **constitutional constraint, not a style choice** — the console is the open-core every registrar
inherits, so commercial registrars may skin it downstream while the reference advantages no one. The **root gains no
console and no self-serve surface** (M16's first constitutional constraint): issuance UI lives only in the registrar
layer, exactly as the ICANN model demands. The M14 write-path rate limits apply unchanged (the console drives the same
guarded API). The CLI remains the power surface; the console exists so a first-time operator sees the whole lifecycle
without reading anything. Baked into the binary (`include_str!`) so every registrar serves it with zero extra files;
self-contained, zero telemetry, talks only to its own registrar.

## D-035 — M17: staging republish is idempotent (the published contract equals the live board)

`tools/stage.sh publish` now `rm -rf`s `stage/public/registrars/` before re-fetching each **live** registrar's
artifacts. Previously it globbed every directory present, so a leftover dir from a prior onboarding (`registrar-22`,
from a one-off `onboard-registrar.sh` run) was folded into the combined `registry.json` — inflating it to 3 registrars
/ 9 issued while the live board (`make stage-status`) showed 2 / 8. **The public contract was advertising a registrar
with no live daemon.** This was a real bug in the deploy/resurrection story, not cosmetic: any consumer reading the
contract (AINRAscan, mirrors, the site's live-data adapter) would trust a dead registrar. Republish now reflects only
what is actually running; the board and the contract agree by construction.

## D-036 — M17: the access-request form is a structured `mailto:` (no PII on any server we run)

The founding-table form composes a `mailto:` (seat + reply-to email, prefilled subject/body) and hands off to the
visitor's own mail client. **No personal data is stored on any server we operate** — consistent with the zero-PII,
zero-telemetry charter — and there is **no fake success state**: the copy says the request completes only when they
actually send the email, and points at the intake address if nothing opened. The alternative (a serverless form
endpoint) would put us in the position of storing contact PII pre-genesis for no operational reason; `mailto:` is the
minimal honest mechanism. The intake address (`founding@ainra.org`) travels with the canonical-host find-replace at
deploy time. No accounts, no billing, no server — the root grows no product surface.

## D-037 — M23: the suite-migration overlap is an AUTO-EXPIRING policy epoch, default closed

When the CLI verifier meets a legacy credential (Ed25519-only, no ML-DSA half) after the registrar has gone hybrid,
the default is **fail closed** — reason `alg_downgrade`, exit 1. A relying party may grant a migration overlap, but
only through a **bounded** switch: `--accept-legacy-until <date>` accepts a legacy credential **only** while that
date is in the future; a past or malformed date parses to `NaN > now → false`, so the overlap **auto-expires to
closed even with the flag present**. (`--accept-legacy` without a date is the unbounded testing form — never a deploy
default.) Two properties make this safe by construction: **(a) fail-closed default** — forgetting to configure a
policy denies legacy credentials rather than admitting them; **(b) no standing exception** — a bounded epoch cannot
silently outlive its window, so "we'll migrate later" cannot decay into a permanent downgrade surface. A **tampered**
credential (ML-DSA half present but broken or non-canonical) is `sig_invalid` and is refused under **every** policy,
the flag included — the overlap forgives an *absent* PQC signature during migration, never an *invalid* one. This is
the exact posture ADR-017 trap (ii) requires of a suite migration over a running network; proven by
`make cli-check` and `make suite-migration-drill`.

## D-038 — M23: push status is advisory transport over a sovereign pull (ADR-018)

Revocation must fail closed in <60 s (ADR-017 depends on it), which tempts a *trusted* push channel — and a trusted
push channel is a new authority to attack. We refuse that: an optional SSE/webhook MAY **announce** that a new
head/delta exists, but the announcement is **unsigned and carries no trust**. The verifier reacts by running the
**normal signed pull + validation** (delegate signature → freshness), identically to a scheduled poll. There is **no
push-only code path**; the pushed bytes are never believed. Push becomes a pure latency optimization — it can make
the sovereign pull happen sooner, never replace it. Two threat cases fix the design and both fail closed:
**suppression** (withhold the push) changes nothing because the scheduled pull enforces freshness (`stale_status`
past the window — F1 ≤ 30 s), and **forgery** (fake the push) changes nothing because the announced bytes are
validated on pull (`checkpoint_invalid`). Alternatives rejected: trusting a pushed head (a forged/withheld push
becomes a revocation bypass) and pull-only on a fixed interval (revocation latency = the whole interval).
`tools/push-announce.mjs` is the reference advisory bridge (poll → SSE frames, unsigned, each frame naming the
pull-to-validate reaction); `make push-advisory-check` proves both threat cases against the real conformance
vectors. Spec: MTS ADR-018 (the only spec change in M23; the Standard stays v5.1).

## D-039 — M23: the genesis ceremony transport is file-based, not networked

The M4 `ceremony` binary runs all nine custodians in one process (a faithful simulation). A real genesis ceremony
must run each custodian's key material on their OWN machine, and the safest such machine is **air-gapped**. So the
distributable ceremony (`dkg-participant`, `make ceremony-rehearsal-multi`) exchanges every DKG + signing round
message through a shared **file "postbox"**, never a socket: a custodian reads the round's inputs from files, writes
its outputs to files, and can power down between rounds. This is deliberately the lowest-common-denominator transport
— a courier carrying a USB stick satisfies it — and it keeps the signing side free of any network dependency (matching
the root's "safe to be dark" posture, ADR-014). No custodian ever sees another's secret; the group secret is never
assembled anywhere; the emergent group key is a standard RFC 8032 Ed25519 key. Alternatives rejected: a networked DKG
coordinator (adds an online attack surface to the most sensitive ceremony and forbids true air-gap) and keeping the
one-process simulation (never exercises the real multi-party choreography). Nine isolated OS processes prove the
transport; the recorded ceremony with independent custodians remains the pending real-world DoD event (no DoD row
moved). `make ceremony-rehearsal-multi`; runbook appendix in `kits/ceremony/RUNBOOK.md`.

## D-040 — M23.1: a release exists only when its board is proven at its commit; the toolchain is pinned to a patch

Two failures in the v0.2.0 work made this rule necessary, so it is now enforced, not trusted. **(1) The board is the
release.** A version is not tag-ready or CHANGELOG-claimable until `make preflight` runs ALL GREEN from a **clean
clone at the exact release commit** and that board is committed to `docs/releases/<version>-board.md`.
`make changelog-board-check` (in `make ci`) fails if the CHANGELOG names a released version whose board evidence is
absent — the claim can never outrun the proof (RELEASING.md, "The one rule"). v0.1.0 is grandfathered (never tagged,
predates this). **(2) The formatter is pinned to a patch.** `rust-toolchain.toml` and every CI job pin
**`1.96.1`** exactly (was the floating `1.96`, which silently resolved to a newer rustfmt whose heuristics reflowed
three committed files — the fmt gate had drifted red without a commit). The whole workspace was re-baselined under
1.96.1 (`cargo fmt --all`; fmt + clippy clean), so a stranger's CI reproduces our fmt result deterministically.
Alternatives rejected: trusting `scripts/release.sh`'s in-process preflight (leaves no committed evidence a stranger
can audit) and a floating toolchain (drifts the fmt gate red between releases with no code change).
