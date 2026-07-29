<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# STATUS — AINRA reference implementation (M1–M9 ladder done · M10 public-ready · M11 public-operational)

<!-- STATUS-LINE -->Engineering ladder M1–M9 complete; M10–M11 make the repository public-ready, public-operational, and the four remaining DoD rows stranger-runnable; M12 bounds credential validity (366 d default, invisible ACME-style renewal with logged continuity — ADR-017); logs sealed by the real root: 0.

Honest state of the tree. If it says green, `make` proves it; if it says M6+, the code does not pretend otherwise.
Prime directive: **nothing fake, ever** (brief §0). Toolchain: Rust 1.96, Node 26, `ml-dsa 0.0.4` / `slh-dsa 0.0.3`
/ `ed25519-dalek 2.2.0` / `frost-ed25519 3.0` (ceremony only — never in the verify path).

## Acceptance bar (brief §8 / MTS §28–29)

A stranger clones, runs `make test && make vectors && make diff`, all green in <10 min on a laptop.

| Target | What it does | State |
|---|---|---|
| `make test` | `cargo test --release --workspace` — **118 tests** (core unit incl. directory + property + frost + ceremony + registrar + service + networked-quorum regression) | ✅ green |
| `make vectors` | regenerate **721 passport (incl. 24 ADR-017 boundary + 29 renewal/REISSUE + 8 D-029 non-canonical-encoding) + 24 delegate-revocation + 17 delta + 9 directory** CC0 vectors + self-check | ✅ green |
| `make vectors-check` | replay ALL three committed corpora back through ainra-core | ✅ green |
| `make diff` | differential (below) — verdicts **745/745**, canon 10/10 + 4/4, delta 17/17, **directory 9/9** | ✅ green |
| `make ceremony` | **M4** genesis rehearsal: FROST 5-of-9 dual root → signed directory → mint/verify → revoke→`checkpoint_invalid` → rotate→VALID → transcript | ✅ green |
| `make testbed` | **M5** the wedge: live registrar → `accredit` → 5-line `ainra-verify` → VALID; revoke → INVALID; **+ 4b: forged all-clear status (clear/strip/swap-uri) → INVALID**; verify-latency | ✅ green |
| `make wedge-test` | **M5+M6** the `@ainra/middleware` gate — **18** fail-closed tests (malformed denied, nothing throws, **the revocation-bypass regression**: forge/DoS/freshness-window, **+ M6 currency-mode**: fresh-head bind + monotonic-seq replay rejected) | ✅ green |
| `make drill` | the M2 pipeline end-to-end + injected-fork drill, **+ M6 witness QUORUM** (5 witnesses, k=3: honest head certified, fork refused 5/5 → not certified) | ✅ green |
| `make demo` | the M3 lifecycle end-to-end: issue → verify → log-verify → revoke (signed delta) → re-verify | ✅ green |
| `make console` / `make explorer` | passport-book viewer + live verify; the registrar explorer over a signed export | ✅ green |
| `make scale` | the billion-device proof: a REAL 1-billion-lineage status list + 16M-leaf trees + sharded issuance, measured → `docs/SCALE.md` | ✅ green |
| `make repro` | **M7** reproducibility: rebuild the 790-file spec artifact set from source into a fresh temp tree ×2, assert **committed == clean-rebuild ×2** byte-identical → `MANIFEST.sha256` | ✅ green |
| `make mirror` / `make verify-mirror` | **M7** byte-verify a mirror against the manifest (fail-closed on tamper/missing/extra/symlink/subdir-manifest); 2 mirrors proven | ✅ green |
| `make check-freeze` | **M7** the normative docs (Standard · MTS · DESIGN) are frozen; drift fails | ✅ green |
| `make genesis-local` | **M8** the whole stack on one laptop (§29/N9): dual root → 2 distinct registrar classes → issue+log → 5-line verify root-dark → revoke/forge fail closed → witness-quorum fork caught → transcript | ✅ green |
| `make verifier-kit-smoke` | **M9** a stranger verifies root-dark + rejects revoked/forged + verifies a fresh secret-coin-flip challenge corpus with only `@ainra/sdk` → **execution-bound** attestation certified against a private answer key; hand-authored/wrong-answer/replay/answer-key-less all fail closed | ✅ green |
| `make ceremony-dry-run` | **M9** N custodians rehearse the commit-reveal choreography; real dual-root ceremony (TEST-ROOT); a witness recomputes the transcript hash; a skipped step fails loud | ✅ green |
| `make soak-smoke` | **M9** revocation-propagation instrument: 3 vantage points, p50/95/99 into a hash-chained log, signed report, SLO computed + fail-closed | ✅ green |
| `make drill-networked` | **M9** the witness quorum over HTTP — N independently-keyed `witnessd` processes; injected fork refused; k stays the relying party's (D-021 transport) | ✅ green |
| `make cli-check` | **M23** the downloadable CLI is hybrid Ed25519 + ML-DSA-65 both-or-invalid; legacy⇒`alg_downgrade` (overlap-only), tampered⇒`sig_invalid` (always closed) | ✅ green |
| `make suite-migration-drill` | **M23** a real Ed25519→hybrid migration over a running network: REISSUE + `prev_leaf` continuity, auto-expiring policy epoch (D-037), legacy-fails/hybrid-passes; staging audited already-hybrid. Transcript: [docs/drills/SUITE-MIGRATION-01.md](drills/SUITE-MIGRATION-01.md) | ✅ green |
| `make ceremony-rehearsal-multi` | **M23** FROST 5-of-9 across NINE isolated OS processes (file-based rounds, D-039): one group key emerges, 5 shares sign / 4 cannot, transcript reproducible | ✅ green |
| `make witness-check` | **M23** witness kit v2: one-file config, self-declared `/info`, `/root` alias, back-compat, quorum still refuses a fork; times the <10-min onboarding | ✅ green |
| `make push-advisory-check` | **M23** ADR-018 threat proof: push is advisory, pull sovereign — suppression fails closed (`stale_status`), forgery ignored (`checkpoint_invalid`) | ✅ green |
| `node tools/s7-lint.mjs` / `license-check.mjs` | neutrality + license gates | ✅ green, 0 hits |

## What is REAL and green

**`crates/ainra-core`** — the product. Pure library, `#![forbid(unsafe_code)]`, **no I/O, no network, no clock**
(the caller supplies `now` and all fetched material). Modules:

| Module | Implements | Spec |
|---|---|---|
| `name` | `ainra:` + `did:ainra:` grammar, parse∘format round-trip, homoglyph rejection, `did:web` mapping | MTS §15, ADR-014 |
| `canon` | one canonical JSON encoder; rejects floats, non-ASCII keys, >2⁵³ ints (cross-impl total) | MTS §14, D-003/D-010 |
| `crypto` | **hybrid Ed25519 + ML-DSA-65** (both mandatory), SLH-DSA verify + TEST-ROOT, TEST-DELEGATE, FIPS size asserts | MTS §14, D-005/D-006 |
| `merkle` | RFC 6962 inclusion + consistency proof verify + in-crate test log | MTS §14, D-008/D-011 |
| `passport` | SD-JWT-VC schema; rejects PII/score/price; dual-sig + log_leaf + chain-linkage validation | MTS §15, D-001/D-012/D-013 |
| `status` | TSL codec (zlib, LSB) + freshness + **M3: signed `StatusDelta` (dual-authorized, single-step monotonic) + delegate-signed `FreshHead` (30 s F1 heartbeat) + `head_hash` identity** | MTS §16, ADR-007, D-015/D-016 |
| `checkpoint` | SLH-DSA-signed checkpoint + ADR-002 delegate signer (scopes `checkpoint`/`delta-countersign`/`fresh-head`) + **M4: `DelegateCert::fingerprint`** | MTS §13/§14, ADR-002/D-011/D-019 |
| `directory` | **M4: dual-root-signed registrar directory** — `accredit` (FROST-Ed25519 + SLH-DSA, both-or-invalid, sorted/unique) → `TrustAnchors` + revoked-delegate set | MTS §13, D-019 |
| `chain` | delegation ∩-narrowing + dual-signed hop verify + hop leaf | MTS §17, D-012 |
| `mandate` | subtree revocation (static path; dynamic/AP2 still M-later, fail-closed rejected) | MTS §18, D-009/D-013 |
| `verify` | the 9-step orchestrator → `Verdict`; fixed order, all 15 frozen reasons reachable + **M4: delegate-revocation input** | MTS §8, D-019 |

**`services/ainra-services`** — thin over `ainra-core`, no novel security logic:
* **`logd`** (M2) persistent append-only log, delegate-signed checkpoints, inclusion + consistency proofs;
* **`witnessd`** (M2) cosigns append-only growth, refuses + alarms on a fork (`make drill`);
* **`statusd`** (M2→M3) signed TSL publisher **+ the delta stream + fresh head** (`/revoke` emits a signed,
  delegate-countersigned delta; `/deltas?since=`, `/fresh-head`, `/root`);
* **`registrar-box`** (M3, spec C5) the REAL issuer engine + daemon: issue (real holder keys + real `cnf.jkt`
  thumbprint, dual-signed hops, logged-before-valid at issue, delegate-signed checkpoint snapshot + RFC 6962
  inclusion proof) · revoke (signed delta) · self-describing datastore · **deterministic reload** (seed in a
  separate 0600 `registrar.secret`, never in the shareable snapshot; reload **re-verifies every replayed delta**
  and refuses a truncated/forged delta log — fail closed on any tampered snapshot).

**`crates/ainra-cli-rs`** — the `ainra` CLI, offline + persistent: `init · accredit · issue · list · verify ·
log-verify · revoke · present · status · fresh-head · deltas · export · seed · reverify · demo`. Every verdict is
the real verifier's. `seed` builds the fictional 3-registrar/12-lineage registry (2 delegation trees, 3
revocations) and self-checks all 12 records against the core verifier; `reverify` is the third-party check.

**`apps/registrar-explorer`** — a functional client-side app over the signed export: search / filter / sort /
URL-state, the visualized narrowing delegation chain, the 9-step verification trace (each step honestly labelled
`re-checked` live vs `core-verified` crypto), a revoke workflow (live daemon or over loaded state), verify-at-time.

**Conformance corpora** — `vectors/v1/` **660** passport vectors (every one of the 15 reasons) + `vectors/v1-delta/`
**17** delta/fresh-head vectors (every accept/reject reason of the delta codec, incl. seq-0 wrap, descending idx,
future-dated head). Both replay-gated (`--check` / `--check-delta`) locally AND in hosted CI.

**`packages/sdk-ts`** — independent verify-only mirror; byte-matches canon + all M2/M3 semantics incl.
`verifyDelta`/`verifyFreshHead` (same fixed order, same reasons, fail-closed on unknown freshness class + canon
errors). **Differential** (`make diff`): verdicts core↔sdk **660/660**; canon core↔sdk↔P0 10/10; canon-reject 4/4;
**delta core↔sdk 17/17**.

**Scale proof** (`make scale` → `docs/SCALE.md`) — the billion-device question answered with measurements, not
slides: a **real 1-billion-lineage status list** built in-process (compresses to ~2.6 MB; O(1) lookups; ~6 KB
signed deltas + a ~220 B fresh head whose cost is independent of device count), **real RFC 6962 trees up to 2²⁴
leaves** (proof measured at 768 B; structurally ~1 KB at 8.6 B leaves; µs verify), **sub-millisecond full 9-step
verify** (≈0.5–0.7 ms measured per laptop core — verification is local, the root does zero per-verify work), and
**~1.1 k real issuances/s per shard, measured FLAT into a log pre-populated with 1,000,000 real entries** plus
near-linear multi-shard scaling (shard-per-registrar shares nothing). The flat rate is real engineering, not a
caveat: the reference log now runs on an **incremental RFC 6962 tree** (`services/…/tree.rs`, O(log N) per-issue
root/proof) proven **byte-identical to the audited core** by exhaustive differential tests (every index at every
size 0–300 + core-verifier spot checks). The report labels every number *measured* or *structural*, states its
own limits (in-RAM tree/index — production is Tessera tiles + DB; per-registrar-segment device budgets; M4+ ops),
and its claims were **adversarially re-verified against the harness code** (3 lenses; 5 findings — a rounding
falsehood, an over-exact formula, flattering all-zero lists, undisclosed per-shard budgets, and the O(N) issuance
extrapolation — all fixed, the last by the incremental tree + the 1M-record measurement).

**M4 — threshold root + signed directory + revocation/rotation** (`make ceremony`). `crates/ainra-ceremony` runs a
real **FROST 5-of-9 DKG** (audited ZF `frost-ed25519`; 9 custodians, group secret never assembled) + threshold
signing whose output is a **standard RFC 8032 Ed25519 signature** — so `ainra-core` verifies it with plain Ed25519
and never links against FROST (N7 preserved); a 4-of-9 quorum cannot sign. The `directory` module makes "accredit
registrars" a concrete **dual-root-signed** object (`accredit` → `TrustAnchors` + revoked-delegate set; both
signatures + sorted/unique entries or `unknown_registrar`). Delegate revocation is a `SHA-256(cert)` fingerprint
published in the directory; `verify::verify` rejects a checkpoint by a revoked delegate as `checkpoint_invalid`
(rotating the same key mints a *different* fingerprint, so rotation restores service). The ceremony rehearsal shows
one minted passport go **VALID → checkpoint_invalid (revoke) → VALID (rotate)** through the full 9-step verify, then
re-verifies its written directory from disk. Cross-checked core↔sdk-ts: 24 delegate-revocation + 9 directory
vectors (diff phases A/E). Decisions D-018/D-019.

**M5 — the verification wedge** (`make testbed` / `make wedge-test`). The Execution Playbook's central primitive:
verify in **~5 lines**, local, offline, fail-closed. `@ainra/sdk` gained a GA **`Verifier`** — build once from a
dual-root-signed directory (`fromDirectory`/`fromDirectoryB64` → anchors + revoked-delegate set, `null` if not
authentic), then `.verify(bundle, now)`; the verifier owns the **clock** and the **revocation set** (a presenter
can dictate neither), and it **never throws** (a broken bundle is an `invalid` Verdict, never a crash or a wrong
`valid`). `@ainra/middleware` wraps it as a Connect/Express `ainraGate` (403 + `x-ainra-reason`, never `next()`s a
deny) + a framework-agnostic `checkRequest` — **13 fail-closed tests** (incl. the bypass regression below).
`registrar-box` emits the `/present` bundle (1:1 with the conformance `presentation` block); `ceremony accredit`
builds a dual-root directory over a *live* registrar's published keys; `ainra-verify` is the CI/edge step (exit
0/1/2, `--bench` latency); `make testbed` composes them: issue → **VALID**, revoke → **INVALID (revoked)**, then
verify-latency — all real. The verify path is unchanged (diff still 684/684 + directory 9/9); the verification
itself is unchanged, so M5 stays packaging (D-020).

**M5 adversarial review — CRITICAL revocation bypass, found and closed.** The review caught that the original wedge
trusted the bundle's status list verbatim: a hostile presenter could forge an all-clear bitmap + a fresh
`issued_at` and make a *revoked* passport verify VALID. A bypassable gate is fake by our own doctrine, so the
M6-planned status-publisher signature was pulled into M5. The registrar now publishes its **Token Status List
signing key in the dual-root-signed directory** (part of the signed body → tamper-proof); the `/present` bundle
carries the **signed publication** (`status_uri` + hybrid sig over the canonical `{bit_len, issued_at, status_list,
uri}`); and the GA `Verifier` authenticates the list against that key — with a **triple URI binding** (passport =
bundle = directory) — *before* core verify trusts a single bit, failing closed to `stale_status` otherwise. This
lives in the GA `Verifier` layer, **not** the frozen 9-step verify, so the differential is untouched (684/684 +
9/9). Shipped with it: the `Verifier` ignores the bundle's `mandate_revocations` and freshness class (both
verifier-sourced); `unpackStatus`/`StatusList::decode` bound the declared length (`MAX_STATUS_BITS = 2²⁴`) and cap
the inflate in **both** impls (no zlib-bomb OOM); anchor/freshness lookups use null-prototype maps + `Object.hasOwn`
(the label `constructor` can't masquerade as an anchor; a `__proto__` freshness label can't defeat the gate). Proven
closed **three ways**: `make testbed` step 4b (forge `clear`/`strip`/`swap-uri` → all INVALID, live daemon);
`make wedge-test`'s hermetic regression on **real captured artifacts** (`packages/middleware/test/fixtures/`, four
forge tests → all INVALID); and the unchanged 684/684 differential. A **second adversarial pass** (5-invariant
attack→verify→synthesize workflow) confirmed the forgery bypass closed and found two residual issues, both fixed: a
**HIGH pre-auth memory-amplification DoS** (the status list was expanded to a `boolean[]` before authentication —
now kept packed as a `Uint8Array` and the signature is checked over the compressed bytes *before* any inflate, so an
unauthenticated request can't OOM the verifier) and a **LOW replay-within-freshness-window** (an inherent
stapled-snapshot latency the docstring overstated — now documented honestly; sub-window currency via fresh-head
binding is M6). See D-020.

**M6 — witness quorum + fresh-head currency** (`make drill` / `make wedge-test`). Two additions, both OUTSIDE the
frozen verify (differential unchanged: **684/684 + 9/9**). **(A) The fork catch is a QUORUM's, not one operator's.**
`WitnessQuorum` (N independently-keyed witnesses + threshold k) produces a verifiable `QuorumCertificate`; a relying
party counts only cosignatures that are cryptographically valid, roster-known, distinct, and over the exact
checkpoint (`valid_cosigns`, fail-closed), and **supplies its OWN k** to `certified` (the certificate carries none).
Once the quorum certifies the honest head at size N, an equivocating fork at N is refused by every honest witness →
gathers cosignatures only from adversarial/partitioned witnesses → certifiable only if **f ≥ k**. `make drill`: 5
witnesses, k=3, fork refused 5/5 → 0 cosigns → not certified; `tests/fork_drill.rs` pins the `f < k` boundary + the
fail-closed counting. **(B) Fresh-head currency mode** closes the M5 review's replay LOW: the `/present` bundle now
carries the registrar's delegate-signed fresh head + cert, and an opt-in `currency` Verifier **requires + verifies**
it (cert → log root, F1 recency), **binds** it to the presented list by head-hash, and enforces a **monotonic seq** —
so once the verifier has observed a newer head, a replayed superseded snapshot is rejected (`stale_status`). Stateful
+ strictly opt-in (the default stateless wedge is unchanged); the honest limit (a purely passive verifier still
relies on the F1 window) is documented. **M6 adversarial review** (5-invariant workflow) confirmed the currency
replay-closure sound and found **1 HIGH** — `certified` read the threshold `k` from the attacker-authorable
certificate (`threshold: 0` → a fork certifies with zero cosigns); **fixed**: k is now a relying-party argument, the
field is gone, and `certified` refuses k=0. Regressions added; `fork_drill.rs` proves zero-cosign/one-traitor forks
can't certify. See D-021.

**M7 — reproducible builds + mirrors + docs freeze** (`make repro` / `make verify-mirror` / `make check-freeze`).
The published spec artifacts (745 + 17 + 9 CC0 vectors + the 3-face sample book, 790 files) are made verifiable by
anyone, with the **source** as trust root. `make repro` rebuilds the whole set from source into a fresh empty temp
tree **twice** and asserts **committed == clean-rebuild ×2** byte-identical (deterministic: seeded RNG, no wall-clock),
then writes `MANIFEST.sha256`. A **mirror** is any host serving that set; `make verify-mirror` recomputes every hash
and passes only if byte-identical with nothing missing/extra — so a relying party checks any mirror against a manifest
it can itself reproduce, trusting neither the mirror nor us. The normative docs are frozen. The `tsc` `dist/` is
deliberately excluded from byte-identity (verified for behaviour by the differential instead) — see
`REPRODUCIBILITY.md`. **M7 adversarial review** (5-invariant workflow) found the machinery could report success while
false — **4 real defects, all fixed**: repro regenerated *in place* so a committed **orphan** was laundered as
reproducible (→ now a clean rebuild into temp, set-compared); mirror-verify excluded extras by **basename** (smuggle
a subdir `MANIFEST.sha256`), **ignored symlinks**, and **skipped the last entry** on a newline-stripped manifest (all
fixed + regression-tested; a planted orphan, subdir-manifest, symlink, and no-newline manifest are now all caught).
See D-022.

**M8 — `make genesis-local`: the whole stack on one laptop** (MTS §29 / N9). One command boots the entire AINRA
world, all real, and writes a transcript: a **dual-root ceremony** (FROST 5-of-9 + SLH-DSA) over **two
cryptographically-distinct registrar classes** → each issues a passport **logged-before-valid** → a stranger's
**5-line SDK verifies with the root DARK** (only directory + roots) → **VALID** → revoke → **INVALID**, forged
all-clear → **INVALID** (fail closed) → an injected log fork **caught by the witness quorum 5/5, not us** →
`transcript.json` (roots, registrars, every verdict, a SHA-256 of every artifact — all reproducible via `make repro`
/ `make verify-mirror`). Every verdict is the real tool's exit code; any wrong outcome exits nonzero. `docs/DOD.md`
opens the §29 Definition-of-Done, marking each criterion **✓ laptop-provable** or **external/pending** (≥3 independent
operators, the p95 < 60 s ×3-region ×14-day soak, the recorded ceremony — real-world items, unfaked). **M8 adversarial
review** found **3 real issues, all fixed**: the two registrar-box daemons seeded from a *constant* → **identical
keys** (now id-derived, cryptographically distinct); hardcoded ports + swallowed stderr let a **stale daemon** serve
the run silently (now a pre-flight port check + post-launch `kill -0` liveness); and the DoD overclaimed the
in-process witnesses (now marked ✓-in-process / external-operators, per D-021). See D-023. **This completes the MTS
§27 milestone ladder M1–M8.**

**M11 — public-operational.** No new protocol; plumbing + durability + the operator loop (D-026). (1) **CI runs the
full gate set on the host** on push/PR + **nightly** (`.github/workflows/ci.yml`): 8 parallel jobs with `timeout-minutes`,
`concurrency` cancel-in-progress, least-privilege perms; a dedicated **`audit` job runs the same `make audit`** a
contributor runs (so no PR can reintroduce a secret or a brand name); reproducibility stays a PR gate in its own job.
(2) **Release hygiene:** `make release` refuses a dirty tree / red preflight, re-checks reproducibility, builds the
reference CLI, and writes a signable `dist/SHA256SUMS` (proven: CLI + vectors tarball + manifest); `CHANGELOG.md` maps
to the ladder + owns the fixed security bugs publicly; `RELEASING.md` gives the downloader's verify-by-rebuild path.
(3) **Community health:** issue forms (security routed **privately**, bug, vector-discrepancy) + a PR template
(tests/preflight/audit/SPDX/DCO). (4) **Operator loop** for the highest-leverage ⏳ row: `mint-challenge --party` (answer
key under gitignored `ops-verifier/`), `check-attestation --party` → durable `evidence/verifier/<party>.json` the board
reads, `kits/verifier/OPERATOR.md`; `make verifier-operator-drill` proves it on 3 dry-run parties (forgery refused).
(5) **Durability:** `TOOLCHAIN.md` + `make doctor`, golden-path scripts point a missing toolchain at `make doctor`,
and `status-consistency.mjs` now also pins the board's ✅/⏳ counts to `docs/DOD.md`. The CI badge is one find/replace
(`<owner>`); the ordered **pre-push checklist** is in `docs/PUBLISH-AUDIT.md`.

**M10 — public-ready + the DoD events made stranger-completable.** No new protocol. (1) **Publish audit**
(`docs/PUBLISH-AUDIT.md`, D-025): full-24-commit-history secret sweep = **0 real secrets** (`gitleaks` FPs on CC0
vector PUBLIC keys, now allowlisted in `.gitleaks.toml` + a CI job over full history); three self-labeled-PRIVATE
strategy docs + the legacy `_archive/` were **excised from all history** (`git filter-repo`, relocated to
`../ainra-private/`) so the tree is brand-clean; the code-cited MTS kept + scrubbed of internal framing. S7 now sweeps
**docs + kit READMEs + `.github` + every commit message** with a curated `s7-brand-denylist.txt` (both passes green);
`THIRD-PARTY.md` inventories all 115 crates + Node deps (OSI-permissive, no forced copyleft); `make preflight` prints
the cold-clone green/red board and `make audit` gates S7+license+gitleaks. (2) **Cold-open onboarding** per kit
(verifier `QUICKSTART`+`TROUBLESHOOTING`+`make verify-as-external`+`verifier-triple-drill`; ceremony role-split RUNBOOK
+ `ceremony-checklist.json` + `verify-transcript`; soak `DEPLOY` + `make soak-verify`). (3) **Genesis board**
(`tools/genesis-board/`, `make genesis-status`): verifies collected attestations/transcript/soak-reports and renders
the §29 table — ✅ only with a signature-checked artifact; today **7/11** (laptop rows green, external rows ⏳ pending
real people). (4) **`outreach/`** — plain, no-hype, no-brand calls for verifiers, witnesses, custodians. Every M10
acceptance green from a fresh clone; the front door (README) and this file are kept in sync by
`tools/status-consistency.mjs`. See D-025 + `docs/PLAN-M10.md`.

**M9 — committed, public-ready, executable by strangers.** The tree is now a real **git repository scoped to the
project** (not `$HOME`), with a strict `.gitignore` (no secrets — the TEST registrar reload-seeds are excluded — no
`target/`, `node_modules/`, `dist/`, run-outputs), dual-license (Apache-2.0 OR MIT) + **CC0** vectors, and 15
milestone-mapped commits. **Acceptance proven:** a fresh `git clone` runs `make test && make diff && make
genesis-local` green (re-proven after every kit change). **CI** (`.github/workflows/ci.yml`) runs every gate on push —
fmt/clippy/test(release)/vectors, the 684/684 differential, wedge, **integration** (drill/testbed/genesis-local),
**reproducibility** (repro + verify-mirror tamper), check-freeze, fuzz, S7/license/N7. Four **kits** let outsiders run
the pending real-world DoD events without us: **`kits/verifier/`** (verify root-dark + reject revoked/forged with only
`@ainra/sdk`, then verify a **fresh challenge corpus** with secret coin-flip revocations → an **execution-bound**
signed attestation the maintainer certifies against a private answer key, so a party who never verified can't fake it),
**`kits/ceremony/`** (the 5-of-9 RUNBOOK + a witness-reproducible dry-run that fails loud on a skipped step **or a
copied/aliased custodian part**), **`kits/soak/`** (revocation-propagation measured into a signed, hash-chained,
tamper-evident report — SLO **pinned by the collector**, never read from the report, fail-closed), and
**`kits/witness/`** (the quorum over HTTP — D-021's transport, `witnessd` now with distinct per-address keys). Each kit
was **twice adversarially reviewed** (two workflow rounds; round 2 caught 2 self-review bypasses — a base64-alias
quorum forge and an attestation that proved agreement not execution — both fixed, see D-024). N7 preserved: any
traction metric is opt-in/count-only in the kit layer, never in `ainra-core` or the SDK. The ordered "how we declare
done" runbook is `GENESIS-CHECKLIST.md`; the honest ✓-vs-⏳ table is `docs/DOD.md`. See D-024.

**M4 adversarial review** (workflow, 5 dimensions): the HIGH/MEDIUM sdk-ts parity gaps flagged were **already fixed
before the verify pass** (a re-read refuted them) — malformed revoked-delegate fingerprints now decode+length-check
(fail closed), `verifyDirectory` catches canon errors, and the fingerprint set is canonicalised. **3 low findings
CONFIRMED + fixed:** registrar-id sort could split Rust (UTF-8) vs sdk-ts (UTF-16) on non-ASCII ids → both now
reject non-ASCII ids; sdk-ts `b64uDecode` was lenient where Rust `b64::decode` is strict → sdk-ts now uses a strict
base64url decode for directory fields; and the `delegate-expired` vector reached `checkpoint_invalid` via a
signature mismatch rather than the expiry branch → it now uses a genuinely-expired, properly-signed cert (+ a new
`directory-malformed-fingerprint` vector). All re-verified: diff **684/684 + directory 9/9**.

**M3 adversarial review** (workflow, 6 review dimensions): **12 candidate findings**, all triaged; the real ones
all fixed and gate-tested before this status:
1. *(high)* reload replayed status deltas **without verifying signatures** → `replay_delta` now re-runs the full
   core `StatusDelta::verify` (both sigs + delegate cert) and binds `uri`; proven by `tampered_snapshot_is_refused_fail_closed`;
2. *(med)* a truncated delta log silently rolled back revocations → `load` now cross-checks the replayed head
   against the persisted `status_seq`, refusing the snapshot;
3. *(med)* attacker-controlled `Content-Length` allocation in the HTTP glue → 1 MiB cap;
4. *(med)* sdk-ts failed OPEN on an unknown freshness class / threw on canon errors → fails closed with the same
   reasons as Rust;
5. *(low)* issued credentials carried fabricated holder keys (`AAAA`/`BBBB`) → real hybrid holder keypair + real
   SHA-256 `cnf.jkt` thumbprint in every credential (registrar-box AND the samples);
6. *(low)* the reload seed lived in the shareable snapshot → moved to `registrar.secret` (0600);
7. *(low)* `issue()` with caller keys + zero hops minted an unverifiable record → guarded;
8. *(low)* delta-corpus coverage gaps + no CI drift gate → 3 new vectors + `--check-delta` + ci.yml regenerates
   and drift-gates `vectors/v1-delta`.

## What is DEFERRED to M5+ (recorded, not faked)

| Item | Why later | Decision |
|---|---|---|
| ~~FROST 5-of-9 root~~ · ~~delegate-cert rotation/revocation~~ | **DONE in M4** — real FROST DKG + threshold sign (verification-identical); revocation+rotation via directory-published fingerprints | D-018/D-019 |
| Real recorded ceremony (live custodian entropy, ≥5 jurisdictions, published transcript hash) | the M4 rehearsal is deterministic (labeled TEST seed), single-host | D-018 (M8) |
| Dynamic (AP2) mandates | needs the AP2 mandate-object model; still fail-closed rejected | D-013 |
| Tessera-backed production log; FROST **witness** thresholding + witness-network onboarding | storage swap / external ceremony work; M2's single-witness fork drill stands | D-005/D-011 |
| Directory distribution + rollback-monotonicity across fetches | the type carries `epoch`; the fetch/rollback policy is deployment work | D-019 (M5/M7) |
| Verifier middleware + TS SDK GA + live testbed · reproducible-build proof · `make genesis-local` | M5 / M7 / M8 | MTS §27 |
| registrar-box hardening (auth, TLS, origin allow-list, real key mgmt/HSM); real cargo-fuzz soak | daemons are local reference tools (documented); fuzz smoke ships now | D-017 |

## M12 — validity & renewal (ADR-017), shipped

The identity (lineage + AINRA Number) is permanent; the credential is bounded: **366-day default window** (one
constants module — `ainra_core::consts` — cited by the issuer, the registrar-box, the demo seeds, the P0 CLI, and
the TS SDK), exact window comparison pinned by `boundary-*` vectors (`nbf` inclusive, `exp` exclusive — no skew,
no grace period), and **REISSUE as a first-class renewal**: fresh window, new status index, and a signed+logged
`prev_leaf` continuity link, ACME-style-validated against the lineage head before anything is logged (wrong /
missing / forked links fail closed, and revocation flips EVERY unexpired generation so renewal can never dodge
it). L3+ issuance/renewal is capped by registrar-side tier-audit evidence (`exp` ≤ the audit's own expiry — the
error says why). `ainra renew <dir> <sub> [--dry-run]` performs it; the T−30 d lead is a deployment cadence, not
protocol. Status-list GC: deferred with the math on the table (D-028) — the wire already carries the cohort
discriminator (the status URI), and `StatusFull` stays a terminal honest error. Details: `PLAN-M12.md`,
DECISIONS D-027/D-028, MTS ADR-017.

## Known limitations honestly stated

- 711+24+17+9 vectors, not the 10 k GA target; broad but not the full combinatorial cross-product.
- Services persist to local files, bind 127.0.0.1, single-key signers — a working reference, not the hardened
  multi-region deployment (M4–M8). The CLI's `registrar.secret` is a TEST-labeled dev keystore, not an HSM.
- Holder keys are real and thumbprint-bound, but proof-of-possession (KB-JWT / RFC 9421 presentation) is not yet
  exercised by the verifier — the schema carries real material for it; the possession check is later work.
- Benchmarks (`make bench` → BENCHMARKS.md) are single-host indicative numbers.

## Next

M4 per MTS §27: FROST integration end-to-end + public rehearsal ceremony; delegate rotation; verifier middleware +
explorer on a live testbed (M5). See `PLAN-M3.md`.
