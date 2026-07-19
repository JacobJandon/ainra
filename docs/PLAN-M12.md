<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# M12 — Validity & renewal (ADR-017): identity eternal, credentials bounded, renewal invisible

ADR-017 (MTS): infinite passports REJECTED (status-list GC, crypto agility, ghost agents/claim staleness,
verifier fragmentation). Lineage + AINRA Number stay permanent. Passports default **366 d**; delegated ≤ 92 d;
renewal is ACME-style at **T−30 d** with **overlap issuance** and a logged **REISSUE** carrying a **`prev_leaf`**
continuity link; **L3+ passport `exp` ≤ the tier audit's own expiry**; long validity is affordable because
revocation **fails closed <60 s** — the opposite of Web PKI's shrinking-cert trajectory. No grace periods.

## Task 0 — audit: what exists vs. what ADR-017 needs

| # | ADR-017 requirement | Status | Evidence (file:line) |
|---|---|---|---|
| a | Passport nbf/exp set per-issuance, 366 d default, named constant | **partial** | Window is a registrar-wide `[nbf, exp]` pair frozen at `RegistrarBox::create` and stamped verbatim on every credential (`registrar.rs:227,517`); the only concrete window is a magic 365 d epoch pair duplicated in ≥6 files (`bin/registrar_box.rs:31`, `cli-rs/seed.rs:19`, `scale_proof.rs:23`, `sample_passport.rs:22`, `ceremony.rs:28`; P0 `plusDays(365)` `ainra.js:148,169`); **no named constant, no 366 anywhere**; core only enforces `exp > nbf` (`passport.rs:237`) |
| b | `not_yet_valid` / `expired` distinct, fail closed, vectors incl. boundary | **partial** | Both reasons exist among the 15 frozen strings (`verdict.rs:52-54,116-117`); verify step 3 is strict `nbf ≤ now < exp`, both Err → INVALID (`verify.rs:118-124`); sdk-ts identical (`index.ts:564-565`); 24+24 conformance vectors — but **all at ±50 s offsets, zero exact-boundary vectors**, and **no skew is applied anywhere** (ADR-016's ±30 s is freshness-layer prose only) |
| c | REISSUE distinct from ROTATE; any renewal path | **missing** (audited as partial only because ROTATE exists) | ROTATE = ceremony drill rotating the checkpoint **delegate key**, re-mints same window into a throwaway TestLog (`ceremony.rs:195-212`); logd entries are untyped canonical bytes (`log.rs:2-8`, `registrar.rs:533-546`); **no `prev_leaf` anywhere**; `issue()` hard-rejects a duplicate sub (`registrar.rs:429-431`) so renewal is structurally impossible today; no renewal vectors |
| d | Tier evidence with its own `audit_expiry`; L3+ clamp | **missing** | `tier` is a bare enum label (`passport.rs:29-38,130`); IssueSpec has no evidence input (`registrar.rs:47-58`); tests mint L3 with zero evidence (`registrar.rs:963`); the only expiries in the system are passport nbf/exp + hop exp; Standard §4 deliberately keeps evidence registrar-side ("never at the root") |
| e | Expiry as the status list's GC; epoch/cohort forward-compat | **partial** | Monotonic index cursor, never reclaimed, `StatusFull` terminal (`registrar.rs:432-435,594`); `StatusRef` frozen to `{idx, uri}` with deny-unknown in Rust **and** sdk-ts (`passport.rs:58-64`, `index.ts:104`); GC-by-truncation structurally impossible — past-end fails closed to Revoked (`status.rs:135-141`); measured math exists (21.2 KB gz @ 10 M, 0.1 % — MTS:31,98,317) |
| f | One constants module; `DELEGATE_CERT_MAX` = 92 d referenced by all | **partial** | `DELEGATE_CERT_MAX_SECS = 92 d` exists, enforced at issue AND verify, vectored ×24 (`checkpoint.rs:32-33,177-217`; vectors `checkpoint-invalid-delegate-expired-*`) — but lives inline; registrar restates a shadow `CERT_VALIDITY = 90 d` without referencing it (`registrar.rs:33`); sdk-ts hand-mirrors (`index.ts:370`); **no consts module; 366 d / 30 d exist nowhere**; instance-cred lifetimes are docs-only prose |

Only the *partial/missing* rows become work. Verdict-code additions are **not** needed (row b: both reasons exist).

## The design (what M12 builds)

1. **Constants** — `crates/ainra-core/src/consts.rs`: `PASSPORT_VALIDITY_DEFAULT_SECS = 366·86400`,
   `RENEWAL_LEAD_SECS = 30·86400`, `DELEGATE_CERT_MAX_SECS` (moved here; `checkpoint.rs` re-exports so existing
   references keep working), `INSTANCE_CRED_DEFAULT_SECS = 3600` (reserved — instance-cred machinery is future
   work; the constant pins the ADR-017 ceiling so it has one home). Registrar's 90 d cert validity gains a
   compile-time assert against the 92 d cap. Every magic 365 d epoch pair is replaced by `NBF + PASSPORT_…`;
   P0's `plusDays(365)` → 366. sdk-ts exports mirrored constants.
2. **Boundary semantics, pinned** — ADR-016's ±30 s skew is a *freshness-layer* tolerance (signed heads); it does
   **not** apply to the passport window — ADR-017: *no grace period, expiry is expiry* (a skewed window is a
   fail-open grace period, which this milestone explicitly forbids). New `boundary-*` vectors pin
   `now == nbf → VALID` (inclusive), `now == exp → expired` (exclusive), `now == exp−1 → VALID`,
   `now == nbf−1 → not_yet_valid`, differential-checked core↔sdk.
3. **REISSUE** — a new optional top-level signed claim `prev_leaf` (base64url leaf hash of the SAME lineage's
   previous credential body). It is deliberately **not** inside `log` — the `log` object is stripped from the
   pre-log body, and the continuity link must be **part of what is logged**. Schema: absent = first issuance;
   present ⇒ must decode to 32 bytes, else `schema_violation` (fail closed, mirrored in sdk-ts).
   `RegistrarBox::reissue(sub, new_version?, now)`: same lineage identity, **fresh window `[now, now+366 d]`**,
   **new status index**, `prev_leaf` = predecessor's leaf; the ACME-style claimed `prev_leaf` is validated
   against the registrar's recorded latest leaf — mismatch/missing ⇒ `ReissueContinuity`, fail closed. The old
   credential is kept (superseded set) and keeps verifying until its own `exp` — that IS the overlap; **no
   record is deleted, no grace period exists**. Chained (delegated) passports are NOT auto-renewable — the
   delegation parties' consent signatures cannot be re-minted by the registrar (their secret keys were never
   ours); renewal of a delegated passport is a re-delegation. Explicitly rejected with a clear error.
   CLI: `ainra renew <dir> <sub> [--version V] [--now T] [--dry-run]`; help documents the T−30 d rhythm
   (`RENEWAL_LEAD_SECS`) and that scheduling is deployment, not protocol.
4. **L3+ audit cap** — `IssueSpec.audit: Option<{reference, expires}>` (registrar-side evidence, **not** on the
   wire — Standard §4 keeps evidence at the registrar, so the passport format is unchanged). `issue`/`reissue`
   refuse L3/L4 when the audit is absent (`AuditRequired`) or when `exp > audit.expires` (`AuditStale` — the
   error says why). L2 without audit still issues.
5. **Status-list GC** — decide honestly: **defer sharding** (D-028). At testbed scale (capacity 4096) and even
   at I1 scale the *size* is a non-problem (21.2 KB gz @ 10 M). The real ceiling is index burn: with 366 d
   renewals each lineage burns ~1 index/year, so a 2^24 segment supports ~16.7 M lineage-years; sharding becomes
   necessary as cumulative per-shard issuance approaches 2^24. Forward-compat needs **no new credential field**:
   the cohort discriminator is the status-list **URI itself** (`StatusRef.uri`) — a registrar rotates cohorts by
   publishing epoch URIs; the additive change lives in the *directory* (list current + prior epoch URIs), not in
   the passport. A fully-expired cohort's list can then be deleted without touching live cohorts. Documented
   with thresholds in DECISIONS; no speculative machinery built.
6. **Docs** — MTS gains ADR-017 (frozen-doc edit → `make freeze` re-record, noted in D-027); DECISIONS D-027/D-028;
   CHANGELOG; STATUS; SDK/verifier validity docs + the public differentiator: *long credentials are safe here
   because revocation fails closed; short certificates are what you need when it doesn't.*

Vector corpus and MANIFEST are regenerated through the sanctioned deterministic generators (`make vectors`,
`make repro` clean-rebuild ×2); the 684 count in README/STATUS updates to the new total. DoD table unchanged.

## Acceptance

`make preflight` (clean clone) green before [proven at 53af7fc] and after; `make diff` all-agree; new unit +
integration tests for reissue continuity, overlap, post-expiry, audit clamp; no existing test weakened.
