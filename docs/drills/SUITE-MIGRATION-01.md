<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Suite Migration Drill 01 — Ed25519 → Ed25519 + ML-DSA-65

**What this proves.** The single event ADR-017 trap (ii) says the protocol must survive: a **cryptographic-suite
migration over a running network**. Existing credentials are carried across by **REISSUE + `prev_leaf` continuity**
— never wiped — and the old suite is retired behind an **auto-expiring, fail-closed policy epoch** (D-037). Every
line below is produced by real hybrid signatures; nothing is fabricated.

**Reproduce it.**

    make suite-migration-drill        # local mechanics (asserts) + the live staging audit
    node tools/suite-migration-drill.mjs   # the local drill with the full transcript below
    node tools/staging-suite-audit.mjs     # the staging half on its own

Serials (`AP-…`) are random per run; the structure and every verdict are invariant.

---

## Part A — the local migration (real crypto, no network)

The root and registrar are hybrid from the start — as the real network already is (Part B). A genuine **legacy**
credential (`issue --legacy`: a real Ed25519-only signature, no PQC half) stands in for one the registrar signed
before it went hybrid. That is the honest shape of the problem: the *authority* has upgraded, but a *credential it
signed under the old suite* is still in the wild.

```
— Suite Migration Drill 01 — Ed25519 → Ed25519 + ML-DSA-65 over a running network —

1. root + registrar accredited HYBRID (Ed25519 + ML-DSA-65) — the network is already on the new suite.
2. issued a LEGACY credential  serial AP-0BB2-CB  fmt 1  sig halves [ed25519]  log #2
  ✓ legacy credential is fmt 1, Ed25519-only (no ML-DSA half)

3. verify the legacy credential:
   default              → ok=false reason=alg_downgrade
   --accept-legacy       → ok=true legacy_credential=true
   --accept-legacy-until 2035-01-01 → ok=true   (overlap open)
   --accept-legacy-until 2020-01-01 → ok=false reason=alg_downgrade  (overlap auto-expired → closed)
  ✓ default policy fails closed as alg_downgrade
  ✓ overlap accepts it (flag) and flags it legacy
  ✓ overlap accepts it while the epoch is open
  ✓ overlap auto-expires: past epoch fails closed even with the flag

4. migrate:
  ✓ dry-run prints a plan and changes nothing
   reissued HYBRID successor  serial AP-0BB2-CB-h  fmt 2  sig halves [ed25519,mldsa65]  log #3  prev_leaf #2
  ✓ successor is hybrid (fmt 2, both signature halves)
  ✓ successor prev_leaf points at the legacy leaf (continuity walks the boundary)
  ✓ nothing deleted — legacy leaf preserved, both credentials on disk

5. after migration, default policy:
   legacy    AP-0BB2-CB   → ok=false reason=alg_downgrade
   hybrid    AP-0BB2-CB-h → ok=true suite=Ed25519+ML-DSA-65
  ✓ the once-valid legacy credential now fails closed (alg_downgrade)
  ✓ its hybrid successor verifies on the new suite
  ✓ log chain intact

Suite mix now: 1 legacy (fails closed) + 1 hybrid (valid), linked #2 → #3 by prev_leaf.

✓ drill complete — every claim proven with real hybrid signatures
```

**Reading the result.**

- **The boundary is walkable.** Log leaf `#2` (the legacy credential) and leaf `#3` (its hybrid successor) are one
  unbroken lineage: the successor carries `prev_leaf #2`. A verifier walking the transparency log crosses the suite
  change without a gap — the identity is eternal, only the credential's cryptography changed (ADR-017).
- **Migration is additive.** REISSUE gives the successor a fresh full validity window and a new hybrid key; the
  legacy leaf is **preserved**, not deleted. History only grows.
- **Retirement is fail-closed and self-limiting.** Once migrated, the legacy credential fails closed as
  `alg_downgrade` by default. An overlap is grantable **only** through `--accept-legacy-until <date>`, which
  **auto-expires**: a past date fails closed even with the flag present (D-037). There is no standing exception that
  can silently outlive its window.
- **Forgiveness is scoped.** The overlap forgives an *absent* PQC signature (a genuine legacy credential). It never
  forgives an *invalid* one: a credential whose ML-DSA half is present but broken or non-canonical is `sig_invalid`
  under every policy (see `make cli-check`).

## Part B — the staging audit (the live network is already hybrid)

The migration is real where legacy exists (Part A, the CLI's own testbed) and **honest where it does not**: the live
staging network — root header `genesis:jai1dHjh4wWCTKhq` — runs the new suite already, so there is nothing to
REISSUE there. `tools/staging-suite-audit.mjs` reads the public contract for the live subjects and inspects each
one's presentation bundle: a hybrid credential carries an ML-DSA-65 signature alongside the 64-byte Ed25519 one.

```
network root header : genesis:jai1dHjh4wWCTKhq
public contract     : 10 versioned subjects

  ainra:registrar-07:acme:data-export@2.0.0  ⇒ HYBRID (ML-DSA present + Ed25519 64B)
  ainra:registrar-07:acme:invoicing@4.2.1  ⇒ HYBRID (ML-DSA present + Ed25519 64B)
  ainra:registrar-07:acme:support-bot@1.0.0  ⇒ HYBRID (ML-DSA present + Ed25519 64B)

audit: inspected 8 live presentations · HYBRID 8 · legacy stragglers 0 · Ed25519 sig 64B
✓ staging is already hybrid — 0 stragglers to REISSUE (confirms PLAN-M23 Task 0)
```

**Honest headline.** The network was hybrid before this drill; the legacy suite lived only in the downloadable CLI,
which M23 Task 1 brought to hybrid. Part A migrates the one place legacy genuinely existed (the CLI's local
credentials) and proves the mechanics end-to-end; Part B confirms the deployed network needs no migration — measured,
not asserted. The `genesis:` root is the operator-run genesis; the distributed public ceremony, ≥3 external
verifiers, and the 14-day soak remain the honestly-pending real-world DoD events, untouched by this drill.
