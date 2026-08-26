<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Retiring a cryptographic primitive

Every primitive in this system will be retired. Ed25519 and ML-DSA-65 are not exceptions to that; they are simply
the ones whose turn has not come. A root of trust designed for decades has to treat suite retirement as **ordinary
maintenance with a written procedure**, not as an emergency.

This is the general procedure. The worked precedent is [SUITE-MIGRATION-01](drills/SUITE-MIGRATION-01.md), which
carried a live network from Ed25519-only to hybrid Ed25519 + ML-DSA-65 without wiping a single credential.

## 1. The signals that start it

Retirement begins when any one of these is true. None of them requires a break to have happened.

| Signal | Why it is enough on its own |
|---|---|
| A standards body deprecates the primitive | The ecosystem will move; being last is worse than being early. |
| A practical attack reduces its security margin | Margin, not breakage. Waiting for a break is waiting to be the incident. |
| A dependency drops or stops maintaining it | An unmaintained implementation is a break with a delay on it. |
| The primitive's own designers say to move | The clearest signal there is, and the most often ignored. |
| A quantum-relevant milestone lands | ML-DSA exists in the suite because this signal was anticipated, not reacted to. |

**What is NOT a signal:** a newer primitive being fashionable, a benchmark, or a smaller key. Churn in a trust root
costs more than it saves.

## 2. The procedure

1. **Add, never swap.** The new primitive joins the suite alongside the old one. Both-or-invalid semantics mean a
   credential carrying both is strictly stronger than either — there is no window where verification is weaker.
2. **Reissue, never wipe.** Existing credentials are carried across by REISSUE with `prev_leaf` continuity
   (ADR-017). A lineage keeps its history and its AINRA Number; the *credential* changes, the *identity* does not.
   Any procedure that invalidates existing identities is the wrong procedure.
3. **Open a fail-closed overlap epoch.** Old-suite credentials remain acceptable only while an explicitly dated
   epoch is open. The epoch is a **date**, not a flag: `--accept-legacy-until <date>` auto-expires, and a past date
   fails closed *even with the flag present* (D-037). There is no standing exception, because a standing exception
   is how a temporary allowance becomes permanent.
4. **Refuse by default, with a named reason.** Outside the epoch, an old-suite credential is refused as
   `alg_downgrade` — a reason a debugging integrator can act on, not a generic failure.
5. **Drill it before announcing it.** The migration is run end-to-end on a live network and a transcript published,
   as SUITE-MIGRATION-01 was. A migration procedure that has not been executed is a plan, and plans are where
   assumptions hide.
6. **Retire the codepoint.** Once the epoch has closed and reissuance is complete, the old suite's codepoint stays
   *reserved and refused* — never reused. A reused codepoint turns an old signature into a valid new one.

## 3. Retiring Ed25519 or ML-DSA-65 themselves

The procedure above is deliberately written so that it applies to the current primitives without amendment. Two
consequences worth stating plainly, because they are the parts people assume away:

- **Hybrid is what makes this survivable.** Retiring one half of a hybrid pair leaves the other half carrying
  verification for the whole overlap. Retiring the *only* primitive in a single-suite system means a flag day, and
  a flag day on a trust root means every dependent verifier breaks at once.
- **The overlap must outlive the longest-lived credential.** A passport is valid for 366 days (ADR-017), so an
  overlap shorter than that strands credentials that were legitimately issued before the migration began. The
  epoch's minimum length is therefore a property of the validity ladder, not a judgement call.

## 4. What is already built

- **Crypto-agility with fail-closed codepoints.** Unknown suite identifiers are refused rather than ignored, so a
  future primitive cannot be silently accepted by an old verifier.
- **The epoch mechanism**, drilled and auto-expiring (D-037).
- **`prev_leaf` continuity**, which is what makes reissue-not-wipe possible, and which is exercised by the
  `instance-under-renewal-*` corpus family added in M31.

## 5. What is not

There is no drill yet for retiring Ed25519 or ML-DSA-65 *specifically* — SUITE-MIGRATION-01 added a primitive, and
adding is the easier direction. The removal direction is written above and unproven, and this section exists so
that gap is visible rather than assumed closed by the existence of this document.
