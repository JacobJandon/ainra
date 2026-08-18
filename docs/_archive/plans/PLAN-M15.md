<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# M15 — Genesis Day: the runbook, the gates, the fail-closed declaration, the rehearsal

M14 put a real staging network online (TEST-ROOT). M15 makes **genesis day executable and safe** — every artifact
here so a competent coordinator who has never met us can run it, and so the ceremony can only ever declare what the
evidence proves. Nothing is run for real: no ceremony, no 14-day clock, no domains, no publishing, no ⏳ row marked
done. The rule that governs the milestone: **an aborted genesis costs a date; a fudged genesis costs the project.**

- **Task 0 gate — DONE, GREEN:** clean-clone preflight 12/12; staging stands up per deploy/README.md; `make
  stage-smoke` green against live endpoints (made idempotent); docs/SCALE.md carries [measured]/[extrapolated]
  labels; AINRAscan browser-verified a live staging proof. M15 is built on M14's reality.
- **The Genesis Day Runbook** (docs/genesis-day/RUNBOOK.md): one imperative countdown, T−30d → T+14d, minute-level
  at T0, driving the real `kits/ceremony/` sequence; any deviation from the kit's expected state = ABORT.
- **Production cutover = config, not a fork** (D-033): deploy/compose.production.yml differs from staging ONLY in
  key source / domains / volumes / banner; `make config-diff` (tools/config-diff.mjs) fails if they diverge
  anywhere else. The STAGING-vs-PRODUCTION banner is **data-driven** — decided by which root key signs the directory
  being read, one codebase honest either way.
- **GO/NO-GO** (docs/genesis-day/GO-NO-GO.md): a one-page binary checklist the coordinator reads aloud at T−1d and
  T−0h; each item checkable by a command/evidence; no gate waived without a written D-0xx.
- **The declaration pipeline fails closed** (tools/declaration.mjs): it renders the founding declaration only when
  every claim resolves to a real artifact (transcript hash + mirrors, recording ref, distinct verifier
  attestations, witness cosigns, the signed 14-day soak report); a missing artifact is a loud TODO and a nonzero
  exit — the fail-closed doctrine applied to prose. Proven: it refuses today.
- **Abort & incident playbooks** (docs/genesis-day/ABORTS.md): enumerated trigger → action → what gets published
  (honesty even in failure) → reschedule, for every failure mode, incl. what does/doesn't abort the soak clock.
- **The full dress rehearsal** (`make genesis-rehearsal`): runs the ENTIRE runbook in test mode against staging —
  dry-run ceremony, mock cutover into a labeled prod-sim namespace, banner flip by key-detection, witness attach,
  soak-smoke as the 14-day stand-in, the declaration pipeline in check-mode (proving it fails closed), and
  `make genesis-status`. Timed report in docs/genesis-day/REHEARSAL-REPORT.md; run twice, the clean run pasted.
- **Acceptance:** the runbook is self-sufficient; GO/NO-GO + ABORTS are binary; config-diff pins parity; the
  declaration provably fails closed; `make genesis-rehearsal` runs clean end-to-end. `make preflight` + `make diff`
  stay green; the DoD table is untouched. Decisions D-033. The next commit after this milestone should be the
  genesis tag itself — everything past here is a human decision.
