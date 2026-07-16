<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M8 — `make genesis-local` + the Genesis DoD (playbook wk12, MTS §29 / N9)

M8 is the capstone: **one command stands up the whole AINRA world on one laptop** (N9), composing every layer M1–M7
with real keys, real logs, real witnesses, real verification — then writes a signed transcript, and opens the §29
Definition-of-Done checklist with honest **✓ (laptop-provable)** vs **external (soak / multi-region / third-party)**
columns. Nothing is asserted that isn't run.

Standing rules unchanged: nothing fake · both sigs or invalid · logged-before-valid · fail closed · pure core (N7)
· no real company names (S7) · every deviation in `DECISIONS.md`.

## Thread A — `make genesis-local` (the whole stack, one command)

`tools/genesis-local.sh` boots and drives the real components end to end (extends the M5 testbed to the full world):

1. **Ceremony / dual root (M4).** Start **two** `registrar-box` daemons (two registrar *classes*: `registrar-07`,
   `registrar-02`), publish each `/accreditation`, and run `ceremony accredit` over BOTH → one **dual-root-signed
   directory** (FROST 5-of-9 Ed25519 + SLH-DSA) + `roots.json`. Self-verified the way a stranger would.
2. **Issue + log (M3).** Each registrar issues a real passport — built claims → hybrid-signed → appended to its
   fsync'd log → delegate-signed checkpoint → inclusion proof (logged-before-valid).
3. **External verify (M1/M5).** A stranger's **5-line SDK** (`ainra-verify`, holding only the directory + roots —
   the root itself dark) verifies each passport → **VALID**. This is the "outsider verifies from public artifacts
   alone" leg of §29.
4. **Revoke + re-verify (M3/M5).** Revoke one lineage (signed TSL delta), re-present, verify → **INVALID (revoked)**
   — the gate fails closed. Plus the forged-status adversarial check (D-020) → INVALID.
5. **Fork caught by the QUORUM, not us (M2/M6).** Run the witness-quorum fork drill: an injected equivocating fork
   is refused by every honest witness → cannot reach quorum.
6. **Transcript + hashes (M7 tie-in).** Write `transcript.json` (ceremony root fingerprints, the two registrars,
   directory hash, each passport's verdict before/after revoke, the quorum fork-catch, and a SHA-256 of every
   emitted artifact). Everything a third party needs to reproduce the run.

Exit: `make genesis-local` green on a clean laptop, all real, transcript written.

## Thread B — the §29 Definition-of-Done checklist (`docs/DOD.md`)

A table of the §29 / N1–N12 exit criteria, each marked honestly:
- **✓ laptop-provable now** — dual root, two registrar classes, logged-before-valid, offline/external verify,
  revocation fails closed, fork caught by witnesses, byte-reproducible + mirrorable artifacts, S7/N7/N3 gates.
- **external / pending** — ≥3 *independent* external verifiers, revocation p95 < 60 s across *three regions* for
  *14 days*, an *outside* party forking the root on their own infra, the recorded in-person ceremony. These are
  real-world/soak items; M8 provides the machinery + the local proof, and marks the external columns unfaked.

## Thread C — adversarial pass + gates

Adversarial review of `genesis-local.sh` (can it report success while a stage silently failed? are the verdicts the
REAL tool's, not narration?), fix findings, then `make ci`-level green + DECISIONS D-023 + STATUS/PLAN.

## What M8 deliberately does NOT do (recorded, not faked)

- No real 14-day/3-region soak, no external ceremony, no third-party verifiers on their infra — these are the
  DoD's *external* columns, honestly marked pending. The laptop proof + the machinery are what M8 delivers.
- The witness-network *transport* remains deployment work (M6 D-021); the quorum fork-catch is run in-process with
  real independent keys + real cosignatures.
