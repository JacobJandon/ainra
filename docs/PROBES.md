<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Probes — compliance measured adversarially, not reported

**A proposed accreditation term, like [`DISCLOSURE.md`](DISCLOSURE.md), and not yet binding on anyone.** The
instrument, however, is real and runs today: `make probe-drill`.

## The arrow

Every trust regime that measured compliance by asking the operator was corrected from outside.

**CAs.** The controls were annual, point-in-time audits against a published criteria set. The mis-issuance that
actually mattered was found by people reading transparency logs — which is why the browser programs stopped treating
the audit as the measurement and made **public logging mandatory**. The audit says what the operator's controls looked
like on the audit date. The log says what it did.

**CT logs themselves.** Once logs became load-bearing, the same question arrived one level up: who checks the checker?
The answer was not a log self-report. Logs are **disqualified** on externally measured grounds — inconsistent signed
tree heads, exceeding the merge delay, uptime below threshold — and the measuring is done by third-party monitors that
the log operator does not control and cannot see coming.

**The pattern in one line:** the useful signal was never the report. It was what an outsider could observe without the
operator's cooperation.

## Why AINRA can do this properly

The reason the arrow is avoidable here is structural, not virtuous. Everything a probe needs is **public by
construction**: issuance is logged before valid, revocation is a published compressed status list plus a signed fresh
head, and the directory that anchors a registrar is root-signed. A verifier holding only the ceremony root keys can
reach a verdict about any registrar without asking it anything. That is what makes an adversarial measurement cheap —
and *cheapest today, never cheaper*, which is the whole reason to build it before there are registrars to point it at.

## The term

An accredited registrar **shall**:

1. **Accept a monitoring identity through its ordinary retail path**, on the same terms as any customer, and **not
   distinguish it from one.** The probe carries no marking, no reserved name, no header, no account flag. A registrar
   that can identify the probe will eventually treat it differently — not necessarily by design; a cache exemption or
   a debug path is enough.

2. **Grant the monitor no privilege whatsoever.** The probe holds nothing the registrar issued it, and it proves this
   before it measures anything: it sends an unauthenticated write and requires a refusal. **If the write succeeds the
   run is void, not failing** — an operator measuring itself with its own token is the self-report this term replaces.

3. **Be probed on an unannounced schedule.** A known schedule is an audit date, and the record on audit dates is the
   arrow above.

4. **Have its probe reports published**, pass or fail, by whoever ran them. A failing probe is an incident under
   [`DISCLOSURE.md`](DISCLOSURE.md) — 72 hours, no severity threshold.

## What the probe measures (`kits/probe/probe.mjs`)

Nine checks, every verdict from a real root-dark `@ainra/sdk` verifier at the strictest policy (F1 freshness, currency
mode on), every latency wall-clock measured:

| | Check | Why it is not a health check |
|---|---|---|
| **P0** | the write door is shut to us | the check that makes the other eight adversarial |
| **P1** | an unmarked lineage mints through the public door | the retail path is open to a stranger |
| **P2a** | the fresh passport verifies against the root-signed directory | issuance reached the log; the delegate chain holds |
| **P2b** | claiming a different log position is REFUSED | inclusion is recomputed, not trusted |
| **P2c** | one flipped claims byte is REFUSED | the leaf commits to the issued document, so the registrar cannot log one thing and issue another |
| **P2d** | the passport with its inclusion proof deleted is REFUSED | the proof path is verified, not merely carried |
| **P3** | the revocation becomes visible to an outsider in < 60 s | measured against the published fabric, not the registrar's internal state |
| **P4** | the pre-revocation bundle, replayed at the same clock, is REFUSED | a genuine older snapshot cannot outlive the revocation |
| **P5** | the published status sequence only moved forward, and it did move | a rewind is a split view; standing still under a write is one too |

**P2d skips itself, loudly, when the log holds a single leaf** — a correct proof for the only leaf in a one-leaf tree
*is* empty, so deleting it is not a manipulation and the check could not fail. A skip is recorded as `pass: null`,
printed with its reason, and excluded from the verdict. It is never reported as a pass.

## Proof the instrument can observe failure

`make probe-drill` runs the probe against an honest registrar and against four dishonest ones
(`kits/probe/dishonest-registrar.mjs`), and requires the **named** check to be the one that fails — because a probe
that fails for the wrong reason will pass for the wrong reason later.

| Sabotage | Verdict required | Check required to fail |
|---|---|---|
| `open-write-door` — answers an unauthenticated write | **INVALID-RUN** (voided, not scored) | P0 |
| `drop-log` — serves presentations with the proof removed | NON-COMPLIANT | P2a |
| `suppress-revocation` — accepts the revoke, answers 200, publishes nothing | NON-COMPLIANT | P3 |
| `rewind-seq` — serves a sequence below what it already published | NON-COMPLIANT | P5 |

`suppress-revocation` is the important one, and it forges nothing: **every byte it serves was signed by the real
registrar.** It simply keeps serving a genuine older snapshot. There is no broken signature to notice, which is the
shape of soft-fail revocation everywhere it has ever shipped, and the probe catches it only because it measures what
an outsider can *see*, not what the registrar *accepted*.

Two things this drill found on its first two runs, both worth keeping in the record because both were mine:

- **P0 caught a real open write door** — the driver set the token env var under the wrong name, so the registrar was
  in its local-dev default (writes open). The probe refused to score the run. That is the check working on its first
  outing, against its own author.
- **The first `rewind-seq` sabotage was not a rewind.** It subtracted a constant from every answer, and the probe
  passed it — correctly, because a constant offset is a relabelling that preserves monotonicity, and monotonicity is
  the entire claim. The control was wrong, not the check. It now rewinds relative to what it has **already served**.

## Honest scope

A run proves these invariants held for **one unmarked lineage at one moment from one vantage point**. It does not
prove they always hold, and it cannot: a registrar that identified the probe could special-case it, which is why
indistinguishability is a term and not an implementation detail. The value is in the **schedule** and in **P0** — not
in any single green report.

The subject's name is not published in the report (only its SHA-256). A named probe subject is a marked probe.
