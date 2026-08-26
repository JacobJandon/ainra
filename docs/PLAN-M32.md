# M32 — turning cultural guarantees into structural ones

The M31 overstatement proved something bigger than itself. Every *number* in "four independent implementations
agree on 1153 conformance vectors" was correct, and the sentence was still false: the defect was the **join**, and
no amount of care would reliably have caught it — only a gate did, and it found three occurrences a careful manual
sweep had missed, including the one on the front page.

That generalises. A root meant to be trusted for decades cannot rest on anyone's memory, care, or continued
existence — including the author's. This milestone finds the rules that currently live only in habit, and converts
as many as possible into things that go red.

---

## Task 0 — The unwritten-rules census

**Method.** For each rule stated in `CONTRIBUTING.md`, `DECISIONS.md`, `SETTLERS.md`, the charter, and the prime
directives, ask one question: *if a stranger with commit rights ignored this tomorrow, what would go red?* Then
**test it** — introduce the violation, run the gates, record what happened, revert. Every row below is the result
of an executed probe, not a reading of the code. Nothing was fixed during the census.

| # | Rule | Where stated | Gate that enforces it | Verdict |
|---|---|---|---|---|
| 1 | No third-party names in **prose** | CONTRIBUTING.md:11, Charter S7 | `make s7` — brand list | **PARTIAL** |
| 2 | No third-party names in **code/fixtures** | CONTRIBUTING.md:11 | `make s7` — denied-name list | **PARTIAL** |
| 3 | Meridian never in examples, defaults, or interfaces | Standard §Meridian (iii), Charter 6 | — | **UNGATED** |
| 4 | The attribution mark is strictly one-way | Standard §Meridian (iii) | — | **UNGATED** |
| 5 | Specimen / TEST-ROOT labelling on demo credentials | site prose; "nothing fake" | — | **UNGATED** |
| 6 | Honest zero — an uncomfortable count is stated, not omitted | prime directives; D-036 | `make claims` (contradiction only) | **PARTIAL** |
| 7 | No claim without its evidence file | prime directives; CONTRIBUTING.md:7 | — | **UNGATED** |
| 8 | A DoD row's published status matches the derived one | DOD.md; "no DoD row moves" | `genesis-status` (derived count only) | **PARTIAL** |
| 9 | Modelled numbers carry `[extrapolated]`; measured ones don't | docs/SCALE.md convention | — | **UNGATED** |
| 10 | Every new gate ships with a negative control | prime directives; CONTRIBUTING.md | — | **UNGATED** |
| 11 | Stated corpus counts match the corpus | doctrine | `make corpus-check` | GATED |
| 12 | A true number may not be joined into a false claim | D-0xx (M31) | `make claims` — overstatement patterns | GATED |
| 13 | Refusal reasons identical in all four implementations | D-029 etc. | `make reasons-check` | GATED |
| 14 | No person's name enters git | D-036 | `make names-check` | GATED |
| 15 | Normative docs do not drift | M7 | `make check-freeze` | GATED |
| 16 | Pushing is not deploying | prime directives | `make deploy-current` | GATED |
| 17 | Published counts trace to a registry | M16 | `campaign check`, `make claims` | GATED |

### The probes, and what each actually showed

Each of these ran against the real tree and was reverted; the tree was verified clean afterwards.

1. **Third-party names in prose — PARTIAL.** A new `docs/_probe.md` containing two third-party names: `S7` caught
   the one on its 27-entry foil-brand list and **passed the one that was not on it**. The rule reads "no
   third-party names anywhere"; the gate enforces "none of these 27 strings". A stranger naming any company not on
   the list is unopposed.
2. **Third-party names in code — PARTIAL, with a scope hole.** `S7`'s fixture scan covers `crates`,
   `packages/sdk-ts/src`, `packages/sdk-py`, `tools`, `vectors`. It does **not** cover `apps/`. A denied name
   planted in `apps/cli-node/bin/ainra.js` — the P0 reference implementation, a shipped artifact — passed.
3. **Meridian in an interface — UNGATED.** Rewrote a CLI usage string to advertise Meridian as the example
   audience. Every gate green. The charter's "never appears in root examples, defaults, or interfaces" is enforced
   by nobody.
4. **The one-way mark, reversed — UNGATED.** Added a page reading "Proudly powered by Meridian — see their mark
   below", i.e. the root displaying a registrar's mark, which the Standard forbids in that direction
   specifically. Every gate green.
5. **Specimen labelling — UNGATED, and the most serious of the nine.** Replaced `SPECIMEN · TEST-ROOT` with
   `VERIFIED · PRODUCTION` and `TYPE AP · SPECIMEN` with `TYPE AP · LIVE`, and rewrote the banner from "every
   passport here is a labelled specimen" to "a production credential". `s7`, `claims`, `claims-live` and
   `link-check` all passed. The difference between an honest demo and a credential that impersonates a production
   one is currently held by nothing but the author remembering.
6. **Honest zero — PARTIAL.** The registry catches a zero *contradicted* (say 3 when it is 0). It does not catch a
   zero **omitted**: changing `0 OPERATORS — GAP` to the neutral heading `INDEPENDENT WITNESS NETWORK` passed,
   because the registry only inspects files that assert, and a file that quietly stops asserting drops out of the
   count instead of failing. Omission is the more likely failure — nobody deletes a zero on purpose, they just
   reword around it.
7. **No claim without evidence — UNGATED.** Added `Measured: 12,400 verifications/sec sustained across three
   regions (p99 4 ms)` to the README. Invented entirely. `claims`, `corpus-check` and `status-consistency` all
   passed. Nothing requires a number to trace to a generator, a board row, or an evidence file.
8. **DoD prose vs derived truth — PARTIAL.** Hand-flipped the `≥3 external verifiers` row from
   `⏳ external (machinery ready)` to `✓`. `genesis-status` correctly still reported **7/11**, because it derives
   from evidence rather than prose — but `status-consistency` reported DOD.md "in lockstep" while the table now
   claimed a row that the evidence does not support. The derived number is safe; the published table is
   hand-maintained, and hand-maintained is future-false.
9. **Extrapolated tags — UNGATED.** Changed `**The CDN argument, honestly [extrapolated].**` to `**The CDN
   argument, measured.**`, promoting a model to a measurement. Every gate green.
10. **Negative controls — UNGATED, structurally.** Four gates document their own negative control in a comment,
    and CONTRIBUTING requires one. Nothing checks that a *new* gate has one. This is the rule above the rules — the one that produced
    every other row in this table, and it is enforced by review alone.

### What the census says

Ten rules examined that were believed enforced. **Six are ungated, four partial, and the four partials all fail in
the same direction**: they check the case where someone states something *wrong*, not the case where someone
states *nothing*. Omission is invisible to every gate in this repository.

The gated rows are not a coincidence either — every one of them exists because that exact rule was broken once and
a gate was written afterwards. The ungated rows are simply the rules nobody has broken yet.

Only the UNGATED and PARTIAL rows become Task 1 work.

---

## Task 1 — Gate the joins and the omissions

`make doctrine` + `make doctrine-negative` ([D-057](DECISIONS.md)). The census table, after:

| # | Rule | Before | After | Gate |
|---|---|---|---|---|
| 1 | No third-party names in prose | PARTIAL | PARTIAL | `make s7` — see the note below |
| 2 | No third-party names in code | PARTIAL | PARTIAL | `make s7` — `apps/` still unscanned |
| 3 | Meridian out of examples/defaults/interfaces | UNGATED | **GATED** | `make doctrine` |
| 4 | The attribution mark is one-way | UNGATED | **GATED** | `make doctrine` |
| 5 | Specimen / TEST-ROOT labelling | UNGATED | **GATED** | `make doctrine` (required-presence) |
| 6 | Honest zero, including by omission | PARTIAL | **GATED** | `make doctrine` (required-presence) |
| 7 | No claim without its evidence | UNGATED | **GATED** | `make doctrine` — trust surfaces |
| 8 | DoD prose matches derived truth | PARTIAL | **GATED** | `make doctrine` |
| 9 | Modelled numbers carry `[extrapolated]` | UNGATED | **GATED** | `make doctrine` |
| 10 | Every new gate ships a negative control | UNGATED | **GATED (ratchet)** | `make doctrine` + baseline |

**Rows 1 and 2 are honestly still partial, and saying so is the point of the table.** "No third-party names
anywhere" cannot be gated by enumeration — the gate knows 27 brand strings and 32 fixture names, and any name
outside those lists passes. Closing it needs either a much larger list (which is the same defect, later) or a
shape-based rule for *promotional and comparative* sentences about a named party, which is a real design problem
and not something to bolt on at the end of a milestone. Row 2 additionally has a scope hole: `apps/` — the P0
reference CLI, a shipped artifact — is not in S7's fixture scan at all. Both are recorded, neither is fixed.

Two of the new checks were wrong on their first run and were caught by their own negative controls: the DoD check
read a prose sentence instead of the table row, and the provenance check flagged two honestly-sourced claims. Both
are the same near-miss class the M31 gate exposed — a check that reads the wrong thing is indistinguishable from
no check.

## Task 3 — The amendment path

[GOVERNANCE-AMENDMENT.md](../GOVERNANCE-AMENDMENT.md) + [docs/AMENDMENTS.md](AMENDMENTS.md) + `make
amendment-check` ([D-056](DECISIONS.md)). Six unamendable prohibitions enumerated; charter / normative /
operational change separated; approver named per era (operator today, custodians at genesis, four constituencies
after); public diff + rationale + dated record required in the same commit.

Negative control, all four rejected: prohibition deleted · prohibition **softened** rather than deleted · record
emptied · normative text changed with no record. The softening case is the one that matters, because nobody
deletes a constitutional line — they reword it.
