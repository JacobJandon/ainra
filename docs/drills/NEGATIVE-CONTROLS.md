<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Negative controls: what each gate proves it can catch, and what it still cannot

PLAN-M51 step 4, 4 November 2026. Fifteen gates were listed in `tools/negative-control-baseline.json`: they could exit 1,
but nothing showed they ever would on the defect they exist for. Each now has a `--negative` mode that plants that
defect (in memory, or in a throwaway tree under the system temp directory, never in the checkout) and requires the
gate's own code path to report it. The baseline is empty, and `make doctrine` keeps it so: a new gate must name its
witness.

`make negative-controls` runs fourteen of them; `make presentation-diff` runs its own, because it needs the Rust CLI.
Both are in `make ci`, in `make preflight` and in CI.

## How they were checked

1. One engineer per gate wrote the control and showed it red with the gate's detection disabled in a scratch copy.
2. A second engineer tried to refute each control with mutants of the gate; eleven of the fifteen were judged weak,
   with the exact mutants that slipped through.
3. Each weak control was repaired until every listed mutant turned it red.
4. A third engineer wrote fresh mutants against the repaired controls.

Step 4 found more. That will always be true of mutation testing: there is always another way to break a checker.
So the claim here is bounded. **Each control catches the defect its gate was written for, and every mutant the first
review listed.** The fresh mutants it does not catch are recorded below, so that nobody reads "has a negative control"
as "cannot be broken".

## The controls

| Gate | `--negative` plants | Third-round mutants it does not catch |
|---|---|---|
| `s7-lint` | a denied name in every scanned directory, file type and shipped manifest; a brand in every prose location, in a shipped README and in a commit message; the real entry point run as a child in a throwaway git repository | 7 of 7, for example a walk that stops recursing, or a scan that reads only a file's first line |
| `license-check` | headerless files in throwaway trees | 6 of 6, for example skipping `*.test.*` files, or failing only when two or more headers are missing |
| `names-check` | tracked names in planted files, in memory | 5 of 6 |
| `reasons-check` | seven drifts between the implementations and the documented reasons | none found in round 2 (not re-reviewed after) |
| `lockfile-sync` | lockfiles that state another version, in throwaway git repositories | none found in round 2 |
| `soak-ingest-check` | consumer copies that misread the soak report | 3: the declaration's soak length, p95 ceiling or SLO verdict changed |
| `one-decode-path` | a second bytes→core decoder in a throwaway tree | none found in round 2 |
| `outreach-check` | synthetic packets (no person in them) with untrue pins, release counts, corpus counts and unpublished names | 8 of 9, for example a pin older than the package, or a count at the start of a sentence |
| `deploy-current` | mismatching manifests, offline | none found in round 2 |
| `bench-gate` | over-ceiling rows in a copy of `docs/BENCHMARKS.md` | a ceiling that drifts between 2001 and 2400 µs; unit-conversion errors on rows that should pass |
| `presentation-diff` | one-byte divergences between the Rust CLI's event lines and the SDK's | 4, for example a CLI line accepted if it matches any SDK line |
| `ainra-verify`, `verify-60s`, `demo-walkthrough`, `render-samples` | tampered bundles, a revoked credential and malformed inputs, offline | 16 of 21 across the four, for example a usage error that exits 0 |

The mutant scripts and the full reviews are not committed: they are working files, and what they found is the table
above. A later pass should take the third-round rows one by one, starting with the gates that guard the release:
`s7-lint`, `license-check` and `presentation-diff`.

`outreach-check`'s positive run reads the gitignored packets in `outreach/ready/`. On 4 November three of them stated
an out-of-date release count. One is the copy of a proposal already submitted, which was true when it was sent, so it
is left as the record of what was sent.
