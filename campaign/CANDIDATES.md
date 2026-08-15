<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Candidate research — what was done, and what it cost

**No person is named in this file, and none ever will be.** D-036: people never enter this repository. Names,
roles and evidence URLs live in `campaign/tracker.local.json`, which is gitignored and which
[`make names-check`](../tools/names-check.mjs) now proves is not leaking into anything git tracks. What is
publishable is a count.

**Nobody has been contacted. No message has been sent to any person, by any channel.**

## The two rules this was run under, and how they were enforced

Research about real people is where a confident fabrication does the most damage. This repo already has the
lesson from a smaller setting: an earlier research pass invented verbatim quotes and attributed them to primary
sources about *filing fees*. Aimed at a person, that same failure invents something they never said.

So the rules stopped being conventions and became code:

| Rule | Enforcement |
|---|---|
| Every claim about a person cites a public URL that names them | `--evidence` is a **required field**. A candidate who cannot be cited cannot be stored at all — there is no softened version to fall back to. |
| A human approves each one before anything happens | Everyone arrives `proposed`. `draft`, `star`, `send` and `nudge` refuse until `approve`, which prints the evidence URL, so approving *is* looking. `drop` stays exempt — declining is not an action taken on someone. |
| Names never reach git | `make names-check` reads the private list and greps every git-tracked file for it. It reports the file and line and the candidate id, **never the name** — a guard that prints what it is guarding is not a guard. |

## The counts

| | researched | verified and loaded | not loaded |
|---|---|---|---|
| **verifier** | 26 | **26** | 0 |
| **interview** | 35 | **7** | 28 |
| **custodian** | 10 | **8** | 2 |
| **witness** | 6 | **1** | 5 |
| | **77** | **42** | 35 |

Every loaded candidate has an evidence URL that was **fetched twice** — once by the researcher, once by a
refutation pass that re-opened the page and tried to kill the entry.

## What the refutation pass actually changed

It is not a formality. Against the verifier list it produced **zero kills but four role corrections**, each one a
claim the page did not support:

- a "project co-founder" title that appears nowhere on the steering-committee page cited for it;
- two certification-team members whose extra credentials (an employer, a spec-contributor history) were not on the
  roster page cited — trimmed to what the roster shows;
- a library co-maintainer credited with a second project the cited page never mentions.

Against the witness list it did real damage, correctly: a company page was cited for **six named individuals**,
and the page names **none**. The organisation survived on verbatim evidence — it publishes that it operates a
transparency log, a log witness and a witness bastion host — and all six personal names were dropped.

It also caught two spelling traps. A standards roster spells one person's first name differently from their own
university's faculty page; the loaded record uses the spelling on the page actually cited, because a name and its
citation have to match. And a draft that prints authors as initials in its header spells them in full in its
Authors' Addresses section — checking rather than assuming saved three real entries, where assuming either way
would have been wrong.

## Why 35 were not loaded

**Not because they failed.** The session's API limit killed three refutation passes mid-flight. Those candidates
were researched with citations, but their evidence URLs were never re-opened by a second pass — and an entry that
has not survived refutation does not get stored, because the storage format has no way to say "probably".

They are not lost: the research is recoverable and the refutation is the only step outstanding. But the tracker
holds only what was checked twice.

## Jurisdictional spread — the custodian hard requirement

Eight custodians loaded. Countries **explicitly stated on the cited page** for: Germany, the Netherlands,
Belgium, Australia. Two more are named on IETF standing-body rosters that state affiliation but no country, and
one has a country derived from a site footer rather than from any line about the person — recorded as
footer-derived rather than quietly counted.

So the honest reading is **four countries evidenced to the standard this project uses, not five.** The requirement
is not met yet, and padding the count with institution-implied countries is exactly the move that would make the
number worthless. Two researched custodians were not loaded for want of a second fetch, and Latin America,
Africa, South Asia and the Middle East are unrepresented — the research recorded that this was caused by blocked
and 403-returning sources rather than by an absence of qualified people, which is a gap to close, not a finding.

## Where the top five came from

Five verifier candidates are approved, starred, and have personalised finals written to the gitignored sendbox,
each marked **AWAITING-APPROVAL**. They were chosen for one reason: they are the people most able to *break* the
specific claims this project makes.

- three whose public work is transparency logs and witness cosigning — the mechanism AINRA's whole argument rests
  on, and the part with the least outside scrutiny;
- two who are named authors on the 2026 IETF drafts about agent authentication and authorization — the people
  best placed to say the model is wrong, which is worth more than another green board.

The asks are written differently for the two groups, because sending a spec author a "please run our script"
message would be tone-deaf: they are asked whether the model duplicates work already happening at the IETF.

**Sending is a human act and has not been taken.**
