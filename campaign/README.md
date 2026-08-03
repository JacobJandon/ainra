<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# campaign — the human half

Everything else in this repository is machinery that runs. This directory is the part that only a person can do.

Three rows in [`docs/DOD.md`](../docs/DOD.md) — independent verifiers, a recorded ceremony, a 14-day soak — cannot
be moved by writing more code, and the project has been honest about that from the beginning. They move when
strangers decide to spend an afternoon on us. So the asking gets the same treatment the code got: a schedule, a
tool, published dates, and counts that come from registries instead of from hope.

| File | What it is |
|---|---|
| [`PLAN.md`](PLAN.md) | The fourteen days. One primary action per day, and the arithmetic that says why. |
| [`GATES.md`](GATES.md) | The public gate register — K1 and K4, their bars, and every re-dating on the record. |
| [`TEMPLATES.md`](TEMPLATES.md) | The six asks, the categories of people to send them to, and the interview script. |
| [`JURISDICTION.md`](JURISDICTION.md) | Which country the root incorporates in. Undecided; due D4. |
| `gates.json` | The machine-readable gate register. `GATES.md`'s table is generated from it. |

## The one command

```sh
make campaign-status
```

It prints the day, today's primary action, every count with the registry it came from, who is due a nudge under the
three-day rule, and what is currently blocking. Run it before noon.

```sh
make campaign-init                                  # once — creates the LOCAL tracker
node tools/campaign.mjs add interview a-name --name "…" --org "…" --contact "…" --why "…"
node tools/campaign.mjs send a-name                 # arms the 3-day nudge
node tools/campaign.mjs reply a-name yes
node tools/campaign.mjs interview a-name            # records a COMPLETED interview + opens the notes file
node tools/campaign.mjs redate K1 2026-08-30 --reason "…"       # the only way a date moves
```

## Two rules this directory exists to enforce

**People never enter this repository.** Names, contacts, employers, and interview notes live in
`campaign/tracker.local.json` and `campaign/notes/`, both gitignored. What is publishable is a **count**. This is
the same rule the root itself runs on — it holds no personal data, and that includes the personal data of people
who were kind enough to reply to an email ([D-036](../docs/DECISIONS.md)). `node tools/campaign.mjs drop <id>`
clears a person on request.

**Nothing here moves a Definition-of-Done row.** There is no command in `tools/campaign.mjs` that can, by
construction. `make campaign-status` *reads* the genesis board, `evidence/verifier/`, and
`witnesses/candidates.json`; it never writes to them. A row moves when a stranger's signed artifact survives
verification — `make genesis-status` is still the only thing that says so.

`node tools/campaign.mjs check` runs in the board and fails the build if a count published in
[`ROADMAP.md`](../ROADMAP.md) has drifted from the registry it claims to read, or if a generated table in `PLAN.md`
or `GATES.md` no longer matches `gates.json`. The claim "counts here are read, not asserted" is enforced rather
than promised.
