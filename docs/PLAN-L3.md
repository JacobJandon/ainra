<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# L3 — the human half gets a schedule, and published counts get a gate

Follows L2 (docs/PLAN-L2.md). L2 finished the machine: public, live, self-verifying, with intake pipelines that
auto-check what strangers submit. What it could not do is make a stranger show up. Three DoD rows — independent
verifiers, a recorded ceremony, a 14-day soak — move only when people act, and they had no schedule, no tracker,
and no published dates. L3 builds that, with the same rules as everything else: nothing fake, fail closed,
full-output checks, zero telemetry, the DoD table untouched.

## What was built

| Piece | What it does | Where |
|---|---|---|
| The fourteen days | One primary action per day (D1 Mon 03 Aug → D14 Sun 16 Aug), the K1 arithmetic, the slippage rule | `campaign/PLAN.md` |
| The gate register | K1 (8 interviews, 16 Aug) and K4 (3 attestations, 05 Sep) — bars, sources, and every re-dating on the record | `campaign/GATES.md` + `campaign/gates.json` |
| The six asks | Verifier · interview · custodian · witness-as-second-yes · regulator letter · the one-sentence nudge, plus the target categories and the 25-minute interview script | `campaign/TEMPLATES.md` |
| The jurisdiction decision | Criteria, both options, a recommendation, and five premises to verify before filing — with a decision block `campaign-status` reports as BLOCKING while empty | `campaign/JURISDICTION.md` |
| The driver | `status` · `init` · `add` · `send` · `nudge` · `reply` · `interview` · `drop` · `gates` · `redate` · `render` · `check` | `tools/campaign.mjs` |
| The publish unblock | Everything checkable before a token is pasted; publishes nothing, holds no credentials | `tools/publish-preflight.sh` |

## The two rules it exists to enforce (D-043)

**People never enter this repository.** The tracker (`campaign/tracker.local.json`) and interview notes
(`campaign/notes/`) are gitignored; no command writes a person into a tracked file; `drop <id>` clears one on
request. Counts are publishable, people are not — D-036 applied to ourselves.

**A published count must be a read count.** `node tools/campaign.mjs check` is wired into
`tools/status-consistency.mjs`, so it runs in the board's status-honesty row and in CI.

## Evidence

| Claim | Proof (command output, this session) |
|---|---|
| Counts are read, not asserted | `campaign check` → `ROADMAP verifier count matches the genesis board (0/3 confirmed; 0 submitted)` · `ROADMAP witness-candidacy count matches the registry (0)` |
| **Negative control** — a false published count fails the build | published `**2 / 3**` in ROADMAP.md → `✗ ROADMAP.md publishes 2/3 confirmed verifiers, the board counts 0` → `STATUS-CONSISTENCY FAILED`, exit 1. Reverted; green again |
| **Negative control** — a drifted generated table fails the build | edited `gates.json` by hand → `✗ campaign/GATES.md is stale`, exit 1 |
| A gate cannot move quietly | `redate K1 2026-08-30` with no reason → refused, exit 1. With a reason → `gates.json` history appended **and** the public table regenerated |
| No campaign command can move a DoD row | `campaign.mjs` opens `evidence/verifier/`, `witnesses/candidates.json`, and the board read-only; the board still reads 7/11, verifiers 0/3 |
| An unreadable source prints `—`, never `0` | K1 with no tracker → `UNTRACKED`, not `0/8` |
| S7 now covers `campaign/` | planted a foil-brand token from `tools/s7-brand-denylist.txt` in `campaign/README.md` → `S7-BRAND HIT campaign/README.md:54`, exit 1. Reverted; green. (The first draft of *this table* quoted the token and the gate failed the board for it — which is the rule working: S7 governs prose, including prose about S7.) |
| The packaged npm tarball is conformant | fresh `npm init` + install of `ainra-sdk-0.3.0.tgz` → **745/745 vectors agree** with the recorded verdicts |
| The built wheel is conformant | fresh venv + `pip install ainra-0.3.0-py3-none-any.whl` → **745/745 vectors agree** |
| **Negative control** — that smoke actually bites | planted a false `expect` on one vector → `744/745`, exact mismatch named, exit 1 |
| The preflight finds real problems | first run: 4 blockers — no README on `@ainra/sdk`, `@ainra/middleware`, `@ainra/mcp` (a blank registry page for the project's front door) and the middleware path dependency. READMEs written; the path dep is now a `[TODO]` with an exact two-command fix |

## Closing board (2026-08-03)

`make preflight` → **ALL GREEN, 18/18** (`build + tests` 7s · `differential` 8s · `conformance` 31s · `CLI hybrid` 2s
· `genesis-local` 4s · `verifier kit` 3s · `ceremony dry-run` 2s · `ceremony multi` 0s · `soak instrument` 3s ·
`witness quorum` 0s · `S7 neutrality` 0s · `license headers` 0s · `status honesty` 0s · `doc freeze` 0s ·
`MCP fidelity` 3s · `presentation shape` 3s · `skills replay` 4s · `reproducibility` 338s).
`make gitleaks` → 173 commits, 24.85 MB, **no leaks found**.

The run before it was **RED on one row** — S7 flagged `docs/PLAN-L3.md` for quoting the foil-brand token used in the
negative control above. That is the gate working on its author, and it is recorded here rather than quietly fixed.

## Deliberately not done

- **No tag, no publish.** `publish-preflight` prints the commands and stops. Publishing stays the maintainer's button.
- **No DoD row moved**, and no soak started. The soak clock begins on genesis day, per the runbook — starting it
  early to make a row green is precisely the self-issued evidence this project exists to refuse.
- **No site change.** The gates are published in `ROADMAP.md`, which the site links; the landing was not touched.
- **The jurisdiction decision is not made.** It is the owner's, it has a date (D4), and the memo names the five
  premises that must be verified against primary sources first — none of them is verified in this repository.

## Resume list

| Item | Command | Blocked on |
|---|---|---|
| npm publish | `make publish-preflight`, then the printed `npm login` + publish block | credentials |
| PyPI publish | same preflight, then the printed venv + `twine upload` block | credentials |
| Start the campaign | `make campaign-init`, then D1 in `campaign/PLAN.md` | nothing |
| Jurisdiction | fill the decision block in `campaign/JURISDICTION.md`, register the same day | the owner, by D4 |
| The three rows | they move when strangers act — that is the whole point of `campaign/` | strangers |
