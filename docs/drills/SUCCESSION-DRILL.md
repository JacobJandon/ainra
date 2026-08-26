<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Drill — succession

**Question.** Can a stranger holding only the repository and `docs/SUCCESSION.md` take this project over?

**Method.** Clone into a scratch directory, then run the documented first-week sequence in order. No local
state, no operator knowledge, no environment prepared in advance. Each step timed.

**Run.** 2026-08-26T14:54:47Z · total **1795s**

| Step | Result | Time |
|---|---|---|
| clone the repository | ✓ | 0s |
| 1 · cold board (make preflight) | ✗ | 1274s |
| 2 · artifacts rebuild + byte-verify | ✗ | 517s |
| 3 · network up locally | ✓ | 4s |
| 5 · state of the world reads | ✓ | 0s |

**Verdict: INHERITANCE GAP — 2 step(s) failed.** A step that fails here is not a broken test; it is
something the project only does because of state on one person's machine. Fix it in the repository or in
docs/SUCCESSION.md, then re-run.

Steps 4, 6 and 7 of `docs/SUCCESSION.md` are deliberately not drilled: two require the network (deploy
credentials a successor is granted, not inherited) and one is a decision by a person. Saying which parts a
drill does **not** cover is part of the drill.
