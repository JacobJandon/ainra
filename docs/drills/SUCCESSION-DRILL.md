<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Drill — succession

**Question.** Can a stranger holding only the repository and `docs/SUCCESSION.md` take this project over?

**Method.** Clone into a scratch directory, then run the documented first-week sequence in order. No local
state, no operator knowledge, no environment prepared in advance. Each step timed.

**Run.** 2026-08-26T15:42:59Z · total **1384s**

| Step | Result | Time |
|---|---|---|
| clone the repository | ✓ | 0s |
| 1 · cold board (make preflight) | ✓ | 863s |
| 2 · artifacts rebuild + byte-verify | ✓ | 517s |
| 3 · network up locally | ✓ | 4s |
| 5 · state of the world reads | ✓ | 0s |

**Verdict: a stranger with the documented artifacts alone can bring this up.** Every step above ran from a
clone with no local state and no operator knowledge.

Steps 4, 6 and 7 of `docs/SUCCESSION.md` are deliberately not drilled: two require the network (deploy
credentials a successor is granted, not inherited) and one is a decision by a person. Saying which parts a
drill does **not** cover is part of the drill.
