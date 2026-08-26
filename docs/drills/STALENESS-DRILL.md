<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Drill — honest degradation

**Question.** If nobody maintains this project, does the published record say so by itself?

**Method.** Take the real stamp from `site/net/published.json` (`2026-08-17T16:02:17Z`) and advance a synthetic clock across
the documented horizon. No copy is edited at any point; the sentence is a pure function of the record's age.

**Horizon.** current → aging → **stale at 45 days** → **unmaintained at 180 days**
(`docs/STALENESS.md`).

| Day | State | What a visitor is told |
|---|---|---|
| 0 | current | published 2026-08-17 (today) |
| 44 | aging | published 2026-08-17 (44 days ago) |
| 45 | stale | STALE — published 2026-08-17, 45 days ago, past the 45-day horizon. Verify against the repository before relying on it. |
| 179 | stale | STALE — published 2026-08-17, 179 days ago, past the 45-day horizon. Verify against the repository before relying on it. |
| 180 | unmaintained | UNMAINTAINED SINCE 2026-08-17 — this record is 180 days old and is no longer being refreshed. Treat everything on this page as historical. |
| 720 | unmaintained | UNMAINTAINED SINCE 2026-08-17 — this record is 720 days old and is no longer being refreshed. Treat everything on this page as historical. |

**Verdict: the record degrades honestly on its own.** The strongest sentence — *UNMAINTAINED
SINCE &lt;date&gt;* — is the one nobody would ever write by hand about their own project, and it appears with no
human involved. That is the whole point: the honesty has to survive the person.

**What this drill does not cover.** It proves the wording is correct for a given age. It does not prove a visitor's
browser renders it, which is `make site-check`'s job, nor that the stamp itself is honestly produced, which is
`make site-net`'s.
