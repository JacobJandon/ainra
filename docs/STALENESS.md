<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# The staleness horizon

A published record ages. This states when it stops being described as current, when it starts describing itself as
unmaintained, and why those two numbers are what they are.

## The failure this prevents

Not the site going down. The site **staying up** and slowly becoming a lie.

If maintenance stops, nothing breaks visibly: pages keep rendering, links keep resolving, the board's last green
result keeps being the last green result. Every sentence written in the present tense goes on implying a present
tense that stopped being true months ago. A stale page that looks current is an active falsehood told to exactly
the person this project exists for — someone deciding whether to trust an identity system.

Uptime is the wrong thing to optimise here. **Truthfulness under neglect** is the right one.

## The horizon

| State | Age | What a visitor is told |
|---|---|---|
| current | 0 – 22 days | `published <date> (N days ago)` |
| aging | 23 – 44 days | the same, and the age is now more than half the horizon |
| **stale** | **≥ 45 days** | `STALE — … past the 45-day horizon. Verify against the repository before relying on it.` |
| **unmaintained** | **≥ 180 days** | `UNMAINTAINED SINCE <date> — … Treat everything on this page as historical.` |

**45 days** is the horizon because the record is refreshed as part of ordinary work, and 45 days without any is
already anomalous — long enough that a holiday or a quiet month never trips it, short enough that a visitor is
warned well before the information could mislead them materially.

**180 days** is when "old" becomes "abandoned". Half a year of silence on infrastructure that publishes revocation
data is not a gap in maintenance; it is the absence of maintenance, and it should be described that way by the
thing itself rather than discovered by a reader.

## Why it is derived, not written

The wording is a pure function of the record's age (`site/js/staleness.mjs`). No human edits copy when the horizon
is crossed — which matters, because the moment the horizon gets crossed is precisely the moment nobody is left to
edit anything. A maintainer who has stopped maintaining will not log in to add a banner saying they stopped.

`UNMAINTAINED SINCE <date>` is a sentence nobody writes about their own project. That is the reason it must not
require anyone to write it.

## How it is proven

`make staleness-drill` takes the real stamp, advances a synthetic clock across both boundaries, and asserts the
state changes where this document says it does — with a control proving the sentence is a function of the data
rather than a constant that would pass every boundary while saying nothing true. The report is
[docs/drills/STALENESS-DRILL.md](drills/STALENESS-DRILL.md).
