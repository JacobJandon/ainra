// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make staleness-drill — fast-forward the clock and check the published surfaces tell the truth by themselves.
//
// The claim under test is the one in docs/SUCCESSION.md §4: if this project stops being maintained, the site
// degrades HONESTLY rather than pretending. That is a claim about a future nobody will be present for, so it is
// worth nothing asserted and everything drilled.
//
// Method: take the REAL published stamp from site/net/published.json, advance a synthetic clock across the
// horizon, and assert the sentence the page would render changes state at the documented boundaries — without any
// copy being edited, because the wording is derived from the data.
//
// WITNESS: could this observe a failure? Yes. Raise HORIZON_DAYS past the drill's own probe points, or make the
// wording a hand-written constant instead of a function of age, and the boundary assertions below fail. The
// negative control at the end proves it on demand rather than claiming it.

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { staleness, HORIZON_DAYS, UNMAINTAINED_DAYS } from "../site/js/staleness.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const pub = JSON.parse(readFileSync(join(ROOT, "site/net/published.json"), "utf8"));
const stamp = pub.published_at_iso;
if (!stamp) { console.error("staleness-drill: site/net/published.json carries no published_at_iso — nothing to drill."); process.exit(2); }

const at = (days) => staleness(stamp, Date.parse(stamp) + days * 86400000);
let bad = 0;
const rows = [];
const expect = (days, state) => {
  const r = at(days);
  const ok = r.state === state;
  if (!ok) { console.error(`  ✗ day ${days}: expected "${state}", got "${r.state}"`); bad++; }
  else console.log(`  ok    day ${String(days).padStart(4)}  →  ${r.state.padEnd(13)} ${r.text.slice(0, 66)}`);
  rows.push(`| ${days} | ${r.state} | ${r.text.replace(/\|/g, "/")} |`);
};

console.log(`staleness-drill · real stamp ${stamp} · horizon ${HORIZON_DAYS}d · unmaintained ${UNMAINTAINED_DAYS}d`);
expect(0, "current");
expect(HORIZON_DAYS - 1, "aging");
expect(HORIZON_DAYS, "stale");                    // the boundary itself
expect(UNMAINTAINED_DAYS - 1, "stale");
expect(UNMAINTAINED_DAYS, "unmaintained");        // and the far boundary
expect(UNMAINTAINED_DAYS * 4, "unmaintained");

// The property that actually matters: the strong wording APPEARS ON ITS OWN. A human would never write
// "UNMAINTAINED SINCE …" about their own project, which is exactly why it must not require one.
const far = at(UNMAINTAINED_DAYS * 2);
if (!/UNMAINTAINED SINCE \d{4}-\d{2}-\d{2}/.test(far.text)) { console.error("  ✗ the unmaintained state does not name the date it went stale"); bad++; }
else console.log(`  ok    the unmaintained state names its own date, derived — no copy was edited`);

// NEGATIVE CONTROL: a hand-written constant would pass every boundary above while saying nothing true. Prove the
// text is a function of the DATA by checking two different ages cannot produce the same sentence.
if (at(HORIZON_DAYS).text === at(UNMAINTAINED_DAYS).text) {
  console.error("  ✗ two very different ages render the same sentence — the wording is not derived from the data");
  bad++;
} else console.log(`  ok    negative control: different ages render different sentences`);

mkdirSync(join(ROOT, "docs/drills"), { recursive: true });
writeFileSync(join(ROOT, "docs/drills/STALENESS-DRILL.md"),
`<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Drill — honest degradation

**Question.** If nobody maintains this project, does the published record say so by itself?

**Method.** Take the real stamp from \`site/net/published.json\` (\`${stamp}\`) and advance a synthetic clock across
the documented horizon. No copy is edited at any point; the sentence is a pure function of the record's age.

**Horizon.** current → aging → **stale at ${HORIZON_DAYS} days** → **unmaintained at ${UNMAINTAINED_DAYS} days**
(\`docs/STALENESS.md\`).

| Day | State | What a visitor is told |
|---|---|---|
${rows.join("\n")}

**Verdict: ${bad ? "FAILED" : "the record degrades honestly on its own"}.** The strongest sentence — *UNMAINTAINED
SINCE &lt;date&gt;* — is the one nobody would ever write by hand about their own project, and it appears with no
human involved. That is the whole point: the honesty has to survive the person.

**What this drill does not cover.** It proves the wording is correct for a given age. It does not prove a visitor's
browser renders it, which is \`make site-check\`'s job, nor that the stamp itself is honestly produced, which is
\`make site-net\`'s.
`);

if (bad) { console.error(`\nSTALENESS-DRILL FAILED — ${bad} check(s).`); process.exit(1); }
console.log(`\nreport → docs/drills/STALENESS-DRILL.md`);
console.log(`STALENESS-DRILL OK: the published record states its own age, crosses the horizon, and declares itself unmaintained without anyone editing copy.`);
