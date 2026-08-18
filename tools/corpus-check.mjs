// SPDX-License-Identifier: Apache-2.0 OR MIT
// make corpus-check — every stated conformance-vector count must equal the corpus actually on disk.
//
// D-044 added 48 vectors to `vectors/v1` and updated the count in exactly zero places. Forty-odd live surfaces went
// on saying 745 — the deployed site in four pages, both SDK READMEs, CONTRIBUTING, RELEASING, the quickstarts, the
// middleware README, STATUS, even the preflight board's own label for the browser-verifier row. A stranger checking
// our most checkable claim would have found it wrong on the front page.
//
// Nothing could have caught it. The four-way differential proves the implementations agree; it has no opinion about
// prose. This gate is the missing witness: it counts the files and holds the words to them.
//
// HISTORICAL RECORDS ARE EXEMPT, and the exemption is the point. CHANGELOG.md, docs/releases/**, docs/_archive/**,
// docs/DECISIONS.md and SECURITY-ADVISORIES.md record what was true on a date. Rewriting them to match today would
// be falsifying a record rather than fixing a claim — "Corpus 737 → 745" is a correct sentence about D-029 forever.
//
// The durable fix for a number that keeps moving is to stop stating it. Where a count is not load-bearing, prefer
// "the whole corpus" — a claim that cannot go stale. This gate exists for the places where the number earns its keep.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const countJson = (d) => {
  try {
    return readdirSync(join(ROOT, d)).filter((f) => f.endsWith(".json") && f !== "manifest.json").length;
  } catch { return 0; }
};

const real = {
  passport: countJson("vectors/v1"),
  delta: countJson("vectors/v1-delta"),
  directory: countJson("vectors/v1-directory"),
};
real.total = real.passport + real.delta + real.directory;
if (real.passport === 0) { console.error("corpus-check: vectors/v1 is empty or missing — refusing to check against nothing"); process.exit(2); }

// Live surfaces: anything a reader or an integrator is told is true NOW.
const LIVE = [
  "README.md", "ROADMAP.md", "CONTRIBUTING.md", "RELEASING.md", "SECURITY.md", "skills.md",
  "docs/STATUS.md", "docs/ARTIFACTS.md", "docs/SETTLERS.md", "docs/BEST-PRACTICES.md", "docs/WASM-DEMO.md",
  "docs/quickstarts/conformance.md", "docs/quickstarts/sdk.md", "docs/quickstarts/python.md",
  "packages/sdk-ts/README.md", "packages/sdk-py/README.md", "packages/middleware/README.md",
  "tools/conformance/CONTRACT.md", "tools/preflight.sh",
  "site/index.html", "site/verify.html", "site/foundation.html", "site/docs.html",
  "campaign/SPONSORS.md", "campaign/TEMPLATES.md", "campaign/FREE-INFRASTRUCTURE.md",
  "ainrascan/index.html",
];

// Any 3-4 digit number sitting next to the word "vector", or an N/N agreement pair, is a claim about the corpus.
const CLAIMS = [
  { re: /\b(\d{3,4})\s*(?:CC0\s+)?(?:passport\s+)?conformance\s+vectors?\b/gi, want: () => real.passport, what: "conformance vectors" },
  // "793 vectors" with no other qualifier — the plainest form, and the one the README uses.
  { re: /\b(\d{3,4})\s+(?:CC0\s+)?vectors?\b/gi, want: () => real.passport, what: "vector count" },
  { re: /\b(\d{3,4})\/(\d{3,4})\b/g, want: () => real.passport, what: "N/N agreement", pair: true },
  // NOT followed by a unit: "passport 366 d" is ADR-017's validity period, not a count of anything.
  { re: /\bpassport\s+(\d{3,4})\b(?!\s*(?:d\b|day|hour|s\b|µs|ms))/gi, want: () => real.passport, what: "passport count" },
  { re: /"passport"\s*:\s*(\d{3,4})/g, want: () => real.passport, what: "passport count (json)", notAfter: "required_minimums" },
  { re: /"total"\s*:\s*(\d{3,4})/g, want: () => real.total, what: "corpus total (json)" },
  { re: /"(?:checked|passed)"\s*:\s*(\d{3,4})/g, want: () => real.total, what: "corpus total (json totals)" },
  { re: /\b(\d{3,4})\s*\+\s*17\s*\+\s*9\b/g, want: () => real.passport, what: "passport in the 3-part sum" },
];

let bad = 0;
for (const f of LIVE) {
  let text;
  try { statSync(join(ROOT, f)); text = readFileSync(join(ROOT, f), "utf8"); } catch { continue; }
  // Strip markdown/HTML emphasis before matching. The first version of this gate required the word "conformance"
  // adjacent to the number, and the README writes "**793** vectors" — so a negative control that reverted the
  // README to 745 PASSED. The gate could not see the failure in the file that matters most, which is the exact
  // defect it was written to prevent. Normalise first, then match.
  // Emphasis only — NOT underscores: stripping those turned "required_minimums" into "requiredminimums" and
  // silently broke the exemption below, so the gate started failing on a deliberate floor.
  text = text.replace(/<\/?[a-z][^>]*>/gi, "").replace(/[*`]/g, "");
  for (const c of CLAIMS) {
    for (const m of text.matchAll(c.re)) {
      const want = c.want();
      const nums = c.pair ? [Number(m[1]), Number(m[2])] : [Number(m[1])];
      // An N/N pair is only a corpus claim when it is plausibly one — 17/17 and 9/9 are the delta and directory
      // corpora, and a negative control legitimately states one-below (792/793).
      if (c.pair) {
        const known = [real.passport, real.delta, real.directory, real.passport - 1];
        if (!nums.every((n) => known.includes(n))) continue;
        if (nums.some((n) => n === real.passport || n === real.passport - 1) &&
            !nums.every((n) => n === real.passport || n === real.passport - 1)) {
          console.error(`  ✗ ${f}: "${m[0]}" mixes the passport corpus with another count`); bad = 1;
        }
        continue;
      }
      // A documented FLOOR ("required_minimums") is deliberately not the corpus size — an implementation may be
      // conformant on a subset. Skip a match that sits inside one.
      if (c.notAfter) {
        const before = text.slice(Math.max(0, m.index - 120), m.index);
        if (before.includes(c.notAfter)) continue;
      }
      if (nums[0] !== want) {
        console.error(`  ✗ ${f}: says "${m[0].trim()}" — the ${c.what} is ${want}`); bad = 1;
      }
    }
  }
}

if (bad) {
  console.error(`\nCORPUS-CHECK FAILED — a stated count disagrees with vectors/ on disk.`);
  console.error(`Real: passport ${real.passport} · delta ${real.delta} · directory ${real.directory} · total ${real.total}`);
  console.error(`Fix the number, or better, state the claim without one ("the whole corpus") where it is not load-bearing.`);
  process.exit(1);
}
console.log(`CORPUS-CHECK OK: ${LIVE.length} live surface(s) agree with the corpus on disk — passport ${real.passport} · delta ${real.delta} · directory ${real.directory} · total ${real.total}.`);
