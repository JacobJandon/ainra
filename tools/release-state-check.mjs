// SPDX-License-Identifier: Apache-2.0 OR MIT
// Release-state drift gate (PLAN-M50 step 6). The honesty sweep found a tagged, published version still called
// "Unreleased" in ROADMAP, drill counts that disagreed in four places, and a site mirror that silently lost a heading.
// Each was fixed by hand; this makes the same drift fail the build instead of waiting for the next sweep.
//
//   1. The newest tag vX.Y.Z has its CHANGELOG section, a ROADMAP "Shipped" row and a RELEASING tag-pin row.
//   2. No current doc calls a tagged version "Unreleased (X.Y.Z)".
//   3. A drill count stated in a current doc equals the drills tools/live-drills.sh actually runs.
//   4. Every generated site mirror keeps the full text of every heading on its page.
//
// Its negative controls run on every invocation, before the real checks: a fixture ROADMAP calling a tagged version
// unreleased, a drill count off by one, and a heading containing `&lt;` must each be caught — or the gate itself fails.
//
//   node tools/release-state-check.mjs
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { toMarkdown, headingTexts, PAGES } from "./site-mirrors.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const read = (p) => readFileSync(join(ROOT, p), "utf8");
const WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve"];
const num = (w) => (/^\d+$/.test(w) ? Number(w) : WORDS.indexOf(w.toLowerCase()));

// ── the checks, as pure functions over text, so the negative controls can feed them fixtures ────────────────────────
function newestReleaseRows(tag, docs) {
  const v = tag.slice(1), out = [];
  if (!new RegExp(`^## \\[v?${v.replace(/\./g, "\\.")}\\]`, "m").test(docs.changelog)) out.push(`CHANGELOG.md has no "## [${v}]" section for ${tag}`);
  if (!docs.roadmap.includes(`| **${tag}** |`)) out.push(`ROADMAP.md has no "| **${tag}** |" row under Shipped`);
  if (!docs.releasing.includes(`| **${tag}** |`)) out.push(`RELEASING.md has no "| **${tag}** |" tag-pin row`);
  return out;
}
function unreleasedButTagged(tags, files) {
  const out = [];
  for (const [name, text] of Object.entries(files))
    for (const m of text.matchAll(/unreleased \((?:v)?(\d+\.\d+\.\d+)\)/gi))
      if (tags.includes(`v${m[1]}`)) out.push(`${name} calls ${m[1]} "${m[0]}" — v${m[1]} is tagged`);
  return out;
}
function drillCounts(script, files) {
  const real = (script.match(/^run "/gm) || []).length;
  const out = [];
  const head = script.match(/^#\s*(\w+) drills prove/m);
  if (!head || num(head[1]) !== real) out.push(`tools/live-drills.sh's header says "${head?.[1] ?? "?"} drills", it runs ${real}`);
  for (const [name, text] of Object.entries(files))
    for (const m of text.matchAll(/\b(\d+|zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve) (?:live )?drills\b/gi))
      if (num(m[1]) !== real) out.push(`${name} says "${m[0]}" — tools/live-drills.sh runs ${real}`);
  return out;
}
function mirrorKeepsHeadings(name, html) {
  const md = toMarkdown(html);
  return headingTexts(html).filter((h) => !md.includes(h)).map((h) => `the ${name} mirror lost the heading "${h}"`);
}

// ── negative controls: each fixture must be caught, or this gate is decoration ──────────────────────────────────────
const controls = [
  ["a tagged version still called unreleased",
    unreleasedButTagged(["v0.6.0"], { "fixture ROADMAP": "| **Unreleased (0.6.0)** | … |" }).length === 1],
  ["a newest tag with no ROADMAP row",
    newestReleaseRows("v9.9.9", { changelog: "## [9.9.9] — x", roadmap: "| **v9.9.8** |", releasing: "| **v9.9.9** |" }).length === 1],
  ["a drill count off by one",
    drillCounts('# Two drills prove\nrun "a" x\nrun "b" y\n', { "fixture SECURITY": "runs the three live drills" }).length === 1],
  ["a heading with &lt; in it",
    // The shape that broke site/status.md: an escaped "<" in a heading, then a real tag later on the page.
    mirrorKeepsHeadings("fixture", '<main><h3>REVOCATION &lt;60s [MEASURED]</h3><p>measured (<span class="m">p95</span>)</p></main>').length === 0],
];
let bad = 0;
for (const [what, caught] of controls) {
  if (!caught) { console.error(`  ✗ negative control not caught: ${what} — the gate cannot see this drift`); bad++; }
}

// ── the real checks ─────────────────────────────────────────────────────────────────────────────────────────────────
const tags = execFileSync("git", ["-C", ROOT, "tag", "--list", "v*", "--sort=-v:refname"], { encoding: "utf8" })
  .split("\n").filter((t) => /^v\d+\.\d+\.\d+$/.test(t));
const problems = [];
if (!tags.length) problems.push("no release tags in this clone — fetch them (git fetch --tags); the gate will not pass on an empty list");
else problems.push(...newestReleaseRows(tags[0], { changelog: read("CHANGELOG.md"), roadmap: read("ROADMAP.md"), releasing: read("RELEASING.md") }));
const current = ["README.md", "ROADMAP.md", "RELEASING.md", "docs/STATUS.md", "docs/PUBLISHING.md", "SECURITY.md", "CHANGELOG.md"];
problems.push(...unreleasedButTagged(tags, Object.fromEntries(current.map((f) => [f, read(f)]))));
// Drill counts: current-state documents only. A dated post-mortem saying "the five drills" was true when written.
problems.push(...drillCounts(read("tools/live-drills.sh"), Object.fromEntries(
  [".github/workflows/ci.yml", "README.md", "docs/STATUS.md", "ROADMAP.md"].map((f) => [f, read(f)]).concat(
    [["SECURITY.md (make live-drills lines)", read("SECURITY.md").split("\n").filter((l) => l.includes("make live-drills")).join("\n")]]))));
for (const p of PAGES) problems.push(...mirrorKeepsHeadings(p.md, read(join("site", p.html))));

for (const p of problems) console.error(`  ✗ ${p}`);
if (bad || problems.length) {
  console.error(`RELEASE-STATE-CHECK FAILED — ${problems.length} drift(s)${bad ? `, ${bad} negative control(s) not caught` : ""}.`);
  process.exit(1);
}
console.log(`RELEASE-STATE-CHECK OK — newest tag ${tags[0]} is recorded in CHANGELOG, ROADMAP and RELEASING; no tagged version is called unreleased; drill counts agree; every mirror keeps its headings (${controls.length} negative controls caught).`);
