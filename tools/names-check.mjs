#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// No candidate's name may ever enter git.
//
// D-036 says people never enter this repository: names, contacts and notes live in campaign/tracker.local.json
// and campaign/notes/, all gitignored, and what is publishable is a COUNT. That has always been a rule people
// followed. It is now a rule the build enforces.
//
// The check is the obvious one and it is only possible because the private list exists locally: read every name
// the tracker holds, then grep everything git actually tracks for those exact strings. If a name appears in a
// tracked file, the build fails — before a commit makes it permanent and a push makes it public.
//
// WHAT THIS FILE WILL NOT DO: print the name it found. A guard that says "leaked: <name>" writes the name into
// your terminal, your scrollback, and — the moment anyone pastes the output into an issue — into the very place
// it was guarding. It prints the file, the line number, and the length of the match. That is enough to fix it and
// nothing more.
//
// It is LOCAL-ONLY by nature: a clean clone has no tracker, so there is nothing to check and it says so rather
// than passing silently, because a skip that reads like a pass is how this class of bug survives.

import { readFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const TRACKER = ROOT + "campaign/tracker.local.json";

if (!existsSync(TRACKER)) {
  console.log("NAMES-CHECK SKIPPED: no local tracker in this checkout (it is gitignored — this check is local-only).");
  process.exit(0);
}

let people = [];
try { people = JSON.parse(readFileSync(TRACKER, "utf8")).people || []; }
catch (e) { console.error(`  ✗ tracker unreadable: ${e.message}`); process.exit(1); }

// Only real, distinctive strings. A one-word name, or anything short, would produce constant false positives
// against ordinary prose — and a guard that cries wolf gets switched off, which is worse than not having it.
const needles = [];
for (const p of people) {
  for (const field of ["name", "contact"]) {
    const v = (p[field] || "").trim();
    if (v.length >= 6 && /\s/.test(v)) needles.push({ v, id: p.id, field });
  }
}
if (!needles.length) {
  console.log(`NAMES-CHECK OK: tracker holds ${people.length} candidate(s), none with a name long enough to leak.`);
  process.exit(0);
}

let files = [];
try { files = execFileSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8" }).split("\n").map((f) => f.trim()).filter(Boolean); }
catch { console.log("NAMES-CHECK SKIPPED: not a git checkout."); process.exit(0); }

// The ONE exemption, and it is the same one S7 makes for the same reason. A CITATION INVENTORY exists to name
// third parties accurately and link to the primary source for each — naming an RFC's authors while citing that
// RFC is the opposite of leaking a candidate. This fired on its first real run against docs/LANDSCAPE.md, which
// cites RFC 9421 and lists its authors; one of them is independently a candidate.
//
// It is NOT a silent skip. A candidate appearing in an inventory is reported as a NOTICE, because it is worth
// knowing — it means that person is already publicly cited in this project's own published analysis, which
// changes how an approach to them reads. What it must never do is let someone quietly ADD a candidate's name to
// an inventory to dodge the gate, so the notice names the file and the id every time.
const CITATION_INVENTORIES = new Set(["THIRD-PARTY.md", "docs/LANDSCAPE.md"]);
const BIN = /\.(png|jpg|jpeg|gif|webp|ico|zip|gz|tgz|wasm|pdf|woff2?|ttf|otf|mp4|bin)$/i;
let hits = 0, scanned = 0, notices = 0;
for (const f of files) {
  if (BIN.test(f)) continue;
  let body;
  try { body = readFileSync(ROOT + f, "utf8"); } catch { continue; }
  scanned++;
  const lower = body.toLowerCase();
  for (const nd of needles) {
    const at = lower.indexOf(nd.v.toLowerCase());
    if (at === -1) continue;
    const line = body.slice(0, at).split("\n").length;
    if (CITATION_INVENTORIES.has(f)) {
      console.log(`  · notice — ${f}:${line} cites tracked candidate "${nd.id}" as a third party (citation inventory, allowed)`);
      notices++;
      continue;
    }
    // File, line, id and length — never the name itself.
    console.error(`  ✗ ${f}:${line} contains the ${nd.field} of tracked candidate "${nd.id}" (${nd.v.length} chars)`);
    hits++;
  }
}

if (hits) {
  console.error(`\nNAMES-CHECK FAILED: ${hits} leak(s) of a candidate's personal data into git-tracked files.`);
  console.error("People never enter this repository (D-036). Move it to campaign/notes/<id>.md, which is gitignored,");
  console.error("and publish the COUNT instead. Do not commit until this is zero.");
  process.exit(1);
}
console.log(`NAMES-CHECK OK: ${needles.length} tracked name(s) checked against ${scanned} git-tracked file(s) — none leaked` +
            `${notices ? `; ${notices} cited in a citation inventory (see notices above)` : ""}.`);
