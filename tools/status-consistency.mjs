// SPDX-License-Identifier: Apache-2.0 OR MIT
// Docs-vs-reality lockstep — one enforced source of truth for "what's done", failing the build on drift:
//   (M10) README.md and docs/STATUS.md must carry the SAME canonical `<!-- STATUS-LINE -->…` claim.
//   (M11) docs/DOD.md's `<!-- DOD-BOARD laptop=N external=M -->` must match the genesis board's actual structural
//         row counts (`node tools/genesis-board/board.mjs --counts`) — so a board row can't be added/removed without
//         the DoD doc being updated in the same change.
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
let ok = true;
const fail = (m) => { console.error("  ✗ " + m); ok = false; };
const pass = (m) => console.log("  ✓ " + m);

// (1) README status line == STATUS status line.
const MARK = "<!-- STATUS-LINE -->";
const line = (rel) => { const l = readFileSync(ROOT + rel, "utf8").split("\n").find((x) => x.includes(MARK)); return l ? l.slice(l.indexOf(MARK) + MARK.length).trim() : null; };
const a = line("README.md"), b = line("docs/STATUS.md");
if (!a || !b) fail(`STATUS-LINE marker missing in ${!a ? "README.md" : "docs/STATUS.md"}`);
else if (a !== b) fail(`README and STATUS disagree on the status line:\n      README: ${a}\n      STATUS: ${b}`);
else pass(`README and STATUS.md agree on the status line — ${a}`);

// (2) DOD.md's declared board counts == the board's actual structural counts.
const dodTxt = readFileSync(ROOT + "docs/DOD.md", "utf8");
const dodM = dodTxt.match(/<!--\s*DOD-BOARD\s+laptop=(\d+)\s+external=(\d+)\s*-->/);
if (!dodM) fail("docs/DOD.md is missing the `<!-- DOD-BOARD laptop=N external=M -->` marker");
else {
  let boardOut = "";
  try { boardOut = execFileSync("node", [ROOT + "tools/genesis-board/board.mjs", "--counts"], { encoding: "utf8" }); }
  catch (e) { fail("could not run the genesis board --counts: " + e.message); }
  const bM = boardOut.match(/laptop=(\d+)\s+external=(\d+)/);
  if (!bM) fail("genesis board --counts produced no parseable counts");
  else if (bM[1] !== dodM[1] || bM[2] !== dodM[2]) {
    fail(`DOD.md declares laptop=${dodM[1]} external=${dodM[2]} but the board has laptop=${bM[1]} external=${bM[2]} — update docs/DOD.md's DOD-BOARD marker (or the board rows) so they match`);
  } else pass(`DOD.md board counts match the genesis board (laptop=${bM[1]} external=${bM[2]})`);
}

if (!ok) { console.error("\nSTATUS-CONSISTENCY FAILED — the docs disagree with reality."); process.exit(1); }
console.log("STATUS OK: README, STATUS.md, and DOD.md are in lockstep.");
