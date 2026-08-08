// SPDX-License-Identifier: Apache-2.0 OR MIT
// Docs-vs-reality lockstep — one enforced source of truth for "what's done", failing the build on drift:
//   (M10) README.md and docs/STATUS.md must carry the SAME canonical `<!-- STATUS-LINE -->…` claim.
//   (M11) docs/DOD.md's `<!-- DOD-BOARD laptop=N external=M -->` must match the genesis board's actual structural
//         row counts (`node tools/genesis-board/board.mjs --counts`) — so a board row can't be added/removed without
//         the DoD doc being updated in the same change.
//   (L3)  the counts ROADMAP.md publishes to the world must equal the counts the registries hold, and campaign/'s
//         generated tables must match campaign/gates.json (`node tools/campaign.mjs check`).
import { readFileSync, existsSync } from "node:fs";
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

// (3) Published counts == registry reality. Delegated to the campaign driver so there is ONE implementation of
//     "what the registries say" — this file only mirrors its verdict into the board's status-honesty row.
try {
  const out = execFileSync("node", [ROOT + "tools/campaign.mjs", "check"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  for (const l of out.trim().split("\n")) console.log("  " + l.trim().replace(/^[✓↻]\s*/, "✓ "));
} catch (e) {
  fail("campaign check failed — a published count or generated table drifted from its source:");
  for (const l of `${e.stdout || ""}${e.stderr || ""}`.trim().split("\n")) if (l.trim()) console.error("      " + l.trim());
}


// ── M27: the agent surface is a claim too ────────────────────────────────────────────────────────────────
// site/llms.txt calls itself an AI agent's "map" and states the release facts. It went stale — "two signed
// releases; current: v0.3.0" while three tags existed and v0.3.1 was current — and survived every board, because
// this gate only ever compared README against docs/STATUS.md. A claim nothing checks is a claim that rots. The
// truth is derived from git tags, never asserted here.
{
  const rel = "site/llms.txt";
  if (existsSync(ROOT + rel)) {
    const txt = readFileSync(ROOT + rel, "utf8");
    let tags = [];
    try {
      tags = execFileSync("git", ["tag", "--list", "v*", "--sort=-v:refname"], { cwd: ROOT, encoding: "utf8" })
        .split("\n").map((t) => t.trim()).filter(Boolean);
    } catch { /* not a git checkout (tarball) — skip rather than assert something unverifiable */ }
    if (tags.length) {
      const words = { 1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six" };
      const cur = txt.match(/current:\s*(v[0-9][0-9.]*)/i);
      if (!cur) fail(`${rel}: no "current: vX.Y.Z" statement — the agent map must name the release it describes`);
      else if (cur[1] !== tags[0]) fail(`${rel}: says current: ${cur[1]}, but the newest tag is ${tags[0]}`);
      else pass(`${rel} names the current release — ${cur[1]}`);
      const cnt = txt.match(/\((one|two|three|four|five|six) signed/i);
      if (cnt && cnt[1].toLowerCase() !== words[tags.length])
        fail(`${rel}: says "${cnt[1]} signed" releases, but ${tags.length} tag(s) exist (${tags.join(", ")})`);
    }
  }
}

if (!ok) { console.error("\nSTATUS-CONSISTENCY FAILED — the docs disagree with reality."); process.exit(1); }
console.log("STATUS OK: README, STATUS.md, DOD.md, and the published counts are in lockstep.");
