// SPDX-License-Identifier: Apache-2.0 OR MIT
// Docs-vs-reality lockstep — one enforced source of truth for "what's done", failing the build on drift:
//   (M10) README.md and docs/STATUS.md must carry the SAME canonical `<!-- STATUS-LINE -->…` claim.
//   (M11) docs/DOD.md's `<!-- DOD-BOARD laptop=N external=M -->` must match the genesis board's actual structural
//         row counts (`node tools/genesis-board/board.mjs --counts`) — so a board row can't be added/removed without
//         the DoD doc being updated in the same change.
//   (L3)  the counts ROADMAP.md publishes to the world must equal the counts the registries hold, and campaign/'s
//         generated tables must match campaign/gates.json (`node tools/campaign.mjs check`).
import { readFileSync, existsSync, readdirSync } from "node:fs";
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
    // Count BOARD-PROVEN releases, not raw tags. This project's own rule is "no board at the release commit, no
    // release" (RELEASING.md), so docs/releases/<v>-board.md IS the definition — and unlike a tag it exists before
    // the tag does. Counting tags made the check circular during a release: the copy claiming "N releases" has to
    // be committed BEFORE the tag that makes it N, so the gate was briefly, unavoidably red on every cut, which
    // is how it trains you to push through it. Board files remove the circularity without weakening the claim.
    let tags = [];
    try {
      tags = readdirSync(ROOT + "docs/releases")
        .map((f) => /^(v[0-9][0-9.]*)-board\.md$/.exec(f)?.[1]).filter(Boolean)
        .sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
    } catch { /* no releases dir — skip rather than assert something unverifiable */ }
    if (tags.length) {
      const words = { 1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six" };
      // "Current version" and "how many releases have boards" are DIFFERENT facts and must be read from different
      // places, or the two surfaces contradict each other mid-release. tools/site.sh already mandates one source
      // for the version — every vX.Y.Z printed in a page must equal apps/cli-node/package.json — so llms.txt reads
      // from that same source. Checking it against the newest board file instead made the HTML and the agent map
      // disagree at exactly the moment a release is being cut, which is the defect M27 spent a milestone removing.
      const cliV = (() => {
        try { return "v" + JSON.parse(readFileSync(ROOT + "apps/cli-node/package.json", "utf8")).version; } catch { return null; }
      })();
      const cur = txt.match(/current:\s*(v[0-9][0-9.]*)/i);
      if (!cur) fail(`${rel}: no "current: vX.Y.Z" statement — the agent map must name the version it describes`);
      else if (cliV && cur[1] !== cliV) fail(`${rel}: says current: ${cur[1]}, but the implementation is ${cliV} (apps/cli-node/package.json — the site's one source of truth)`);
      else pass(`${rel} names the current version — ${cur[1]}`);
      // Every release-count claim ANYWHERE the site publishes prose, not just this file. The first version of this
      // check looked only at llms.txt and only for a parenthesised "(two signed" — so the identical stale sentence
      // in foundation.html's description and share card ("a reference CLI, two signed releases") walked straight
      // past it, on the one page whose whole job is to state what exists today. Checking one instance of a claim
      // does not check the claim.
      const claim = /\b(one|two|three|four|five|six|seven|eight|nine)\s+signed(?:,\s*board-proven)?\s+releases?\b/gi;
      // TRACKED files only. site/status.md and the other markdown mirrors are GENERATED from the HTML and are
      // gitignored, so their content is derived — checking them gates on an artifact instead of a source. Worse,
      // it is unreliable in both directions: in a reused build directory a stale mirror fails the board for a
      // claim its source no longer makes (it did exactly that here), and in a genuinely fresh clone the file does
      // not exist at all, so the same check passes vacuously. Check what a human wrote; the mirrors follow.
      let surfaces = [];
      try {
        surfaces = execFileSync("git", ["ls-files", "site"], { cwd: ROOT, encoding: "utf8" })
          .split("\n").map((f) => f.trim()).filter((f) => /\.(html|txt|md)$/i.test(f));
      } catch {
        surfaces = readdirSync(ROOT + "site").filter((f) => /\.(html|txt|md)$/i.test(f)).map((f) => "site/" + f);
      }
      let claims = 0;
      for (const f of surfaces) {
        const body = readFileSync(ROOT + f, "utf8");
        for (const m of body.matchAll(claim)) {
          claims++;
          if (m[1].toLowerCase() !== words[tags.length])
            fail(`${f}: says "${m[0]}", but ${tags.length} board-proven release(s) exist (${tags.join(", ")})`);
        }
      }
      if (claims) pass(`${claims} release-count claim(s) across site/ agree with the ${tags.length} board-proven releases`);
    }
  }
}

// ── A documented install pin is a claim about a version, and it rots exactly like the others ─────────────
// `"@ainra/sdk": "^0.3.1"` sat in three verifier-kit files across two releases. Walk finding 5 corrected it once
// by hand, and it went stale again one release later — which is the signal that hand-correction is the wrong
// tool. The pin a reader is told to paste must be the version the packages are actually at.
{
  const cur = (() => {
    try { return JSON.parse(readFileSync(ROOT + "packages/sdk-ts/package.json", "utf8")).version; } catch { return null; }
  })();
  if (cur) {
    const pin = /["'`]@ainra\/sdk["'`]\s*:\s*["'`]\^?([0-9]+\.[0-9]+\.[0-9]+)["'`]/g;
    let files;
    try {
      files = execFileSync("git", ["ls-files", "*.md", "*.json"], { cwd: ROOT, encoding: "utf8" })
        .split("\n").map((f) => f.trim()).filter(Boolean)
        .filter((f) => !f.includes("node_modules") && !f.endsWith("package-lock.json"));
    } catch { files = []; }
    let pins = 0, stale = 0;
    for (const f of files) {
      let body;
      try { body = readFileSync(ROOT + f, "utf8"); } catch { continue; }
      for (const m of body.matchAll(pin)) {
        // The in-repo manifests point at the local build by path; only WRITTEN-DOWN pins are claims to a reader.
        pins++;
        if (m[1] !== cur) { fail(`${f}: documents \`@ainra/sdk\` at ${m[1]}, but the package is at ${cur}`); stale++; }
      }
    }
    if (pins && !stale) pass(`${pins} documented @ainra/sdk pin(s) all match the real package version (${cur})`);
  }
}

if (!ok) { console.error("\nSTATUS-CONSISTENCY FAILED — the docs disagree with reality."); process.exit(1); }
console.log("STATUS OK: README, STATUS.md, DOD.md, and the published counts are in lockstep.");
