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
//
// WITNESS: `--negative` runs in two halves, and needs no real candidate and no tracker, so it runs in a clean clone
// too. The first runs the same needle selection and the same matcher over an invented tracker and invented files
// held in memory. It plants a name in a tracked doc in different letter case, a contact string in a source file,
// and the name in three files that only resemble a citation inventory (one beside docs/LANDSCAPE.md, one that ends
// in docs/LANDSCAPE.md one directory down, one named THIRD-PARTY.md outside the root); every one must be reported
// as a leak. It also requires that no leak or notice line ever contains the name it found (the rule above), that the
// same name inside docs/LANDSCAPE.md or THIRD-PARTY.md is a notice and not a leak, that a one-word or short name
// never becomes a needle, and that a binary file is not read. The second half runs this very file as a child
// process, with no flag, over a throwaway git repository in os.tmpdir() holding an invented tracker: with the name
// in a tracked doc it must exit 1 and point at that line, with the name only in an untracked file or an inventory it
// must exit 0 and say OK, and neither run may print the name anywhere. A matcher that went blind, lost its
// case-folding, started printing names, widened the inventory exemption, or a real run that stopped reading git's
// file list or stopped failing, fails it.
import { readFileSync, existsSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import os from "node:os";
import path from "node:path";

// AINRA_NAMES_CHECK_ROOT exists for the witness below and nothing else: it lets `--negative` run this file's real
// entry point over a throwaway repository. Unset, the root is the repository this file sits in.
const ROOT = process.env.AINRA_NAMES_CHECK_ROOT
  ? path.resolve(process.env.AINRA_NAMES_CHECK_ROOT) + path.sep
  : fileURLToPath(new URL("../", import.meta.url));
const TRACKER = ROOT + "campaign/tracker.local.json";

// Only real, distinctive strings. A one-word name, or anything short, would produce constant false positives
// against ordinary prose — and a guard that cries wolf gets switched off, which is worse than not having it.
function needlesFrom(people) {
  const needles = [];
  for (const p of people) {
    for (const field of ["name", "contact"]) {
      const v = (p[field] || "").trim();
      if (v.length >= 6 && /\s/.test(v)) needles.push({ v, id: p.id, field });
    }
  }
  return needles;
}

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

// The matcher both modes share. `read` returns a file's text or throws; `notice` and `leak` receive one line each.
function scan(files, read, needles, { notice, leak }) {
  let hits = 0, scanned = 0, notices = 0;
  for (const f of files) {
    if (BIN.test(f)) continue;
    let body;
    try { body = read(f); } catch { continue; }
    scanned++;
    const lower = body.toLowerCase();
    for (const nd of needles) {
      const at = lower.indexOf(nd.v.toLowerCase());
      if (at === -1) continue;
      const line = body.slice(0, at).split("\n").length;
      if (CITATION_INVENTORIES.has(f)) {
        notice(`  · notice — ${f}:${line} cites tracked candidate "${nd.id}" as a third party (citation inventory, allowed)`);
        notices++;
        continue;
      }
      // File, line, id and length — never the name itself.
      leak(`  ✗ ${f}:${line} contains the ${nd.field} of tracked candidate "${nd.id}" (${nd.v.length} chars)`);
      hits++;
    }
  }
  return { hits, scanned, notices };
}

if (process.argv.includes("--negative")) {
  // Invented people. The names are made up for this control and belong to no candidate.
  const people = [
    { id: "plant-name", name: "Orla Vantressel" },
    { id: "plant-contact", name: "", contact: "o.vantressel at example dot org" },
    { id: "plant-oneword", name: "Vantressel" },
    { id: "plant-short", name: "O V" },
  ];
  const needles = needlesFrom(people);
  const FILES = new Map([
    ["docs/PLAN-X.md", "Intro.\nWe met ORLA VANTRESSEL at the meeting.\n"],
    ["tools/plant.mjs", "// reach O.Vantressel at example dot org\n"],
    ["docs/LANDSCAPE-NOTES.md", "Cited beside the inventory: Orla Vantressel.\n"],
    ["archive/docs/LANDSCAPE.md", "An old copy: Orla Vantressel.\n"],
    ["docs/THIRD-PARTY.md", "Not the root inventory: Orla Vantressel.\n"],
    ["docs/LANDSCAPE.md", "RFC authors: Orla Vantressel.\n"],
    ["THIRD-PARTY.md", "Notices.\nOrla Vantressel wrote one.\n"],
    ["site/logo.png", "Orla Vantressel"],
    ["docs/prose.md", "Vantressel is also a word in this sentence, and so is O V.\n"],
  ]);
  const read = (f) => { if (!FILES.has(f)) throw new Error("absent"); return FILES.get(f); };
  const leaks = [], notices = [];
  const r = scan([...FILES.keys(), "docs/absent.md"], read, needles, { notice: (l) => notices.push(l), leak: (l) => leaks.push(l) });
  const leaked = (at, id) => leaks.some((l) => l.startsWith(`  ✗ ${at} `) && l.includes(`"${id}"`));
  const CHECKS = [
    ["caught ", "name in a tracked doc, different case", leaked("docs/PLAN-X.md:2", "plant-name")],
    ["caught ", "contact string in a source file", leaked("tools/plant.mjs:1", "plant-contact")],
    ["caught ", "name in a file that only resembles an inventory", leaked("docs/LANDSCAPE-NOTES.md:1", "plant-name")],
    ["caught ", "name in a file whose path ends in an inventory's path", leaked("archive/docs/LANDSCAPE.md:1", "plant-name")],
    ["caught ", "name in a file that shares an inventory's file name", leaked("docs/THIRD-PARTY.md:1", "plant-name")],
    ["caught ", "no leak or notice line prints the name or contact it found",
      leaks.length > 0 && notices.length > 0 &&
      ![...leaks, ...notices].some((l) => needles.some((nd) => l.toLowerCase().includes(nd.v.toLowerCase())))],
    ["allowed", "same name in docs/LANDSCAPE.md and THIRD-PARTY.md is a notice, not a leak",
      !leaks.some((l) => l.startsWith("  ✗ docs/LANDSCAPE.md:") || l.startsWith("  ✗ THIRD-PARTY.md:")) &&
      notices.some((l) => l.includes("— docs/LANDSCAPE.md:1 ") && l.includes('"plant-name"')) &&
      notices.some((l) => l.includes("— THIRD-PARTY.md:2 ") && l.includes('"plant-name"')) && r.notices === 2],
    ["allowed", "one-word and short names never become needles",
      !needles.some((nd) => nd.id === "plant-oneword" || nd.id === "plant-short") && !leaks.some((l) => l.includes("docs/prose.md"))],
    ["allowed", "a binary file is not read, an unreadable one is skipped", !leaks.some((l) => l.includes("site/logo.png")) && r.scanned === 8],
    ["caught ", "exactly the five planted leaks, no more", r.hits === 5 && leaks.length === 5],
  ];

  // The second half: the real entry point, as `make names-check` runs it, over a throwaway git repository. Git's
  // own variables are dropped so a run from inside a hook cannot point the child at this repository's index.
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("GIT_")));
  const tmp = mkdtempSync(path.join(os.tmpdir(), "names-check-negative-"));
  try {
    const put = (rel, body) => { mkdirSync(path.dirname(path.join(tmp, rel)), { recursive: true }); writeFileSync(path.join(tmp, rel), body); };
    const git = (...a) => execFileSync("git", a, { cwd: tmp, env, stdio: "pipe" });
    git("init", "-q");
    put("campaign/tracker.local.json", JSON.stringify({ people: people.slice(0, 2) }));
    put("docs/x.md", "Intro.\nWe met orla vantressel there.\n");
    put("docs/LANDSCAPE.md", "RFC authors: Orla Vantressel.\n");
    put("notes-untracked.md", "Orla Vantressel, o.vantressel at example dot org\n");
    git("add", "docs/x.md", "docs/LANDSCAPE.md");
    const run = () => {
      const c = spawnSync(process.execPath, [fileURLToPath(import.meta.url)], { encoding: "utf8", env: { ...env, AINRA_NAMES_CHECK_ROOT: tmp } });
      const all = `${c.stdout}${c.stderr}`;
      return { ...c, all, quiet: !needles.some((nd) => all.toLowerCase().includes(nd.v.toLowerCase())) };
    };
    const red = run();
    CHECKS.push(["caught ", "real run, name in a tracked doc: exit 1, file and line named, name not printed",
      red.status === 1 && red.stderr.includes('  ✗ docs/x.md:2 contains the name of tracked candidate "plant-name"') &&
      red.stderr.includes("NAMES-CHECK FAILED: 1 leak(s)") && !red.all.includes("notes-untracked") && red.quiet]);
    put("docs/x.md", "Intro.\nNobody named here.\n");
    const green = run();
    CHECKS.push(["allowed", "real run, name only untracked or in an inventory: exit 0, OK, name not printed",
      green.status === 0 && green.stdout.includes("NAMES-CHECK OK: 2 tracked name(s) checked against 2 git-tracked file(s)") &&
      green.stdout.includes('· notice — docs/LANDSCAPE.md:1 cites tracked candidate "plant-name"') && green.quiet]);
  } catch (e) {
    CHECKS.push(["caught ", `real run over a throwaway git repository could not be set up (${e.code || e.message})`, false]);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  let bad = 0;
  for (const [kind, what, ok] of CHECKS) {
    console.log(`  ${ok ? `ok  ${kind}` : "✗   WRONG  "} ${what}`);
    if (!ok) bad++;
  }
  if (bad) { console.error(`NAMES-CHECK NEGATIVE FAILED — ${bad} planted case(s) judged wrongly`); process.exit(1); }
  console.log(`NAMES-CHECK NEGATIVE OK — all ${CHECKS.length} planted cases judged correctly, no name printed`);
  process.exit(0);
}

if (!existsSync(TRACKER)) {
  console.log("NAMES-CHECK SKIPPED: no local tracker in this checkout (it is gitignored — this check is local-only).");
  process.exit(0);
}

let people = [];
try { people = JSON.parse(readFileSync(TRACKER, "utf8")).people || []; }
catch (e) { console.error(`  ✗ tracker unreadable: ${e.message}`); process.exit(1); }

const needles = needlesFrom(people);
if (!needles.length) {
  console.log(`NAMES-CHECK OK: tracker holds ${people.length} candidate(s), none with a name long enough to leak.`);
  process.exit(0);
}

let files = [];
try { files = execFileSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8" }).split("\n").map((f) => f.trim()).filter(Boolean); }
catch { console.log("NAMES-CHECK SKIPPED: not a git checkout."); process.exit(0); }

const { hits, scanned, notices } = scan(files, (f) => readFileSync(ROOT + f, "utf8"), needles,
  { notice: (l) => console.log(l), leak: (l) => console.error(l) });

if (hits) {
  console.error(`\nNAMES-CHECK FAILED: ${hits} leak(s) of a candidate's personal data into git-tracked files.`);
  console.error("People never enter this repository (D-036). Move it to campaign/notes/<id>.md, which is gitignored,");
  console.error("and publish the COUNT instead. Do not commit until this is zero.");
  process.exit(1);
}
console.log(`NAMES-CHECK OK: ${needles.length} tracked name(s) checked against ${scanned} git-tracked file(s) — none leaked` +
            `${notices ? `; ${notices} cited in a citation inventory (see notices above)` : ""}.`);
