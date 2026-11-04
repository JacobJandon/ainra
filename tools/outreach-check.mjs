#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The outreach packets are the only public-facing prose no mechanical gate could reach.
//
// `outreach/ready/` is gitignored, and correctly so — D-036 says people never enter this repository, and those
// folders carry the drafts addressed to them. But "not committed" quietly became "not checked": every other gate
// enumerates files with `git ls-files`, which can never see this directory, so a v0.3.0-era snapshot of the
// project's claims survived there through three releases while every tracked surface moved on.
//
// So this checks them where they actually live, on disk, and never prints anything but a file path and the
// offending claim — no names, no addresses, nothing about a person.
//
// It is deliberately a LOCAL check. From a clean clone the directory does not exist and this SKIPS and says so,
// rather than passing silently as if it had verified something. A skip that reads like a pass is the failure mode
// this whole class of bug is made of.
//
// WITNESS: `--negative` does not need outreach/ at all, so it runs from a clean clone. Everything it writes goes
// into one fresh directory under the OS temp directory, holds no person, and is removed afterwards. Two parts:
//
// 1. The rules, against today's facts. Synthetic packets are walked with the same walker and run through the same
//    per-packet rules against the same facts the real run reads. Each carries one untrue claim — an @ainra/sdk pin
//    one patch off, a release count one off (as a word, as a word with "board-proven", and as digits), an install
//    line for a package marked unpublished, a corpus count a stale adjective away from "vectors", a passport +
//    delta + directory triple with one figure wrong, and "see it live" — and each must be reported by the rule it
//    belongs to. Rule 3's list is empty today, so this part lends it one synthetic unpublished name; the matching
//    and the report are what it proves, not the list. One clean packet holding every claim stated truly, including
//    the "a fourth is tagged" form rule 2 deliberately allows, must come back silent. If the release count has
//    outgrown the number words rule 2 knows, this part fails outright instead of quietly testing less.
//
// 2. The real run, end to end. A copy of this file is run as a child process (no flag) from a planted root with
//    its own made-up facts: an sdk version, twelve release boards beside two files that are not boards, and three
//    corpus folders whose manifest and non-JSON files must not count. Its outreach/ holds one packet per checkable
//    claim, each wrong against those facts, plus a "see it live" in a .txt that must be ignored. The child must
//    exit 1, name each planted packet exactly once with the claim it got wrong, and count exactly that many. With
//    only the clean packet left it must exit 0 and print the facts it read; with no outreach/ it must skip. This
//    proves the path from file to exit code, and that the facts are read correctly, not only the rules.

import { readFileSync, existsSync, readdirSync, statSync, mkdtempSync, mkdirSync, writeFileSync, rmSync, copyFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
let bad = 0;
const fail = (f, m) => { console.error(`  ✗ ${f}: ${m}`); bad++; };

const NEGATIVE = process.argv.includes("--negative");
if (!NEGATIVE && !existsSync(join(ROOT, "outreach"))) {
  console.log("OUTREACH-CHECK SKIPPED: no outreach/ in this checkout (it is gitignored — this check is local-only).");
  process.exit(0);
}

const walk = (d, out = []) => {
  for (const e of readdirSync(d)) {
    const p = join(d, e);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.md$/i.test(e)) out.push(p);
  }
  return out;
};

// The facts every packet must agree with, read from the same places the rest of the board reads them.
const sdkV = JSON.parse(readFileSync(join(ROOT, "packages/sdk-ts/package.json"), "utf8")).version;
const releases = readdirSync(join(ROOT, "docs/releases"))
  .map((f) => /^(v[0-9][0-9.]*)-board\.md$/.exec(f)?.[1]).filter(Boolean);
// Number words up to twenty. The count is already past nine, so a table that stopped there would let "ten signed
// releases" through unchecked. `--negative` fails when the count outgrows this table.
const WORDS = ["", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve",
  "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen", "twenty"];
const countJson = (d) => readdirSync(join(ROOT, d)).filter((f) => f.endsWith(".json") && f !== "manifest.json").length;
const CORPUS = { passport: countJson("vectors/v1"), delta: countJson("vectors/v1-delta"), directory: countJson("vectors/v1-directory") };

// Every untrue claim in one packet. Both modes go through this and nothing else; `extraUnpublished` is only ever
// passed by the negative run (see WITNESS above).
function check(body, extraUnpublished = []) {
  const found = [];
  const fail = (_rel, m) => found.push(m);   // the rules keep their fail(rel, …) form; the caller adds the path
  const rel = "";

  // 1. A documented install pin must be the version the packages are at.
  for (const m of body.matchAll(/["'`]@ainra\/sdk["'`]\s*:\s*["'`]\^?([0-9]+\.[0-9]+\.[0-9]+)["'`]/g))
    if (m[1] !== sdkV) fail(rel, `documents @ainra/sdk at ${m[1]}, but the package is at ${sdkV}`);

  // 2. A release count must match the board-proven releases.
  // A count that names WHICH thing it counts is not caught here — "three signed releases are published and a
  // fourth is tagged" is more precise than any single number, and a gate that punished it would push writers
  // toward the vaguer sentence. Only a bare count is checked, written as a word or as digits. The count must not
  // follow a letter or a hyphen, so the "one" in "twenty-one" is not read as a count of one.
  const COUNT = new RegExp(String.raw`(?<![\w-])(\d+|${WORDS.slice(1).join("|")})\s+signed(?:,\s*board-proven)?\s+releases?\b(?!\s+are\s+published\s+and\s+a\s+\w+\s+is\s+tagged)`, "gi");
  for (const m of body.matchAll(COUNT)) {
    const said = /^\d+$/.test(m[1]) ? Number(m[1]) : WORDS.indexOf(m[1].toLowerCase());
    if (said !== releases.length)
      fail(rel, `says "${m[0]}", but ${releases.length} board-proven release(s) exist`);
  }

  // 3. An install command must name a package that is ACTUALLY published.
  //
  // This rule used to forbid every install command, because nothing was on a registry. As of v0.4.0
  // (2026-09-15) @ainra/sdk and @ainra/middleware are live on npm with provenance, so telling a reader to
  // install them is now true and useful — the whole point of publishing. The rule inverts rather than
  // disappears: the packages that are still unpublished must never appear in an install line, and that list
  // is the thing to keep honest.
  //
  // As of v0.4.1 NOTHING is unpublished: @ainra/sdk, @ainra/middleware, @ainra/mcp and PyPI `ainra` are all live,
  // so every install line the packets can contain is now a true instruction. The list stays here, empty, because
  // the next package to exist will be unpublished for a while and this is where it belongs on day one — deleting
  // the mechanism because it currently has nothing to say is how the check would fail to exist when it matters.
  const UNPUBLISHED = [];
  for (const u of [...UNPUBLISHED, ...extraUnpublished])
    for (const m of body.matchAll(u.re))
      fail(rel, `tells a reader to install via "${m[0].trim()}" — ${u.why}`);

  // 4. A corpus count must be the corpus on disk.
  //
  // Added after the packets were found quoting a corpus size three generations stale, while this gate printed OK.
  // The stale figure is deliberately not repeated here: a number written into a comment is a claim like any other,
  // and the registry reads this file. It checked version pins, release counts, install commands and liveness,
  // and a stranger reading a packet would have found the most checkable claim in the project wrong.
  //
  // This is the SECOND time this directory has drifted behind every tracked surface, and the header above already
  // describes the first. The lesson that did not transfer: "the packets are checked" is not a property of the
  // directory, it is a property of each individual claim, and a new kind of claim arrives unchecked by default.
  // `make corpus-check` holds 27 tracked surfaces to this number and cannot see these files, because they are
  // gitignored and it enumerates with `git ls-files`.
  // One pattern, deliberately loose: a 3-4 digit number with up to three words between it and "vector(s)". The
  // first version of this rule required the number adjacent to "conformance vectors" or "vectors", and it MISSED
  // "<stale-count> published conformance vectors" in a packet it had just scanned — the same class of near-miss
  // that once let corpus-check pass a README with the count wrapped in emphasis. A gate for stale numbers that a
  // single adjective can
  // slip past is not a gate.
  for (const m of body.matchAll(/\b(\d{3,4})\s+(?:[A-Za-z0-9-]+\s+){0,3}vectors?\b/g)) {
    if (Number(m[1]) === CORPUS.passport) continue;
    if (Number(m[1]) === CORPUS.delta || Number(m[1]) === CORPUS.directory) continue; // the other two corpora
    fail(rel, `says "${m[0].trim().replace(/\s+/g, " ")}", but the corpus on disk is ${CORPUS.passport}`);
  }
  for (const m of body.matchAll(/\b(\d{3,4})\s+passport\s*\+\s*(\d+)\s+delta\s*\+\s*(\d+)\s+directory\b/gi))
    if (Number(m[1]) !== CORPUS.passport || Number(m[2]) !== CORPUS.delta || Number(m[3]) !== CORPUS.directory)
      fail(rel, `says "${m[0].trim()}", but the corpus on disk is ${CORPUS.passport} + ${CORPUS.delta} + ${CORPUS.directory}`);

  // 5. The published-record wording. "See it live" was removed from the site in M27 for overstating what exists;
  //    a packet is the last place it should survive, because it is read by the people we are asking to trust us.
  for (const m of body.matchAll(/see it live/gi)) fail(rel, `"${m[0]}" — the site is a published record of a STAGING network, not a live one`);
  return found;
}

if (NEGATIVE) {
  let wrong = 0;
  const judge = (ok, okText, badText, label) => { console.log(`  ${ok ? okText : badText} ${label}`); if (!ok) wrong++; };
  // A count with no number word cannot be planted truly, so the run stops here rather than test less.
  const n = releases.length;
  if (n === 0) {
    console.error("OUTREACH-CHECK NEGATIVE FAILED — no board-proven releases found in docs/releases; the facts were not read");
    process.exit(1);
  }
  if (!WORDS[n]) {
    console.error(`OUTREACH-CHECK NEGATIVE FAILED — ${n} board-proven releases, but rule 2 only knows number words`
      + ` up to "${WORDS[WORDS.length - 1]}": extend WORDS, or the true count written as a word goes unchecked`);
    process.exit(1);
  }
  const tmp = mkdtempSync(join(tmpdir(), "outreach-check-negative-"));
  const plant = (root, path, body) => {
    mkdirSync(join(root, path, ".."), { recursive: true });
    writeFileSync(join(root, path), body);
  };
  try {
    // ---- 1. The rules, against today's facts.
    const wrongWord = WORDS[n - 1] || WORDS[n + 1];
    const [major, minor, patch] = sdkV.split(".").map(Number);
    const taken = new Set([CORPUS.passport, CORPUS.delta, CORPUS.directory]);
    let stale = Math.max(100, CORPUS.passport + 1);
    while (taken.has(stale)) stale++;
    const PLANTED_UNPUBLISHED = [{ re: /npm install @ainra\/planted-unpublished\b/g, why: "planted: on no registry" }];
    // [label, packet path under the temp root, body, the report it must produce — or null for "must be silent"]
    const PLANTS = [
      ["sdk pin one patch off", "ready/a/README.md",
        `"dependencies": { "@ainra/sdk": "^${major}.${minor}.${patch + 1}" }\n`, "documents @ainra/sdk at"],
      ["bare release count one off", "ready/b/email.md",
        `There are ${wrongWord} signed releases.\n`, "board-proven release(s) exist"],
      ["board-proven release count one off", "ready/c/nested/email.md",
        `There are ${wrongWord} signed, board-proven releases.\n`, "board-proven release(s) exist"],
      ["release count one off, in digits", "ready/b2/email.md",
        `There are ${n + 1} signed releases.\n`, "board-proven release(s) exist"],
      ["install line for an unpublished package", "ready/d/email.md",
        "Run npm install @ainra/planted-unpublished to start.\n", "tells a reader to install via"],
      ["stale corpus count behind an adjective", "ready/e/email.md",
        `It ships ${stale} published conformance vectors.\n`, "but the corpus on disk is"],
      ["corpus triple with one figure wrong", "ready/f/email.md",
        `${CORPUS.passport} passport + ${CORPUS.delta + 1} delta + ${CORPUS.directory} directory\n`,
        `the corpus on disk is ${CORPUS.passport} + ${CORPUS.delta} + `],
      ["the withdrawn liveness wording", "ready/g/email.MD", "See it live at the site.\n", "STAGING network"],
      ["every claim stated truly", "ready/h/email.md", [
        `"@ainra/sdk": "^${sdkV}"`,
        `${WORDS[n]} signed releases.`,
        `${n} signed, board-proven releases.`,
        "three signed releases are published and a fourth is tagged.",
        `${CORPUS.passport} conformance vectors and ${CORPUS.delta} delta vectors.`,
        `${CORPUS.passport} passport + ${CORPUS.delta} delta + ${CORPUS.directory} directory`,
        "npm install @ainra/sdk",
      ].join("\n") + "\n", null],
    ];
    const rules = join(tmp, "rules");
    for (const [, path, body] of PLANTS) plant(rules, path, body);
    const walked = new Set(walk(rules).map((abs) => abs.slice(rules.length + 1)));
    for (const [label, path, , want] of PLANTS) {
      const found = walked.has(path) ? check(readFileSync(join(rules, path), "utf8"), PLANTED_UNPUBLISHED) : [];
      if (want === null) judge(found.length === 0, "ok  allowed", "✗   FLAGGED", label);
      else judge(found.some((m) => m.includes(want)), "ok  caught ", "✗   MISSED ", label);
    }

    // ---- 2. The real run, end to end, from a planted root with made-up facts.
    // The facts are deliberately not today's: twelve boards puts the count past nine, and none of these numbers
    // come from the files the real run reads, so a broken fact reader cannot move the plants along with it.
    const root = join(tmp, "root");
    plant(root, "tools/outreach-check.mjs", "");
    copyFileSync(fileURLToPath(import.meta.url), join(root, "tools/outreach-check.mjs"));
    // the synthetic corpus size, held in a name so these planted untrue sentences are not read as claims by claims-check
    const SYN = 120;
    plant(root, "packages/sdk-ts/package.json", JSON.stringify({ version: "3.4.5" }));
    for (let i = 1; i <= 12; i++) plant(root, `docs/releases/v0.${i}.0-board.md`, "board\n");
    plant(root, "docs/releases/v0.13.0.md", "not a board\n");
    plant(root, "docs/releases/stranger-board.md", "not a release board\n");
    for (const [dir, count] of [["vectors/v1", SYN], ["vectors/v1-delta", 7], ["vectors/v1-directory", 5]]) {
      for (let i = 0; i < count; i++) plant(root, `${dir}/c${i}.json`, "{}\n");
      plant(root, `${dir}/manifest.json`, "{}\n");
      plant(root, `${dir}/notes.txt`, "not a vector\n");
    }
    // [packet path, the claim the child must report for it]
    const WRONG = [
      ["outreach/ready/p/README.md", `documents @ainra/sdk at 3.4.6, but the package is at 3.4.5`],
      ["outreach/ready/q/email.md", `says "eleven signed releases", but 12 board-proven release(s) exist`],
      ["outreach/ready/q/deep/email.md", `says "13 signed, board-proven releases", but 12 board-proven release(s) exist`],
      ["outreach/r.MD", `says "130 published conformance vectors", but the corpus on disk is ${SYN}`],
      ["outreach/ready/s/email.md", `says "${SYN} passport + 8 delta + 5 directory", but the corpus on disk is ${SYN} + 7 + 5`],
      ["outreach/ready/t/email.md", `"see it live" — the site is a published record of a STAGING network`],
    ];
    const BODY = {
      "outreach/ready/p/README.md": `"@ainra/sdk": "^3.4.6"\n`,
      "outreach/ready/q/email.md": "There are eleven signed releases.\n",
      "outreach/ready/q/deep/email.md": "There are 13 signed, board-proven releases.\n",
      "outreach/r.MD": "It ships 130 published conformance vectors.\n",
      "outreach/ready/s/email.md": `${SYN} passport + 8 delta + 5 directory\n`,
      "outreach/ready/t/email.md": "Come and see it live.\n",
    };
    for (const [path] of WRONG) plant(root, path, BODY[path]);
    plant(root, "outreach/ready/u/notes.txt", "see it live\n");
    plant(root, "outreach/ready/v/email.md", [
      `"@ainra/sdk": "^3.4.5"`, "twelve signed releases.", "12 signed, board-proven releases.",
      "three signed releases are published and a fourth is tagged.", "twenty-one signed releases is a hope, not a count.",
      `${SYN} conformance vectors and 7 delta vectors.`, `${SYN} passport + 7 delta + 5 directory`, "npm install @ainra/sdk",
    ].join("\n") + "\n");
    const child = () => spawnSync(process.execPath, [join(root, "tools/outreach-check.mjs")], { cwd: root, encoding: "utf8" });

    let r = child();
    const lines = (r.stderr || "").split("\n").filter((l) => l.startsWith("  ✗ "));
    judge(r.status === 1, "ok  caught ", "✗   MISSED ", `real run exits 1 on wrong packets (got ${r.status})`);
    for (const [path, claim] of WRONG) {
      const hits = lines.filter((l) => l.startsWith(`  ✗ ${path}: `));
      judge(hits.length === 1 && hits[0].includes(claim), "ok  caught ", "✗   MISSED ", `real run names ${path}`);
    }
    judge(lines.length === WRONG.length && r.stderr.includes(`FAILED — ${WRONG.length} claim(s)`),
      "ok  counted", "✗   MISCOUNT", `real run reports exactly ${WRONG.length} claims (got ${lines.length})`);

    for (const [path] of WRONG) rmSync(join(root, path));
    r = child();
    judge(r.status === 0 && r.stdout.includes("OUTREACH-CHECK OK")
      && r.stdout.includes(`scanned 1 outreach file(s) against: sdk 3.4.5 · 12 board-proven releases · corpus ${SYN}+7+5`),
      "ok  allowed", "✗   FLAGGED", `real run passes the true packet and reads the planted facts (got ${r.status})`);

    rmSync(join(root, "outreach"), { recursive: true });
    r = child();
    judge(r.status === 0 && r.stdout.includes("OUTREACH-CHECK SKIPPED"),
      "ok  skipped", "✗   NO SKIP", `real run skips with no outreach/ (got ${r.status})`);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  if (wrong) { console.error(`OUTREACH-CHECK NEGATIVE FAILED — ${wrong} planted check(s) judged wrongly`); process.exit(1); }
  console.log("OUTREACH-CHECK NEGATIVE OK — every planted untrue claim caught, every true one left alone, and the real run's exit code follows");
  process.exit(0);
}

const files = walk(join(ROOT, "outreach"));
for (const abs of files) {
  const rel = abs.slice(ROOT.length);
  for (const m of check(readFileSync(abs, "utf8"))) fail(rel, m);
}

console.log(`  scanned ${files.length} outreach file(s) against: sdk ${sdkV} · ${releases.length} board-proven releases · corpus ${CORPUS.passport}+${CORPUS.delta}+${CORPUS.directory} · registry state`);
if (bad) { console.error(`\nOUTREACH-CHECK FAILED — ${bad} claim(s) a recipient would find untrue.`); process.exit(1); }
console.log("OUTREACH-CHECK OK: every version pin, release count, corpus count, install command and liveness claim matches reality.");
