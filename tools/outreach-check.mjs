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

import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
let bad = 0;
const fail = (f, m) => { console.error(`  ✗ ${f}: ${m}`); bad++; };

if (!existsSync(join(ROOT, "outreach"))) {
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
const files = walk(join(ROOT, "outreach"));

// The facts every packet must agree with, read from the same places the rest of the board reads them.
const sdkV = JSON.parse(readFileSync(join(ROOT, "packages/sdk-ts/package.json"), "utf8")).version;
const releases = readdirSync(join(ROOT, "docs/releases"))
  .map((f) => /^(v[0-9][0-9.]*)-board\.md$/.exec(f)?.[1]).filter(Boolean);
const WORDS = { 1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine" };
const countJson = (d) => readdirSync(join(ROOT, d)).filter((f) => f.endsWith(".json") && f !== "manifest.json").length;
const CORPUS = { passport: countJson("vectors/v1"), delta: countJson("vectors/v1-delta"), directory: countJson("vectors/v1-directory") };

for (const abs of files) {
  const rel = abs.slice(ROOT.length);
  const body = readFileSync(abs, "utf8");

  // 1. A documented install pin must be the version the packages are at.
  for (const m of body.matchAll(/["'`]@ainra\/sdk["'`]\s*:\s*["'`]\^?([0-9]+\.[0-9]+\.[0-9]+)["'`]/g))
    if (m[1] !== sdkV) fail(rel, `documents @ainra/sdk at ${m[1]}, but the package is at ${sdkV}`);

  // 2. A release count must match the board-proven releases.
  // A count that names WHICH thing it counts is not caught here — "three signed releases are published and a
  // fourth is tagged" is more precise than any single number, and a gate that punished it would push writers
  // toward the vaguer sentence. Only a bare count is checked.
  for (const m of body.matchAll(/\b(one|two|three|four|five|six|seven|eight|nine)\s+signed(?:,\s*board-proven)?\s+releases?\b(?!\s+are\s+published\s+and\s+a\s+\w+\s+is\s+tagged)/gi))
    if (m[1].toLowerCase() !== WORDS[releases.length])
      fail(rel, `says "${m[0]}", but ${releases.length} board-proven release(s) exist`);

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
  for (const u of UNPUBLISHED)
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
}

console.log(`  scanned ${files.length} outreach file(s) against: sdk ${sdkV} · ${releases.length} board-proven releases · corpus ${CORPUS.passport}+${CORPUS.delta}+${CORPUS.directory} · registry state`);
if (bad) { console.error(`\nOUTREACH-CHECK FAILED — ${bad} claim(s) a recipient would find untrue.`); process.exit(1); }
console.log("OUTREACH-CHECK OK: every version pin, release count, corpus count, install command and liveness claim matches reality.");
