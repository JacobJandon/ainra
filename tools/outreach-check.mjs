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

  // 3. An install command for a package that is not published sends a stranger to an E404.
  for (const m of body.matchAll(/(?:npm\s+(?:i|install)|pip\s+install|npx)\s+[^\n`]*?(@ainra\/[a-z-]+|\bainra\b)/gi))
    fail(rel, `tells a reader to install "${m[1]}" — nothing is published to a registry yet, so this fails with E404`);

  // 4. The published-record wording. "See it live" was removed from the site in M27 for overstating what exists;
  //    a packet is the last place it should survive, because it is read by the people we are asking to trust us.
  for (const m of body.matchAll(/see it live/gi)) fail(rel, `"${m[0]}" — the site is a published record of a STAGING network, not a live one`);
}

console.log(`  scanned ${files.length} outreach file(s) against: sdk ${sdkV} · ${releases.length} board-proven releases · registry state`);
if (bad) { console.error(`\nOUTREACH-CHECK FAILED — ${bad} claim(s) a recipient would find untrue.`); process.exit(1); }
console.log("OUTREACH-CHECK OK: every version pin, release count, install command and liveness claim matches reality.");
