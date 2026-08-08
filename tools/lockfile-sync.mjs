#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// A committed lockfile must state the version its package.json states.
//
// This gate exists because of a specific, expensive silence. `packages/sdk-ts/package-lock.json` said `0.1.0`
// while its package.json had moved through 0.2.0, 0.3.0, 0.3.1 and 0.3.2 — three tagged releases, none of which
// touched it. Nothing noticed, because nothing looked, and locally nothing ever would: the lockfile is only
// rewritten when `npm install` runs, and a developer machine already has node_modules.
//
// It surfaced in the worst possible place. The publish workflow provisions the SDK before running the release
// gate, `npm install` synced the lockfile from 0.1.0 to the real version as a side effect, and the gate then
// diffed a tree that its own provisioning step had just dirtied:
//
//     [BLOCK] tag matches tree   packages differ from tag v0.3.2 — Drifted: packages/sdk-ts/package-lock.json
//
// So the publish path had never once got past its own preflight, and could not have, on any version. That is the
// same family as the three never-run checks M26 found: a gate that is never reached is not a gate.
//
// Two things had to change — the drift, and the mechanism that hid it. This checks the drift; the workflow now
// provisions with `npm ci`, which READS the lockfile and never writes it, so a future drift fails loudly at
// install time instead of being silently rewritten underneath the release gate.

import { readFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
let bad = 0;

const locks = execFileSync("git", ["ls-files", "*package-lock.json"], { cwd: ROOT, encoding: "utf8" })
  .split("\n").map((s) => s.trim()).filter(Boolean);

for (const lockRel of locks) {
  const dir = dirname(lockRel);
  const pkgRel = join(dir, "package.json");
  if (!existsSync(join(ROOT, pkgRel))) continue; // a lockfile with no manifest beside it is not this gate's business

  let lock, pkg;
  try {
    lock = JSON.parse(readFileSync(join(ROOT, lockRel), "utf8"));
    pkg = JSON.parse(readFileSync(join(ROOT, pkgRel), "utf8"));
  } catch (e) { console.error(`  ✗ ${lockRel}: unreadable (${e.message})`); bad++; continue; }

  // A private/workspace-only manifest carries no version to agree with.
  if (!pkg.version) continue;

  // npm writes the version in two places; both must agree, because either one alone can be stale.
  const spots = [["version", lock.version], ['packages[""].version', lock.packages?.[""]?.version]]
    .filter(([, v]) => v !== undefined);
  if (!spots.length) { console.error(`  ✗ ${lockRel}: states no version at all`); bad++; continue; }

  const wrong = spots.filter(([, v]) => v !== pkg.version);
  if (wrong.length) {
    for (const [where, v] of wrong)
      console.error(`  ✗ ${lockRel}: ${where} = ${v}, but ${pkgRel} says ${pkg.version}` +
        ` — run \`npm --prefix ${dir} install --package-lock-only\` and commit the result`);
    bad++;
  } else {
    console.log(`  ✓ ${dir} — lockfile and manifest agree at ${pkg.version}`);
  }
}

if (bad) {
  console.error(`\nLOCKFILE-SYNC FAILED — ${bad} lockfile(s) disagree with their manifest.`);
  console.error("A stale lockfile is rewritten by the next `npm install`, which dirties the tree the release gate");
  console.error("diffs against the tag. That is how the publish path stayed blocked without anyone seeing it.");
  process.exit(1);
}
console.log(`LOCKFILE-SYNC OK: ${locks.length} lockfile(s) checked, every one states its package's version.`);
