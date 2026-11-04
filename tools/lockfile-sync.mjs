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
//
// WITNESS: `--negative` builds throwaway git repositories under the OS temp directory, each holding one planted
// package — the historical defect itself (lockfile at 0.1.0, manifest at 0.3.2), a lockfile stale in only its
// top-level `version`, one stale in only `packages[""].version`, one that states no version, and one that is not
// JSON — and runs the same check, git enumeration included, against each. Every plant must fail for its own
// reason; a clean pair and a version-less private manifest must still pass, so a check that fails everything
// cannot pass the control either. Nothing in this repository is touched.

import { readFileSync, existsSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";

const ROOT = fileURLToPath(new URL("../", import.meta.url));

// The whole check, against any git checkout. `out` and `err` receive every line it would print.
function check(root, out = console.log, err = console.error) {
  let bad = 0;

  const locks = execFileSync("git", ["ls-files", "*package-lock.json"], { cwd: root, encoding: "utf8" })
    .split("\n").map((s) => s.trim()).filter(Boolean);

  for (const lockRel of locks) {
    const dir = dirname(lockRel);
    const pkgRel = join(dir, "package.json");
    if (!existsSync(join(root, pkgRel))) continue; // a lockfile with no manifest beside it is not this gate's business

    let lock, pkg;
    try {
      lock = JSON.parse(readFileSync(join(root, lockRel), "utf8"));
      pkg = JSON.parse(readFileSync(join(root, pkgRel), "utf8"));
    } catch (e) { err(`  ✗ ${lockRel}: unreadable (${e.message})`); bad++; continue; }

    // A private/workspace-only manifest carries no version to agree with.
    if (!pkg.version) continue;

    // npm writes the version in two places; both must agree, because either one alone can be stale.
    const spots = [["version", lock.version], ['packages[""].version', lock.packages?.[""]?.version]]
      .filter(([, v]) => v !== undefined);
    if (!spots.length) { err(`  ✗ ${lockRel}: states no version at all`); bad++; continue; }

    const wrong = spots.filter(([, v]) => v !== pkg.version);
    if (wrong.length) {
      for (const [where, v] of wrong)
        err(`  ✗ ${lockRel}: ${where} = ${v}, but ${pkgRel} says ${pkg.version}` +
          ` — run \`npm --prefix ${dir} install --package-lock-only\` and commit the result`);
      bad++;
    } else {
      out(`  ✓ ${dir} — lockfile and manifest agree at ${pkg.version}`);
    }
  }
  return { bad, count: locks.length };
}

if (process.argv.includes("--negative")) {
  const pkg = (version) => JSON.stringify(version ? { name: "planted", version } : { name: "planted", private: true });
  const lock = (top, inner) => JSON.stringify({ name: "planted", ...(top && { version: top }), lockfileVersion: 3,
    packages: { "": { name: "planted", ...(inner && { version: inner }) } } });
  // [what is planted, manifest, lockfile, the words the failure must contain — or null where it must pass]
  const CASES = [
    ["lockfile left at 0.1.0 while the manifest moved to 0.3.2", pkg("0.3.2"), lock("0.1.0", "0.1.0"), "version = 0.1.0"],
    ["only the top-level version is stale", pkg("0.3.2"), lock("0.1.0", "0.3.2"), "package-lock.json: version = 0.1.0"],
    ['only packages[""].version is stale', pkg("0.3.2"), lock("0.3.2", "0.1.0"), 'packages[""].version = 0.1.0'],
    ["a lockfile that states no version", pkg("0.3.2"), lock(null, null), "states no version at all"],
    ["a lockfile that is not JSON", pkg("0.3.2"), "{ not json", "unreadable"],
    ["a clean pair (control)", pkg("0.3.2"), lock("0.3.2", "0.3.2"), null],
    ["a private manifest with no version (control)", pkg(null), lock("0.1.0", "0.1.0"), null],
  ];
  let missed = 0;
  for (const [what, manifest, lockfile, must] of CASES) {
    const repo = mkdtempSync(join(tmpdir(), "ainra-lockfile-sync-"));
    try {
      mkdirSync(join(repo, "pkg"));
      writeFileSync(join(repo, "pkg", "package.json"), manifest);
      writeFileSync(join(repo, "pkg", "package-lock.json"), lockfile);
      execFileSync("git", ["init", "-q"], { cwd: repo });
      execFileSync("git", ["add", "-A"], { cwd: repo });
      const lines = [];
      const { bad, count } = check(repo, (l) => lines.push(l), (l) => lines.push(l));
      const right = count !== 1 ? false
        : must === null ? bad === 0
        : bad > 0 && lines.some((l) => l.includes(must));
      console.log(`  ${right ? (must === null ? "ok  passed " : "ok  caught ") : (must === null ? "✗   FLAGGED" : "✗   MISSED ")} ${what}`);
      if (!right) { missed++; for (const l of lines) console.error(`        ${l}`); }
    } finally { rmSync(repo, { recursive: true, force: true }); }
  }
  if (missed) { console.error(`LOCKFILE-SYNC NEGATIVE FAILED — ${missed} planted case(s) judged wrongly.`); process.exit(1); }
  console.log(`LOCKFILE-SYNC NEGATIVE OK — all ${CASES.length - 2} planted drifts caught, both controls passed.`);
  process.exit(0);
}

const { bad, count } = check(ROOT);
if (bad) {
  console.error(`\nLOCKFILE-SYNC FAILED — ${bad} lockfile(s) disagree with their manifest.`);
  console.error("A stale lockfile is rewritten by the next `npm install`, which dirties the tree the release gate");
  console.error("diffs against the tag. That is how the publish path stayed blocked without anyone seeing it.");
  process.exit(1);
}
console.log(`LOCKFILE-SYNC OK: ${count} lockfile(s) checked, every one states its package's version.`);
