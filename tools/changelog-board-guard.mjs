// SPDX-License-Identifier: Apache-2.0 OR MIT
// M23.1 — the CHANGELOG cannot claim a version whose board evidence is absent.
//
// A version is only "released" once the FULL preflight board ran ALL GREEN from a clean clone at the release commit
// and that board was committed to docs/releases/<version>-board.md (see RELEASING.md, "The one rule"). This guard
// makes the discipline enforceable: for every `## [vX.Y.Z]` section in CHANGELOG.md, the matching board file must
// exist. `## [Unreleased]` is exempt (it claims nothing). v0.1.0 is grandfathered — it was never tagged, predates
// this discipline, and is superseded by v0.2.0; it is named here so the exemption is explicit, not silent.
//
//   node tools/changelog-board-guard.mjs      (or `make changelog-board-check`)
import { readFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const changelog = readFileSync(resolve(ROOT, "CHANGELOG.md"), "utf8");
const GRANDFATHERED = new Set(["v0.1.0"]); // never tagged; predates the M23.1 board rule; superseded by v0.2.0

const versions = [...changelog.matchAll(/^##\s*\[(v?\d+\.\d+\.\d+)\]/gm)].map((m) =>
  m[1].startsWith("v") ? m[1] : "v" + m[1],
);
if (!versions.length) {
  console.error("✗ no version sections found in CHANGELOG.md — expected `## [vX.Y.Z]`");
  process.exit(1);
}

const missing = [];
for (const ver of versions) {
  if (GRANDFATHERED.has(ver)) {
    console.log(`  · ${ver} — grandfathered (pre-discipline, never tagged, superseded)`);
    continue;
  }
  const rel = `docs/releases/${ver}-board.md`;
  if (existsSync(resolve(ROOT, rel))) console.log(`  ✓ ${ver} — board evidence present (${rel})`);
  else {
    missing.push(ver);
    console.error(`  ✗ ${ver} — CHANGELOG claims it, but ${rel} is ABSENT`);
  }
}

if (missing.length) {
  console.error(
    `\n✗ CHANGELOG claims ${missing.join(", ")} without a committed preflight board.\n` +
      `  Run the full board from a clean clone at the release commit (RELEASING.md, "The one rule")\n` +
      `  and commit docs/releases/<version>-board.md. The claim must never outrun the proof.`,
  );
  process.exit(1);
}
console.log("\n✓ every CHANGELOG-claimed release has committed board evidence");
