// SPDX-License-Identifier: Apache-2.0 OR MIT
// Every authored source file must carry the dual-license SPDX header (code is Apache-2.0 OR MIT; the CC0 vectors
// are covered by vectors/LICENSE, not this check). Exit nonzero on any missing header.
//
// WITNESS: `--negative` builds throwaway trees under os.tmpdir() and checks them two ways. First it runs the same
// walk and header test over a planted tree: a headerless file of every extension the check reads (.mjs, .js, .rs,
// .py, .ts — the .ts one directory deep), a header pushed past the 200-character window, and a single-license header
// (Apache-2.0 alone is not the dual grant); every one must be reported. Beside them sit a correctly headed file and
// headerless files under node_modules, dist and target, and a headerless .md, which must not be. Then it runs this
// very file as a child process, with no flag, pointed at a second tree that has one headerless file in every
// directory the real run scans: it must exit 1 and name exactly those files, and after they gain a header it must
// exit 0 and say LICENSE OK. So the control fails if detection goes blind, if it starts crying wolf over what it was
// never meant to read, and if the real run stops scanning a directory or stops failing. Nothing in the repository is
// touched.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// AINRA_LICENSE_CHECK_ROOT exists for the witness below and nothing else: it lets `--negative` run this file's real
// entry point over a planted tree. Unset, the root is the repository this file sits in.
const ROOT = process.env.AINRA_LICENSE_CHECK_ROOT || fileURLToPath(new URL("../", import.meta.url));
const SPDX = "SPDX-License-Identifier: Apache-2.0 OR MIT";
// Every directory that ships or tests shipped code. The list used to stop at the SDK's src/, so a test file that
// lost its header in an edit (packages/sdk-ts/test/presentation.test.mjs, M34) passed this check while every
// neighbour carried one by habit. A rule enforced by habit is the kind M32 set out to remove.
const DIRS = [
  "crates",
  "packages/sdk-ts/src",
  "packages/sdk-ts/test",
  "packages/middleware/src",
  "packages/middleware/test",
  "packages/mcp/src",
  "packages/mcp/test",
  "packages/sdk-py/ainra",
  "packages/sdk-py/tests",
  "apps/cli-node/bin",
  "kits",
  "tools",
  "fuzz/fuzz_targets",
];
const EXT = new Set([".rs", ".ts", ".mjs", ".js", ".py"]);
const SKIP = new Set(["node_modules", "dist", "target"]);

function* walk(dir) {
  if (!fs.existsSync(dir)) return;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name)) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) yield* walk(full);
    else if (EXT.has(path.extname(e.name))) yield full;
  }
}

// The one detection both modes share: every scanned file under `root`/`dirs` whose first 200 characters lack the
// header, as a path relative to `root`, in walk order.
function scan(root, dirs) {
  const out = [];
  for (const dir of dirs) {
    for (const file of walk(path.join(root, dir))) {
      const head = fs.readFileSync(file, "utf8").slice(0, 200);
      if (!head.includes(SPDX)) out.push(path.relative(root, file));
    }
  }
  return out;
}

if (process.argv.includes("--negative")) {
  const good = `// ${SPDX}\nexport const x = 1;\n`;
  const PLANTS = [
    ["src/no-header.mjs", "export const x = 1;\n"],
    ["src/no-header.js", "module.exports = 1;\n"],
    ["src/late-header.rs", `${"// padding line before the header\n".repeat(8)}// ${SPDX}\nfn main() {}\n`],
    ["src/single-license.py", "# SPDX-License-Identifier: Apache-2.0\nx = 1\n"],
    ["src/deep/nested/no-header.ts", "export const y = 2;\n"],
  ];
  const ALLOWED = [
    ["src/headed.js", good],
    ["src/node_modules/dep/index.js", "module.exports = 1;\n"],
    ["src/dist/bundle.js", "module.exports = 1;\n"],
    ["src/target/debug/build.rs", "fn main() {}\n"],
    ["src/README.md", "no header, and not source\n"],
  ];
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "license-check-negative-"));
  let bad = 0;
  try {
    for (const [rel, body] of [...PLANTS, ...ALLOWED]) {
      fs.mkdirSync(path.dirname(path.join(tmp, rel)), { recursive: true });
      fs.writeFileSync(path.join(tmp, rel), body);
    }
    const flagged = new Set(scan(tmp, ["src"]));
    for (const [rel] of PLANTS) {
      const caught = flagged.has(rel);
      console.log(`  ${caught ? "ok  caught " : "✗   MISSED "} ${rel}`);
      if (!caught) bad++;
    }
    for (const [rel] of ALLOWED) {
      const wrong = flagged.has(rel);
      console.log(`  ${wrong ? "✗   FLAGGED" : "ok  allowed"} ${rel}`);
      if (wrong) bad++;
    }

    // The real entry point, as `make license` runs it. One headerless file in every scanned directory; the walk
    // reads only by extension, so .js serves everywhere.
    const live = path.join(tmp, "live");
    const plants = DIRS.map((d) => path.join(d, "negative-plant.js"));
    for (const rel of plants) {
      fs.mkdirSync(path.dirname(path.join(live, rel)), { recursive: true });
      fs.writeFileSync(path.join(live, rel), "module.exports = 1;\n");
    }
    const run = () => spawnSync(process.execPath, [fileURLToPath(import.meta.url)],
      { encoding: "utf8", env: { ...process.env, AINRA_LICENSE_CHECK_ROOT: live } });
    const red = run();
    const named = new Set([...red.stderr.matchAll(/^ {2}MISSING SPDX: (.+)$/gm)].map((m) => m[1]));
    const redOk = red.status === 1 && plants.every((rel) => named.has(rel)) && named.size === plants.length &&
      red.stderr.includes(`LICENSE FAILED: ${plants.length} file(s)`);
    console.log(`  ${redOk ? "ok  caught " : "✗   MISSED "} real run, one headerless file in each of ${plants.length} scanned dirs: exit 1, all named` +
      (redOk ? "" : ` (exit ${red.status}, named ${named.size})`));
    if (!redOk) bad++;
    for (const rel of plants) fs.writeFileSync(path.join(live, rel), good);
    const green = run();
    const greenOk = green.status === 0 && green.stdout.includes("LICENSE OK") && !green.stderr.includes("MISSING SPDX");
    console.log(`  ${greenOk ? "ok  allowed" : "✗   FLAGGED"} real run, the same files headed: exit 0, LICENSE OK` +
      (greenOk ? "" : ` (exit ${green.status})`));
    if (!greenOk) bad++;
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  if (bad) { console.error(`LICENSE NEGATIVE FAILED — ${bad} planted case(s) judged wrongly`); process.exit(1); }
  console.log(`LICENSE NEGATIVE OK — all ${PLANTS.length} planted headerless files caught, ${ALLOWED.length} out-of-scope files allowed, ` +
    "real run fails on a planted tree and passes once it is headed");
  process.exit(0);
}

const missing = scan(ROOT, DIRS);
for (const rel of missing) console.error(`  MISSING SPDX: ${rel}`);
if (missing.length) {
  console.error(`\nLICENSE FAILED: ${missing.length} file(s) without the SPDX header`);
  process.exit(1);
}
console.log("LICENSE OK: every scanned source file carries the dual-license SPDX header");
