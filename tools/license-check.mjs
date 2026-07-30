// SPDX-License-Identifier: Apache-2.0 OR MIT
// Every authored source file must carry the dual-license SPDX header (code is Apache-2.0 OR MIT; the CC0 vectors
// are covered by vectors/LICENSE, not this check). Exit nonzero on any missing header.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const SPDX = "SPDX-License-Identifier: Apache-2.0 OR MIT";
const DIRS = [
  "crates",
  "packages/sdk-ts/src",
  "packages/sdk-py/ainra",
  "packages/sdk-py/tests",
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

let missing = 0;
for (const dir of DIRS) {
  for (const file of walk(path.join(ROOT, dir))) {
    const head = fs.readFileSync(file, "utf8").slice(0, 200);
    if (!head.includes(SPDX)) {
      missing++;
      console.error(`  MISSING SPDX: ${path.relative(ROOT, file)}`);
    }
  }
}
if (missing) {
  console.error(`\nLICENSE FAILED: ${missing} file(s) without the SPDX header`);
  process.exit(1);
}
console.log("LICENSE OK: every scanned source file carries the dual-license SPDX header");
