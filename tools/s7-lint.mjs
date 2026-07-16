// SPDX-License-Identifier: Apache-2.0 OR MIT
// S7 neutrality linter (MTS §28: "CI greps fixtures for real names"). Scans authored code + conformance fixtures
// for real company/product names used as placeholder data. Exit nonzero on any hit. Registrars are registrar-NN;
// operators are acme / globex / operator-NN.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const DENY = fs
  .readFileSync(path.join(ROOT, "tools/s7-denylist.txt"), "utf8")
  .split("\n")
  .map((l) => l.trim())
  .filter((l) => l && !l.startsWith("#"));

// Directories of AUTHORED code + fixtures to scan. The landscape/spec docs are intentionally excluded (they cite
// real standards bodies + prior art as technical reference, which is analysis, not placeholder impersonation).
const SCAN_DIRS = ["crates", "packages/sdk-ts/src", "tools", "vectors"];
const SCAN_EXT = new Set([".rs", ".ts", ".mjs", ".js", ".json", ".toml", ".sh", ".txt"]);
const SKIP = new Set(["node_modules", "dist", "target"]);
const SELF = new Set([path.join(ROOT, "tools/s7-denylist.txt"), path.join(ROOT, "tools/s7-lint.mjs")]);

function* walk(dir) {
  if (!fs.existsSync(dir)) return;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name)) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) yield* walk(full);
    else if (SCAN_EXT.has(path.extname(e.name))) yield full;
  }
}

// Match a denied name as a standalone token, NOT as a member access (`.windows(2)`, `import.meta`) — a real company
// used as placeholder DATA appears as a string value or bare word, never after a `.`.
const patterns = DENY.map((n) => {
  const esc = n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return { name: n, re: new RegExp(`(?<![.\\w])${esc}(?![\\w])`, "i") };
});
let hits = 0;
for (const dir of SCAN_DIRS) {
  for (const file of walk(path.join(ROOT, dir))) {
    if (SELF.has(file)) continue;
    const text = fs.readFileSync(file, "utf8");
    text.split("\n").forEach((line, i) => {
      for (const p of patterns) {
        if (p.re.test(line)) {
          hits++;
          console.error(`  S7 HIT ${path.relative(ROOT, file)}:${i + 1}  "${p.name}"  ${line.trim().slice(0, 80)}`);
        }
      }
    });
  }
}

if (hits) {
  console.error(`\nS7 FAILED: ${hits} real-name occurrence(s) in code/fixtures`);
  process.exit(1);
}
console.log(`S7 OK: ${DENY.length} denied names, none present in ${SCAN_DIRS.join(", ")}`);
