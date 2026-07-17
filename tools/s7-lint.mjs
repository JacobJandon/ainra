// SPDX-License-Identifier: Apache-2.0 OR MIT
// S7 neutrality linter (MTS §28: "CI greps fixtures for real names"). Scans authored code + conformance fixtures
// for real company/product names used as placeholder data. Exit nonzero on any hit. Registrars are registrar-NN;
// operators are acme / globex / operator-NN.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";

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
const SELF = new Set([
  path.join(ROOT, "tools/s7-denylist.txt"),
  path.join(ROOT, "tools/s7-brand-denylist.txt"),
  path.join(ROOT, "tools/s7-lint.mjs"),
]);

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

if (hits) console.error(`\nS7 (fixtures) FAILED: ${hits} real-name occurrence(s) in code/fixtures`);
else console.log(`S7 OK (fixtures): ${DENY.length} denied names, none present in ${SCAN_DIRS.join(", ")}`);

// ── PASS 2 (M10): commercial/foil BRAND names in PROSE + commit messages ──────────────────────────────────────────
// Everything now public — docs/, kit READMEs, front-door md, .github/ templates, AND git commit messages — is swept
// for commercial-brand names a NEUTRAL root must not be seen naming. Uses a CURATED denylist (tools/s7-brand-denylist
// .txt) restricted to tokens that only appear AS a brand, so it runs over prose without the common-word false
// positives (windows / chrome / apple / meta / oracle) that the fixture list above would trip. Standards bodies and
// this repo's own attribution trailers (Anthropic/Claude) are intentionally NOT on that list.
const BRAND = fs
  .readFileSync(path.join(ROOT, "tools/s7-brand-denylist.txt"), "utf8")
  .split("\n")
  .map((l) => l.trim())
  .filter((l) => l && !l.startsWith("#"));
// Legitimate, unavoidable technical references (name + a substring that must be on the line to allow it). Empty today.
const PROSE_ALLOW = [];
const brandPat = BRAND.map((n) => {
  const esc = n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return { name: n, re: new RegExp(`(?<![.\\w])${esc}(?![\\w])`, "i") };
});
const PROSE_DIRS = ["docs", "kits", "outreach", ".github"];
const PROSE_EXT = new Set([".md", ".txt", ".yml", ".yaml"]);
const PROSE_FILES = ["README.md", "CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md", "GENESIS-CHECKLIST.md"];
let brandHits = 0;
function scanProse(label, text) {
  text.split("\n").forEach((line, i) => {
    for (const p of brandPat) {
      if (!p.re.test(line)) continue;
      if (PROSE_ALLOW.some((a) => a.name === p.name && line.includes(a.ctx))) continue;
      brandHits++;
      console.error(`  S7-BRAND HIT ${label}:${i + 1}  "${p.name}"  ${line.trim().slice(0, 80)}`);
    }
  });
}
function* walkProse(dir) {
  if (!fs.existsSync(dir)) return;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name)) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) yield* walkProse(full);
    else if (PROSE_EXT.has(path.extname(e.name))) yield full;
  }
}
for (const dir of PROSE_DIRS) for (const f of walkProse(path.join(ROOT, dir))) scanProse(path.relative(ROOT, f), fs.readFileSync(f, "utf8"));
for (const f of PROSE_FILES) { const full = path.join(ROOT, f); if (fs.existsSync(full)) scanProse(f, fs.readFileSync(full, "utf8")); }
try {
  scanProse("<commit-messages>", execSync("git log --format=%B", { cwd: ROOT, encoding: "utf8" }));
} catch { /* not a git checkout (e.g. tarball) — skip commit-message scan */ }

if (brandHits) console.error(`\nS7 (brand) FAILED: ${brandHits} commercial-brand occurrence(s) in prose/commit messages`);
else console.log(`S7 OK (brand): ${BRAND.length} foil brands, none present in docs/kits/outreach/.github/front-door/commit-messages`);

if (hits || brandHits) process.exit(1);
console.log("S7 OK: neutral — no impersonation in fixtures, no commercial brands in public prose or history");
