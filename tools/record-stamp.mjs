// SPDX-License-Identifier: Apache-2.0 OR MIT
// Final state first (MOTION.md B0.1): every number and record line the living elements show is in the HTML at its
// final value at first paint, so a page reads completely with JavaScript off. The values come from the published
// record in site/net/*.json, through the SAME pure renderer the browser uses (site/js/record-view.mjs), so the
// stamped HTML and the running page cannot disagree with each other or with the record.
//
//   <b data-stamp="issued">9</b>                    a value (text only)
//   <!--stamp:ticker-->…<!--/stamp:ticker-->         a block of generated markup
//   <meta name="ainra-checkpoints" content="…">      the checkpoint files the page reads (named by height)
//
//   node tools/record-stamp.mjs           → write (idempotent); run by `make site` before the include sync
//   node tools/record-stamp.mjs --check   → exit 1 if any page or include differs from what the record gives
//
// WITNESS (negative control, executed): hand-editing one stamped number in site/index.html (ISSUED 9 → 8, a number a
// reader would believe) makes --check exit 1 naming the page. By construction, refreshing site/net/ without `make site`
// would do the same.
import { readFileSync, writeFileSync, readdirSync, existsSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SITE = join(ROOT, "site"), NET = join(SITE, "net");
const view = await import(pathToFileURL(join(SITE, "js", "record-view.mjs")).href);
const j = (p) => JSON.parse(readFileSync(join(NET, p), "utf8"));

const checkpoints = {}, cpFiles = [];
const regDir = join(NET, "registrars");
if (existsSync(regDir)) for (const id of readdirSync(regDir).sort()) {
  const d = join(regDir, id, "checkpoints");
  if (!existsSync(d)) continue;
  const top = readdirSync(d).map((f) => (f.match(/^(\d+)\.json$/) || [])[1]).filter(Boolean).map(Number).sort((a, b) => b - a)[0];
  if (top === undefined) continue;
  const file = `net/registrars/${id}/checkpoints/${top}.json`, c = j(`registrars/${id}/checkpoints/${top}.json`);
  checkpoints[id] = { file, size: c.size, root: c.root, origin: c.origin }; cpFiles.push(file);
}
const m = view.model({ published: j("published.json"), registry: j("registry.json"), roots: j("roots.json"), checkpoints });
const values = view.stampValues(m);

const check = process.argv.includes("--check");
const files = [...readdirSync(SITE).filter((f) => f.endsWith(".html")).map((f) => join(SITE, f)),
  ...readdirSync(join(SITE, "_includes")).filter((f) => f.endsWith(".html")).map((f) => join(SITE, "_includes", f))];
let drift = 0, wrote = 0, unknown = 0;
for (const file of files) {
  const s = readFileSync(file, "utf8");
  let t = s.replace(/(<([a-z0-9]+)\b[^>]*\bdata-stamp="([a-z0-9-]+)"[^>]*>)([^<]*)(<\/\2>)/g, (all, open, _tag, key, _v, close) => {
    if (!(key in values)) { console.log(`  ? ${file.slice(ROOT.length + 1)}: unknown stamp "${key}"`); unknown++; return all; }
    return open + values[key].replace(/&/g, "&amp;").replace(/</g, "&lt;") + close;
  });
  t = t.replace(/<!--stamp:([a-z0-9-]+)-->[\s\S]*?<!--\/stamp:\1-->/g, (all, key) => {
    const f = view.stampBlocks[key];
    if (!f) { console.log(`  ? ${file.slice(ROOT.length + 1)}: unknown block "${key}"`); unknown++; return all; }
    return `<!--stamp:${key}-->${f(m)}<!--/stamp:${key}-->`;
  });
  t = t.replace(/(<meta name="ainra-checkpoints" content=")[^"]*(")/g, `$1${cpFiles.join(" ")}$2`);
  if (t !== s) {
    if (check) { console.log(`  ✗ ${file.slice(ROOT.length + 1)}: stamped values differ from site/net/*.json`); drift++; }
    else { writeFileSync(file, t); wrote++; console.log(`  ↻ ${file.slice(ROOT.length + 1)}: stamped from site/net/`); }
  }
}
if (unknown) process.exit(1);
if (check) {
  console.log(drift ? `\nRECORD-STAMP: ${drift} page(s) out of step with the record — run \`make site\`` : `RECORD-STAMP OK: every stamped value and record block equals what site/net/*.json gives (record published ${m.publishedIso}).`);
  process.exit(drift ? 1 : 0);
}
console.log(`record-stamp: ${wrote} file(s) written from the record published ${m.publishedIso}`);
