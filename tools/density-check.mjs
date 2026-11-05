// SPDX-License-Identifier: Apache-2.0 OR MIT
// The emptiness gate (MOTION.md B5): no page may leave a large region of unstructured emptiness.
//
// Method — each page in headless Chromium at 1440×900 and 390×844:
//   1. collect the boxes of everything visible inside <main>: every non-blank text node (its line boxes), img, svg,
//      canvas, iframe, video, input, select, textarea, button, hr, every drawn border edge (a rule), and every solid
//      dark surface (a code panel) — a light card counts only by what is inside it; a position:sticky element counts
//      over its container's height, since it stays on screen there;
//   2. rasterise them onto a 40px grid over the page;
//   3. drop the grid rows that lie wholly inside a declared section gap (the padding-top of each .section: 112px at
//      1440, 64px at 390), so the beat between sections is allowed;
//   4. find any empty axis-aligned rectangle of at least 320×320 px at 1440, or 358×200 px at 390.
// A failure prints its page, the rectangle in page coordinates, and the nearest section id. Exit 1 on any failure.
//
//   node tools/density-check.mjs [--base http://127.0.0.1:PORT] [--pages index,verify] [--widths 1440,390]
// WITNESS (negative control, executed): the Spec Sheet content pages as they stood before this pass (shots/spec-*)
// fail it with 25 regions — docs.html's empty right third on every chapter (19), verify.html's verdict column (2),
// the hero halves of foundation.html (2) and landscape.html (1), the bare 404 (1); it went green only as each was
// filled.
// Without --base it serves site/ itself on a free local port. Needs playwright-core: from node_modules, or the path
// in $PLAYWRIGHT_CORE (a playwright-core directory), e.g. the gstack browse skill's copy.
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join, extname, normalize } from "node:path";
import { createRequire } from "node:module";
import { homedir } from "node:os";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SITE = join(ROOT, "site");
const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const PAGES = arg("--pages", "index,verify,get,docs,foundation,landscape,404").split(",");
const WIDTHS = arg("--widths", "1440,390").split(",").map(Number);
const CELL = 40;
const LIMIT = { 1440: [320, 320], 390: [358, 200] };

async function playwright() {
  const tries = [process.env.PLAYWRIGHT_CORE, join(homedir(), ".claude/skills/gstack/node_modules/playwright-core")].filter(Boolean);
  try { return createRequire(join(ROOT, "package.json"))("playwright-core"); } catch { /* not installed here */ }
  for (const t of tries) if (existsSync(join(t, "index.mjs"))) return import(pathToFileURL(join(t, "index.mjs")).href);
  console.error("✗ density-check needs playwright-core (npm i playwright-core, or set PLAYWRIGHT_CORE to its directory)"); process.exit(2);
}

const TYPES = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".mjs": "text/javascript", ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png", ".woff2": "font/woff2", ".wasm": "application/wasm", ".md": "text/markdown", ".txt": "text/plain", ".ico": "image/x-icon" };
function serve() {
  return new Promise((ok) => {
    const srv = createServer(async (req, res) => {
      let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
      if (p.endsWith("/")) p += "index.html";
      const f = normalize(join(SITE, p));
      if (!f.startsWith(SITE)) { res.writeHead(403).end(); return; }
      try { const s = await stat(f); if (!s.isFile()) throw 0; res.writeHead(200, { "content-type": TYPES[extname(f)] || "application/octet-stream" }); res.end(await readFile(f)); }
      catch { res.writeHead(404, { "content-type": "text/html" }); res.end(await readFile(join(SITE, "404.html")).catch(() => "")); }
    });
    srv.listen(0, "127.0.0.1", () => ok(srv));
  });
}

// runs in the page: boxes of visible content inside <main>, in page coordinates
function collect() {
  const main = document.querySelector("main") || document.body;
  const sy = scrollY, sx = scrollX, out = [], gaps = [];
  const vis = (el) => { const cs = getComputedStyle(el); return cs.visibility !== "hidden" && cs.display !== "none" && +cs.opacity > 0; };
  const add = (r) => { if (r.width > 0.5 && r.height > 0.5) out.push([r.left + sx, r.top + sy, r.right + sx, r.bottom + sy]); };
  const walk = document.createTreeWalker(main, NodeFilter.SHOW_TEXT, { acceptNode: (n) => (/\S/.test(n.nodeValue) ? 1 : 2) });
  const range = document.createRange();
  for (let n; (n = walk.nextNode());) { const p = n.parentElement; if (!p || !vis(p) || p.closest("[hidden],svg")) continue; range.selectNodeContents(n); for (const r of range.getClientRects()) add(r); }
  for (const el of main.querySelectorAll("img,svg,canvas,iframe,video,input,select,textarea,button,hr")) { if (el.closest("[hidden]") || !vis(el)) continue; if (el.tagName === "svg" && el.parentElement.closest("svg")) continue; add(el.getBoundingClientRect()); }
  for (const el of main.querySelectorAll("*")) {
    if (el.closest("[hidden]")) continue;
    const cs = getComputedStyle(el); if (cs.display === "none" || cs.visibility === "hidden") continue;
    const r = el.getBoundingClientRect(); if (!r.width || !r.height) continue;
    // a sticky element (the docs and foundation chapter rails) is on screen over its whole container: count it there
    if (cs.position === "sticky" && el.parentElement) { const pr = el.parentElement.getBoundingClientRect(); add({ left: r.left, right: r.right, top: r.top, bottom: pr.bottom, width: r.width, height: pr.bottom - r.top }); }
    // a solid dark surface (a code panel) is a visible object, not emptiness; light cards still need content inside
    const bg = cs.backgroundColor.match(/\d+(\.\d+)?/g)?.map(Number);
    if (bg && (bg.length < 4 || bg[3] === 1) && (0.2126 * bg[0] + 0.7152 * bg[1] + 0.0722 * bg[2]) < 80) add(r);
    const side = (w, c) => parseFloat(w) > 0 && c !== "transparent" && !/rgba\(.*,\s*0\)$/.test(c);
    if (side(cs.borderTopWidth, cs.borderTopColor)) add({ left: r.left, right: r.right, top: r.top, bottom: r.top + 1, width: r.width, height: 1 });
    if (side(cs.borderBottomWidth, cs.borderBottomColor)) add({ left: r.left, right: r.right, top: r.bottom - 1, bottom: r.bottom, width: r.width, height: 1 });
    if (side(cs.borderLeftWidth, cs.borderLeftColor)) add({ left: r.left, right: r.left + 1, top: r.top, bottom: r.bottom, width: 1, height: r.height });
    if (side(cs.borderRightWidth, cs.borderRightColor)) add({ left: r.right - 1, right: r.right, top: r.top, bottom: r.bottom, width: 1, height: r.height });
  }
  for (const s of main.querySelectorAll(".section")) { const r = s.getBoundingClientRect(), pt = parseFloat(getComputedStyle(s).paddingTop) || 0; if (pt) gaps.push([r.top + sy, r.top + sy + pt]); }
  const secs = [...main.querySelectorAll("[id]")].map((e) => { const r = e.getBoundingClientRect(); return [e.id, r.top + sy, r.bottom + sy]; }).filter((x) => x[2] > x[1]);
  const mr = main.getBoundingClientRect();
  return { boxes: out, gaps, secs, top: mr.top + sy, bottom: mr.bottom + sy, width: document.documentElement.clientWidth, scrollW: document.documentElement.scrollWidth };
}

function analyse(d, w) {
  const [LW, LH] = LIMIT[w] || LIMIT[1440];
  const cols = Math.ceil(d.width / CELL), y0 = Math.floor(d.top / CELL), y1 = Math.ceil(d.bottom / CELL);
  const rowsAll = []; for (let r = y0; r < y1; r++) rowsAll.push(r);
  const inGap = (r) => d.gaps.some(([a, b]) => r * CELL >= a - 0.5 && (r + 1) * CELL <= b + 0.5);
  const rows = rowsAll.filter((r) => !inGap(r));
  const idx = new Map(rows.map((r, i) => [r, i]));
  const H = rows.length, W = cols, filled = new Uint8Array(H * W);
  for (const [l, t, r, b] of d.boxes) {
    const c0 = Math.max(0, Math.floor(l / CELL)), c1 = Math.min(W - 1, Math.floor((r - 0.01) / CELL));
    for (let rr = Math.floor(t / CELL); rr <= Math.floor((b - 0.01) / CELL); rr++) { const i = idx.get(rr); if (i === undefined) continue; for (let c = c0; c <= c1; c++) filled[i * W + c] = 1; }
  }
  const pre = new Int32Array((H + 1) * (W + 1));
  for (let i = 0; i < H; i++) for (let j = 0; j < W; j++) pre[(i + 1) * (W + 1) + j + 1] = filled[i * W + j] + pre[i * (W + 1) + j + 1] + pre[(i + 1) * (W + 1) + j] - pre[i * (W + 1) + j];
  const sum = (i, j, h, wd) => pre[(i + h) * (W + 1) + j + wd] - pre[i * (W + 1) + j + wd] - pre[(i + h) * (W + 1) + j] + pre[i * (W + 1) + j];
  const bw = Math.ceil(LW / CELL), bh = Math.ceil(LH / CELL), hits = [];
  for (let i = 0; i + bh <= H; i++) for (let j = 0; j + bw <= W; j++) {
    if (sum(i, j, bh, bw)) continue;
    let wd = bw; while (j + wd < W && !sum(i, j + wd, bh, 1)) wd++;
    let h = bh; while (i + h < H && !sum(i + h, j, 1, wd)) h++;
    const y = rows[i] * CELL, yb = (rows[i + h - 1] + 1) * CELL, x = j * CELL;
    const mid = (y + yb) / 2, sec = d.secs.filter((s) => s[1] <= mid && s[2] >= mid).sort((a, b) => (a[2] - a[1]) - (b[2] - b[1]))[0];
    hits.push({ x, y, w: Math.min(wd * CELL, d.width - x), h: yb - y, section: sec ? sec[0] : "(none)" });
    j += wd;
  }
  // one report per empty region (overlapping finds collapse into the first)
  const res = [];
  for (const h of hits) if (!res.some((r) => h.x < r.x + r.w && r.x < h.x + h.w && h.y < r.y + r.h && r.y < h.y + h.h)) res.push(h);
  return res;
}

const base = arg("--base", null);
const srv = base ? null : await serve();
const BASE = base || `http://127.0.0.1:${srv.address().port}`;
const { chromium } = await playwright();
const browser = await chromium.launch({ headless: true });
let fails = 0;
for (const w of WIDTHS) {
  const page = await browser.newPage({ viewport: { width: w, height: w > 600 ? 900 : 844 } });
  for (const p of PAGES) {
    await page.goto(`${BASE}/${p}.html`, { waitUntil: "networkidle" });
    await page.waitForTimeout(1200);
    // bring every lazy figure in (they draw only near the viewport), then measure from the top
    const h = await page.evaluate(() => document.documentElement.scrollHeight);
    for (let y = 0; y < h; y += 700) { await page.evaluate((y) => scrollTo(0, y), y); await page.waitForTimeout(60); }
    await page.waitForTimeout(800); await page.evaluate(() => scrollTo(0, 0)); await page.waitForTimeout(200);
    const d = await page.evaluate(collect);
    const hits = analyse(d, w);
    const side = d.scrollW > d.width ? ` · ✗ sideways scroll ${d.scrollW}px > ${d.width}px` : "";
    if (side) fails++;
    if (hits.length) { fails += hits.length; console.log(`  ✗ ${p}.html @${w}: ${hits.length} empty region(s)${side}`); for (const x of hits) console.log(`      ${x.w}×${x.h} at (${x.x}, ${x.y}) · nearest #${x.section}`); }
    else console.log(`  ✓ ${p}.html @${w}: no empty region ≥ ${LIMIT[w].join("×")}${side}`);
  }
  await page.close();
}
await browser.close(); srv?.close();
console.log(fails ? `\nDENSITY FAIL: ${fails} problem(s)` : `\nDENSITY OK: ${PAGES.length} pages × ${WIDTHS.join(" and ")} — no unstructured empty region, no sideways scroll.`);
process.exit(fails ? 1 : 0);
