// SPDX-License-Identifier: Apache-2.0 OR MIT
// The motion budget (MOTION.md B2, E2.2–E2.4), measured in a real browser:
//   * CPU — the home page's one animation loop times every step+draw with performance.now(). Over 10 s at 1440×900
//     and at 390×844, dwelling 2 s on each of five living regions, the main-thread script per frame must average
//     ≤ 1.5 ms with p95 ≤ 4 ms. Run unthrottled and with Chromium's CPU throttled 4× (a mid laptop's headroom).
//   * Stillness — under prefers-reduced-motion: reduce, and separately with the Motion switch off, two viewport
//     screenshots 2 s apart (hero, Life band, FIG. 02) must be byte-identical: zero changed pixels.
//
//   node tools/motion-budget.mjs [--base http://127.0.0.1:PORT] [--throttle 4]
// Serves site/ itself when no --base is given. Needs playwright-core (see tools/density-check.mjs).
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
const THROTTLE = Number(arg("--throttle", "4"));
const AVG = 1.5, P95 = 4;

async function playwright() {
  try { return createRequire(join(ROOT, "package.json"))("playwright-core"); } catch { /* not installed here */ }
  for (const t of [process.env.PLAYWRIGHT_CORE, join(homedir(), ".claude/skills/gstack/node_modules/playwright-core")].filter(Boolean))
    if (existsSync(join(t, "index.mjs"))) return import(pathToFileURL(join(t, "index.mjs")).href);
  console.error("✗ motion-budget needs playwright-core"); process.exit(2);
}
const TYPES = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".mjs": "text/javascript", ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png", ".woff2": "font/woff2", ".wasm": "application/wasm" };
const serve = () => new Promise((ok) => {
  const srv = createServer(async (req, res) => {
    let p = decodeURIComponent(new URL(req.url, "http://x").pathname); if (p.endsWith("/")) p += "index.html";
    const f = normalize(join(SITE, p)); if (!f.startsWith(SITE)) { res.writeHead(403).end(); return; }
    try { if (!(await stat(f)).isFile()) throw 0; res.writeHead(200, { "content-type": TYPES[extname(f)] || "application/octet-stream" }); res.end(await readFile(f)); }
    catch { res.writeHead(404).end(); }
  });
  srv.listen(0, "127.0.0.1", () => ok(srv));
});

const REGIONS = ["#hero", '.life[data-name="band"]', "[data-chain]", "[data-status-grid]", '.life[data-name="ribbon-1"]'];
const base = arg("--base", null), srv = base ? null : await serve();
const BASE = base || `http://127.0.0.1:${srv.address().port}`;
const { chromium } = await playwright();
const browser = await chromium.launch({ headless: true });
let fail = 0;
const results = [];

for (const [w, h] of [[1440, 900], [390, 844]]) for (const rate of [1, THROTTLE]) {
  const ctx = await browser.newContext({ viewport: { width: w, height: h } });
  const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  await page.goto(`${BASE}/index.html`, { waitUntil: "networkidle" });
  await page.waitForTimeout(800);
  if (rate > 1) await cdp.send("Emulation.setCPUThrottlingRate", { rate });
  await page.evaluate(() => window.ainraMotion.reset());
  for (const sel of REGIONS) {
    await page.evaluate((s) => { const e = document.querySelector(s); if (e) scrollTo(0, e.getBoundingClientRect().top + scrollY - 80); }, sel);
    await page.waitForTimeout(2000);
  }
  const s = await page.evaluate(() => window.ainraMotion.stats());
  if (rate > 1) await cdp.send("Emulation.setCPUThrottlingRate", { rate: 1 });
  const ok = s.avg_ms <= AVG && s.p95_ms <= P95;
  if (!ok) fail++;
  results.push({ w, rate, ...s });
  console.log(`  ${ok ? "✓" : "✗"} ${w}px · CPU ${rate}× · ${s.frames} frames · avg ${s.avg_ms} ms · p95 ${s.p95_ms} ms · max ${s.max_ms} ms`);
  for (const [k, v] of Object.entries(s.elements)) console.log(`      ${k.padEnd(14)} ${String(v.steps).padStart(5)} steps · mean ${v.mean_ms} ms · max ${v.max_ms} ms`);
  await ctx.close();
}

// WITNESS (negative control, built in): the same screenshot pair taken with motion ON must differ — the globe turns
// and the band steps — or this stillness test cannot see motion at all, and it fails rather than pass blind.
{
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: "no-preference" });
  const page = await ctx.newPage();
  await page.goto(`${BASE}/index.html`, { waitUntil: "networkidle" }); await page.waitForTimeout(1200);
  const a = await page.screenshot(); await page.waitForTimeout(2000); const b = await page.screenshot();
  const moved = Buffer.compare(a, b) !== 0;
  if (!moved) fail++;
  console.log(`  ${moved ? "✓" : "✗"} control · motion on · 1440px · #hero: ${moved ? "the frame changed in 2 s, so the test can see motion" : "NO change with motion on — the stillness test is blind"}`);
  await ctx.close();
}
// stillness: reduced motion, and Motion off
for (const mode of ["reduced-motion", "motion-off"]) for (const [w, h] of [[1440, 900], [390, 844]]) {
  const ctx = await browser.newContext({ viewport: { width: w, height: h }, reducedMotion: mode === "reduced-motion" ? "reduce" : "no-preference" });
  const page = await ctx.newPage();
  await page.goto(`${BASE}/index.html`, { waitUntil: "networkidle" });
  if (mode === "motion-off") await page.evaluate(() => window.ainraMotion.set("off"));
  await page.waitForTimeout(1200);
  for (const sel of ["#hero", '.life[data-name="band"]', "[data-chain]"]) {
    await page.evaluate((s) => { const e = document.querySelector(s); if (e) scrollTo(0, e.getBoundingClientRect().top + scrollY - 80); }, sel);
    await page.waitForTimeout(900);
    const a = await page.screenshot(); await page.waitForTimeout(2000); const b = await page.screenshot();
    const same = Buffer.compare(a, b) === 0;
    if (!same) fail++;
    console.log(`  ${same ? "✓" : "✗"} ${mode} · ${w}px · ${sel}: ${same ? "0 changed pixels in 2 s" : "the frame CHANGED in 2 s"}`);
  }
  await ctx.close();
}
await browser.close(); srv?.close();
console.log(fail ? `\nMOTION-BUDGET FAIL: ${fail} problem(s)` : `\nMOTION-BUDGET OK: every run within avg ≤ ${AVG} ms and p95 ≤ ${P95} ms per frame; reduced motion and Motion off are perfectly still.`);
process.exit(fail ? 1 : 0);
