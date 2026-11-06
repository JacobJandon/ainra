// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make control-page-drill — does site/control.html show red for each lie, in a real browser? (PLAN-M52 step 3)
//
// The page is served unchanged, with /net/ answered from a planted contract instead of site/net/. The contracts are
// built from the signed epoch vectors (vectors/v1-directory-epoch: epochs 1, 2 and 3 under one pair of test roots),
// with the epoch index computed here from the SDK's own canonical bytes. Each case loads the page and reads its
// verdict; a case that shares a browser profile with an earlier one tests the page's memory.
//
// The claim is deliberately narrow: an HONEST page given substituted data shows the alarm. A replaced page can show
// anything, and the page says so; that defence is `ainra ctl` and a fingerprint compared out of band.
//
// WITNESS: the rollback case runs twice — after the honest case in the same profile (it must alarm), and in a fresh
// profile (the same old contract must pass). And the honest contract must show NO ALARM, so a page that always
// showed red would fail here too.
import { createServer } from "node:http";
import { readFileSync, existsSync, statSync, readdirSync } from "node:fs";
import { join, extname, dirname } from "node:path";
import { createRequire } from "node:module";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const SITE = join(ROOT, "site");
const sdk = await import(join(ROOT, "packages/sdk-ts/dist/index.js"));

function loadDriver() {
  const roots = [import.meta.url,
    ...(process.env.PLAYWRIGHT_DRIVER_PATH ? [`file://${process.env.PLAYWRIGHT_DRIVER_PATH}/x.js`] : []),
    `file://${join(process.env.HOME ?? "", ".claude/skills/gstack/node_modules/x.js")}`];
  for (const r of roots) { try { return createRequire(r)("playwright-core"); } catch { /* next */ } }
  return null;
}
function resolveBrowser(chromium) {
  const isExec = (p) => { try { return statSync(p).isFile(); } catch { return false; } };
  if (process.env.AINRA_BROWSER && isExec(process.env.AINRA_BROWSER)) return process.env.AINRA_BROWSER;
  try { const p = chromium.executablePath(); if (isExec(p)) return p; } catch { /* keep looking */ }
  const base = process.env.PLAYWRIGHT_BROWSERS_PATH || join(process.env.HOME ?? "", ".cache", "ms-playwright");
  // as tools/wasm-differential.mjs does: an executable of browser size, identified by shape, never by a product name
  let best = null;
  (function walk(d, depth) {
    if (depth > 4) return;
    let es; try { es = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of es) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p, depth + 1);
      else if (e.isFile()) {
        let st; try { st = statSync(p); } catch { continue; }
        if ((st.mode & 0o111) && st.size > 50_000_000 && (!best || st.size > best.size)) best = { p, size: st.size };
      }
    }
  })(base, 0);
  return best?.p ?? null;
}
const driver = loadDriver();
if (!driver) { console.error("playwright-core is not installed (npm i -D playwright-core, or set PLAYWRIGHT_DRIVER_PATH)"); process.exit(1); }
const exe = resolveBrowser(driver.chromium);
if (!exe) { console.error("no headless browser found (npx playwright install chromium --only-shell)"); process.exit(1); }

// ── the contracts ──────────────────────────────────────────────────────────────────────────────────────────────
const V = join(ROOT, "vectors/v1-directory-epoch");
const e01 = JSON.parse(readFileSync(join(V, "e01-newer-each-time.json"), "utf8"));
const roots = { root_ed25519: e01.root_ed25519, root_slh: e01.root_slh };
const [d1, d2, d3] = e01.directories;
const digest = (d) => createHash("sha256").update(sdk.canonicalize({ entries: d.entries, epoch: d.epoch, issued_at: d.issued_at, revoked_delegates: d.revoked_delegates ?? [] })).digest("hex");
// the epoch log head (D-097), computed here independently of the Rust that writes it: RFC 6962 over the epoch leaves
const H = (...parts) => createHash("sha256").update(Buffer.concat(parts.map((x) => Buffer.from(x)))).digest();
const mthOf = (l) => { if (l.length === 1) return l[0]; let k = 1; while (k * 2 < l.length) k *= 2; return H([1], mthOf(l.slice(0, k)), mthOf(l.slice(k))); };
const elogRoot = (dirs) => mthOf(dirs.map((d) => H([0], `ainra-directory/v1\n${d.epoch}\n${digest(d)}\n`))).toString("base64url");
const { publicKey: wPub, privateKey: wKey } = generateKeyPairSync("ed25519");
const cosig = (dirs) => { const root = elogRoot(dirs), n = dirs.length;
  return { origin: "ainra-directory", size: n, root, witness_key: wPub.export({ format: "jwk" }).x, sig: sign(null, Buffer.from(`ainra-directory\n${n}\n${root}\n`), wKey).toString("base64url") }; };
function contract(dirs, { rootsOverride, mutate, cosigned } = {}) {
  const files = new Map();
  const put = (p, v) => files.set(p, typeof v === "string" ? v : JSON.stringify(v));
  const current = dirs[dirs.length - 1];
  put("roots.json", rootsOverride ?? roots);
  put("directory.json", current);
  put("index.json", { network: "drill", root: "test-root" });
  put("epochs.json", { version: 1, epochs: dirs.map((d) => ({ epoch: d.epoch, digest: digest(d), issued_at: d.issued_at, path: `epochs/${d.epoch}.json` })) });
  for (const d of dirs) put(`epochs/${d.epoch}.json`, d);
  if (dirs.every((d, i) => d.epoch === i + 1)) put("epoch-log.json", { origin: "ainra-directory", size: dirs.length, root: elogRoot(dirs) });
  if (cosigned) put("epoch-log-cosignatures.json", { origin: "ainra-directory", cosignatures: [cosig(dirs)] });
  for (const e of current.entries) put(`registrars/${e.registrar}/export.json`, { status_seq: 5, records: [{ record: { checkpoint_size: 12, checkpoint_root: "rootB" }, verdict: { verdict: "valid" } }] });
  mutate?.(files);
  return files;
}
const edit = (p, f) => (files) => { const v = JSON.parse(files.get(p)); f(v); files.set(p, JSON.stringify(v)); };

let planted = new Map();
const types = { ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css", ".json": "application/json", ".woff2": "font/woff2", ".svg": "image/svg+xml", ".png": "image/png", ".wasm": "application/wasm" };
const server = createServer((req, res) => {
  const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (path.startsWith("/net/")) {
    const body = planted.get(path.slice(5));
    if (body === undefined) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" }); return res.end(body);
  }
  const file = join(SITE, path === "/" ? "index.html" : path);
  if (!file.startsWith(SITE) || !existsSync(file) || statSync(file).isDirectory()) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { "content-type": types[extname(file)] ?? "application/octet-stream" }); res.end(readFileSync(file));
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const url = `http://127.0.0.1:${server.address().port}/control.html`;

const browser = await driver.chromium.launch({ executablePath: exe, headless: true });
let failed = 0;
let QS = "";
async function look(ctx) {
  const page = await ctx.newPage();
  const errors = []; page.on("pageerror", (e) => errors.push(e.message));
  // a 404 for an optional file (fresh-head.json is not planted) is the browser reporting a fetch, not a page error
  page.on("console", (m) => { if (m.type() === "error" && !/Failed to load resource/.test(m.text())) errors.push(m.text()); });
  await page.goto(url + QS);
  try {
    await page.waitForFunction(() => !/CHECKING/.test(document.getElementById("verdict").textContent), null, { timeout: 30000 });
  } catch { errors.push("the page never finished checking"); }
  const verdict = await page.textContent("#verdict"), alarms = await page.textContent("#rows-alarms");
  await page.close();
  return { verdict, alarms, errors };
}
async function expect(label, ctx, files, want, text) {
  planted = files;
  const r = await look(ctx);
  const red = /ALARM/.test(r.verdict) && !/NO ALARM/.test(r.verdict);
  const ok = r.errors.length === 0 && (want === "green" ? /NO ALARM/.test(r.verdict) : red && (!text || new RegExp(text).test(r.alarms)));
  console.log(`  ${ok ? "ok  " : "✗   "} ${label}${ok ? "" : ` — verdict "${r.verdict.trim()}", alarms "${r.alarms.trim().slice(0, 200)}", errors ${JSON.stringify(r.errors)}`}`);
  if (!ok) failed++;
}

console.log("control-page-drill · site/control.html in a real browser, against planted copies of the record");
const profile = await browser.newContext();
const honest = contract([d1, d2, d3]);
// read at a fixed clock a day after the latest epoch (the vectors' issued_at is fixed); the page shows that it is fixed
QS = `?now=${d3.issued_at + 86400}`;
await expect("an honest contract shows NO ALARM", profile, honest, "green");
await expect("a directory whose bytes no longer match its signatures", await browser.newContext(), contract([d1, d2, d3], { mutate: edit("directory.json", (v) => { v.issued_at += 1; }) }), "red", "does not verify");
const otherRoots = { ...roots, root_slh: roots.root_slh.slice(0, -4) + "AAAA" };
await expect("roots swapped for other keys", await browser.newContext(), contract([d1, d2, d3], { rootsOverride: otherRoots }), "red", "does not verify");
await expect("an epoch index that lies about a digest", await browser.newContext(), contract([d1, d2, d3], { mutate: edit("epochs.json", (v) => { v.epochs[1].digest = "00".repeat(32); }) }), "red", "digest");
await expect("an epoch index that skips an epoch", await browser.newContext(), contract([d1, d3]), "red", "skips");
await expect("rollback to epoch 2, after epoch 3 was seen in this browser", profile, contract([d1, d2]), "red", "rollback");
await expect("WITNESS: the same old contract in a fresh browser passes", await browser.newContext(), contract([d1, d2]), "green");
await expect("the honest contract again: still no alarm", profile, honest, "green");
const reg = d3.entries[0].registrar;
await expect("an epoch log head the epochs do not make", await browser.newContext(), contract([d1, d2, d3], { mutate: edit("epoch-log.json", (v) => { v.root = "A".repeat(43); }) }), "red", "epoch-log.json says");
await expect("a witness cosignature over this history: still no alarm", await browser.newContext(), contract([d1, d2, d3], { cosigned: true }), "green");
await expect("a forged witness cosignature", await browser.newContext(), contract([d1, d2, d3], { cosigned: true, mutate: edit("epoch-log-cosignatures.json", (v) => { const s = v.cosignatures[0].sig; v.cosignatures[0].sig = (s[0] === "A" ? "B" : "A") + s.slice(1); }) }), "red", "cosignature");
await expect("a registrar's log shrinks, after a larger one was seen", profile, contract([d1, d2, d3], { mutate: edit(`registrars/${reg}/export.json`, (v) => { v.records = [{ record: { checkpoint_size: 9, checkpoint_root: "rootA" }, verdict: { verdict: "valid" } }]; }) }), "red", "shrank");

// WITNESS (D-094): the same honest contract, read 93 days after its latest epoch, is red — the published cadence alone
QS = `?now=${d3.issued_at + 93 * 86400}`;
const prod = contract([d1, d2, d3], { mutate: edit("index.json", (v) => { v.network = "production"; v.root = "production"; }) });
await expect("a production contract read 93 days after its epoch shows the stale directory", await browser.newContext(), prod, "red", "stale directory");
await expect("a TEST-ROOT copy read 93 days after its epoch: a labelled warning, not an alarm (ctl still alarms)", await browser.newContext(), honest, "green");
QS = `?now=${d3.issued_at + 86400}`;

await browser.close(); server.close();
if (failed) { console.error(`CONTROL-PAGE-DRILL FAILED — ${failed} case(s)`); process.exit(1); }
console.log("CONTROL-PAGE-DRILL OK — every planted lie showed red by name, the honest record showed none, and the memory is what caught the rollback");
