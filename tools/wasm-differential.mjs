// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The browser verifier joins the differential as a VERIFIED SURFACE.
//
// "It runs in your browser" is otherwise a description of a demo. This makes it a claim the corpus can defend:
// every v1 conformance vector is pushed through the compiled WASM inside a real headless browser, and both the
// verdict AND the named reason must equal what ainra-core answered. A surface that agrees on 744 of 745 is not a
// verifier, so anything short of N/N fails.
//
// Deliberately: no test framework, no bundler, no third-party server. A static file server written here (~30 lines)
// serves the artifact over http, because ES modules and WebAssembly both refuse to load from file:// — the one
// non-obvious reason a naive "just open the page" harness reports a false pass.
import { createServer } from "node:http";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { extname, join } from "node:path";
import { createRequire } from "node:module";
import { statSync } from "node:fs";

const ROOT = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const WASM_DIR = join(ROOT, "site/assets/wasm");

if (!existsSync(join(WASM_DIR, "ainra_wasm_bg.wasm"))) {
  console.error("no browser verifier built. Run: make wasm");
  process.exit(1);
}

// The corpus, and the answer ainra-core gave for each. The generator self-checks every recorded `expect` against
// core, so `expect` IS core's verdict — the same baseline (A) and (F) hold the SDK and Python to.
const VEC_DIR = join(ROOT, "vectors/v1");
const vectors = readdirSync(VEC_DIR).filter((f) => f.endsWith(".json") && f !== "manifest.json").sort()
  .map((f) => JSON.parse(readFileSync(join(VEC_DIR, f), "utf8")));

// A differential that cannot report a mismatch proves nothing, so the negative control is a permanent, runnable
// property rather than something someone once checked by hand. With NEGATIVE_CONTROL=1 exactly one byte of one
// valid vector's issuer signature is flipped before it reaches the browser; the run MUST then fail. If it passes,
// the harness is broken and every green result it has ever printed is worthless.
const NEG = process.env.NEGATIVE_CONTROL === "1";
if (NEG) {
  const victim = vectors.find((v) => v.expect.verdict === "valid");
  if (!victim) { console.error("negative control: no valid vector in the corpus"); process.exit(1); }
  const b = Buffer.from(victim.presentation.issuer_sig.ed25519, "base64url");
  b[0] ^= 0x01;
  victim.presentation.issuer_sig.ed25519 = b.toString("base64url");
  console.log(`negative control: flipped one bit of ${victim.name}'s issuer signature — this run MUST fail`);
}

const MIME = { ".js": "text/javascript", ".wasm": "application/wasm", ".json": "application/json", ".html": "text/html" };
const PAGE = `<!doctype html><meta charset="utf-8"><title>wasm differential</title><script type="module">
import init, { run_vector, version } from "/site/assets/wasm/ainra_wasm.js";
window.__run = (async () => {
  await init();
  const vectors = await (await fetch("/__vectors")).json();
  const mismatches = [];
  for (const v of vectors) {
    const got = JSON.parse(run_vector(JSON.stringify(v)));
    const want = v.expect;
    const gotReason = got.verdict === "valid" ? null : got.reason;
    const wantReason = want.verdict === "valid" ? null : (want.reason ?? null);
    if (got.verdict !== want.verdict || gotReason !== wantReason) {
      mismatches.push({ name: v.name, want: want.verdict + (wantReason ? "/" + wantReason : ""),
                        got: got.verdict + (gotReason ? "/" + gotReason : "") });
    }
  }
  return { total: vectors.length, mismatches, version: version() };
})();
</script>`;

const server = createServer((req, res) => {
  if (req.url === "/") return res.writeHead(200, { "content-type": "text/html" }).end(PAGE);
  if (req.url === "/__vectors") return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(vectors));
  const p = join(ROOT, decodeURIComponent(req.url.split("?")[0]));
  if (!p.startsWith(ROOT) || !existsSync(p)) return res.writeHead(404).end("no");
  res.writeHead(200, { "content-type": MIME[extname(p)] ?? "application/octet-stream" }).end(readFileSync(p));
});

const require = createRequire(join(process.env.HOME, ".claude/skills/gstack/node_modules/x.js"));
const { chromium } = require("playwright-core");

// Resolve a browser WITHOUT hard-coding a vendor's binary path. Beyond neutrality (S7 rightly flags a product name
// baked into source), a pinned path is simply wrong on anyone else's machine — the driver's own default already
// points at a build that is not installed here. Order: an explicit override, the driver's guess if it exists, then
// a scan of the driver's download root.
function resolveBrowser() {
  const isExec = (p) => { try { return statSync(p).isFile(); } catch { return false; } };
  if (process.env.AINRA_BROWSER && isExec(process.env.AINRA_BROWSER)) return process.env.AINRA_BROWSER;
  try { const p = chromium.executablePath(); if (isExec(p)) return p; } catch { /* keep looking */ }
  const root = process.env.PLAYWRIGHT_BROWSERS_PATH || join(process.env.HOME, ".cache", "ms-playwright");
  let best = null;
  (function walk(d, depth) {
    if (depth > 3) return;
    let entries; try { entries = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p, depth + 1);
      else if (e.isFile()) {
        let st; try { st = statSync(p); } catch { continue; }
        // an executable of browser size — identified by shape, not by name
        if ((st.mode & 0o111) && st.size > 50_000_000 && (!best || st.size > best.size)) best = { p, size: st.size };
      }
    }
  })(root, 0);
  return best?.p ?? null;
}

const BROWSER = resolveBrowser();
if (process.argv.includes("--probe")) {
  if (!BROWSER) { console.error("no headless browser found. Set AINRA_BROWSER=/path/to/browser."); process.exit(1); }
  console.log(`browser: ${BROWSER}`);
  process.exit(0);
}
if (!BROWSER) {
  console.error("No headless browser found, so the browser surface cannot be checked.");
  console.error("Set AINRA_BROWSER=/path/to/a/headless/browser, or install one via the Playwright driver.");
  process.exit(1);
}

await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;

const browser = await chromium.launch({ executablePath: BROWSER, args: ["--no-sandbox", "--disable-gpu"] });
let out;
try {
  const page = await browser.newPage();
  const errs = [];
  page.on("pageerror", (e) => errs.push(String(e)));
  await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: "load" });
  out = await page.evaluate(() => window.__run);
  if (errs.length) throw new Error("page errors: " + errs.join(" | "));
} finally {
  await browser.close();
  server.close();
}

const pass = out.total - out.mismatches.length;
for (const m of out.mismatches.slice(0, 10)) console.error(`  WASM MISMATCH ${m.name}: core=${m.want} wasm=${m.got}`);
console.log(`(G) verdict diff core↔wasm : ${pass}/${out.total} agree  (headless browser, ainra-wasm v${out.version})`);
if (out.mismatches.length) {
  console.error(`WASM DIFFERENTIAL FAILED: ${out.mismatches.length} of ${out.total} disagree with ainra-core.`);
  process.exit(1);
}
if (NEG) {
  console.error("NEGATIVE CONTROL FAILED: a corrupted signature still agreed with core — the harness is not checking.");
  process.exit(1);
}
console.log("WASM DIFF OK: the browser surface agrees with ainra-core on every vector.");
