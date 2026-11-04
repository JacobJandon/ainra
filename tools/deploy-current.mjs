// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make deploy-current — is what production SERVES the same as what this repo BUILDS?
//
// WHY THIS EXISTS, and it is a mistake of mine rather than a hypothetical. `make claims-live` verifies that the
// tracked CLAIMS match production, and it passed green while the deployment was two milestones stale — because
// M30's site edits (llms.txt gaining a section, verify.html gaining a sentence) did not happen to touch any
// tracked claim. I then reported the site as "deployed and verified live" on the strength of a gate that was
// answering a different question.
//
// Claim parity and deploy currency are different properties. This checks the second: every built page's bytes,
// compared against what the host actually returns.
//
// Ignorable differences are named explicitly rather than hand-waved: the deploy pipeline drops build-internal
// files, and a host may re-serve HTML with different whitespace or injected analytics (we have none, but the
// comparison should fail loudly if that ever changes rather than silently tolerate it).
//
//   node tools/deploy-current.mjs [--base URL]   compare production (default https://ainra.org) with site/
//   node tools/deploy-current.mjs --negative     offline: the comparison must refuse every planted stale deploy
//
// WITNESS: `--negative` never touches the network. It writes a small planted build under os.tmpdir() (three pages,
// plus README.md, DEPLOY.md, _includes/ and an image that the export pipeline does not publish) and runs the same
// compare() the real check uses against an in-memory "production" built from those bytes, with one defect each:
// one byte flipped at the same length (a stale page the size check alone would miss), an analytics snippet
// injected, a trailing newline stripped (whitespace re-flow), a page missing (HTTP 404), and the host unreachable
// (fetch throws). Every one must be refused. A control the other way, production byte-identical to the build with
// the unpublished files absent there, must pass, so a compare() that refuses everything, or that starts fetching
// files the pipeline never publishes, fails the witness too. A real stale deploy looks like one of these plants.

import { readFileSync, readdirSync, statSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SITE = join(ROOT, "site");
const argBase = process.argv.indexOf("--base");
const BASE = (argBase >= 0 ? process.argv[argBase + 1] : "https://ainra.org").replace(/\/+$/, "");

// The export pipeline (tools/export-site.sh) excludes these from the published tree.
const NOT_PUBLISHED = new Set(["_includes", "DEPLOY.md", "README.md"]);
const sha = (b) => createHash("sha256").update(b).digest("hex").slice(0, 16);

const listPages = (site) => readdirSync(site)
  .filter((f) => !NOT_PUBLISHED.has(f))
  .filter((f) => /\.(html|txt|md|json)$/.test(f))
  .filter((f) => { try { return statSync(join(site, f)).isFile(); } catch { return false; } })
  .sort();

// One comparison for production and for every plant: `get` is the fetch, `out`/`err` are where lines go.
async function compare(base, site, pages, get, out, err) {
  let bad = 0, checked = 0;
  for (const f of pages) {
    const local = readFileSync(join(site, f));
    let res;
    try { res = await get(`${base}/${f}`, { redirect: "follow" }); }
    catch (e) { err(`  ✗ ${f} — fetch failed: ${e.message}`); bad = 1; continue; }
    if (!res.ok) { err(`  ✗ ${f} — HTTP ${res.status}`); bad = 1; continue; }
    const served = Buffer.from(await res.arrayBuffer());
    checked++;
    if (sha(served) !== sha(local)) {
      err(`  ✗ ${f} — SERVED bytes differ from the built page (local ${sha(local)} vs served ${sha(served)}, ${local.length} vs ${served.length} bytes)`);
      bad = 1;
    } else {
      out(`  ok    ${f.padEnd(22)} ${sha(local)}`);
    }
  }
  return { bad, checked };
}

if (process.argv.includes("--negative")) {
  const dir = mkdtempSync(join(tmpdir(), "deploy-current-negative-"));
  try {
    const BUILT = {
      "index.html": "<!doctype html>\n<title>planted</title>\n<p>the built page</p>\n",
      "llms.txt": "# planted\n\nA line production must serve byte for byte.\n",
      "verify.md": "# verify\n\nOne more planted page.\n",
    };
    for (const [f, t] of Object.entries(BUILT)) writeFileSync(join(dir, f), t);
    for (const f of ["README.md", "DEPLOY.md"]) writeFileSync(join(dir, f), "not published\n");
    mkdirSync(join(dir, "_includes")); writeFileSync(join(dir, "_includes", "nav.html"), "<nav></nav>\n");
    writeFileSync(join(dir, "og-cover.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47]));
    const pages = listPages(dir);
    const B = "https://production.invalid";
    // "Production" is a map from URL to bytes; anything absent is a 404, exactly as a host answers it.
    const host = (served) => async (url) => {
      if (served === "unreachable") throw new Error("getaddrinfo ENOTFOUND production.invalid");
      const f = url.slice(B.length + 1);
      return f in served ? new Response(served[f], { status: 200 }) : new Response("not found", { status: 404 });
    };
    const flip = (t) => { const b = Buffer.from(t); b[b.length - 2] ^= 0x01; return b; };
    const PLANTS = [
      ["one byte flipped, same length", { ...BUILT, "index.html": flip(BUILT["index.html"]) }],
      ["an analytics snippet injected", { ...BUILT, "index.html": BUILT["index.html"] + "<script src=/a.js></script>\n" }],
      ["a trailing newline stripped", { ...BUILT, "llms.txt": BUILT["llms.txt"].trimEnd() }],
      ["a page missing (HTTP 404)", (({ "verify.md": _, ...rest }) => rest)(BUILT)],
      ["the host unreachable", "unreachable"],
    ];
    const quiet = () => {};
    let missed = 0;
    console.log(`deploy-current negative control: ${PLANTS.length} planted stale deploys of a ${pages.length}-page build, offline`);
    if (pages.join(",") !== "index.html,llms.txt,verify.md") {
      console.error(`  ✗ page discovery picked ${pages.join(", ")} — it must skip what the export pipeline does not publish`); missed++;
    }
    for (const [what, served] of PLANTS) {
      const lines = [];
      const r = await compare(B, dir, pages, host(served), quiet, (l) => lines.push(l));
      if (r.bad) console.log(`  ok caught ${what}:${lines[0].replace(/^\s*✗/, "")}`);
      else { console.error(`  ✗ MISSED ${what}: all ${r.checked} page(s) judged byte-identical`); missed++; }
    }
    const control = await compare(B, dir, pages, host(BUILT), quiet, quiet);
    if (control.bad || control.checked !== pages.length) { console.error(`  ✗ the byte-identical control was refused: compare() refuses a current deploy`); missed++; }
    else console.log(`  ok passed the byte-identical control (${control.checked} page(s); unpublished files never fetched)`);
    if (missed) { console.error(`DEPLOY-CURRENT NEGATIVE FAILED — ${missed} planted case(s) judged wrongly`); process.exitCode = 1; }
    else console.log(`DEPLOY-CURRENT NEGATIVE OK — all ${PLANTS.length} planted stale deploys refused, the current deploy passed`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
  process.exit(process.exitCode ?? 0);
}

const pages = listPages(SITE);
console.log(`deploy-current · ${BASE} · ${pages.length} built page(s)`);
const { bad, checked } = await compare(BASE, SITE, pages, fetch, console.log, console.error);

if (bad) {
  console.error(`\nDEPLOY-CURRENT FAILED — production is not serving what this repo builds.`);
  console.error(`Run \`make site && bash tools/export-site.sh\`, wait for the host, then re-run.`);
  console.error(`A green claims-live does NOT imply this: it checks the tracked claims, not every byte.`);
  process.exit(1);
}
console.log(`DEPLOY-CURRENT OK: all ${checked} published page(s) byte-identical to the build.`);
