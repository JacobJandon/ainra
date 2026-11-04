// SPDX-License-Identifier: Apache-2.0 OR MIT
// S7 neutrality linter (MTS §28: "CI greps fixtures for real names"). Scans authored code + conformance fixtures
// for real company/product names used as placeholder data. Exit nonzero on any hit. Registrars are registrar-NN;
// operators are acme / globex / operator-NN.
//
// WITNESS: `--negative` checks the matchers in memory, then copies this file and its two denylists into a temporary
// root under os.tmpdir() (never the tree), plants defects there, makes a throwaway git repo, and runs the copy as a
// child process — the real entry point, so every walk, filter, count and exit code is the one the real run uses.
// Planted: a denied name in one file of every kind (extension) each scanned directory really holds, and in every
// directory, single file and manifest a registry ships (read from each packages/*/package.json "files", dist/ counting
// as its src/, and the sdk-py pyproject); a foil brand in every prose directory, every prose kind under docs/, every
// front-door file, every shipped README, and the commit message. The run must report each plant exactly once, print
// those totals, and exit 1; a root with only a fixture hit, only a prose hit, or only a branded commit must each exit
// 1; and a clean root holding the allowed constructs (a `.member` access, the allowlisted HTML tag, a citation
// inventory, a brand in a gitignored local draft) must exit 0. A shipped kind the fixture pass skips must be named in
// NOT_SCANNED with a reason (today: the built .wasm binary), or it goes red.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import os from "node:os";
import { execSync, execFileSync, spawnSync } from "node:child_process";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const DENY = fs
  .readFileSync(path.join(ROOT, "tools/s7-denylist.txt"), "utf8")
  .split("\n")
  .map((l) => l.trim())
  .filter((l) => l && !l.startsWith("#"));

// Directories of AUTHORED code + fixtures to scan. The landscape/spec docs are intentionally excluded (they cite
// real standards bodies + prior art as technical reference, which is analysis, not placeholder impersonation).
const SCAN_DIRS = [
  "crates",
  "packages/sdk-ts/src",
  "packages/sdk-py/ainra",
  "packages/sdk-py/tests",
  "tools",
  "vectors",
  // What ships to npm (each package.json "files"): the middleware and SDK publish dist/, built from src/ (scanned
  // here and above); @ainra/mcp publishes src/; @ainra/edge publishes src/ and wasm/ (the built bundle, gitignored,
  // scanned when present). PyPI ships packages/sdk-py/ainra (above). The READMEs every registry shows are prose,
  // so they go through the brand pass below, not this one.
  "packages/middleware/src",
  "packages/mcp/src",
  "packages/edge/src",
  "packages/edge/wasm",
];
// Package manifests ship too (name, description, keywords are what a registry page displays).
const SCAN_FILES = [
  "packages/sdk-ts/package.json",
  "packages/middleware/package.json",
  "packages/mcp/package.json",
  "packages/edge/package.json",
  "packages/sdk-py/pyproject.toml",
];
const SCAN_EXT = new Set([".rs", ".ts", ".mjs", ".js", ".py", ".json", ".toml", ".sh", ".txt"]);
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
// Narrow, documented allowlist: a denied token that is unmistakably a technical construct, not placeholder DATA
// impersonating a product. Only `<meta …>` (the HTML tag) so far — a tool that renders HTML (e.g. the genesis board)
// is not impersonating the company "Meta". Keep this list tiny and specific; never allow a bare brand word.
const FIXTURE_ALLOW = [
  { name: "meta", re: /<meta[\s/>]/i },
  // `kits/verifier/sample-artifacts/meta.json` is a committed fixture. Naming a file that exists in this
  // repository is a technical reference, not a product impersonating a company — the same reasoning as the HTML
  // tag above. Requires the `.json` extension so a bare brand word is still refused.
  { name: "meta", re: /meta\.json/ },
];
// One file's code/fixture hits, as the lines the gate prints. The real scan and `--negative` both call this.
function fixtureHits(label, text) {
  const out = [];
  text.split("\n").forEach((line, i) => {
    for (const p of patterns) {
      if (!p.re.test(line)) continue;
      if (FIXTURE_ALLOW.some((a) => a.name === p.name && a.re.test(line))) continue;
      out.push(`  S7 HIT ${label}:${i + 1}  "${p.name}"  ${line.trim().slice(0, 80)}`);
    }
  });
  return out;
}
function* fixtureFiles(root) {
  for (const dir of SCAN_DIRS) yield* walk(path.join(root, dir));
  for (const f of SCAN_FILES) { const full = path.join(root, f); if (fs.existsSync(full)) yield full; }
}
let hits = 0;
function passFixtures() {
  for (const file of fixtureFiles(ROOT)) {
    if (SELF.has(file)) continue;
    for (const h of fixtureHits(path.relative(ROOT, file), fs.readFileSync(file, "utf8"))) { hits++; console.error(h); }
  }
  if (hits) console.error(`\nS7 (fixtures) FAILED: ${hits} real-name occurrence(s) in code/fixtures`);
  else console.log(`S7 OK (fixtures): ${DENY.length} denied names, none present in ${SCAN_DIRS.join(", ")}`);
}

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
// ── Citation inventories: the ONE narrow, documented exemption ───────────────────────────────────────────────
// S7 exists so we never use a real company's name as marketing, as a foil, or as impersonated fixture data. A
// CITATION INVENTORY is the opposite act: its whole purpose is to name third parties accurately and link to the
// primary source for each, so a reader can check us. THIRD-PARTY.md has always been exempt for exactly this reason
// (it inventories every dependency by name); it was exempt only by living outside the scanned tree, which is a
// weak kind of exemption. This makes the rule explicit instead.
//
// The bar for adding a file here is high and deliberately awkward: the file must (a) exist to cite third parties,
// (b) carry a source link for every named party, and (c) make no comparative or promotional claim about them.
// Marketing prose does not qualify, and never will. Keep this list at two entries unless there is a real reason.
const CITATION_INVENTORIES = new Set(["THIRD-PARTY.md", "docs/LANDSCAPE.md"]);

const PROSE_DIRS = ["docs", "kits", "outreach", "campaign", ".github", "site"];
const PROSE_EXT = new Set([".md", ".txt", ".yml", ".yaml", ".html"]);
const PROSE_FILES = ["README.md", "CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md", "GENESIS-CHECKLIST.md",
  // The README each registry renders on the package page (npm ships it whatever "files" says; PyPI via `readme`).
  "packages/sdk-ts/README.md", "packages/middleware/README.md", "packages/mcp/README.md", "packages/edge/README.md",
  "packages/sdk-py/README.md"];
let brandHits = 0;
function proseHits(label, text) {
  const out = [];
  if (CITATION_INVENTORIES.has(label)) return out;   // see the note above — citing a source is not branding
  text.split("\n").forEach((line, i) => {
    for (const p of brandPat) {
      if (!p.re.test(line)) continue;
      if (PROSE_ALLOW.some((a) => a.name === p.name && line.includes(a.ctx))) continue;
      out.push(`  S7-BRAND HIT ${label}:${i + 1}  "${p.name}"  ${line.trim().slice(0, 80)}`);
    }
  });
  return out;
}
function scanProse(label, text) {
  for (const h of proseHits(label, text)) { brandHits++; console.error(h); }
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
// S7 is about what this project PUBLISHES. The prose walk reads the filesystem, not the git index, so it also
// sees working files that are gitignored by design — campaign/sendbox/ (personalised drafts) and campaign/notes/
// (per-person notes). Those contain real people and their real employers, deliberately, and they never reach a
// reader outside this machine. It fired on exactly that: a draft addressed to a person whose employer is on the
// foil list. Failing the board for the contents of a local draft would train the operator to run S7 with a
// mental asterisk, which is how a neutrality gate stops meaning anything.
//
// So: gitignored paths are skipped, and only for the PROSE pass. The fixture pass, the commit-message pass, and
// every tracked file are untouched — a brand in anything that ships still fails exactly as before.
function passBrand() {
  const ignored = (() => {
    try {
      const all = PROSE_DIRS.flatMap((d) => [...walkProse(path.join(ROOT, d))]).map((f) => path.relative(ROOT, f));
      if (!all.length) return new Set();
      const out = execSync("git check-ignore --stdin || true", { cwd: ROOT, input: all.join("\n"), encoding: "utf8" });
      return new Set(out.split("\n").map((l) => l.trim()).filter(Boolean));
    } catch { return new Set(); }
  })();
  for (const dir of PROSE_DIRS) for (const f of walkProse(path.join(ROOT, dir))) {
    const rel = path.relative(ROOT, f);
    if (ignored.has(rel)) continue;
    scanProse(rel, fs.readFileSync(f, "utf8"));
  }
  for (const f of PROSE_FILES) { const full = path.join(ROOT, f); if (fs.existsSync(full)) scanProse(f, fs.readFileSync(full, "utf8")); }
  try {
    scanProse("<commit-messages>", execSync("git log --format=%B", { cwd: ROOT, encoding: "utf8" }));
  } catch { /* not a git checkout (e.g. tarball) — skip commit-message scan */ }

  if (brandHits) console.error(`\nS7 (brand) FAILED: ${brandHits} commercial-brand occurrence(s) in prose/commit messages`);
  else console.log(`S7 OK (brand): ${BRAND.length} foil brands, none present in ${PROSE_DIRS.join("/")}/front-door/commit-messages`);
}

// ── --negative: the WITNESS at the top of this file ──────────────────────────────────────────────────────────────
// What the registries actually ship, read from the manifests rather than from SCAN_DIRS, so the two can disagree.
// A "files" entry with an extension is a single file (wasm/ainra_wasm.js); one without is a directory (src/).
function published() {
  const dirs = new Set(), files = new Set(), manifests = new Set(), readmes = new Set();
  for (const pkg of fs.readdirSync(path.join(ROOT, "packages"))) {
    const base = `packages/${pkg}`;
    const npm = path.join(ROOT, base, "package.json");
    if (fs.existsSync(npm)) {
      manifests.add(`${base}/package.json`);
      readmes.add(`${base}/README.md`);   // npm always ships the README
      for (const f of JSON.parse(fs.readFileSync(npm, "utf8")).files ?? []) {
        const name = f.replace(/\/$/, "");
        if (name.endsWith(".md")) readmes.add(`${base}/${name}`);
        else if (path.extname(name)) files.add(`${base}/${name}`);
        else dirs.add(`${base}/${name === "dist" ? "src" : name}`);   // dist/ is built from src/
      }
    }
    const py = path.join(ROOT, base, "pyproject.toml");
    if (fs.existsSync(py)) {
      const toml = fs.readFileSync(py, "utf8");
      manifests.add(`${base}/pyproject.toml`);
      const readme = toml.match(/^readme\s*=\s*"([^"]+)"/m);
      if (readme) readmes.add(`${base}/${readme[1]}`);
      for (const m of (toml.match(/^packages\s*=\s*\[([^\]]*)\]/m)?.[1] ?? "").matchAll(/"([^"]+)"/g)) dirs.add(`${base}/${m[1]}`);
    }
  }
  return { dirs, files, manifests, readmes };
}
// File kinds found in a scanned directory that the fixture pass deliberately does not read. Every other kind found
// there gets a planted file, so dropping an extension from SCAN_EXT goes red. Add here only with a reason.
const NOT_SCANNED = new Map([
  [".md", "prose; the fixture list's common words would trip on English, and shipped READMEs get the brand pass"],
  ["", "no extension (the vectors LICENSE text)"],
  [".pyc", "bytecode compiled from the scanned .py, gitignored"],
  [".wasm", "binary built from the scanned crates"],
]);
// The extensions of the files in one real directory: tracked files when this is a git checkout, else the disk.
function kinds(dir) {
  let names;
  try {
    names = execFileSync("git", ["ls-files", "-z", "--", dir], { cwd: ROOT, encoding: "utf8" }).split("\0").filter(Boolean);
  } catch {
    names = [];
    const all = function* (d) {
      if (!fs.existsSync(d)) return;
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        if (SKIP.has(e.name)) continue;
        if (e.isDirectory()) yield* all(path.join(d, e.name)); else yield e.name;
      }
    };
    names = [...all(path.join(ROOT, dir))];
  }
  return new Set(names.map((n) => path.extname(n)));
}
// The prose places the brand pass must read. Written out again on purpose, not read from PROSE_DIRS / PROSE_EXT:
// if one is dropped there, this still plants into it and the run goes red.
const PROSE_MUST_DIRS = ["docs", "kits", "outreach", "campaign", ".github", "site"];
const PROSE_MUST_EXT = [".md", ".txt", ".yml", ".yaml", ".html"];

// Run THIS file, unmodified, as a child process over a planted temporary root. It is copied to <tmp>/tools/ with
// the two denylists, so its ROOT is the temp root, and every walk, filter, count and exit code is the real one.
// Git config is isolated so a global hook, signing key or excludes file cannot change the result.
const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: os.devNull, GIT_CONFIG_NOSYSTEM: "1" };
function plantedRun(files, commitMsg) {
  const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "s7-negative-")));
  const put = (rel, text) => { fs.mkdirSync(path.dirname(path.join(tmp, rel)), { recursive: true }); fs.writeFileSync(path.join(tmp, rel), text); };
  try {
    put("tools/s7-lint.mjs", fs.readFileSync(fileURLToPath(import.meta.url), "utf8"));
    for (const f of ["tools/s7-denylist.txt", "tools/s7-brand-denylist.txt"]) put(f, fs.readFileSync(path.join(ROOT, f), "utf8"));
    for (const [rel, text] of Object.entries(files)) put(rel, text);
    const git = (...a) => execFileSync("git", a, { cwd: tmp, env: GIT_ENV, stdio: "pipe" });
    git("init", "-q");
    git("-c", "user.name=s7-negative", "-c", "user.email=s7@example.invalid", "-c", "commit.gpgsign=false",
      "commit", "-q", "--allow-empty", "--no-verify", "-m", commitMsg);
    const r = spawnSync(process.execPath, [path.join(tmp, "tools/s7-lint.mjs")], { cwd: tmp, env: GIT_ENV, encoding: "utf8", timeout: 60_000 });
    const fixture = [...r.stderr.matchAll(/^ {2}S7 HIT (\S+):\d+ /gm)].map((m) => m[1]);
    const brand = [...r.stderr.matchAll(/^ {2}S7-BRAND HIT (\S+):\d+ /gm)].map((m) => m[1]);
    return { status: r.status, out: r.stdout, err: r.stderr, fixture, brand };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

// Tokens come from the denylists and the allowlist themselves, so no real name is ever written into this file.
function negative() {
  let bad = 0;
  const expect = (want, what, got) => {
    const ok = want ? got.length > 0 : got.length === 0;
    console.log(`  ${ok ? (want ? "ok  caught " : "ok  allowed") : (want ? "✗   MISSED " : "✗   FLAGGED")} ${what}`);
    if (!ok) bad++;
  };
  const check = (ok, what) => expect(true, what, ok ? [what] : []);
  const deny = DENY.find((n) => !FIXTURE_ALLOW.some((a) => a.name === n)) ?? DENY[0];
  const brand = BRAND[0];
  const tag = FIXTURE_ALLOW.find((a) => DENY.includes(a.name) && a.re.test(`<${a.name} charset="utf-8">`));
  const planted = `{ "operator": "${deny}" }\n`;
  // 1. the matchers, in memory
  expect(true, "fixture: denied name as a quoted placeholder value", fixtureHits("vectors/plant.json", planted));
  expect(true, "fixture: denied name as a bare word in code, upper-cased",
    fixtureHits("crates/plant.rs", `let issuer = ${deny.toUpperCase()}; // placeholder`));
  expect(false, "fixture: the same token after a `.` (a member access, not data)",
    fixtureHits("crates/plant.rs", `let w = xs.${deny}(2);`));
  if (tag) expect(false, `fixture: \`<${tag.name} charset>\` (an HTML tag, allowlisted)`,
    fixtureHits("tools/plant.mjs", `const head = '<${tag.name} charset="utf-8">';`));
  expect(true, "prose: foil brand in a doc line", proseHits("docs/PLANT.md", `Unlike ${brand}, AINRA keeps revocation.`));
  expect(true, "prose: foil brand in a commit message", proseHits("<commit-messages>", `fix: match ${brand} behaviour\n`));
  expect(false, "prose: foil brand in a citation inventory (exempt by rule)",
    proseHits("THIRD-PARTY.md", `${brand} — https://example.org/source`));

  // 2. the real entry point over a planted root. Fixture plants: one file of every kind each scanned or shipped
  // directory really holds, each single file a package.json "files" names, and every manifest.
  const pub = published();
  const dirs = [...new Set([...SCAN_DIRS, ...pub.dirs])];
  const fixturePlants = new Set();
  for (const d of dirs) {
    const exts = [...kinds(d)].filter((e) => !NOT_SCANNED.has(e));
    for (const e of exts.length ? exts : [".mjs"]) fixturePlants.add(`${d}/plant${e}`);   // absent dir: still walked
  }
  for (const f of pub.files) {
    if (NOT_SCANNED.has(path.extname(f))) console.log(`  ok  exempt  shipped ${f} (${NOT_SCANNED.get(path.extname(f))})`);
    else fixturePlants.add(f);
  }
  for (const m of pub.manifests) fixturePlants.add(m);
  // Prose plants: every prose dir (and every prose kind under docs/), every front-door file and every shipped README.
  const prosePlants = new Set([...PROSE_MUST_DIRS.map((d) => `${d}/plant.md`), ...PROSE_MUST_EXT.map((e) => `docs/plant${e}`),
    ...PROSE_FILES, ...pub.readmes]);
  const files = {};
  for (const rel of fixturePlants) files[rel] = planted;
  for (const rel of prosePlants) files[rel] = `Works the way ${brand} does.\n`;
  let run;
  try { run = plantedRun(files, `fix: match ${brand} behaviour`); }
  catch (e) { console.error(`  ✗   could not build the planted root (git is required): ${e.message.split("\n")[0]}`); process.exit(1); }
  for (const rel of [...fixturePlants].sort()) expect(true, `walk: planted ${rel}`, run.fixture.includes(rel) ? [rel] : []);
  for (const rel of [...prosePlants].sort()) expect(true, `prose: planted ${rel}`, run.brand.includes(rel) ? [rel] : []);
  expect(true, "prose: planted brand in the temp root's only commit message", run.brand.includes("<commit-messages>") ? [1] : []);
  // Exact counts: one hit per plant, nothing from the copied gate or its denylists (the SELF skip), and the totals
  // the run prints must be the ones it counted.
  check(run.fixture.length === fixturePlants.size, `run: ${fixturePlants.size} fixture hits, got ${run.fixture.length}`);
  check(run.brand.length === prosePlants.size + 1, `run: ${prosePlants.size + 1} brand hits, got ${run.brand.length}`);
  check(run.err.includes(`S7 (fixtures) FAILED: ${fixturePlants.size} `), "run: fixtures summary reports the count");
  check(run.err.includes(`S7 (brand) FAILED: ${prosePlants.size + 1} `), "run: brand summary reports the count");
  check(run.status === 1, `run: exits 1 on a planted root (got ${run.status})`);

  // 3. each pass alone must fail the run, and a clean root holding only the allowed constructs must pass it:
  // the allowlisted tag and member access, a citation inventory, and a brand in a gitignored local draft.
  const fixtureOnly = plantedRun({ "vectors/plant.json": planted }, "chore: s7 control");
  check(fixtureOnly.status === 1 && fixtureOnly.fixture.length === 1, `run: one fixture hit alone exits 1 (got ${fixtureOnly.status})`);
  const brandOnly = plantedRun({ "docs/PLANT.md": `Unlike ${brand}, AINRA keeps revocation.\n` }, "chore: s7 control");
  check(brandOnly.status === 1 && brandOnly.brand.length === 1, `run: one brand hit alone exits 1 (got ${brandOnly.status})`);
  const commitOnly = plantedRun({}, `fix: match ${brand} behaviour`);
  check(commitOnly.status === 1 && commitOnly.brand.length === 1, `run: a brand in history alone exits 1 (got ${commitOnly.status})`);
  const clean = plantedRun({
    "tools/allowed.mjs": `let w = xs.${deny}(2);\n${tag ? `const head = '<${tag.name} charset="utf-8">';\n` : ""}`,
    "docs/LANDSCAPE.md": `${brand} — https://example.org/source\n`,
    ".gitignore": "campaign/sendbox/\n",
    "campaign/sendbox/draft.md": `A local draft that names ${brand}.\n`,
  }, "chore: s7 control");
  check(clean.status === 0 && clean.out.includes("S7 OK: neutral") && !clean.fixture.length && !clean.brand.length,
    `run: a clean root with only allowed constructs exits 0 (got ${clean.status})`);
  if (bad) {
    for (const r of [run, fixtureOnly, brandOnly, commitOnly, clean]) if (r.status !== 0 && r.status !== 1) console.error(r.err.slice(0, 2000));   // a crash, not a verdict
    console.error(`S7 NEGATIVE FAILED — ${bad} planted case(s) judged wrongly`);
    process.exit(1);
  }
  console.log(`S7 NEGATIVE OK — every planted name and brand caught by the real entry point, every allowlisted construct allowed, ${fixturePlants.size} fixture plants across ${dirs.length} scan dirs + ${pub.files.size} shipped files + ${pub.manifests.size} manifests, ${prosePlants.size} prose plants + 1 commit, exit 1 per pass and 0 when clean`);
  process.exit(0);
}

if (process.argv.includes("--negative")) negative();
passFixtures();
passBrand();
if (hits || brandHits) process.exit(1);
console.log("S7 OK: neutral — no impersonation in fixtures, no commercial brands in public prose or history");
