// SPDX-License-Identifier: Apache-2.0 OR MIT
// make reasons-check — the DOCUMENTED refusal reasons must be exactly the reasons the implementations can return.
//
// This gate exists because they weren't. D-044 added `registrar_distrusted` to ainra-core, the TS SDK, the Python
// SDK and 48 conformance vectors — four implementations and a test corpus, all agreeing — while `docs/reasons.json`
// went on listing fifteen, and four docs went on saying "one of the 15". The four-way differential could not catch
// it: every implementation agreed, and the prose was the only thing that was wrong. Nothing reads prose.
//
// The published list is not decoration. `tools/verify-60s.mjs` loads it at runtime, the SDK and Python quickstarts
// point readers at it, and `tools/conformance/CONTRACT.md` makes it the definition an outside implementer builds
// against. A reason an implementation can return but the contract does not name is a verdict a conformant
// implementation is entitled to reject as unknown.
//
// Authority order: ainra-core's `Reason::ALL` is the source of truth (it is what the wire strings come from), then
// the TS SDK's `Reason` union, then the documented list. All three must match exactly.
//
// WITNESS: `node tools/reasons-check.mjs --negative` runs the same check against the real files with one defect
// planted IN MEMORY per run (nothing on disk is touched), and every plant must be reported by the check it targets:
// Reason::ALL's declared length one too high; one reason dropped from the TS union; one name dropped from the Python
// ALL tuple (the exact D-044 blind spot); an undocumented reason added to docs/reasons.json and the shipped copy
// alike; a stale "one of the N reasons" sentence in README.md (the exact D-044 prose drift); the @ainra/mcp copy one
// byte off; and the @ainra/mcp copy missing. A plant that passes, or fails for a different check, is a miss.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const readDisk = (p) => readFileSync(join(ROOT, p), "utf8");

// The whole check, against any reader. It returns what it found instead of printing, so the negative control can
// run the very same code on planted inputs. `fatal` is a file the check could not parse at all (exit 2, not 1).
function check(read) {
  const failures = [];
  const fail = (msg) => failures.push(msg);
  const fatal = (msg) => ({ failures, fatal: msg });

  // ── 1 · ainra-core: the `ALL` table in verdict.rs, which is what serializes to the wire ────────────────────────
  const verdictRs = read("crates/ainra-core/src/verdict.rs");
  const allBlock = verdictRs.match(/const ALL: \[\(Reason, &str\); (\d+)\] = \[([\s\S]*?)\n {4}\];/);
  if (!allBlock) return fatal("reasons-check: could not find Reason::ALL in crates/ainra-core/src/verdict.rs");
  const declaredLen = Number(allBlock[1]);
  const core = [...allBlock[2].matchAll(/"([a-z_]+)"/g)].map((m) => m[1]);
  // The array's declared length is load-bearing: it is what forces a cross-implementation update when a reason is
  // added, so a mismatch between it and the entries means the table itself is inconsistent.
  if (core.length !== declaredLen) fail(`Reason::ALL declares length ${declaredLen} but holds ${core.length} entries`);

  // ── 2 · the TS SDK's Reason union ──────────────────────────────────────────────────────────────────────────────
  const sdk = read("packages/sdk-ts/src/engine.ts");
  const unionBlock = sdk.match(/export type Reason =([\s\S]*?);/);
  if (!unionBlock) return fatal("reasons-check: could not find `export type Reason` in packages/sdk-ts/src/engine.ts");
  const ts = [...unionBlock[1].matchAll(/"([a-z_]+)"/g)].map((m) => m[1]);

  // ── 3 · the published list ─────────────────────────────────────────────────────────────────────────────────────
  const doc = JSON.parse(read("docs/reasons.json"));
  const documented = Object.keys(doc).filter((k) => k !== "_note" && k !== "valid");

  const cmp = (label, a, b, aName, bName) => {
    const missing = a.filter((x) => !b.includes(x));
    const extra = b.filter((x) => !a.includes(x));
    if (missing.length) fail(`${label}: in ${aName} but not ${bName} — ${missing.join(", ")}`);
    if (extra.length) fail(`${label}: in ${bName} but not ${aName} — ${extra.join(", ")}`);
  };
  // ── 3b · the Python SDK's closed set ───────────────────────────────────────────────────────────────────────────
  // This comparison was MISSING from the first version of this gate, and the omission cost something real: D-044's
  // `registrar_distrusted` had been defined in reasons.py since that milestone but never added to `ALL`, so the
  // Python SDK's closed set was one short and nothing noticed. A gate that checks three of four implementations is
  // a gate with a blind spot exactly where the next defect will live.
  const py = read("packages/sdk-py/ainra/reasons.py");
  const pyAll = (py.match(/^ALL = \(([\s\S]*?)\)/m)?.[1] ?? "")
    .split(",").map((x) => x.trim()).filter((x) => x && !x.startsWith("#"))
    .map((name) => py.match(new RegExp(`^${name} = "([a-z_]+)"`, "m"))?.[1])
    .filter(Boolean);
  if (pyAll.length === 0) return fatal("reasons-check: could not parse ALL from packages/sdk-py/ainra/reasons.py");

  cmp("core ↔ sdk-ts", core, ts, "ainra-core", "sdk-ts");
  cmp("core ↔ sdk-py", core, pyAll, "ainra-core", "sdk-py");
  cmp("core ↔ docs", core, documented, "ainra-core", "docs/reasons.json");

  // ── 4 · no doc may state a count that contradicts the list ─────────────────────────────────────────────────────
  // The count appears in prose in several places and drifted silently once already. Any "N frozen reasons" / "one of
  // the N" must equal the real number.
  const n = core.length;
  const proseFiles = ["docs/reasons.json", "tools/conformance/CONTRACT.md", "docs/quickstarts/sdk.md",
                      "docs/quickstarts/python.md", "README.md", "docs/PRESENTATION.md"];
  const countRe = /(?:one of the|the)\s+(\d+)\s+(?:frozen\s+)?(?:INVALID\s+)?reason/gi;
  for (const f of proseFiles) {
    let text;
    try { text = read(f); } catch { continue; }
    for (const m of text.matchAll(countRe)) {
      if (Number(m[1]) !== n) fail(`${f}: says "${m[0].trim()}" but there are ${n}`);
    }
  }

  // ── 5 · the shipped copy must be the canonical file ───────────────────────────────────────────────────────────
  // `@ainra/mcp` is installed from a registry, where no `docs/` directory exists, so it carries its own copy of the
  // reason glosses inside the published tarball. A copy is a second source of truth unless something fails when the
  // two differ — an agent reading a stale gloss for a refusal is exactly the confusion the frozen list exists to end.
  const MCP_COPY = "packages/mcp/src/reasons.json";
  try {
    if (read(MCP_COPY) !== read("docs/reasons.json"))
      fail(`${MCP_COPY} differs from docs/reasons.json — refresh it: cp docs/reasons.json ${MCP_COPY}`);
  } catch {
    fail(`${MCP_COPY} is missing — the published package would have no reason glosses: cp docs/reasons.json ${MCP_COPY}`);
  }

  return { failures, n };
}

// ── the negative control: one planted defect per run, each of which the check it targets must report ────────────
if (process.argv.includes("--negative")) {
  // Each plant rewrites one file as the check reads it; `expect` is the failure that proves the RIGHT check fired.
  const once = (s, from, to) => {
    const out = s.replace(from, to);
    if (out === s) throw new Error(`reasons-check --negative: plant did not apply (${from}) — the source moved`);
    return out;
  };
  const docs = readDisk("docs/reasons.json");
  const withExtra = JSON.stringify({ ...JSON.parse(docs), planted_unknown_reason: "planted" }, null, 2) + "\n";
  const STALE_COUNT = 15; // what README.md once said, before D-044 added another reason
  const PLANTS = [
    { what: "Reason::ALL declares one more entry than it holds", expect: "Reason::ALL declares length",
      file: "crates/ainra-core/src/verdict.rs",
      edit: (s) => s.replace(/(const ALL: \[\(Reason, &str\); )(\d+)\]/, (_, a, d) => `${a}${Number(d) + 1}]`) },
    { what: "sdk-ts Reason union drops \"sig_invalid\"", expect: "core ↔ sdk-ts: in ainra-core but not sdk-ts — sig_invalid",
      file: "packages/sdk-ts/src/engine.ts", edit: (s) => once(s, /\n\s*\| "sig_invalid"/, "") },
    { what: "sdk-py ALL drops REGISTRAR_DISTRUSTED (the D-044 blind spot)",
      expect: "core ↔ sdk-py: in ainra-core but not sdk-py — registrar_distrusted",
      file: "packages/sdk-py/ainra/reasons.py", edit: (s) => once(s, /(^ALL = \([\s\S]*?)\n\s*REGISTRAR_DISTRUSTED,/m, "$1") },
    { what: "docs/reasons.json (and its shipped copy) names a reason no implementation returns",
      expect: "core ↔ docs: in docs/reasons.json but not ainra-core — planted_unknown_reason",
      files: { "docs/reasons.json": withExtra, "packages/mcp/src/reasons.json": withExtra } },
    // The stale count is built from a variable so this planted, deliberately false sentence is not itself read as a
    // claim by `make claims-check`.
    { what: `README.md says "one of the ${STALE_COUNT} reasons" (the D-044 prose drift)`, expect: `README.md: says "one of the ${STALE_COUNT}`,
      file: "README.md", edit: (s) => s + `\nA refusal is one of the ${STALE_COUNT} reasons.\n` },
    { what: "the @ainra/mcp copy is one byte off the canonical file", expect: "differs from docs/reasons.json",
      file: "packages/mcp/src/reasons.json", edit: (s) => s + " " },
    { what: "the @ainra/mcp copy is missing", expect: "packages/mcp/src/reasons.json is missing",
      file: "packages/mcp/src/reasons.json", edit: () => { throw new Error("ENOENT (planted)"); } },
  ];

  const baseline = check(readDisk);
  if (baseline.fatal || baseline.failures.length) {
    console.error("REASONS-CHECK NEGATIVE: the unplanted tree does not pass — run `node tools/reasons-check.mjs` first");
    process.exit(1);
  }
  console.log(`negative control: ${PLANTS.length} defects planted one at a time, in memory — each must be caught`);
  let missed = 0;
  for (const p of PLANTS) {
    const planted = p.files ?? { [p.file]: p.edit };
    const read = (f) => {
      if (!(f in planted)) return readDisk(f);
      const v = planted[f];
      return typeof v === "function" ? v(readDisk(f)) : v;
    };
    const r = check(read);
    const hit = !r.fatal && r.failures.some((m) => m.includes(p.expect));
    console.log(`  ${hit ? "ok  caught " : "✗   MISSED "} ${p.what}`);
    if (!hit) {
      missed++;
      console.error(`      expected a failure containing: ${p.expect}`);
      console.error(`      got: ${r.fatal ?? (r.failures.join(" | ") || "PASS")}`);
    }
  }
  if (missed) { console.error(`REASONS-CHECK NEGATIVE FAILED — ${missed} planted defect(s) not caught`); process.exit(1); }
  console.log(`REASONS-CHECK NEGATIVE OK — all ${PLANTS.length} planted defects caught, by the check each one targets`);
  process.exit(0);
}

const { failures, fatal, n } = check(readDisk);
for (const msg of failures) console.error(`  ✗ ${msg}`);
if (fatal) { console.error(fatal); process.exit(2); }

if (failures.length) {
  console.error(`\nREASONS-CHECK FAILED — the contract and the implementations disagree.`);
  console.error(`Fix: add the reason to docs/reasons.json with a plain-words gloss, and update any prose count.`);
  process.exit(1);
}
console.log(`REASONS-CHECK OK: ${n} refusal reasons, identical in ainra-core, sdk-ts, sdk-py, docs/reasons.json and the copy @ainra/mcp ships; every documented count agrees.`);
