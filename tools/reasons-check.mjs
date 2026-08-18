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

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(ROOT, p), "utf8");
let bad = 0;
const fail = (msg) => { console.error(`  ✗ ${msg}`); bad = 1; };

// ── 1 · ainra-core: the `ALL` table in verdict.rs, which is what serializes to the wire ──────────────────────────
const verdictRs = read("crates/ainra-core/src/verdict.rs");
const allBlock = verdictRs.match(/const ALL: \[\(Reason, &str\); (\d+)\] = \[([\s\S]*?)\n {4}\];/);
if (!allBlock) { console.error("reasons-check: could not find Reason::ALL in crates/ainra-core/src/verdict.rs"); process.exit(2); }
const declaredLen = Number(allBlock[1]);
const core = [...allBlock[2].matchAll(/"([a-z_]+)"/g)].map((m) => m[1]);
// The array's declared length is load-bearing: it is what forces a cross-implementation update when a reason is
// added, so a mismatch between it and the entries means the table itself is inconsistent.
if (core.length !== declaredLen) fail(`Reason::ALL declares length ${declaredLen} but holds ${core.length} entries`);

// ── 2 · the TS SDK's Reason union ────────────────────────────────────────────────────────────────────────────────
const sdk = read("packages/sdk-ts/src/index.ts");
const unionBlock = sdk.match(/export type Reason =([\s\S]*?);/);
if (!unionBlock) { console.error("reasons-check: could not find `export type Reason` in packages/sdk-ts/src/index.ts"); process.exit(2); }
const ts = [...unionBlock[1].matchAll(/"([a-z_]+)"/g)].map((m) => m[1]);

// ── 3 · the published list ───────────────────────────────────────────────────────────────────────────────────────
const doc = JSON.parse(read("docs/reasons.json"));
const documented = Object.keys(doc).filter((k) => k !== "_note" && k !== "valid");

const cmp = (label, a, b, aName, bName) => {
  const missing = a.filter((x) => !b.includes(x));
  const extra = b.filter((x) => !a.includes(x));
  if (missing.length) fail(`${label}: in ${aName} but not ${bName} — ${missing.join(", ")}`);
  if (extra.length) fail(`${label}: in ${bName} but not ${aName} — ${extra.join(", ")}`);
};
// ── 3b · the Python SDK's closed set ─────────────────────────────────────────────────────────────────────────────
// This comparison was MISSING from the first version of this gate, and the omission cost something real: D-044's
// `registrar_distrusted` had been defined in reasons.py since that milestone but never added to `ALL`, so the
// Python SDK's closed set was one short and nothing noticed. A gate that checks three of four implementations is
// a gate with a blind spot exactly where the next defect will live.
const py = read("packages/sdk-py/ainra/reasons.py");
const pyAll = (py.match(/^ALL = \(([\s\S]*?)\)/m)?.[1] ?? "")
  .split(",").map((x) => x.trim()).filter((x) => x && !x.startsWith("#"))
  .map((name) => py.match(new RegExp(`^${name} = "([a-z_]+)"`, "m"))?.[1])
  .filter(Boolean);
if (pyAll.length === 0) { console.error("reasons-check: could not parse ALL from packages/sdk-py/ainra/reasons.py"); process.exit(2); }

cmp("core ↔ sdk-ts", core, ts, "ainra-core", "sdk-ts");
cmp("core ↔ sdk-py", core, pyAll, "ainra-core", "sdk-py");
cmp("core ↔ docs", core, documented, "ainra-core", "docs/reasons.json");

// ── 4 · no doc may state a count that contradicts the list ───────────────────────────────────────────────────────
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

if (bad) {
  console.error(`\nREASONS-CHECK FAILED — the contract and the implementations disagree.`);
  console.error(`Fix: add the reason to docs/reasons.json with a plain-words gloss, and update any prose count.`);
  process.exit(1);
}
console.log(`REASONS-CHECK OK: ${n} refusal reasons, identical in ainra-core, sdk-ts, sdk-py and docs/reasons.json; every documented count agrees.`);
