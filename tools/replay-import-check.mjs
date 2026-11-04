// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make replay-imports — nothing in the repository replays a vector through a package ROOT (PLAN-M51 step 2).
//
// A corpus runner believes the vector's own clock, freshness class and status list. That is what lets the corpus pin
// every reason, and it is why a runner must never decide trust: a revoked agent carrying an all-clear list of its own
// reads valid through one (D-074, D-075). Since 0.6.0 the runners live behind their own import — `@ainra/sdk/
// conformance`, `ainra.conformance`, `@ainra/edge/conformance`, and the browser bundle's `conformance` namespace —
// so that which of the two a caller is doing shows in the import line. The root exports go in 0.7.0; this gate is
// what makes that removal one line, by refusing any in-repo caller that still reaches a runner through a root.
//
// What counts as a root: `@ainra/sdk`, `@ainra/edge`, any path to a package's `dist/index.js` or `src/index`,
// and the browser bundle (`…/ainra-sdk.js`) at its top level. In Python, `ainra.verify` (the
// fixture-semantics function) from the package root.
//
// The forms it reads: named imports, namespace imports (`import * as X` / `X = await import(…)`) followed by
// `X.runVector`, destructured dynamic imports, and a loader function returning a dynamic import (`const sdk = async
// () => (… await import(root))`, then `{ … } = await sdk()`). A destructure nested under `conformance:` is the
// namespace and is allowed.
//
// WITNESS: `--negative` feeds one planted caller of each form through the same analysis; every one must be caught.
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const REPLAY = ["runVector", "expectedVerdict", "runDeltaVector", "runDirectoryVector", "runGateVector", "runLinkVector",
  "runDecisionVector", "runDirectoryEpochVector", "runCurrencyVector", "runPresentationVector"];
const REPLAY_RE = new RegExp(`\\b(${REPLAY.join("|")})\\b`);
const isRoot = (spec) =>
  /^@ainra\/(sdk|edge)$/.test(spec) ||
  // any package's built or source root, however it is reached — including `../dist/index.js` from the package's own
  // tests, which a sdk-ts/-anchored pattern missed
  /(^|\/)dist\/index\.js$/.test(spec) || /(^|\/)src\/index(\.js|\.ts|\.mjs)?$/.test(spec) ||
  /(^|\/)ainra-sdk\.js$/.test(spec);
// A dynamic import's argument may be a literal or join(ROOT, "…"): the first quoted string inside it is the spec.
const specOf = (arg) => (arg.match(/["'`]([^"'`]+)["'`]/) || [])[1] || "";

// Top-level names of a destructuring pattern, skipping anything nested under `conformance: { … }`.
function topNames(pattern) {
  let depth = 0, cur = "", out = [];
  const inner = pattern.trim().replace(/^\{/, "").replace(/\}$/, "");
  for (const ch of inner) {
    if (ch === "{") depth++;
    if (ch === "}") depth--;
    if (ch === "," && depth === 0) { out.push(cur); cur = ""; } else cur += ch;
  }
  out.push(cur);
  return out.map((p) => p.trim()).filter(Boolean).filter((p) => !/^conformance\s*:/.test(p))
    .map((p) => p.split(/\s*[:=]\s*|\s+as\s+/)[0].trim());
}

export function analyzeJs(text) {
  const hits = [];
  // 1 · static imports
  for (const m of text.matchAll(/import\s+([\s\S]*?)\s+from\s+["'`]([^"'`]+)["'`]/g)) {
    if (!isRoot(m[2])) continue;
    const clause = m[1];
    const named = clause.match(/\{([\s\S]*)\}/);
    if (named) for (const n of topNames(`{${named[1]}}`)) if (REPLAY.includes(n)) hits.push(`imports ${n} from ${m[2]}`);
    const ns = clause.match(/\*\s+as\s+(\w+)/);
    if (ns) for (const u of text.matchAll(new RegExp(`\\b${ns[1]}\\.(\\w+)`, "g"))) if (REPLAY.includes(u[1])) hits.push(`${ns[1]}.${u[1]} (namespace of ${m[2]})`);
  }
  // 2 · loader functions: const NAME = async () => (… await import(ROOT …))
  const loaders = [];
  for (const m of text.matchAll(/(?:const|let|var)\s+(\w+)\s*=\s*async\s*\(\s*\)\s*=>[^;\n]*?import\(([^)]*)\)/g))
    if (isRoot(specOf(m[2]))) loaders.push(m[1]);
  // 3 · dynamic imports (and loader calls) bound to a name or a destructure
  const bindings = [];
  for (const m of text.matchAll(/(?:const|let|var)\s+(\{[\s\S]*?\}|\w+)\s*=\s*await\s+import\(((?:[^()]|\([^()]*\))*)\)/g))
    if (isRoot(specOf(m[2]))) bindings.push([m[1], specOf(m[2])]);
  for (const L of loaders)
    for (const m of text.matchAll(new RegExp(`(?:const|let|var)\\s+(\\{[\\s\\S]*?\\}|\\w+)\\s*=\\s*await\\s+${L}\\(\\)`, "g")))
      bindings.push([m[1], `${L}()`]);
  for (const [b, spec] of bindings) {
    if (b.startsWith("{")) { for (const n of topNames(b)) if (REPLAY.includes(n)) hits.push(`destructures ${n} from ${spec}`); }
    else for (const u of text.matchAll(new RegExp(`\\b${b}\\.(\\w+)`, "g"))) if (REPLAY.includes(u[1])) hits.push(`${b}.${u[1]} (module ${spec})`);
  }
  return hits;
}

export function analyzePy(text) {
  const hits = [];
  for (const m of text.matchAll(/from\s+ainra\s+import\s+(\([^)]*\)|[^\n]+)/g)) {
    const names = m[1].replace(/[()]/g, "").split(",").map((s) => s.trim().split(/\s+as\s+/)[0]);
    if (names.includes("verify")) hits.push("from ainra import verify");
  }
  for (const m of text.matchAll(/^\s*import\s+ainra(?:\s+as\s+(\w+))?\s*$/gm)) {
    const alias = m[1] || "ainra";
    if (new RegExp(`\\b${alias}\\.verify\\(`).test(text)) hits.push(`${alias}.verify(…)`);
  }
  return hits;
}

const PLANTS = [
  ["js", `import { Verifier, runVector } from "../packages/sdk-ts/dist/index.js";`],
  ["js", `import { runGateVector } from "@ainra/sdk";`],
  ["js", `import * as S from "@ainra/sdk"; S.runDeltaVector(v);`],
  ["js", `const sdk = await import(join(ROOT, "packages/sdk-ts/dist/index.js")); sdk.runVector(v);`],
  ["js", `const { runPresentationVector } = await import("../packages/edge/src/index.mjs");`],
  ["js", `import { runVector, verdictEvent } from "../vendor/ainra-sdk.js";`],
  ["js", `const sdk = async () => (SDK ||= await import("./vendor/ainra-sdk.js"));\nconst { runVector } = await sdk();`],
  ["js", `import { runLinkVector } from "@ainra/edge";`],
  ["js", `import { runVector, Verifier } from "../dist/index.js";`],
  ["py", `from ainra import Verifier, verify`],
  ["py", `import ainra\nainra.verify(anchors, pres, now)`],
];
const ALLOWED = [
  ["js", `import { runVector } from "../packages/sdk-ts/dist/conformance.js";`],
  ["js", `import { conformance, verdictEvent } from "../vendor/ainra-sdk.js";\nconst { runVector } = conformance;`],
  ["js", `const sdk = async () => (SDK ||= await import("./vendor/ainra-sdk.js"));\nconst { conformance: { runVector }, verdictEvent } = await sdk();`],
  ["js", `import { Verifier } from "@ainra/sdk"; import { runGateVector } from "@ainra/edge/conformance";`],
  ["py", `from ainra import Verifier, verify_directory\nfrom ainra.conformance import run_vector`],
];

if (process.argv.includes("--negative")) {
  let bad = 0;
  for (const [k, src] of PLANTS) {
    const caught = (k === "js" ? analyzeJs : analyzePy)(src).length > 0;
    console.log(`  ${caught ? "ok  caught " : "✗   MISSED "} ${src.split("\n").pop()}`);
    if (!caught) bad++;
  }
  for (const [k, src] of ALLOWED) {
    const flagged = (k === "js" ? analyzeJs : analyzePy)(src).length > 0;
    console.log(`  ${flagged ? "✗   FLAGGED" : "ok  allowed"} ${src.split("\n").pop()}`);
    if (flagged) bad++;
  }
  if (bad) { console.error(`REPLAY-IMPORTS NEGATIVE FAILED — ${bad} planted case(s) judged wrongly`); process.exit(1); }
  console.log(`REPLAY-IMPORTS NEGATIVE OK — all ${PLANTS.length} planted root callers caught, ${ALLOWED.length} conformance callers allowed`);
  process.exit(0);
}

// The definitions themselves, and bundles generated from them, are not callers.
const SKIP = [/^packages\/sdk-ts\/src\//, /^packages\/sdk-ts\/browser\/entry\.ts$/, /^packages\/edge\/src\//,
  /(^|\/)vendor\/ainra-sdk\.js$/, /^examples\/verify-in-browser\/ainra-sdk\.js$/, /^packages\/sdk-py\/ainra\//,
  /^vectors\//, /^tools\/replay-import-check\.mjs$/];
const files = execFileSync("git", ["ls-files", "-co", "--exclude-standard"], { cwd: ROOT, encoding: "utf8" })
  .split("\n").filter((f) => /\.(m?js|ts|html|sh|py)$/.test(f) && !SKIP.some((r) => r.test(f)));
let found = 0;
for (const f of files) {
  let text;
  try { text = readFileSync(ROOT + f, "utf8"); } catch { continue; }
  const hits = f.endsWith(".py") ? analyzePy(text) : REPLAY_RE.test(text) ? analyzeJs(text) : [];
  for (const h of hits) { console.error(`  ✗ ${f}: ${h}`); found++; }
}
if (found) {
  console.error(`REPLAY-IMPORTS FAILED — ${found} caller(s) replay a vector through a package root. Import the runner from its`);
  console.error("conformance path (@ainra/sdk/conformance, @ainra/edge/conformance, ainra.conformance, the bundle's `conformance`).");
  process.exit(1);
}
console.log(`REPLAY-IMPORTS OK — ${files.length} files read; every vector replay goes through a conformance import`);
