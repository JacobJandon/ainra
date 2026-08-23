// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make number-syntax — pin what each implementation does with NON-CANONICAL INTEGER SYNTAX on the wire.
//
// This gate does NOT assert agreement, because there is none, and pretending otherwise is how a known divergence
// becomes a forgotten one. D-054 records the finding: `"exp": 2.6e3` and `"exp": 2600` are the same JSON number,
// and the implementations do not treat them the same way.
//
// What is actually true (measured, not assumed):
//   • ainra-core and @ainra/sdk parse the exponent form to exactly 2600 and return VALID. After parsing, the two
//     spellings are indistinguishable — `Number.isInteger(2600)` is true either way — so no post-parse check can
//     tell them apart.
//   • ainra-py type-checks and gets a float, so it refuses. Since D-054 the reason is `schema_violation`, which is
//     the honest one: a float where an integer belongs is a serializer fault, not an expiry.
//
// So the same bytes get VALID from two implementations and INVALID from the third. That is a verdict divergence,
// not merely a reason divergence, and it is bigger than the M30b note that first recorded it claimed.
//
// Why it is not closed here: every implementation decodes a PARSED object, not the wire text. `-0` and `2.6e3`
// are gone by the time any of this code runs. Closing it means the SDKs must consume bytes and lex numbers
// themselves — an API change to both SDKs, for a divergence that grants no privilege (a mutated `exp` breaks the
// credential signature; the exponent form that survives denotes the identical value). That trade is a decision,
// recorded in D-054, not something to slip into a patch.
//
// WITNESS: could this observe a change? Yes — it asserts the CURRENT measured behaviour per implementation. Any
// implementation that becomes stricter or laxer flips a row and this exits nonzero, so the divergence cannot
// widen, narrow, or be silently "fixed" in one place without the others noticing.

import { readFileSync, readdirSync, writeFileSync, mkdtempSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const V = join(ROOT, "vectors/v1");
const name = readdirSync(V).filter((f) => f.startsWith("instance-valid-")).sort()[0];
const base = readFileSync(join(V, name), "utf8");

const sdk = await import(join(ROOT, "packages/sdk-ts/dist/index.js"));
const m = await import(join(ROOT, "site/assets/wasm/ainra_wasm.js"));
await m.default({ module_or_path: readFileSync(join(ROOT, "site/assets/wasm/ainra_wasm_bg.wasm")) });

const ts = (v) => { try { const r = sdk.runVector(v); return r.verdict === "valid" ? "valid" : r.reason; } catch (e) { return "threw"; } };
const core = (v) => {
  try {
    const e = JSON.parse(m.verify_aud(JSON.stringify(v.presentation), JSON.stringify(v.anchors), v.presentation.now, v.presentation.audience ?? ""));
    return e.status === "valid" ? "valid" : e.reason;
  } catch { return "threw"; }
};
const py = (txt) => {
  const f = join(mkdtempSync(join(tmpdir(), "ns-")), "v.json");
  writeFileSync(f, txt);
  return execFileSync("python3", ["-c", `
import json, sys
sys.path.insert(0, ${JSON.stringify(join(ROOT, "packages/sdk-py"))})
from ainra.verify import verify
v = json.load(open(${JSON.stringify(f)}))
p = v["presentation"]
r = verify(v["anchors"], p, p["now"])
print("valid" if r.valid else r.reason)
`], { encoding: "utf8" }).trim();
};

// Each row: the mutation, and the behaviour measured for D-054. `null` means "must not be exercised" — a pattern
// that no longer appears in the corpus makes the row meaningless, and a meaningless row must fail loudly rather
// than pass by vacuity.
const ROWS = [
  { label: "baseline — untouched", from: null, to: null, want: { core: "valid", ts: "valid", py: "valid" } },
  { label: "exp in exponent notation", from: '"exp": 2600', to: '"exp": 2.6e3',
    want: { core: "valid", ts: "valid", py: "schema_violation" } },
  { label: "nbf written as -0", from: '"nbf": 1940', to: '"nbf": -0',
    want: { core: "instance_sig_invalid", ts: "schema_violation", py: "instance_sig_invalid" } },
];

let bad = 0;
console.log("number-syntax · D-054 · non-canonical integer spellings on the wire");
console.log("  (this gate pins a KNOWN DIVERGENCE — rows are expected to differ between implementations)");
for (const r of ROWS) {
  let txt = base;
  if (r.from !== null) {
    if (!base.includes(r.from)) {
      console.error(`  ✗ ${r.label}: the pattern ${r.from} is not in ${name} — this row tests nothing. Re-point it.`);
      bad = 1; continue;
    }
    txt = base.replace(r.from, r.to);
  }
  const v = JSON.parse(txt);
  const got = { core: core(v), ts: ts(v), py: py(txt) };
  const ok = ["core", "ts", "py"].every((k) => got[k] === r.want[k]);
  if (!ok) bad = 1;
  const shape = ["core", "ts", "py"].map((k) => `${k}=${got[k]}`).join("  ");
  console.log(`  ${ok ? "pinned" : "CHANGED"}  ${r.label.padEnd(26)} ${shape}`);
  if (!ok) console.error(`        ↑ expected ${JSON.stringify(r.want)} — an implementation's number handling moved. Update D-054 deliberately, or revert.`);
}

if (bad) {
  console.error(`\nNUMBER-SYNTAX FAILED — measured behaviour no longer matches what D-054 records.`);
  process.exit(1);
}
console.log(`NUMBER-SYNTAX OK: ${ROWS.length} row(s) match D-054. The divergence is bounded and unchanged.`);
