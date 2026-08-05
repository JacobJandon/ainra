// SPDX-License-Identifier: Apache-2.0 OR MIT
// L5's governing constraint, enforced mechanically: exactly ONE Rust path turns external bytes into core verify
// types, and it lives in crates/ainra-adapter.
//
// This is not style policing. Mapping the boundary for L5 found a SECOND anchor decoder had already grown in the
// CLI's seed path, and it disagreed with the first — it failed OPEN, substituting an all-zero issuer key for a
// malformed one. A duplicate parser is how a verifier quietly stops agreeing with itself, which is the one class
// of bug the four-way differential exists to catch and the one this repository cannot afford.
//
//   node tools/one-decode-path.mjs
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const ADAPTER = "crates/ainra-adapter";

// Signatures of the moved implementations. If one of these appears outside the adapter, someone re-created a
// parse path — either by copy-paste or by writing a "small local helper" that is the same thing again.
const MOVED = [
  { re: /struct\s+WirePresentation\b/,        what: "the wire presentation shape" },
  { re: /struct\s+WireRegistrar\b/,           what: "the wire registrar/anchor shape" },
  { re: /struct\s+WireCheckpointSig\b/,       what: "the wire checkpoint-signature shape" },
  { re: /struct\s+WireDeltaVector\b/,         what: "the wire delta-vector shape" },
  { re: /fn\s+decode_cp_sig\b/,               what: "checkpoint-signature decoding" },
  { re: /fn\s+delta_verify\b/,                what: "delta-vector verification" },
  { re: /fn\s+directory_result\b/,            what: "directory-vector evaluation" },
  { re: /fn\s+anchors_from_export\b/,         what: "the fail-open anchor decoder deleted in L5" },
];
// A second decoder rarely announces itself; it looks like an innocent local conversion. Flag the shape.
// Assembling TrustAnchors from IN-PROCESS values is legitimate — a registrar knows its own keys and never parsed
// them. The parse signal is building them out of a serde_json::Value, i.e. interpreting wire bytes.
const SHAPES = [
  { re: /fn[^\n]*\(\s*[a-z_]+\s*:\s*&serde_json::Value[^\n]*\)\s*->\s*[^\n]*TrustAnchors/, 
    what: "TrustAnchors decoded from JSON outside the adapter" },
  { re: /Presentation\s*\{[\s\S]{0,400}?serde_json::from_str/, 
    what: "a Presentation built directly from parsed JSON outside the adapter" },
];

const files = [];
(function walk(d) {
  for (const e of readdirSync(d, { withFileTypes: true })) {
    if (["target", "node_modules", ".git", "fuzz"].includes(e.name)) continue;
    const p = join(d, e.name);
    if (e.isDirectory()) walk(p);
    else if (e.name.endsWith(".rs")) files.push(p);
  }
})(ROOT);

let hits = 0;
for (const f of files) {
  const rel = relative(ROOT, f);
  if (rel.startsWith(ADAPTER)) continue;               // the one legitimate home
  const text = readFileSync(f, "utf8");
  for (const m of MOVED) {
    if (m.re.test(text)) { console.error(`  ✗ ${rel} — ${m.what} reappeared outside ${ADAPTER}`); hits++; }
  }
  for (const s of SHAPES) {
    if (s.re.test(text) && !(s.allow||[]).some((a) => a.test(rel))) {
      console.error(`  ✗ ${rel} — ${s.what}`); hits++;
    }
  }
}
if (hits) {
  console.error(`\nONE-DECODE-PATH FAILED: ${hits} occurrence(s). Route it through ${ADAPTER} instead of parsing again.`);
  console.error(`If the adapter genuinely cannot express what you need, that is a design question to raise — not a`);
  console.error(`second parser to write.`);
  process.exit(1);
}
console.log(`ONE-DECODE-PATH OK: ${files.length} Rust files scanned; every bytes→core-types conversion lives in ${ADAPTER}.`);
