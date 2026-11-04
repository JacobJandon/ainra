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
//   node tools/one-decode-path.mjs --negative
//
// WITNESS: `--negative` builds a throwaway Rust tree under the OS temp directory and runs the same walk and the
// same per-file scan over it. It plants one file per moved signature and one per decoder shape (a WireRegistrar
// struct in the CLI, an `anchors_from_export` helper, a `fn …(&serde_json::Value) -> TrustAnchors`, a Presentation
// filled straight from `serde_json::from_str`, …), each outside the adapter, and every one must be reported. It
// also plants what must stay quiet: the same signatures inside crates/ainra-adapter, TrustAnchors assembled from
// in-process keys, and a duplicate decoder under target/ (build output, not source). A scan that stopped matching,
// stopped walking, or stopped exempting the adapter would show up as a MISSED or FLAGGED line and exit 1.
import { readFileSync, readdirSync, statSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join, relative, dirname } from "node:path";
import { tmpdir } from "node:os";
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
  // The verdict EVENT is wire vocabulary too. It lived in the CLI binary while the CLI was Rust's only emitter;
  // the browser surface would have made it a third copy alongside the SDK's, in the same drift class as a second
  // decoder — a log format that is "canonical" in three places is a log format with three answers.
  { re: /fn\s+number_from_name\b/,            what: "the AINRA-Number derivation" },
  { re: /fn\s+event_json\b/,                  what: "the canonical verdict-event serializer" },
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

function rustFiles(root) {
  const files = [];
  (function walk(d) {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      if (["target", "node_modules", ".git", "fuzz"].includes(e.name)) continue;
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".rs")) files.push(p);
    }
  })(root);
  return files;
}

// Every finding for one file, by its repository-relative path. Both modes go through this and nothing else.
function scan(rel, text) {
  const out = [];
  if (rel.startsWith(ADAPTER)) return out;             // the one legitimate home
  for (const m of MOVED) {
    if (m.re.test(text)) out.push(`  ✗ ${rel} — ${m.what} reappeared outside ${ADAPTER}`);
  }
  for (const s of SHAPES) {
    if (s.re.test(text) && !(s.allow||[]).some((a) => a.test(rel))) out.push(`  ✗ ${rel} — ${s.what}`);
  }
  return out;
}

if (process.argv.includes("--negative")) {
  // [relative path, source, must it be reported?]. One defect per planted file, so a miss names its own rule.
  const PLANTS = [
    ["crates/ainra-cli-rs/src/p_presentation.rs", "pub struct WirePresentation { pub claims: String }\n", true],
    ["crates/ainra-cli-rs/src/p_registrar.rs",    "struct WireRegistrar { key: String }\n", true],
    ["crates/ainra-core/src/p_cpsig.rs",          "pub(crate) struct WireCheckpointSig { sig: Vec<u8> }\n", true],
    ["crates/ainra-core/src/p_delta.rs",          "struct WireDeltaVector {}\n", true],
    ["crates/ainra-cli-rs/src/p_decode.rs",       "fn decode_cp_sig(b: &[u8]) -> Option<[u8; 64]> { None }\n", true],
    ["crates/ainra-cli-rs/src/p_dverify.rs",      "pub fn delta_verify(v: &str) -> bool { true }\n", true],
    ["crates/ainra-cli-rs/src/p_dir.rs",          "fn directory_result(v: &str) -> &str { v }\n", true],
    ["crates/ainra-cli-rs/src/p_seed.rs",         "fn anchors_from_export(s: &str) -> Vec<u8> { vec![0; 32] }\n", true],
    ["crates/ainra-cli-rs/src/p_number.rs",       "fn number_from_name(n: &str) -> String { n.into() }\n", true],
    ["crates/ainra-cli-rs/src/p_event.rs",        "pub fn event_json(v: &Verdict) -> String { String::new() }\n", true],
    ["crates/ainra-cli-rs/src/p_anchors.rs",
      "fn local_anchors(v: &serde_json::Value) -> Result<TrustAnchors, String> {\n    todo!()\n}\n", true],
    ["crates/ainra-cli-rs/src/p_pres_json.rs",
      "let p = Presentation {\n    claims: serde_json::from_str(&raw)?,\n    ..Default::default()\n};\n", true],
    // What must stay quiet.
    [`${ADAPTER}/src/lib.rs`,
      "pub struct WirePresentation {}\nstruct WireRegistrar {}\nfn anchors_from_export(v: &serde_json::Value) -> TrustAnchors { todo!() }\n", false],
    ["crates/ainra-registrar/src/p_own_keys.rs",  "let anchors = TrustAnchors { keys: own_keys.clone() };\n", false],
    ["target/debug/build/p_generated.rs",         "struct WireRegistrar {}\n", false],
  ];
  const tmp = mkdtempSync(join(tmpdir(), "one-decode-path-negative-"));
  let bad = 0;
  try {
    for (const [rel, src] of PLANTS) {
      mkdirSync(dirname(join(tmp, rel)), { recursive: true });
      writeFileSync(join(tmp, rel), src);
    }
    const reported = new Map(rustFiles(tmp).map((f) => [relative(tmp, f), scan(relative(tmp, f), readFileSync(f, "utf8"))]));
    for (const [rel, , expect] of PLANTS) {
      const got = (reported.get(rel) || []).length > 0;
      if (expect) console.log(`  ${got ? "ok  caught " : "✗   MISSED "} ${rel}`);
      else console.log(`  ${got ? "✗   FLAGGED" : "ok  allowed"} ${rel}`);
      if (got !== expect) bad++;
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  const n = PLANTS.filter((p) => p[2]).length;
  if (bad) { console.error(`ONE-DECODE-PATH NEGATIVE FAILED — ${bad} planted case(s) judged wrongly`); process.exit(1); }
  console.log(`ONE-DECODE-PATH NEGATIVE OK — all ${n} planted second decoders caught, ${PLANTS.length - n} legitimate files left alone`);
  process.exit(0);
}

const files = rustFiles(ROOT);
let hits = 0;
for (const f of files) {
  for (const line of scan(relative(ROOT, f), readFileSync(f, "utf8"))) { console.error(line); hits++; }
}
if (hits) {
  console.error(`\nONE-DECODE-PATH FAILED: ${hits} occurrence(s). Route it through ${ADAPTER} instead of parsing again.`);
  console.error(`If the adapter genuinely cannot express what you need, that is a design question to raise — not a`);
  console.error(`second parser to write.`);
  process.exit(1);
}
console.log(`ONE-DECODE-PATH OK: ${files.length} Rust files scanned; every bytes→core-types conversion lives in ${ADAPTER}.`);
