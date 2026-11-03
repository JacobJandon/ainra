// SPDX-License-Identifier: Apache-2.0 OR MIT
// The AINRA conformance runner (M24 Task 2a; contract v2, PLAN-M50 step 3). Language-agnostic: point it at ANY
// executable that follows the contract (tools/conformance/CONTRACT.md) and it drives the public corpus against that
// executable, then writes a machine-readable JSON report — pass/fail per vector, divergence detail per failure, the
// corpus hash, totals. Profile `full` (the default) is every corpus; `core` is the three v1 kinds alone. The root publishes this and certifies no one; anyone
// runs it against their own implementation to prove conformance themselves.
//
// The contract, in one paragraph: the implementation under test is an executable. The runner invokes it once per
// corpus part with the part's KIND as the final argument (`passport`, `delta`, `directory`, and in the full profile
// `presentation`, `gate`, `link`, `decision`, `directory-epoch`), streams that part's
// vectors to its stdin as JSON Lines (one published vector object per line, each carrying its `name`), and reads
// one line `<name>\t<result-json>` per vector from its stdout. `<result-json>` is the implementation's verdict:
//   passport   {"verdict":"valid"} | {"verdict":"invalid","reason":"<reason>"}
//   delta      {"accept":true}     | {"accept":false,"reason":"<reason>"}
//   directory  {"accept":true,"registrars":<n>} | {"accept":false}
//   the full-profile kinds: the shape that corpus records in `expect` (CONTRACT.md has the table)
// Key order and insignificant whitespace do not matter — the runner canonicalises both sides before comparing.
// The implementation reads no files and opens no network connection; everything it needs is on stdin. Fail closed:
// an empty/partial corpus, a missing verdict, or a below-minimum count all FAIL (no vacuous pass).
//
//   node tools/conformance/run.mjs --impl "<command...>" [--profile full|core] [--name NAME] [--version VER] [--out report.json]
//
// --impl is the executable command (may include its own arguments); the runner appends the kind. Exit 0 iff the
// implementation matches the recorded core verdict on every vector AND the corpus clears the count guard.

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const RUNNER_VERSION = "2";
const ROOT = fileURLToPath(new URL("../../", import.meta.url));
// The corpus lives at vectors/{v1,v1-delta,v1-directory} under the repo root by default; a stranger verifying a
// downloaded corpus tarball can point AINRA_CONFORMANCE_ROOT at the dir that contains that `vectors/` tree.
const CORPUS_ROOT = process.env.AINRA_CONFORMANCE_ROOT || ROOT;

// The published corpus parts. Each vector's `expect` is the recorded ainra-core answer, already in the exact result
// shape; each part has a fail-closed minimum count. `core` is contract v1's three kinds, which a verifier that takes
// status on the presenter's word still passes (D-072); `full` adds what a gate, a link check and a decision log decide.
const PARTS = [
  { kind: "passport", dir: "vectors/v1", min: 500, profile: "core" },
  { kind: "delta", dir: "vectors/v1-delta", min: 15, profile: "core" },
  { kind: "directory", dir: "vectors/v1-directory", min: 9, profile: "core" },
  { kind: "presentation", dir: "vectors/v1-presentation", min: 40, profile: "full" },
  { kind: "gate", dir: "vectors/v1-gate", min: 27, profile: "full" },
  { kind: "link", dir: "vectors/v1-link", min: 40, profile: "full" },
  { kind: "decision", dir: "vectors/v1-decision", min: 30, profile: "full" },
  { kind: "directory-epoch", dir: "vectors/v1-directory-epoch", min: 9, profile: "full" },
  { kind: "currency", dir: "vectors/v1-currency", min: 18, profile: "full" },
];
export const PROFILES = ["full", "core"];
const partsOf = (profile) => PARTS.filter((p) => profile === "full" || p.profile === "core");

// Canonical JSON: sorted keys, no insignificant whitespace. Both the implementation's line and the vector's
// recorded expect pass through this before comparison, so an impl need not emit sorted keys.
function stable(o) {
  return o === null || typeof o !== "object"
    ? JSON.stringify(o)
    : Array.isArray(o)
      ? `[${o.map(stable).join(",")}]`
      : `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${stable(o[k])}`).join(",")}}`;
}

function sha256hex(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

// Compact a pretty-printed JSON document to a single line by stripping ONLY insignificant whitespace (outside
// strings). Crucially this preserves number literals VERBATIM — a vector carries a u64 near 2^64 (delta seq wrap)
// that JSON.parse→stringify would mangle into a lossy float. The implementation must receive the published bytes,
// not a JS round-trip, so we minify the raw text instead of re-serialising the parsed object.
function compactJson(text) {
  let out = "";
  let inStr = false;
  let esc = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inStr) {
      out += ch;
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === '"') inStr = false;
    } else if (ch === '"') {
      inStr = true;
      out += ch;
    } else if (ch !== " " && ch !== "\n" && ch !== "\t" && ch !== "\r") {
      out += ch;
    }
  }
  return out;
}

// Load one corpus part: the vector files (sorted, manifest.json excluded), each parsed, with its file bytes kept
// so the corpus hash pins the EXACT bytes a stranger ran against.
function loadPart(part) {
  const dir = path.join(CORPUS_ROOT, part.dir);
  if (!fs.existsSync(dir)) return { files: [] };
  const names = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".json") && f !== "manifest.json")
    .sort();
  const files = names.map((f) => {
    const bytes = fs.readFileSync(path.join(dir, f));
    const text = bytes.toString("utf8");
    return {
      relpath: `${part.dir}/${f}`,
      // `vector` is used only to read `name`/`expect` (no >2^53 ints there, so JS parse is safe); the bytes
      // streamed to the implementation are the verbatim published document, minified.
      vector: JSON.parse(text),
      line: compactJson(text),
      sha256: sha256hex(bytes),
    };
  });
  return { files };
}

// The corpus hash: sha256 over sorted `<relpath>\0<sha256(file-bytes)>\n` lines across every vector file in every
// part (manifest.json excluded). Pins the exact corpus set + contents, so a partial/empty corpus can never pass
// vacuously and two parties can confirm they ran the identical corpus. Recompute: this exact procedure.
function corpusHash(parts) {
  const lines = [];
  for (const p of parts) for (const f of p.files) lines.push(`${f.relpath}\0${f.sha256}`);
  lines.sort();
  return "sha256:" + sha256hex(Buffer.from(lines.join("\n") + "\n", "utf8"));
}

// Drive the implementation for one part: stream the part's vectors as JSON Lines to the executable's stdin and
// parse `<name>\t<result-json>` lines from stdout into a name -> result-json map.
function driveImpl(implArgv, kind, files) {
  const input = files.map((f) => f.line).join("\n") + "\n";
  const res = spawnSync(implArgv[0], [...implArgv.slice(1), kind], {
    input,
    encoding: "utf8",
    maxBuffer: 512 * 1024 * 1024,
    env: { ...process.env },
  });
  if (res.error) throw new Error(`implementation failed to start for kind=${kind}: ${res.error.message}`);
  if (res.status !== 0) {
    throw new Error(
      `implementation exited ${res.status} for kind=${kind}` +
        (res.stderr ? `:\n${res.stderr.trim().split("\n").slice(-6).join("\n")}` : "")
    );
  }
  const map = new Map();
  for (const line of res.stdout.split("\n")) {
    if (!line) continue;
    const t = line.indexOf("\t");
    if (t < 0) continue;
    map.set(line.slice(0, t), line.slice(t + 1));
  }
  return map;
}

// Run the full corpus against one implementation and build the report object. Pure: does not exit or print.
export function runConformance(implArgv, info = {}) {
  const profile = info.profile || "full";
  if (!PROFILES.includes(profile)) throw new Error(`unknown profile: ${profile} (expected full|core)`);
  const loaded = partsOf(profile).map((p) => ({ ...p, ...loadPart(p) }));
  const partsCount = {};
  const requiredMin = {};
  let total = 0;
  for (const p of loaded) {
    partsCount[p.kind] = p.files.length;
    requiredMin[p.kind] = p.min;
    total += p.files.length;
  }

  const divergences = [];
  let checked = 0;
  let passed = 0;
  // Fail closed on a partial/empty corpus BEFORE running anything — the count guard, alongside the corpus hash,
  // is the M9 verifier-collector lesson: never report success on a corpus that is too small to be the real one.
  const guardFailures = [];
  for (const p of loaded) {
    if (p.files.length < p.min) {
      guardFailures.push(`${p.kind}: ${p.files.length} vector(s) < required minimum ${p.min}`);
    }
  }

  if (guardFailures.length === 0) {
    for (const p of loaded) {
      const got = driveImpl(implArgv, p.kind, p.files);
      for (const f of p.files) {
        checked++;
        const expected = stable(f.vector.expect);
        const raw = got.get(f.vector.name);
        let gotCanon = null;
        if (raw === undefined) {
          divergences.push({ part: p.kind, vector: f.vector.name, expected: f.vector.expect, got: null, note: "no verdict emitted" });
          continue;
        }
        try {
          gotCanon = stable(JSON.parse(raw));
        } catch {
          divergences.push({ part: p.kind, vector: f.vector.name, expected: f.vector.expect, got: raw, note: "unparseable result" });
          continue;
        }
        if (gotCanon === expected) passed++;
        else divergences.push({ part: p.kind, vector: f.vector.name, expected: f.vector.expect, got: JSON.parse(raw) });
      }
    }
  }

  const result = guardFailures.length === 0 && divergences.length === 0 ? "pass" : "fail";
  return {
    report_version: "2",
    runner_version: RUNNER_VERSION,
    generated_at: new Date().toISOString(),
    profile,
    implementation: { name: info.name || "unknown", version: info.version || "unknown" },
    corpus: {
      hash: corpusHash(loaded),
      hash_input: "sorted `<relpath>\\0<sha256(file-bytes)>` lines over every vector file (manifest.json excluded)",
      parts: partsCount,
      total,
      required_minimums: requiredMin,
    },
    totals: { checked, passed, failed: checked - passed },
    guard_failures: guardFailures,
    result,
    divergences,
  };
}

function parseArgs(argv) {
  const out = { impl: null, profile: "full", name: undefined, version: undefined, report: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--impl") out.impl = argv[++i];
    else if (a === "--profile") out.profile = argv[++i];
    else if (a === "--name") out.name = argv[++i];
    else if (a === "--version") out.version = argv[++i];
    else if (a === "--out") out.report = argv[++i];
    else {
      console.error(`unknown argument: ${a}`);
      process.exit(2);
    }
  }
  return out;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.impl) {
    console.error('usage: node tools/conformance/run.mjs --impl "<command...>" [--profile full|core] [--name NAME] [--version VER] [--out report.json]');
    process.exit(2);
  }
  const implArgv = args.impl.split(/\s+/).filter(Boolean);
  let report;
  try {
    report = runConformance(implArgv, { profile: args.profile, name: args.name, version: args.version });
  } catch (e) {
    console.error(`CONFORMANCE ERROR: ${e.message}`);
    process.exit(1);
  }
  const json = JSON.stringify(report, null, 2) + "\n";
  if (args.report) fs.writeFileSync(args.report, json);

  const c = report.corpus.parts;
  const perPart = partsOf(report.profile).map((p) => {
    const bad = report.divergences.filter((d) => d.part === p.kind).length;
    return `${p.kind} ${c[p.kind] - bad}/${c[p.kind]}`;
  }).join("  ");
  console.log(
    `impl=${report.implementation.name}@${report.implementation.version}  profile=${report.profile}  corpus=${report.corpus.hash}\n` +
      `  ${perPart}  divergences=${report.divergences.length}  → ${report.result.toUpperCase()}`
  );
  if (report.guard_failures.length) for (const g of report.guard_failures) console.error(`  GUARD FAIL: ${g}`);
  for (const d of report.divergences.slice(0, 20)) {
    console.error(`  DIVERGENCE ${d.part}/${d.vector}: expected ${stable(d.expected)} got ${d.got === null ? "<none>" : stable(d.got)}${d.note ? " (" + d.note + ")" : ""}`);
  }
  if (report.divergences.length > 20) console.error(`  … and ${report.divergences.length - 20} more`);
  if (args.report) console.log(`  report → ${args.report}`);
  process.exit(report.result === "pass" ? 0 : 1);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
