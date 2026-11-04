// SPDX-License-Identifier: Apache-2.0 OR MIT
// The site says verification happens "in milliseconds" and "offline in ~5 lines". Everywhere else in this
// repository a claim is backed by a gate; this makes the SPEED claim one too.
//
// It deliberately does NOT adopt a third-party benchmarking service or a new benchmark dependency: `make bench`
// already produces a real measurement from the existing vector corpus, and a neutral root should not put a vendor
// in the path of proving its own claim. This reads that output and fails if the number stops supporting the copy.
//
//   make bench && node tools/bench-gate.mjs
//   node tools/bench-gate.mjs --file <path>  judge another BENCHMARKS.md (the witness uses this on its plants)
//   node tools/bench-gate.mjs --negative     the gate must refuse every planted BENCHMARKS.md (offline, no bench)
//
// WITNESS: `--negative` builds seven planted BENCHMARKS.md files from the real file's verify row: the row deleted,
// the per-op cell made unreadable ("fast"), a malformed number (1.2.3 µs, which reads as NaN), a zero figure
// (0 µs), the figure set to 2500 µs, the same regression written as 2.5 ms (so a unit-conversion slip that read
// "ms" as µs would pass it and be caught), and 2500000 ns. Each plant is written to a temp directory and this very
// file is run on it as a child process, exactly as `make bench-gate` runs it, so the plant goes through the real
// judge, the real printing and the real exit code. Every plant must exit 1 and never print "BENCH OK". One control
// the other way, 1999 µs, must exit 0 and print "BENCH OK" with that figure, so a gate that refuses everything, or
// a real run that reads the wrong number, cannot pass the witness either. A real slowdown lands in BENCHMARKS.md as
// exactly such a row, so a gate that lets any plant through would let that slowdown through too.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
// The public claim is "milliseconds" (plural, small). The ceiling is deliberately ~4x the measured 456 µs so that
// ordinary host variance never fails the build, while a real regression — an accidental O(n²), a debug build, a
// dropped short-circuit — does. Raise it only with a measurement and a reason, never to make a red build green.
const CEILING_US = 2000;

// One judge for the real file and for every plant: returns the failure lines, or the measured figure.
function judge(md) {
  const row = md.split("\n").find((l) => /Full credential verify/i.test(l));
  if (!row) return { fail: ["✗ BENCHMARKS.md has no verify row — run `make bench` first"] };

  const m = row.match(/\|\s*([\d.]+)\s*(µs|us|ms|ns)\s*\|/);
  if (!m) return { fail: [`✗ could not read a per-op figure from:\n  ${row.trim()}`] };
  const [, n, unit] = m;
  const us = { ns: +n / 1000, "µs": +n, us: +n, ms: +n * 1000 }[unit];
  // "1.2.3" and "." match the cell pattern but read as NaN, and NaN is never "over" anything, so check it here.
  if (!Number.isFinite(us) || us <= 0) return { fail: [`✗ per-op figure is not a positive number: ${n} ${unit}`] };

  if (us > CEILING_US) return { fail: [
    `✗ verify is ${us} µs — over the ${CEILING_US} µs ceiling.`,
    `  The site claims verification takes milliseconds. Either the regression is real and gets fixed,`,
    `  or the claim changes. Do not raise the ceiling to make this pass.`,
  ] };
  return { us };
}

const SELF = fileURLToPath(import.meta.url);
const fileAt = process.argv.indexOf("--file");
const md = readFileSync(fileAt > 0 ? process.argv[fileAt + 1] : ROOT + "docs/BENCHMARKS.md", "utf8");

if (process.argv.includes("--negative")) {
  const lines = md.split("\n");
  const at = lines.findIndex((l) => /Full credential verify/i.test(l));
  if (at < 0) { console.error("✗ BENCHMARKS.md has no verify row to plant against — run `make bench` first"); process.exit(1); }
  // Replace only the per-op cell of the real row, so every plant is the real file with one defect.
  const withCell = (cell) => lines.map((l, i) => (i === at ? l.replace(/\|\s*[\d.]+\s*(µs|us|ms|ns)\s*\|/, `| ${cell} |`) : l)).join("\n");
  const PLANTS = [
    ["the verify row deleted", lines.filter((_, i) => i !== at).join("\n")],
    ["the per-op figure unreadable", withCell("fast")],
    ["a malformed number (1.2.3 µs)", withCell("1.2.3 µs")],
    ["a zero figure (0 µs)", withCell("0 µs")],
    ["2500 µs, over the ceiling", withCell("2500 µs")],
    ["2.5 ms, the same regression in ms", withCell("2.5 ms")],
    ["2500000 ns, the same regression in ns", withCell("2500000 ns")],
  ];
  // Run this file, as the real gate, on one planted text. Returns its exit code and output.
  const dir = mkdtempSync(join(tmpdir(), "bench-gate-negative-"));
  const gate = (text, i) => {
    const file = join(dir, `BENCHMARKS-${i}.md`);
    writeFileSync(file, text);
    const r = spawnSync(process.execPath, [SELF, "--file", file], { encoding: "utf8" });
    return { status: r.status, out: r.stdout || "", err: (r.stderr || "").trim() };
  };
  let missed = 0;
  console.log(`bench-gate negative control: ${PLANTS.length} planted BENCHMARKS.md, every one must be refused`);
  try {
    PLANTS.forEach(([what, text], i) => {
      const r = gate(text, i);
      if (r.status === 1 && !r.out.includes("BENCH OK")) console.log(`  ok caught ${what}: ${r.err.replace(/^✗ /, "").split("\n")[0]}`);
      else { console.error(`  ✗ MISSED ${what}: the gate exited ${r.status}${r.out.includes("BENCH OK") ? " and printed BENCH OK" : ""}`); missed++; }
    });
    const want = `BENCH OK: full credential verify ${CEILING_US - 1} µs`;
    const control = gate(withCell(`${CEILING_US - 1} µs`), "control");
    if (control.status !== 0 || !control.out.includes(want)) {
      console.error(`  ✗ the in-ceiling control (${CEILING_US - 1} µs) was not passed as "${want}": the gate exited ${control.status}`);
      if (control.err) console.error(`    ${control.err.split("\n")[0]}`);
      missed++;
    } else console.log(`  ok passed the in-ceiling control (${CEILING_US - 1} µs, exit 0)`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  if (missed) { console.error(`BENCH-GATE NEGATIVE FAILED — ${missed} planted case(s) judged wrongly`); process.exit(1); }
  console.log(`BENCH-GATE NEGATIVE OK — all ${PLANTS.length} planted regressions refused, the in-ceiling control passed`);
  process.exit(0);
}

const r = judge(md);
if (r.fail) { for (const l of r.fail) console.error(l); process.exit(1); }
const { us } = r;
const claim = us < 1000 ? "sub-millisecond" : `${(us / 1000).toFixed(2)} ms`;
console.log(`BENCH OK: full credential verify ${us} µs (${claim}) — under the ${CEILING_US} µs ceiling.`);
console.log(`  nine steps, hybrid Ed25519 + ML-DSA-65, SLH-DSA checkpoint, RFC 6962 inclusion — measured, not asserted.`);
