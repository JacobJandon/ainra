// SPDX-License-Identifier: Apache-2.0 OR MIT
// The site says verification happens "in milliseconds" and "offline in ~5 lines". Everywhere else in this
// repository a claim is backed by a gate; this makes the SPEED claim one too.
//
// It deliberately does NOT adopt a third-party benchmarking service or a new benchmark dependency: `make bench`
// already produces a real measurement from the existing vector corpus, and a neutral root should not put a vendor
// in the path of proving its own claim. This reads that output and fails if the number stops supporting the copy.
//
//   make bench && node tools/bench-gate.mjs
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
// The public claim is "milliseconds" (plural, small). The ceiling is deliberately ~4x the measured 456 µs so that
// ordinary host variance never fails the build, while a real regression — an accidental O(n²), a debug build, a
// dropped short-circuit — does. Raise it only with a measurement and a reason, never to make a red build green.
const CEILING_US = 2000;

const md = readFileSync(ROOT + "docs/BENCHMARKS.md", "utf8");
const row = md.split("\n").find((l) => /Full credential verify/i.test(l));
if (!row) { console.error("✗ BENCHMARKS.md has no verify row — run `make bench` first"); process.exit(1); }

const m = row.match(/\|\s*([\d.]+)\s*(µs|us|ms|ns)\s*\|/);
if (!m) { console.error(`✗ could not read a per-op figure from:\n  ${row.trim()}`); process.exit(1); }
const [, n, unit] = m;
const us = { ns: +n / 1000, "µs": +n, us: +n, ms: +n * 1000 }[unit];

const claim = us < 1000 ? "sub-millisecond" : `${(us / 1000).toFixed(2)} ms`;
if (us > CEILING_US) {
  console.error(`✗ verify is ${us} µs — over the ${CEILING_US} µs ceiling.`);
  console.error(`  The site claims verification takes milliseconds. Either the regression is real and gets fixed,`);
  console.error(`  or the claim changes. Do not raise the ceiling to make this pass.`);
  process.exit(1);
}
console.log(`BENCH OK: full credential verify ${us} µs (${claim}) — under the ${CEILING_US} µs ceiling.`);
console.log(`  nine steps, hybrid Ed25519 + ML-DSA-65, SLH-DSA checkpoint, RFC 6962 inclusion — measured, not asserted.`);
