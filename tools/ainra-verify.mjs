// SPDX-License-Identifier: Apache-2.0 OR MIT
// `ainra-verify` — the CI/edge verification step. Verifies an AINRA presentation bundle against a dual-root-signed
// directory and exits 0 (VALID) or 1 (INVALID) — fail closed. Drop it into a pipeline as an `ainra-verify` step,
// or run it at an edge to gate a request. No network, no state, no telemetry.
//
//   node tools/ainra-verify.mjs --directory dir.json --roots roots.json --bundle bundle.json [--now T] [--quiet]
//
// Exit codes: 0 VALID · 1 INVALID (reason on stderr) · 2 usage/untrusted-directory.

import { readFileSync } from "node:fs";
import { Verifier } from "../packages/sdk-ts/dist/index.js";

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : def;
}
const has = (name) => process.argv.includes(`--${name}`);

const dirPath = arg("directory");
const rootsPath = arg("roots");
const bundlePath = arg("bundle");
const quiet = has("quiet");
if (!dirPath || !rootsPath || !bundlePath) {
  console.error("usage: ainra-verify --directory D --roots R --bundle B [--now T] [--quiet]");
  process.exit(2);
}

let directory, roots, bundle;
try {
  directory = JSON.parse(readFileSync(dirPath, "utf8"));
  roots = JSON.parse(readFileSync(rootsPath, "utf8"));
  bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
} catch (e) {
  console.error(`ainra-verify: cannot read/parse inputs: ${e.message}`);
  process.exit(2);
}
const now = arg("now") ? Number(arg("now")) : Math.floor(Date.now() / 1000);

const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh);
if (!verifier) {
  console.error("ainra-verify: untrusted directory (not signed by the expected roots)");
  process.exit(2);
}

// `--bench N` — time N verifies of this bundle (the "how cheap is verification" number: it's LOCAL CPU, once per
// relationship). Verification is client-side, so N devices verifying is N × this, and the root does zero work.
const benchN = arg("bench");
if (benchN) {
  const n = Number(benchN) || 10000;
  verifier.verify(bundle, now); // warm
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < n; i++) verifier.verify(bundle, now);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  console.log(`ainra-verify bench: ${(ms / n).toFixed(3)} ms/verify · ${Math.round(n / (ms / 1000))} verifies/s (local, 1 core)`);
  process.exit(0);
}

const verdict = verifier.verify(bundle, now);
if (verdict.verdict === "valid") {
  if (!quiet) console.log("ainra-verify: VALID");
  process.exit(0);
}
console.error(`ainra-verify: INVALID (${verdict.reason})`);
process.exit(1);
