// SPDX-License-Identifier: Apache-2.0 OR MIT
// The AINRA verification wedge, in 5 lines. Local, offline, fail-closed — no network, no fee, no rate limit.
//
//   Run:  node examples/verify-5-lines.mjs <directory.json> <roots.json> <bundle.json> [now]
//   In your app you'd write the SAME five lines against `@ainra/sdk`:
//
//     import { Verifier } from "@ainra/sdk";
//     const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh);
//     const verdict  = verifier.verify(bundle, Math.floor(Date.now() / 1000));
//     if (verdict.verdict !== "valid") deny(verdict.reason);
//     // else: the agent's passport is genuine, current, logged, and not revoked.

import { readFileSync } from "node:fs";
import { Verifier } from "../packages/sdk-ts/dist/index.js"; // published form: import { Verifier } from "@ainra/sdk";

const [dirPath, rootsPath, bundlePath, nowArg] = process.argv.slice(2);
if (!dirPath || !rootsPath || !bundlePath) {
  console.error("usage: node verify-5-lines.mjs <directory.json> <roots.json> <bundle.json> [now]");
  process.exit(2);
}
const directory = JSON.parse(readFileSync(dirPath, "utf8"));
const roots = JSON.parse(readFileSync(rootsPath, "utf8"));
const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
const now = nowArg ? Number(nowArg) : Math.floor(Date.now() / 1000);

// ── the whole thing ──────────────────────────────────────────────────────────────────────────────────────────
const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh);
if (!verifier) {
  console.error("untrusted directory — not signed by the expected roots");
  process.exit(2);
}
const verdict = verifier.verify(bundle, now);
console.log(verdict.verdict === "valid" ? "VALID" : `INVALID (${verdict.reason})`);
process.exit(verdict.verdict === "valid" ? 0 : 1);
