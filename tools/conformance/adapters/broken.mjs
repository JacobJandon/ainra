// SPDX-License-Identifier: Apache-2.0 OR MIT
// A DELIBERATELY BROKEN implementation (M24 Task 2b) — the proof the runner detects nonconformance. A conformance
// tool that cannot fail is theatre: this adapter is a verifier with ONE realistic bug — it skips the credential
// validity-window checks, so it wrongly ACCEPTS an expired or not-yet-valid credential as valid. Every other class
// (and all delta/directory vectors) it gets right, so the runner's report names EXACTLY the vectors it breaks:
// `expected {"reason":"expired","verdict":"invalid"} got {"verdict":"valid"}`. Run the runner against this and it
// MUST fail with those named divergences. Not shipped, not on any conformance path — it exists only to be caught.
import { runVector, runDeltaVector, runDirectoryVector } from "../../../packages/sdk-ts/dist/index.js";

const stable = (o) =>
  o === null || typeof o !== "object"
    ? JSON.stringify(o)
    : Array.isArray(o)
      ? `[${o.map(stable).join(",")}]`
      : `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${stable(o[k])}`).join(",")}}`;

// The bug: a verifier that never checks exp/nbf silently upgrades those rejections to "valid".
const SKIPPED = new Set(["expired", "not_yet_valid"]);

function result(kind, v) {
  if (kind === "delta") return runDeltaVector(v);
  if (kind === "directory") return runDirectoryVector(v);
  if (kind === "passport") {
    const r = runVector(v);
    if (r.verdict === "invalid" && SKIPPED.has(r.reason)) return { verdict: "valid" }; // ← the sabotage
    return r;
  }
  throw new Error(`unknown kind: ${kind}`);
}

async function main() {
  const kind = process.argv[2];
  let input = "";
  for await (const chunk of process.stdin) input += chunk;
  const out = [];
  for (const line of input.split("\n")) {
    if (!line.trim()) continue;
    const v = JSON.parse(line);
    out.push(`${v.name}\t${stable(result(kind, v))}`);
  }
  process.stdout.write(out.join("\n") + (out.length ? "\n" : ""));
}

main().catch((e) => {
  console.error(`broken adapter error: ${e.message}`);
  process.exit(1);
});
