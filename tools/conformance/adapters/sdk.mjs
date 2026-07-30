// SPDX-License-Identifier: Apache-2.0 OR MIT
// Conformance adapter for the TypeScript SDK (packages/sdk-ts), fitting tools/conformance/CONTRACT.md. Reads the
// runner's JSON-Lines vectors on stdin, runs the REAL published sdk-ts verifier (runVector / runDeltaVector /
// runDirectoryVector from dist), and prints one `<name>\t<result-json>` line per vector. No files, no network.
//
//   node tools/conformance/adapters/sdk.mjs <passport|delta|directory>   (requires: cd packages/sdk-ts && npm run build)
import { runVector, runDeltaVector, runDirectoryVector } from "../../../packages/sdk-ts/dist/index.js";

const stable = (o) =>
  o === null || typeof o !== "object"
    ? JSON.stringify(o)
    : Array.isArray(o)
      ? `[${o.map(stable).join(",")}]`
      : `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${stable(o[k])}`).join(",")}}`;

function result(kind, v) {
  if (kind === "passport") return runVector(v);
  if (kind === "delta") return runDeltaVector(v);
  if (kind === "directory") return runDirectoryVector(v);
  throw new Error(`unknown kind: ${kind}`);
}

async function main() {
  const kind = process.argv[2];
  if (!kind) {
    console.error("usage: node sdk.mjs <passport|delta|directory>  (vectors as JSON Lines on stdin)");
    process.exit(2);
  }
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
  console.error(`sdk adapter error: ${e.message}`);
  process.exit(1);
});
