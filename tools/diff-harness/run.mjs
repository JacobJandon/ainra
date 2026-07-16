// SPDX-License-Identifier: Apache-2.0 OR MIT
// 3-way differential harness. Exit nonzero unless every implementation agrees.
//
//   (A) Verdict differential — ainra-core (the recorded verdict in each CC0 vector) vs sdk-ts `runVector`, over the
//       whole corpus. ainra-core produced those verdicts (its generator self-checks them), so agreement here is a
//       true core-vs-sdk cross-check on every reason.
//   (B) Canonical-encoding 3-way — the SAME JSON inputs through ainra-core's canon (shelled), sdk-ts `canonicalize`,
//       and the P0 cli-node `cjson` (extracted from source, never edited/executed). All three MUST be byte-identical
//       for conformant inputs (property P-5).
//   (C) Canon rejection agreement — divergent inputs (float / non-ASCII key / out-of-range int) that ainra-core and
//       sdk-ts both refuse (P0's cjson has no such guard, so it is excluded from C by design).

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { runVector, expectedVerdict, canonicalize, runDeltaVector, runDirectoryVector } from "../../packages/sdk-ts/dist/index.js";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const VEC = path.join(ROOT, "vectors/v1");
const VEC_DELTA = path.join(ROOT, "vectors/v1-delta");
const VEC_DIR = path.join(ROOT, "vectors/v1-directory");
const P0 = path.join(ROOT, "apps/cli-node/bin/ainra.js");
let failures = 0;

function rustCanon(inputs) {
  const tmp = path.join(os.tmpdir(), `ainra-canon-${process.pid}.jsonl`);
  fs.writeFileSync(tmp, inputs.map((x) => JSON.stringify(x)).join("\n") + "\n");
  try {
    const out = execFileSync("cargo", ["run", "--release", "-q", "-p", "ainra-vector-gen", "--", "--canon", tmp], {
      cwd: ROOT,
      encoding: "utf8",
    });
    return out.replace(/\n$/, "").split("\n");
  } finally {
    fs.unlinkSync(tmp);
  }
}

// ── (A) Verdict differential ──────────────────────────────────────────────────────────────────────────────────
const files = fs.readdirSync(VEC).filter((f) => f.endsWith(".json") && f !== "manifest.json");
let vpass = 0;
for (const f of files) {
  const v = JSON.parse(fs.readFileSync(path.join(VEC, f), "utf8"));
  const got = JSON.stringify(runVector(v));
  const want = JSON.stringify(expectedVerdict(v));
  if (got === want) vpass++;
  else {
    failures++;
    console.error(`  VERDICT MISMATCH ${v.name}: core=${want} sdk=${got}`);
  }
}
console.log(`(A) verdict diff  core↔sdk : ${vpass}/${files.length} agree`);

// ── (B) Canonical-encoding 3-way ──────────────────────────────────────────────────────────────────────────────
const src = fs.readFileSync(P0, "utf8");
const m = src.match(/function cjson\(o\)[\s\S]*?\n\}/);
if (!m) {
  console.error("could not extract P0 cjson from source");
  process.exit(1);
}
const cjson = new Function(m[0] + "\nreturn cjson;")(); // P0's real canonical encoder, unmodified

const acceptInputs = [
  { b: 1, a: { z: true, y: [3, 2, 1] }, c: 'x"q' }, // the golden case
  { iss: "did:ainra:registrar-07:acme:invoicing", caps: ["read:x", "sign:y"], n: 9007199254740991 },
  { s: "x\"q\\y\nz\ttab", u: "café ünïcode 日本語 value" }, // non-ASCII in a VALUE (allowed), escapes
  [1, 2, 3, { k: null, j: false }],
  "just a string",
  42,
  true,
  null,
  { nested: { deep: { deeper: ["a", "b"] } }, arr: [] },
  { zzz: 1, aaa: 2, mmm: { qqq: 9, bbb: 8 } }, // key-sort at multiple levels
];
const rustAccept = rustCanon(acceptInputs);
let cpass = 0;
acceptInputs.forEach((inp, i) => {
  const sdkC = canonicalize(inp);
  const p0C = cjson(inp);
  const rustC = rustAccept[i];
  if (sdkC === p0C && sdkC === rustC) cpass++;
  else {
    failures++;
    console.error(`  CANON MISMATCH #${i}: rust=${JSON.stringify(rustC)} sdk=${JSON.stringify(sdkC)} p0=${JSON.stringify(p0C)}`);
  }
});
console.log(`(B) canon 3-way  core↔sdk↔P0 : ${cpass}/${acceptInputs.length} byte-identical`);

// ── (C) Canon rejection agreement (core vs sdk) ───────────────────────────────────────────────────────────────
const rejectInputs = [
  { x: 1.5 }, // float
  { "\u{1F600}": 1 }, // astral-plane key
  { café: 1 }, // BMP non-ASCII key
  { n: 9007199254740992 }, // 2^53
];
const rustReject = rustCanon(rejectInputs);
let rpass = 0;
rejectInputs.forEach((inp, i) => {
  let sdkRejected = false;
  try {
    canonicalize(inp);
  } catch {
    sdkRejected = true;
  }
  const rustRejected = rustReject[i] === "REJECT";
  if (sdkRejected && rustRejected) rpass++;
  else {
    failures++;
    console.error(`  REJECT DISAGREE #${i}: rustRejected=${rustRejected} sdkRejected=${sdkRejected}`);
  }
});
console.log(`(C) canon reject core↔sdk : ${rpass}/${rejectInputs.length} both refuse`);

// ── (D) Delta / fresh-head differential (core-baked expect vs sdk runDeltaVector) ─────────────────────────────
if (fs.existsSync(VEC_DELTA)) {
  const dfiles = fs.readdirSync(VEC_DELTA).filter((f) => f.endsWith(".json") && f !== "manifest.json");
  let dpass = 0;
  for (const f of dfiles) {
    const v = JSON.parse(fs.readFileSync(path.join(VEC_DELTA, f), "utf8"));
    const got = JSON.stringify(runDeltaVector(v));
    const want = JSON.stringify(v.expect.accept ? { accept: true } : { accept: false, reason: v.expect.reason });
    if (got === want) dpass++;
    else {
      failures++;
      console.error(`  DELTA MISMATCH ${v.name}: core=${want} sdk=${got}`);
    }
  }
  console.log(`(D) delta diff   core↔sdk : ${dpass}/${dfiles.length} agree`);
}

// ── (E) Directory differential (core-baked expect vs sdk runDirectoryVector) ──────────────────────────────────
if (fs.existsSync(VEC_DIR)) {
  const dfiles = fs.readdirSync(VEC_DIR).filter((f) => f.endsWith(".json") && f !== "manifest.json");
  let epass = 0;
  for (const f of dfiles) {
    const v = JSON.parse(fs.readFileSync(path.join(VEC_DIR, f), "utf8"));
    const got = JSON.stringify(runDirectoryVector(v));
    const want = JSON.stringify(v.expect.accept ? { accept: true, registrars: v.expect.registrars } : { accept: false });
    if (got === want) epass++;
    else {
      failures++;
      console.error(`  DIRECTORY MISMATCH ${v.name}: core=${want} sdk=${got}`);
    }
  }
  console.log(`(E) directory diff core↔sdk : ${epass}/${dfiles.length} agree`);
}

if (failures) {
  console.error(`\nDIFF FAILED: ${failures} disagreement(s)`);
  process.exit(1);
}
console.log("\nDIFF OK: all implementations agree");
