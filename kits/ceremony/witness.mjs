// SPDX-License-Identifier: Apache-2.0 OR MIT
// An independent WITNESS to the AINRA genesis ceremony (dry-run). It trusts nobody: it recomputes the ceremony
// transcript's hash itself, and checks every custodian's commit-reveal + signature. If the transcript hash it
// computes differs from the published one, or any custodian is missing or their reveal doesn't open their commit,
// it FAILS LOUDLY — the whole point of an on-camera, cross-witnessed ceremony.
//
//   node witness.mjs --dir <ceremony-dry-run-dir>
//
// The dir holds: transcript.json + transcript.sha256 (from the ceremony), ceremony-manifest.json (how many
// custodians were required + the coordinator's transcript hash), and operator-1..N.json (the commit-reveal records).

import { readFileSync, readdirSync } from "node:fs";
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : def;
}
const dir = arg("dir");
if (!dir) { console.error("usage: witness.mjs --dir <ceremony-dry-run-dir>"); process.exit(2); }

const sha256hex = (b) => createHash("sha256").update(b).digest("hex");
const sortedStringify = (o) => JSON.stringify(o, Object.keys(o).sort());
let ok = true;
const pass = (m) => console.log("  ✓ " + m);
const fail = (m) => { console.error("  ✗ " + m); ok = false; };

console.log(`witnessing ceremony dry-run in ${dir}\n`);
const manifest = JSON.parse(readFileSync(`${dir}/ceremony-manifest.json`, "utf8"));

// (1) THE core check: recompute the ceremony transcript's SHA-256 ourselves and confirm it matches BOTH the
// ceremony's own `transcript.sha256` AND the coordinator's manifest. A witness computes the same hash independently.
const tBytes = readFileSync(`${dir}/transcript.json`);
const computed = sha256hex(tBytes);
const published = readFileSync(`${dir}/transcript.sha256`, "utf8").trim();
computed === published
  ? pass(`transcript hash independently recomputed = published (${computed.slice(0, 16)}…)`)
  : fail(`transcript hash MISMATCH — computed ${computed.slice(0, 16)}… vs published ${published.slice(0, 16)}…`);
computed === manifest.ceremony_transcript_sha256
  ? pass("transcript hash matches the coordinator's manifest")
  : fail("transcript hash does NOT match the coordinator's manifest (tampered assembly)");

// (2) every required custodian committed, cross-read, and revealed — no step skipped.
const required = manifest.required_operators;
const present = readdirSync(dir).filter((f) => /^operator-\d+\.json$/.test(f)).length;
present === required
  ? pass(`all ${required} custodians present`)
  : fail(`only ${present}/${required} custodians present — A STEP WAS SKIPPED`);

for (let k = 1; k <= required; k++) {
  let rec;
  try { rec = JSON.parse(readFileSync(`${dir}/operator-${k}.json`, "utf8")); }
  catch { fail(`custodian ${k} missing`); continue; }
  const b = rec.body;
  // signature under the custodian's own key
  let sigOk = false;
  try {
    const pub = createPublicKey({ key: Buffer.from(b.pubkey_spki_b64, "base64"), format: "der", type: "spki" });
    sigOk = edVerify(null, Buffer.from(sortedStringify(b)), pub, Buffer.from(rec.sig_ed25519_b64, "base64"));
  } catch { /* sigOk stays false */ }
  // the reveal opens the commit
  const revealOk = sha256hex(Buffer.from(b.reveal_hex, "hex")) === b.commit_sha256;
  sigOk && revealOk
    ? pass(`custodian ${k}: signature valid + reveal opens commit`)
    : fail(`custodian ${k}: ${!sigOk ? "bad signature " : ""}${!revealOk ? "reveal does not open commit" : ""}`);
}

console.log("");
if (ok) { console.log("CEREMONY WITNESS: PASS — the transcript is what an independent party computes, and every custodian's part checks out."); process.exit(0); }
console.error("CEREMONY WITNESS: FAIL — the ceremony is not trustworthy as recorded.");
process.exit(1);
