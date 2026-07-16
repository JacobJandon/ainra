// SPDX-License-Identifier: Apache-2.0 OR MIT
// Collect an external verifier's attestation WITHOUT trusting their word (the maintainer's side).
//
// A stranger runs verify-kit.mjs and sends us `verifier-attestation.json`. This confirms it is genuine evidence:
//   1. the attestation's Ed25519 signature verifies under the verifier's own published public key (tamper-evident);
//   2. the artifact hashes they attest to match the CANONICAL published artifacts we hold (they verified the REAL
//      corpus, not a doctored one);
//   3. their verdicts are exactly the conformant ones (VALID / invalid:revoked / invalid:stale_status).
// If all three hold, the attestation counts toward the §29 "≥3 external verifiers" bar — no trust in the submitter.
//
//   node check-attestation.mjs --attestation <file> --canonical <dir-of-published-artifacts>

import { readFileSync } from "node:fs";
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : def;
}
const attPath = arg("attestation");
const canonDir = arg("canonical", new URL("./sample-artifacts", import.meta.url).pathname);
if (!attPath) {
  console.error("usage: check-attestation.mjs --attestation <file> --canonical <dir>");
  process.exit(2);
}
const sha256 = (s) => createHash("sha256").update(s).digest("hex");
const sortedStringify = (o) => JSON.stringify(o, Object.keys(o).sort());

const att = JSON.parse(readFileSync(attPath, "utf8"));
const body = att.body;
let ok = true;
const fail = (m) => { console.error("  ✗ " + m); ok = false; };
const pass = (m) => console.log("  ✓ " + m);

console.log(`checking attestation ${attPath} against canonical ${canonDir}\n`);

// (1) signature verifies under the verifier's own key.
try {
  const pub = createPublicKey({ key: Buffer.from(body.verifier_pubkey_spki_b64, "base64"), format: "der", type: "spki" });
  const good = edVerify(null, Buffer.from(sortedStringify(body)), pub, Buffer.from(att.sig_ed25519_b64, "base64"));
  good ? pass("signature verifies under the verifier's published key") : fail("signature does NOT verify");
} catch (e) {
  fail("signature check errored: " + e.message);
}

// (2) the artifacts they hashed are the CANONICAL published ones (not a doctored corpus).
for (const [name, want] of Object.entries(body.artifacts_sha256 || {})) {
  let got;
  try { got = sha256(readFileSync(`${canonDir}/${name}`, "utf8")); } catch { fail(`canonical ${name} missing locally`); continue; }
  got === want ? pass(`${name} matches the canonical artifact`) : fail(`${name} hash MISMATCH — they verified a different file`);
}

// (3) the verdicts are exactly conformant.
const expect = { valid: "valid", revoked: "invalid:revoked", forged: "invalid:stale_status" };
for (const [k, want] of Object.entries(expect)) {
  const got = body.verdicts?.[k];
  got === want ? pass(`verdict[${k}] = ${got}`) : fail(`verdict[${k}] = ${got} (expected ${want})`);
}

console.log("");
if (ok) {
  console.log(`ATTESTATION VALID — this is a genuine external-verifier result (verifier key ${body.verifier_pubkey_spki_b64.slice(0, 16)}…, sdk ${body.sdk}).`);
  process.exit(0);
}
console.error("ATTESTATION REJECTED — does not count as external-verifier evidence.");
process.exit(1);
