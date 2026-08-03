// SPDX-License-Identifier: Apache-2.0 OR MIT
// Probe a witness candidacy's declared endpoint (L2 intake). Read-only, fail-closed, no secrets.
// It reports; it never accepts. Acceptance is a human decision recorded in witnesses/candidates.json.
//   node tools/witness-probe.mjs evidence/witness/<id>.json
import { readFileSync } from "node:fs";

const file = process.argv[2];
if (!file) { console.error("usage: node tools/witness-probe.mjs <candidacy.json>"); process.exit(2); }
const j = JSON.parse(readFileSync(file, "utf8"));
const base = String(j.endpoint || "").replace(/\/+$/, "");
if (!/^https?:\/\//.test(base)) { console.log(`✗ ${file}: endpoint is not an http(s) URL`); process.exit(1); }

const timeout = (ms) => new Promise((_, r) => setTimeout(() => r(new Error(`timeout after ${ms}ms`)), ms));
async function get(path) {
  const res = await Promise.race([fetch(base + path, { redirect: "error" }), timeout(8000)]);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

let fail = 0;
console.log(`probing ${j.candidate_id} → ${base}`);
try {
  const info = await get("/info");
  console.log(`  ✓ /info answered: ${JSON.stringify(info).slice(0, 160)}`);
  // the witness self-declares; we report what it says and whether the claim is coherent with the candidacy file
  const declaredOp = info.operator || info.name || "(none)";
  if (j.operator && declaredOp !== "(none)" && !String(declaredOp).toLowerCase().includes(String(j.operator).toLowerCase().slice(0, 6)))
    console.log(`  · note: endpoint self-declares operator "${declaredOp}", candidacy says "${j.operator}" — a human should reconcile`);
  const keyish = info.pubkey || info.public_key || info.key || info.ed25519 || info.cosign_key;
  if (!keyish) { console.log("  ✗ /info declares no public key — a witness without a published key cannot cosign verifiably"); fail++; }
  else console.log("  ✓ /info publishes a cosigning key");
} catch (e) {
  console.log(`  ✗ /info unreachable or malformed: ${e.message}`);
  fail++;
}
console.log(fail
  ? `\n✗ probe failed — candidacy cannot be evaluated (fail closed). This is not a rejection of the operator, only of the file as submitted.`
  : `\n✓ probe answered. NOT an acceptance: a candidacy confers no quorum standing; production witnesses are constituted through the charter process.`);
process.exit(fail ? 1 : 0);
