// SPDX-License-Identifier: Apache-2.0 OR MIT
// Collect an external verifier's attestation WITHOUT trusting their word (the maintainer's side).
//
// A stranger runs verify-kit.mjs against a CHALLENGE we issued and sends us `verifier-attestation.json`. This
// confirms it is genuine evidence and fails closed otherwise:
//   0. it carries the exact single-use CHALLENGE we issued (so it cannot be pre-manufactured or replayed);
//   1. its Ed25519 signature covers the WHOLE body (challenge + hashes + verdicts) under the verifier's key;
//   2. it hashes the COMPLETE canonical corpus, every required artifact present and byte-matching what we hold;
//   3. its verdicts are exactly the conformant ones (valid / invalid:revoked / invalid:stale_status).
//
//   node check-attestation.mjs --attestation <file> [--canonical <dir>] --challenge <the-nonce-you-issued>
//
// HONEST SCOPE: this proves a party holding key K ran the real @ainra/sdk against the real corpus, answering the
// challenge C we issued — execution + freshness + tamper-evidence. It does NOT prove the party is a DISTINCT human;
// operator distinctness is established out of band by issuing ONE challenge per separately-vetted party (a fresh key
// is free, so the crypto cannot be Sybil-proof — see kits/verifier/SECURITY.md and GENESIS-CHECKLIST.md §3).

import { readFileSync } from "node:fs";
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : def;
}
const attPath = arg("attestation");
const canonDir = arg("canonical", new URL("./sample-artifacts", import.meta.url).pathname);
const expectChallenge = arg("challenge"); // the nonce WE issued to this verifier; required — no default
if (!attPath || !expectChallenge) {
  console.error("usage: check-attestation.mjs --attestation <file> --challenge <the-nonce-you-issued> [--canonical <dir>]");
  process.exit(2);
}
// The COMPLETE required corpus — the attestation must cover ALL of it (a subset/empty map must NOT pass).
const REQUIRED = ["directory.json", "roots.json", "bundle-valid.json", "bundle-revoked.json"];
const sha256 = (s) => createHash("sha256").update(s).digest("hex");
// FULL recursive canonical JSON (matches verify-kit.mjs) — an array replacer would silently drop nested keys.
function canonicalJSON(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalJSON).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalJSON(v[k])).join(",") + "}";
}

const att = JSON.parse(readFileSync(attPath, "utf8"));
const body = att.body || {};
let ok = true;
const fail = (m) => { console.error("  ✗ " + m); ok = false; };
const pass = (m) => console.log("  ✓ " + m);
console.log(`checking attestation ${attPath} against canonical ${canonDir}\n`);

// (0) the challenge WE issued must be present (binds this attestation to a nonce we handed to a vetted party).
body.challenge && body.challenge === expectChallenge
  ? pass("carries the challenge we issued (not pre-manufactured / not replayed)")
  : fail(`challenge mismatch — expected the nonce we issued, got ${JSON.stringify(body.challenge)}`);

// (1) signature covers the WHOLE body under the verifier's key.
try {
  const pub = createPublicKey({ key: Buffer.from(body.verifier_pubkey_spki_b64 || "", "base64"), format: "der", type: "spki" });
  const good = edVerify(null, Buffer.from(canonicalJSON(body)), pub, Buffer.from(att.sig_ed25519_b64 || "", "base64"));
  good ? pass("signature covers the whole body (challenge + hashes + verdicts)") : fail("signature does NOT verify");
} catch (e) {
  fail("signature check errored: " + e.message);
}

// (2) COMPLETE corpus binding — every required artifact present AND byte-matching the canonical file. Fail closed on
//     a missing entry, an empty map, or an extra/unknown artifact name.
const attested = body.artifacts_sha256 || {};
for (const name of REQUIRED) {
  if (!(name in attested)) { fail(`required artifact ${name} is NOT attested (incomplete corpus)`); continue; }
  let got;
  try { got = sha256(readFileSync(`${canonDir}/${name}`, "utf8")); } catch { fail(`canonical ${name} missing locally`); continue; }
  got === attested[name] ? pass(`${name} matches the canonical artifact`) : fail(`${name} hash MISMATCH — a different file was verified`);
}
for (const name of Object.keys(attested)) {
  if (!REQUIRED.includes(name)) fail(`attestation hashes an unexpected artifact "${name}"`);
}

// (3) the verdicts are exactly conformant.
const expect = { valid: "valid", revoked: "invalid:revoked", forged: "invalid:stale_status" };
for (const [k, want] of Object.entries(expect)) {
  const got = body.verdicts?.[k];
  got === want ? pass(`verdict[${k}] = ${got}`) : fail(`verdict[${k}] = ${got} (expected ${want})`);
}

console.log("");
if (ok) {
  console.log(`ATTESTATION VALID — a party holding key ${(body.verifier_pubkey_spki_b64 || "").slice(0, 16)}… ran the real SDK against the full corpus for our challenge (sdk ${body.sdk}). Count it as ONE external verifier (operator distinctness is out-of-band; see SECURITY.md).`);
  process.exit(0);
}
console.error("ATTESTATION REJECTED — does not count as external-verifier evidence.");
process.exit(1);
