// SPDX-License-Identifier: Apache-2.0 OR MIT
// Collect an external verifier's attestation WITHOUT trusting their word (the maintainer's side).
//
// A stranger runs verify-kit.mjs against (1) the published sample corpus and (2) a FRESH challenge corpus we minted
// for them (mint-challenge.mjs), then sends us `verifier-attestation.json`. We confirm it is genuine EXECUTION
// evidence and fail closed otherwise:
//   0. it carries the exact single-use CHALLENGE nonce we issued (not pre-manufactured / not replayed);
//   1. its Ed25519 signature covers the WHOLE body under the verifier's key;
//   2. it hashes the COMPLETE sample corpus, every required artifact present and byte-matching (the on-screen demo);
//   3. its sample verdicts are the conformant ones (valid / invalid:revoked / invalid:stale_status);
//   4. THE DECISIVE CHECK — its verdicts on our FRESH challenge bundles match our private ANSWER KEY exactly, over a
//      corpus byte-identical to the one we minted. The revocation state of each challenge bundle was a secret coin
//      flip we never published, so a party who did not actually verify must guess all K (success 2^-K).
//
//   node check-attestation.mjs --attestation <file> --challenge <nonce> --secret <the-answer-key.json> [--canonical <dir>]
//
// WHAT A PASS PROVES (honest): a party holding key K, answering the challenge C we issued, CORRECTLY VERIFIED K fresh
// bundles whose answers we never published — i.e. they actually performed AINRA verification (not merely asserted the
// public sample constants). It does NOT prove they used our exact @ainra/sdk BINARY vs. a conformant reimplementation,
// and it does NOT prove they are a DISTINCT human — operator distinctness is established out of band by minting ONE
// challenge per separately-vetted party (see SECURITY.md, GENESIS-CHECKLIST §3).

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : def;
}
const attPath = arg("attestation");
const canonDir = arg("canonical", new URL("./sample-artifacts", import.meta.url).pathname);
const expectChallenge = arg("challenge"); // the nonce WE issued to this verifier; required — no default
const secretPath = arg("secret"); // the private answer key from mint-challenge.mjs; required to COUNT as a verifier
// --party <id> (operator flow): on success, write a durable evidence file `make genesis-status` reads (never the secret).
const party = arg("party", "");
const evidenceOut = arg("evidence-out", party ? `evidence/verifier/${party}.json` : "");
if (!attPath || !expectChallenge || !secretPath) {
  console.error("usage: check-attestation.mjs --attestation <file> --challenge <the-nonce-you-issued> --secret <answer-key.json> [--canonical <dir>]");
  console.error("  (--secret is REQUIRED: without the private answer key, execution cannot be checked and the attestation cannot count.)");
  process.exit(2);
}
// The COMPLETE required SAMPLE corpus — the attestation must cover ALL of it (a subset/empty map must NOT pass).
const REQUIRED = ["directory.json", "roots.json", "bundle-valid.json", "bundle-revoked.json"];
const sha256 = (s) => createHash("sha256").update(s).digest("hex");
// FULL recursive canonical JSON (matches verify-kit.mjs) — an array replacer would silently drop nested keys.
function canonicalJSON(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalJSON).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalJSON(v[k])).join(",") + "}";
}
const eqArr = (a, b) => Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => x === b[i]);

const att = JSON.parse(readFileSync(attPath, "utf8"));
const body = att.body || {};
const secret = JSON.parse(readFileSync(secretPath, "utf8"));
let ok = true;
const fail = (m) => { console.error("  ✗ " + m); ok = false; };
const pass = (m) => console.log("  ✓ " + m);
console.log(`checking attestation ${attPath} against canonical ${canonDir} + secret ${secretPath}\n`);

// (0) the challenge WE issued must be present AND match the answer key's nonce (binds attestation ↔ this challenge).
body.challenge && body.challenge === expectChallenge && secret.nonce === expectChallenge
  ? pass("carries the challenge we issued (not pre-manufactured / not replayed) and it matches the answer key")
  : fail(`challenge mismatch — attestation ${JSON.stringify(body.challenge)}, answer-key ${JSON.stringify(secret.nonce)}, expected ${JSON.stringify(expectChallenge)}`);

// (1) signature covers the WHOLE body under the verifier's key.
try {
  const pub = createPublicKey({ key: Buffer.from(body.verifier_pubkey_spki_b64 || "", "base64"), format: "der", type: "spki" });
  const good = edVerify(null, Buffer.from(canonicalJSON(body)), pub, Buffer.from(att.sig_ed25519_b64 || "", "base64"));
  good ? pass("signature covers the whole body (challenge + hashes + verdicts + execution binding)") : fail("signature does NOT verify");
} catch (e) {
  fail("signature check errored: " + e.message);
}

// (2) COMPLETE sample-corpus binding — every required artifact present AND byte-matching. Fail closed on a missing
//     entry, an empty map, or an extra/unknown artifact name. (This is the on-screen demo; step 4 is the real gate.)
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

// (3) the sample verdicts are exactly conformant.
const expect = { valid: "valid", revoked: "invalid:revoked", forged: "invalid:stale_status" };
for (const [k, want] of Object.entries(expect)) {
  const got = body.verdicts?.[k];
  got === want ? pass(`sample verdict[${k}] = ${got}`) : fail(`sample verdict[${k}] = ${got} (expected ${want})`);
}

// (4) THE DECISIVE EXECUTION CHECK — the fresh challenge corpus. The attestation MUST be execution-bound, cover the
//     exact corpus we minted (byte-identical hashes), and its per-bundle verdicts MUST equal our private answer key.
if (body.execution_bound !== true) {
  fail("attestation is NOT execution-bound (no --challenge-dir was verified) — conformance-only cannot count as an external verifier");
} else {
  const corpus = body.challenge_corpus_sha256 || {};
  const want = secret.corpus_sha256 || {};
  const wantNames = Object.keys(want).sort();
  const gotNames = Object.keys(corpus).sort();
  if (!eqArr(wantNames, gotNames)) {
    fail(`challenge corpus set differs from the answer key (got ${gotNames.length} files, expected ${wantNames.length})`);
  } else {
    let corpusOk = true;
    for (const name of wantNames) if (corpus[name] !== want[name]) { fail(`challenge ${name} hash MISMATCH — a different bundle was verified than we minted`); corpusOk = false; }
    if (corpusOk) pass(`verified the exact fresh challenge corpus we minted (${wantNames.length} files byte-identical)`);
  }
  // the answer key: EVERY per-bundle verdict must match, over the count we minted.
  if (!Array.isArray(body.challenge_verdicts) || body.challenge_verdicts.length !== secret.expected.length) {
    fail(`challenge verdict count ${body.challenge_verdicts?.length} != minted count ${secret.expected.length}`);
  } else if (!eqArr(body.challenge_verdicts, secret.expected)) {
    const wrong = secret.expected.reduce((n, v, i) => n + (v === body.challenge_verdicts[i] ? 0 : 1), 0);
    fail(`${wrong}/${secret.expected.length} challenge verdicts WRONG — did not actually verify the fresh bundles (guessing succeeds only ${secret.forge_probability || "2^-K"})`);
  } else {
    pass(`all ${secret.expected.length} fresh-challenge verdicts match the private answer key (forge probability ${secret.forge_probability || "2^-K"})`);
  }
}

console.log("");
if (ok) {
  console.log(`ATTESTATION VALID (EXECUTION-BOUND) — a party holding key ${(body.verifier_pubkey_spki_b64 || "").slice(0, 16)}… CORRECTLY VERIFIED ${secret.expected.length} fresh bundles whose answers we never published, root-dark, for challenge ${expectChallenge} (sdk ${body.sdk}). They actually performed AINRA verification. Count it as ONE external verifier (this does NOT prove the exact binary vs. a conformant reimplementation, nor operator distinctness — that is out-of-band; see SECURITY.md).`);
  // Durable evidence the genesis board reads. It embeds the FULL attestation (so the board re-checks the signature
  // independently) + the operator's answer-key verdict + the answer-key HASH (auditable), but NEVER the secret itself.
  if (evidenceOut) {
    const evidence = {
      kind: "ainra/verifier-evidence/v1",
      party: party || null,
      valid: true,
      verifier_pubkey_spki_b64: body.verifier_pubkey_spki_b64,
      challenge_nonce: expectChallenge,
      challenge_count: secret.expected.length,
      forge_probability: secret.forge_probability || `2^-${secret.expected.length}`,
      answer_key_sha256: sha256(JSON.stringify(secret)), // auditable link to the key, without exposing it
      attestation: att, // full body+sig, so the board verifies the signature without needing the private key
      note: "Execution-bound: challenge verdicts matched the private answer key. Distinctness is out-of-band (one challenge per vetted party).",
    };
    try { mkdirSync(dirname(evidenceOut), { recursive: true }); } catch { /* exists */ }
    writeFileSync(evidenceOut, JSON.stringify(evidence, null, 2) + "\n");
    console.log(`  → wrote evidence ${evidenceOut} (no secret inside) — 'make genesis-status' now counts ${party ? `"${party}"` : "this verifier"}.`);
  }
  process.exit(0);
}
console.error("ATTESTATION REJECTED — does not count as external-verifier evidence.");
process.exit(1);
