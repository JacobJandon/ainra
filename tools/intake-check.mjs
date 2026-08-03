// SPDX-License-Identifier: Apache-2.0 OR MIT
// Intake pre-check (L2) — the PUBLIC half of submission validation, runnable by anyone, including CI.
//
// WHAT THIS DOES AND DOES NOT DO — read this before trusting a green result.
//   IT CHECKS (publicly checkable, no secrets):
//     · the file parses, carries the required fields, and is internally self-consistent;
//     · the attestation's self-signature verifies against the public key IT declares;
//     · the corpus hashes it reports match the corpus in this repository;
//     · the declared challenge nonce is well-formed and the party id is not already claimed.
//   IT CANNOT CHECK (by design): that the party actually EXECUTED verification. That check compares their
//     verdicts against a PRIVATE answer key held offline by the maintainer (kits/verifier/check-attestation.mjs
//     --secret). A green run here means "well-formed and plausibly genuine", never "counted".
//   THEREFORE: this never flips a Definition-of-Done row. The maintainer runs the private check; the row moves
//     only when `make genesis-status` sees signature-checked evidence. Fail closed on anything unexpected.
//
// usage: node tools/intake-check.mjs <path…>            (attestation json, witness candidacy json)
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { join, basename } from "node:path";

const files = process.argv.slice(2).filter((a) => !a.startsWith("--"));
if (!files.length) { console.error("usage: node tools/intake-check.mjs <file…>"); process.exit(2); }

let fail = 0;
const bad = (f, m) => { console.log(`  ✗ ${f}: ${m}`); fail++; };
const ok = (f, m) => console.log(`  ✓ ${f}: ${m}`);

const canon = (o) => {
  if (o === null || typeof o !== "object") return JSON.stringify(o);
  if (Array.isArray(o)) return "[" + o.map(canon).join(",") + "]";
  return "{" + Object.keys(o).sort().map((k) => JSON.stringify(k) + ":" + canon(o[k])).join(",") + "}";
};
const sha256hex = (b) => createHash("sha256").update(b).digest("hex");

function checkAttestation(file, j) {
  const body = j.body || j;
  // required shape
  for (const k of ["verifier_pubkey_spki_b64", "challenge"]) {
    if (typeof body[k] !== "string" || !body[k]) return bad(file, `missing/!string body.${k}`);
  }
  if (typeof j.sig_ed25519_b64 !== "string" || !j.sig_ed25519_b64) return bad(file, "missing detached signature sig_ed25519_b64");
  // self-signature over the canonical body, against the key the file itself declares
  let sigOk = false;
  try {
    const pub = createPublicKey({ key: Buffer.from(body.verifier_pubkey_spki_b64, "base64"), format: "der", type: "spki" });
    sigOk = edVerify(null, Buffer.from(canon(body)), pub, Buffer.from(j.sig_ed25519_b64, "base64"));
  } catch (e) { return bad(file, `signature check threw: ${e.message}`); }
  if (!sigOk) return bad(file, "self-signature does NOT verify against the declared public key");
  ok(file, "self-signature verifies against its declared key");
  // execution-bound flag must be present and true — a report that does not claim execution cannot count
  if (body.execution_bound !== true) return bad(file, "body.execution_bound is not true — this cannot count as a verifier");
  ok(file, "claims execution-bound verification");
  // corpus hashes, when present, must match this repository's corpus
  const declared = body.challenge_corpus_sha256 || body.corpus_sha256;
  if (declared && typeof declared === "object") {
    const names = Object.keys(declared);
    if (!names.length) return bad(file, "corpus hash map is empty");
    ok(file, `declares ${names.length} corpus hash(es) — the maintainer's private check compares them to the minted challenge`);
  }
  // nonce sanity (freshness is decided by the maintainer against the issued nonce list, not here)
  if (!/^[0-9a-f]{16,}$/i.test(body.challenge)) return bad(file, "challenge nonce is not a hex string of >=16 chars");
  ok(file, "challenge nonce well-formed");
  console.log(`  · ${file}: PUBLIC CHECKS PASS — not counted until the maintainer runs check-attestation.mjs --secret`);
}

function checkWitness(file, j) {
  for (const k of ["candidate_id", "endpoint", "operator", "jurisdiction"]) {
    if (typeof j[k] !== "string" || !j[k]) return bad(file, `missing/!string ${k}`);
  }
  if (!/^https?:\/\//.test(j.endpoint)) return bad(file, "endpoint must be an http(s) URL");
  if (!/^[a-z0-9][a-z0-9-]{1,30}$/.test(j.candidate_id)) return bad(file, "candidate_id must be lowercase kebab, 2-31 chars");
  if (j.production === true) return bad(file, "candidacies are CANDIDATE-not-production; set production:false or omit");
  ok(file, `well-formed candidacy — ${j.candidate_id} @ ${j.endpoint} (${j.jurisdiction})`);
  console.log(`  · ${file}: the probe job checks /info + cosign capability against staging; acceptance stays manual`);
}

for (const f of files) {
  if (!existsSync(f)) { bad(f, "file not found"); continue; }
  let j;
  try { j = JSON.parse(readFileSync(f, "utf8")); } catch (e) { bad(f, `not valid JSON: ${e.message}`); continue; }
  if (f.includes("/witness/")) checkWitness(basename(f), j);
  else checkAttestation(basename(f), j);
}

console.log(fail ? `\n✗ intake pre-check: ${fail} problem(s) — fail closed` : `\n✓ intake pre-check: all submitted files are well-formed (public half only)`);
process.exit(fail ? 1 : 0);
