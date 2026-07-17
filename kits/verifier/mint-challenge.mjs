// SPDX-License-Identifier: Apache-2.0 OR MIT
// AINRA verifier CHALLENGE minter — the MAINTAINER's side (run when issuing a challenge to an external verifier).
//
// WHY THIS EXISTS: an attestation over a STATIC, PUBLISHED corpus proves nothing about execution — the corpus hashes
// and the conformant verdicts are all public, so a party who never ran the SDK can hand-author a passing attestation
// (M9 review, D-024 round 2). To make the attestation actually require verification, the maintainer mints a FRESH
// corpus of K bundles whose revocation state is decided HERE and NOT published: a coin flip per bundle. A genuine
// verifier learns each verdict only BY VERIFYING; a forger who never ran a verifier must GUESS all K (success 2^-K).
//
//   node mint-challenge.mjs --registrar <url> --now <unix> --count <K> --out <challenge-dir> --secret <secret.json>
//                           [--nonce <hex>]
//
// It talks to a real registrar-box over HTTP (issue / revoke / present) and verifies each minted bundle with the real
// @ainra/sdk to record GROUND-TRUTH verdicts (so a genuine stranger's verdicts match exactly). The <challenge-dir> is
// PUBLIC (handed to the verifier); the <secret.json> is PRIVATE (the maintainer keeps it — it holds the answer key).

import { writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { createHash, randomBytes, randomInt } from "node:crypto";
import { Verifier } from "@ainra/sdk";

const A = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : d; };
const registrar = A("registrar");
const now = Number(A("now"));
const count = Number(A("count", "8"));
// --party <id> (operator flow): organizes output per named party under a gitignored ops dir and defaults --out/--secret
// so the maintainer never has to pick paths (and the private answer key lands somewhere .gitignore already excludes).
const party = A("party", "");
const opsDir = A("ops-dir", "ops-verifier");
const outDir = A("out", party ? `${opsDir}/${party}/challenge` : undefined);
const secretPath = A("secret", party ? `${opsDir}/${party}/answer-key.json` : undefined);
const nonce = A("nonce", randomBytes(16).toString("hex"));
if (!registrar || !now || !outDir || !secretPath) {
  console.error("usage: mint-challenge.mjs --registrar <url> --now <unix> --count <K> {--party <id> | --out <dir> --secret <file>} [--nonce <hex>]");
  console.error("  --party <id> stores the public corpus + the PRIVATE answer key under ops-verifier/<id>/ (gitignored). See kits/verifier/OPERATOR.md.");
  process.exit(2);
}
if (!(count >= 1)) { console.error("--count must be >= 1"); process.exit(2); }
mkdirSync(outDir, { recursive: true });
const sha256 = (s) => createHash("sha256").update(s).digest("hex");

async function post(path, body) {
  const r = await fetch(`${registrar}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`POST ${path} → ${r.status}`);
  return r.json();
}
async function present(sub) {
  const r = await fetch(`${registrar}/present?sub=${encodeURIComponent(sub)}&now=${now}`);
  if (!r.ok) throw new Error(`present → ${r.status}`);
  return r.json();
}

// The challenge directory is the registrar's accreditation (written next to us by the caller: accredit → directory/roots).
const directory = JSON.parse(readFileSync(`${outDir}/directory.json`, "utf8"));
const roots = JSON.parse(readFileSync(`${outDir}/roots.json`, "utf8"));
const registrarId = directory.entries[0].registrar;
// A root-dark verifier used ONLY to record ground truth (holds the public directory + roots, never a secret).
const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh);
if (!verifier) { console.error("FAIL: challenge directory not trust-anchored by its roots"); process.exit(2); }
const asStr = (v) => (v.verdict === "valid" ? "valid" : `invalid:${v.reason}`);

const bundles = [];
const expected = [];
for (let i = 0; i < count; i++) {
  const op = `op${i % 90}`;
  // lineage MUST be lowercase-alphanumeric (the name grammar rejects underscores/uppercase). nonce is lowercase hex.
  const lineage = `chal${nonce}${i}`;
  const sub = `ainra:${registrarId}:${op}:${lineage}@1.0.0`;
  await post("/issue", { operator: op, lineage, version: "1.0.0", tier: "L1", auth_class: "A2", principal_proof: "0011223344556677", capabilities: ["read:x"], scope_ceiling: ["read:x"], hops: [] });
  // secret coin flip — revoke this lineage or not. The result is NOT published; only this process + secret.json know.
  const revoke = randomInt(2) === 1;
  if (revoke) await post("/revoke", { sub, now });
  const bundle = await present(sub);
  // record GROUND TRUTH: what a correct root-dark verifier actually says at `now` (so a genuine stranger matches).
  const verdict = asStr(verifier.verify(bundle, now));
  // sanity: the coin flip must have actually taken effect, else the answer key would be wrong.
  const wantRevoked = revoke;
  const isRevoked = verdict === "invalid:revoked";
  if (wantRevoked !== isRevoked) { console.error(`FAIL: bundle ${i} coin flip (revoke=${revoke}) did not match verdict ${verdict}`); process.exit(1); }
  const file = `bundle-${i}.json`;
  writeFileSync(`${outDir}/${file}`, JSON.stringify(bundle, null, 2) + "\n");
  bundles.push(file);
  expected.push(verdict);
}

// PUBLIC challenge descriptor handed to the verifier (says WHAT to verify + at what `now` — never the answers).
const challenge = {
  kind: "ainra/verifier-challenge/v1",
  nonce,
  ...(party ? { party } : {}),
  now,
  registrar: registrarId,
  bundles,
  note: "Verify each bundle root-dark (holding only this directory.json + roots.json) at `now`; report the verdict per bundle. The revocation state of each is a secret coin flip — you can only report the correct set by actually verifying.",
};
writeFileSync(`${outDir}/challenge.json`, JSON.stringify(challenge, null, 2) + "\n");

// The corpus the verifier must hash-match (binds them to OUR fresh bundles, not their own).
const corpusFiles = ["directory.json", "roots.json", "challenge.json", ...bundles];
const corpus_sha256 = Object.fromEntries(corpusFiles.map((f) => [f, sha256(readFileSync(`${outDir}/${f}`, "utf8"))]));

// PRIVATE answer key (the maintainer keeps this; the verifier NEVER sees it).
const secret = {
  kind: "ainra/verifier-challenge-secret/v1",
  nonce,
  ...(party ? { party } : {}),
  now,
  count,
  expected, // ground-truth verdict per bundle — the un-precomputable part
  corpus_sha256,
  forge_probability: `2^-${count}`,
};
writeFileSync(secretPath, JSON.stringify(secret, null, 2) + "\n");

const nRevoked = expected.filter((v) => v === "invalid:revoked").length;
console.log(`minted challenge ${nonce}${party ? ` for party "${party}"` : ""}: ${count} fresh bundles (${nRevoked} revoked / ${count - nRevoked} valid) — a forger must guess all ${count} (${secret.forge_probability}).`);
console.log(`  public  → ${outDir}/ (directory.json, roots.json, challenge.json, ${bundles.length} bundles) — hand to the verifier`);
console.log(`  private → ${secretPath} — KEEP THIS (the answer key); never publish it`);
if (party) {
  console.log(`\n── operator: onboard "${party}" ──`);
  console.log(`  1. Send them ${outDir}/ (a zip is fine) + the outreach one-pager outreach/EXTERNAL-VERIFIER-CALL.md.`);
  console.log(`  2. They run:   make verify-as-external CHALLENGE=<the folder you sent>   → they send back verifier-attestation.json`);
  console.log(`  3. You check:  node kits/verifier/check-attestation.mjs --attestation <their-file> --challenge ${nonce} --secret ${secretPath} --party ${party}`);
  console.log(`     → on success it writes evidence/verifier/${party}.json, which 'make genesis-status' counts.`);
}
