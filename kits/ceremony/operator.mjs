// SPDX-License-Identifier: Apache-2.0 OR MIT
// One custodian's part of the AINRA genesis ceremony DRY-RUN, run on THEIR OWN machine.
//
// ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
// │ DRY-RUN ONLY — TEST-ROOT MATERIAL. This models the OPERATOR CHOREOGRAPHY (commit → on-camera cross-read →   │
// │ reveal), NOT the real threshold key material. In the REAL recorded ceremony (RUNBOOK.md), the custodian's   │
// │ entropy is a FROST 5-of-9 share generated on an air-gapped, ephemeral-OS machine and NEVER leaves it. This  │
// │ script generates a throwaway key + nonce so the choreography can be rehearsed end to end with nothing real. │
// └──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
//
//   node operator.mjs --id <K> --out <dir>
//
// Produces `<dir>/operator-<K>.json`: a signed commit-reveal record. At "commit" time the custodian publishes
// `commit = SHA-256(nonce)`; at "reveal" time (after everyone has cross-read all commits on camera) they reveal the
// nonce. This file carries both so a witness can later confirm `SHA-256(reveal) == commit` and the signature.

import { writeFileSync, mkdirSync } from "node:fs";
import { createHash, generateKeyPairSync, sign as edSign, randomBytes } from "node:crypto";

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : def;
}
const id = arg("id");
const out = arg("out");
if (!id || !out) {
  console.error("usage: operator.mjs --id <K> --out <dir>");
  process.exit(2);
}
mkdirSync(out, { recursive: true });

const sha256hex = (b) => createHash("sha256").update(b).digest("hex");
const sortedStringify = (o) => JSON.stringify(o, Object.keys(o).sort());

// TEST-ROOT throwaway identity + entropy contribution (never a real ceremony share).
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const nonce = randomBytes(32); // the custodian's contribution (TEST); revealed after cross-read
const commit = sha256hex(nonce);

const body = {
  kind: "ainra/ceremony-operator/v1-TESTROOT",
  operator_id: Number(id),
  pubkey_spki_b64: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
  commit_sha256: commit, // published at COMMIT time
  reveal_hex: nonce.toString("hex"), // published at REVEAL time (after the on-camera cross-read)
  warning: "TEST-ROOT — not a real threshold share; see RUNBOOK.md for the real air-gapped step",
};
const sig = edSign(null, Buffer.from(sortedStringify(body)), privateKey).toString("base64");
writeFileSync(`${out}/operator-${id}.json`, JSON.stringify({ body, sig_ed25519_b64: sig }, null, 2) + "\n");
console.log(`operator ${id}: committed ${commit.slice(0, 16)}… (TEST-ROOT) → ${out}/operator-${id}.json`);
