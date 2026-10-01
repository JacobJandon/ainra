#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// One request, two readers (D-070) — the offline proof.
//
// Some vectors in vectors/v1-presentation carry a signature agent's signature beside the running copy's: the Web Bot
// Auth profile (Ed25519, `tag="web-bot-auth"`, its own `signature-agent` member), under the label `sig1`. The vector
// generator builds that signature by hand, and AINRA's three implementations do not read it — so on its own, the
// corpus could carry a signature-agent signature that no signature-agent verifier would accept, and nothing would
// notice. This check closes that: an INDEPENDENT, open-source implementation of the signature-agent profile, pinned in
// package-lock.json, verifies the `sig1` member of every such vector, and must conclude what the vector records. On
// the same request, AINRA's verdict (from @ainra/sdk) must still be the recorded one.
//
//   node check.mjs              both readers, every vector that carries both signatures
//   node check.mjs --negative   flip one byte of each signature agent's signature: every signature the vectors
//                               record as valid must now be refused, or this check could not have failed
import { readFileSync, readdirSync } from "node:fs";
import { verify } from "web-bot-auth";
import { verifierFromJWK } from "web-bot-auth/crypto";
import { runPresentationVector } from "../../packages/sdk-ts/dist/index.js";

const DIR = new URL("../../vectors/v1-presentation/", import.meta.url);
const NEGATIVE = process.argv.includes("--negative");

function flipFirstByte(field, label) {
  return field.replace(new RegExp(`${label}=:([A-Za-z0-9+/=]+):`), (_, b64) => {
    const raw = Buffer.from(b64, "base64");
    raw[0] ^= 1;
    return `${label}=:${raw.toString("base64")}:`;
  });
}

async function otherReader(v) {
  const o = v.other_signer;
  const r = v.request;
  const headers = new Headers();
  for (const [k, val] of r.headers) headers.append(k, NEGATIVE && k.toLowerCase() === "signature" ? flipFirstByte(val, o.label) : val);
  const req = new Request(`https://${r.authority}${r.path}`, {
    method: r.method,
    headers,
    body: r.body_b64u === null ? undefined : Buffer.from(r.body_b64u, "base64url"),
  });
  try {
    const res = await verify(req, {
      label: o.label,
      now: new Date(v.now * 1000),
      resolver: async () => verifierFromJWK(o.jwk),
    });
    if (res.signatureAgent?.uri !== o.signature_agent) return { valid: false, why: `attributed to ${res.signatureAgent?.uri}` };
    return { valid: true };
  } catch (e) {
    return { valid: false, why: e.message };
  }
}

const stable = (x) => JSON.stringify(x, Object.keys(x).sort());

const names = readdirSync(DIR).filter((f) => f.endsWith(".json") && f !== "manifest.json").sort();
let both = 0, agree = 0, caught = 0, recordedValid = 0, ainraHeld = 0;
for (const f of names) {
  const v = JSON.parse(readFileSync(new URL(f, DIR), "utf8"));
  if (!v.other_signer) continue;
  both++;
  const theirs = await otherReader(v);
  const ours = runPresentationVector(v);
  const oursOk = stable(ours) === stable(v.expect);
  const theirsOk = theirs.valid === v.other_signer.valid;
  const tag = theirsOk && oursOk ? "ok  " : "FAIL";
  if (theirsOk && oursOk) agree++;
  if (oursOk) ainraHeld++;
  if (v.other_signer.valid) { recordedValid++; if (!theirs.valid) caught++; }
  console.log(`  ${tag} ${v.name}`);
  console.log(`         signature agent: ${theirs.valid ? "valid" : `invalid (${theirs.why})`}${theirsOk ? "" : `  ← the vector records ${v.other_signer.valid ? "valid" : "invalid"}`}`);
  console.log(`         AINRA:           ${ours.ok ? "valid" : ours.reason}${oursOk ? "" : `  ← the vector records ${JSON.stringify(v.expect)}`}`);
}
if (both === 0) {
  console.error("no vector carries a signature agent's signature — nothing was checked");
  process.exit(1);
}
if (NEGATIVE) {
  // The corruption touches only the signature agent's member: every signature the vectors record as valid must now
  // fail its own verifier, and AINRA's verdicts must not move — it never read that member.
  console.log(`\nnegative control: ${caught}/${recordedValid} corrupted signature-agent signatures refused; AINRA unchanged on ${ainraHeld}/${both}.`);
  if (recordedValid === 0 || caught !== recordedValid || ainraHeld !== both) {
    console.error("NEGATIVE CONTROL FAILED");
    process.exit(1);
  }
  process.exit(0);
}
console.log(`\n${agree}/${both} vectors carrying both signatures: the signature-agent verifier and AINRA each reach the recorded answer.`);
if (agree !== both) process.exit(1);
