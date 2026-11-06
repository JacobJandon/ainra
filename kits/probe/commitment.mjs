// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The probe subject, published as a salted commitment (PLAN-M52 step 11, D-096).
//
// A probe report must say WHICH lineage it measured — so the measurement can be re-checked later — without letting
// the measured registrar find that lineage in its own log. The registrar knows every name it ever issued. A plain
// SHA-256 of the name is therefore no disguise at all: the registrar hashes each name in its log once and the probe
// is found. (This is what the probe published up to 2026-11-06.)
//
// So the report carries SHA-256(salt ‖ subject) with a fresh 32-byte salt that stays with the prober, unpublished,
// until the probe identity retires. Then salt and subject are revealed and anyone recomputes the commitment, so no
// report can be re-labelled after the fact. Until then, finding the probe means guessing 256 random bits.
//
//   import { commit, open } from "./commitment.mjs"
//   node kits/probe/commitment.mjs --drill    → the witness
//
// WITNESS (--drill): a simulated registrar log of 2,000 lineages contains the probe subject. Hashing every name in
// that log finds the old plain hash and must NOT find the commitment; the reveal (salt, subject) must reopen the
// commitment; a reveal with the wrong subject or a changed salt must not; two commitments to the same subject must
// differ. Remove the salt from commit() and the first check fails.
import { createHash, randomBytes } from "node:crypto";

export const SCHEME = "sha256(salt32 || subject) · salt revealed when the probe identity retires";
const hex = (b) => Buffer.from(b).toString("hex");
const digest = (salt, subject) => createHash("sha256").update(Buffer.concat([salt, Buffer.from(subject, "utf8")])).digest("hex");

/** commit(subject) → { commitment, salt } — publish `commitment`; keep `salt` (hex) private until the identity retires. */
export function commit(subject, salt = randomBytes(32)) {
  if (typeof subject !== "string" || !subject) throw new Error("commit: no subject");
  if (salt.length !== 32) throw new Error("commit: the salt must be 32 bytes");
  return { commitment: digest(salt, subject), salt: hex(salt) };
}

/** open(commitment, subject, saltHex) → true only if the reveal recomputes the published commitment. */
export function open(commitment, subject, saltHex) {
  if (!/^[0-9a-f]{64}$/.test(saltHex || "")) return false;
  return digest(Buffer.from(saltHex, "hex"), subject) === commitment;
}

if (process.argv[1] && process.argv[1].endsWith("commitment.mjs") && process.argv.includes("--drill")) {
  let bad = 0; const ok = (c, m) => { if (c) console.log(`  ok    ${m}`); else { console.error(`  ✗ ${m}`); bad++; } };
  const log = Array.from({ length: 2000 }, (_, i) => `ainra:registrar-07:lineage-${String(i).padStart(4, "0")}@1.0`);
  const subject = log[1337];
  const plain = createHash("sha256").update(subject).digest("hex");
  const { commitment, salt } = commit(subject);
  const hashed = new Set(log.map((n) => createHash("sha256").update(n).digest("hex")));
  ok(hashed.has(plain), "the registrar finds the OLD plain hash by hashing its own log (the defect, reproduced)");
  ok(!hashed.has(commitment), "the registrar does NOT find the salted commitment by hashing its own log");
  ok(open(commitment, subject, salt), "the reveal (salt, subject) reopens the commitment");
  ok(!open(commitment, log[1338], salt), "a reveal naming another subject does not");
  const flipped = (parseInt(salt[0], 16) ^ 1).toString(16) + salt.slice(1);
  ok(!open(commitment, subject, flipped), "a reveal with one bit of the salt changed does not");
  ok(commit(subject).commitment !== commitment, "two probes of the same subject publish different commitments");
  if (bad) { console.error("PROBE-COMMITMENT DRILL FAILED"); process.exit(1); }
  console.log("PROBE-COMMITMENT DRILL OK — the measured registrar cannot find the probe in its own log; the reveal binds the report");
}
