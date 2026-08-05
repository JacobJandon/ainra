// SPDX-License-Identifier: Apache-2.0 OR MIT
// C2SP tlog-checkpoint / tlog-witness conformance — emit and verify the signed-note form of our log checkpoints.
//
// WHY: third-party witness cosigning is the single change that converts "AINRA says its log is append-only" into
// "AINRA cannot lie about its log" — and it is free. The bar for joining a witness network is not adopting anyone's
// library; it is speaking the wire format. Our log already produces the right FACTS (origin, size, root hash,
// delegate signature); it serialises them as JSON, which no witness can read. This module is the translation, and
// it keeps the implementation ours (no Go dependency, no vendor in the path).
//
// THE FORMAT (C2SP signed-note, as used by tlog-checkpoint):
//
//   <origin>\n<size>\n<base64(root)>\n\n— <key-name> <base64(keyhash || signature)>\n
//
//   * the body is the first three lines plus the blank line; the signature covers exactly those bytes
//   * keyhash = first 4 bytes of SHA-256(key-name || "\n" || 0x01 || ed25519-public-key)
//     0x01 is the algorithm identifier for Ed25519 in the note key-hash construction
//   * root is STANDARD base64 (with padding) in a note, not base64url — our internal artifacts use base64url,
//     so the conversion is part of conformance, not cosmetic
//
//   node tools/c2sp-checkpoint.mjs emit  <checkpoint.json> --key <ed25519.key> --name <origin>
//   node tools/c2sp-checkpoint.mjs verify <note.txt> --pub <ed25519.pub.b64> --name <origin>
//   node tools/c2sp-checkpoint.mjs selftest        # round-trips a generated key and a real checkpoint
import { readFileSync, existsSync } from "node:fs";
import { createHash, generateKeyPairSync, sign as edSign, verify as edVerify, createPublicKey, createPrivateKey } from "node:crypto";

const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 ? process.argv[i + 1] : d; };
const b64uToBuf = (s) => Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");

/** The exact bytes a witness signs: three lines and the terminating blank line. Nothing else. */
export function noteBody(origin, size, rootB64url) {
  const root = b64uToBuf(rootB64url).toString("base64");   // notes use standard base64, padded
  return `${origin}\n${size}\n${root}\n`;
}

/** keyhash = SHA-256(name || "\n" || 0x01 || pubkey)[0..4] — the 4-byte prefix every note signature carries. */
export function keyHash(name, pubRaw) {
  return createHash("sha256").update(Buffer.concat([Buffer.from(`${name}\n`), Buffer.from([0x01]), pubRaw])).digest().subarray(0, 4);
}

export function signNote(body, name, privKey, pubRaw) {
  const sig = edSign(null, Buffer.from(body), privKey);
  const line = Buffer.concat([keyHash(name, pubRaw), sig]).toString("base64");
  return `${body}\n— ${name} ${line}\n`;
}

export function verifyNote(note, name, pubRaw) {
  const i = note.indexOf("\n\n— ");
  if (i < 0) return { ok: false, why: "no signature block — a note is body, blank line, then '— <name> <b64>'" };
  const body = note.slice(0, i + 1);
  const sigLine = note.slice(i + 2).trim();
  const m = sigLine.match(/^— (\S+) (\S+)$/);
  if (!m) return { ok: false, why: "malformed signature line" };
  if (m[1] !== name) return { ok: false, why: `signature names "${m[1]}", expected "${name}"` };
  const raw = Buffer.from(m[2], "base64");
  const kh = raw.subarray(0, 4), sig = raw.subarray(4);
  if (!kh.equals(keyHash(name, pubRaw))) return { ok: false, why: "key hash does not match this public key" };
  const pub = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pubRaw]), format: "der", type: "spki" });
  if (!edVerify(null, Buffer.from(body), pub, sig)) return { ok: false, why: "signature does not verify over the body" };
  const [origin, size, root] = body.split("\n");
  return { ok: true, origin, size: Number(size), root };
}

// ── CLI ──────────────────────────────────────────────────────────────────────────────────────────────────────
const cmd = process.argv[2];

if (cmd === "selftest") {
  // Round-trip against a REAL checkpoint from the published record, with a freshly generated key.
  const cp = JSON.parse(readFileSync(arg("checkpoint", "site/net/registrars/registrar-07/checkpoints/126.json"), "utf8"));
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pubRaw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const name = cp.origin;

  const body = noteBody(cp.origin, cp.size, cp.root);
  const note = signNote(body, name, privateKey, pubRaw);

  console.log("── the note a witness would receive ──");
  console.log(note.replace(/\n/g, "\n"));
  console.log("── checks ──");
  const v = verifyNote(note, name, pubRaw);
  console.log(`  round-trip verify        ${v.ok ? "PASS" : "FAIL — " + v.why}`);
  console.log(`  origin preserved         ${v.origin === cp.origin ? "PASS" : "FAIL"}  (${v.origin})`);
  console.log(`  size preserved           ${v.size === cp.size ? "PASS" : "FAIL"}  (${v.size})`);
  console.log(`  root re-encodes to ours  ${Buffer.from(v.root, "base64").toString("base64url") === cp.root ? "PASS" : "FAIL"}`);

  // Negative controls — a format checker that never fails is not a checker.
  const tamperedBody = note.replace(`\n${cp.size}\n`, `\n${cp.size + 1}\n`);
  console.log(`  tampered size REFUSED    ${verifyNote(tamperedBody, name, pubRaw).ok ? "FAIL — accepted a forged size" : "PASS"}`);
  const otherPub = generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  console.log(`  wrong key REFUSED        ${verifyNote(note, name, otherPub).ok ? "FAIL — accepted a foreign key" : "PASS"}`);
  console.log(`  wrong origin REFUSED     ${verifyNote(note, "ainra-log/not-us", pubRaw).ok ? "FAIL — accepted a foreign origin" : "PASS"}`);

  const allPass = v.ok && v.origin === cp.origin && v.size === cp.size
    && !verifyNote(tamperedBody, name, pubRaw).ok && !verifyNote(note, name, otherPub).ok;
  console.log(`\n${allPass ? "C2SP CHECKPOINT OK" : "C2SP CHECKPOINT FAILED"} — our checkpoints serialise to the signed-note form a witness reads.`);
  process.exit(allPass ? 0 : 1);
}

if (cmd === "emit") {
  const cp = JSON.parse(readFileSync(process.argv[3], "utf8"));
  const keyPath = arg("key"), name = arg("name", cp.origin);
  if (!keyPath || !existsSync(keyPath)) { console.error("emit needs --key <ed25519 PEM private key>"); process.exit(2); }
  const priv = createPrivateKey(readFileSync(keyPath));
  const pubRaw = createPublicKey(priv).export({ format: "der", type: "spki" }).subarray(-32);
  process.stdout.write(signNote(noteBody(cp.origin, cp.size, cp.root), name, priv, pubRaw));
  process.exit(0);
}

if (cmd === "verify") {
  const note = readFileSync(process.argv[3], "utf8");
  const pubRaw = b64uToBuf(arg("pub", ""));
  const r = verifyNote(note, arg("name", ""), pubRaw);
  console.log(r.ok ? `OK — ${r.origin} @ size ${r.size}` : `INVALID — ${r.why}`);
  process.exit(r.ok ? 0 : 1);
}

console.error("usage: c2sp-checkpoint.mjs selftest | emit <checkpoint.json> --key <pem> [--name <origin>] | verify <note> --pub <b64> --name <origin>");
process.exit(2);
