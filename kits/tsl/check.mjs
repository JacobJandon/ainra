#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make tsl-check — AINRA revocations, read by independent open-source IETF Token Status List and JOSE
// implementations (D-078 step 4). Pinned in package-lock.json; neither knows anything about AINRA.
//
//   1. a registrar (the reference CLI) issues two passports and revokes one
//   2. it publishes its status list as a statuslist+jwt, signed with the Ed25519 half of its status key
//   3. the JOSE library verifies the token (EdDSA, typ statuslist+jwt) under the key from the registrar's
//      accreditation; the Token Status List library reads both passports' bits: revoked 1, valid 0
//   4. the bits are the same bytes as AINRA's own hybrid-signed publication
//   5. negative controls: an edited payload and another key are both refused by the JOSE library
//
// WITNESS: could this fail? Yes — step 3 asserts both bits by index, and step 5 proves the signature check is real.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { importJWK, jwtVerify, generateKeyPair } from "jose";
import { getListFromStatusListJWT } from "@sd-jwt/jwt-status-list";

const AINRA = new URL("../../target/release/ainra", import.meta.url).pathname;
const run = (...a) => execFileSync(AINRA, a, { encoding: "utf8" });
let bad = 0;
const ok = (m) => console.log(`  ok    ${m}`);
const fail = (m) => { console.error(`  ✗     ${m}`); bad = 1; };

const dir = mkdtempSync(join(tmpdir(), "ainra-tsl-"));
run("init", dir, "registrar-07", "--seed", "4711");
run("issue", dir, "--operator", "acme", "--lineage", "invoicing", "--version", "1.0.0");
run("issue", dir, "--operator", "acme", "--lineage", "billing", "--version", "1.0.0");
run("revoke", dir, "ainra:registrar-07:acme:billing@1.0.0");
const snap = JSON.parse(readFileSync(join(dir, "registrar.json"), "utf8"));
const idx = Object.fromEntries(snap.records.map((r) => [r.sub, r.status_idx]));
const acc = snap.accreditation;
const jwt = run("status-jwt", dir).trim();
const iat = JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString("utf8")).iat;
ok(`a registrar issued two passports, revoked one, and published ${jwt.length} bytes of statuslist+jwt`);

// The status key's Ed25519 half, as a JWK, from the registrar's public accreditation.
const key = await importJWK({ kty: "OKP", crv: "Ed25519", x: acc.status_key.ed25519 }, "EdDSA");
const at = { currentDate: new Date(iat * 1000), typ: "statuslist+jwt" };
try {
  const { protectedHeader } = await jwtVerify(jwt, key, at);
  ok(`the JOSE library verifies it: alg ${protectedHeader.alg}, typ ${protectedHeader.typ}`);
} catch (e) { fail(`JOSE verification: ${e.message}`); }

const list = getListFromStatusListJWT(jwt);
const revoked = list.getStatus(idx["ainra:registrar-07:acme:billing@1.0.0"]);
const valid = list.getStatus(idx["ainra:registrar-07:acme:invoicing@1.0.0"]);
revoked === 1 && valid === 0
  ? ok(`the Token Status List library reads the bits: revoked passport → ${revoked}, valid passport → ${valid}`)
  : fail(`bits read as revoked=${revoked}, valid=${valid}`);

const hybrid = JSON.parse(run("status", dir));
const lst = JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString("utf8")).status_list.lst;
lst === hybrid.status_list_b64
  ? ok(`the bits are the same bytes as AINRA's own hybrid-signed publication`)
  : fail(`the mirror's list differs from the hybrid publication`);

{
  const [h, p, s] = jwt.split(".");
  const payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
  payload.status_list.lst = hybrid.status_list_b64.replace(/^./, (c) => (c === "e" ? "f" : "e"));
  const edited = [h, Buffer.from(JSON.stringify(payload)).toString("base64url"), s].join(".");
  try { await jwtVerify(edited, key, at); fail("an edited payload verified"); }
  catch { ok("an edited payload is refused by the JOSE library"); }
  const { publicKey } = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  try { await jwtVerify(jwt, publicKey, at); fail("another key verified the token"); }
  catch { ok("another key is refused"); }
}

console.log(bad ? "\nTSL-CHECK FAILED" : "\nTSL-CHECK OK: AINRA revocations read by independent Token Status List and JOSE implementations");
process.exit(bad);
