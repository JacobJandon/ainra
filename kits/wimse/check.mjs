#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make wimse-check — an AINRA running copy as a WIMSE workload, read by somebody else's code (D-076), offline.
//
// Both directions, through independent open-source implementations pinned in package-lock.json (see independent.mjs):
//   A. AINRA's `mintWit` + `signWimseRequest` produce the token and the signature; the independent WIMSE verifier
//      (`jose` + `http-message-sig`) must accept them.
//   B. the independent libraries mint a WIT and sign a request as any WIMSE workload would; AINRA's
//      `verifyWimseRequest` must accept it.
// Three request shapes each way: a GET, a GET with a query, a POST with a JSON body.
//
//   node check.mjs              both directions must accept
//   node check.mjs --negative   WITNESS: flip one byte of the request signature, then of the WIT's signature, then
//                               change the method — in both directions every one must be refused, or this check
//                               could not have failed
//
// The passport beneath is not this check's subject: it is synthetic here and its verifier accepts. The passport step —
// a revoked passport refused though its WIT is perfect — is held to the real gate corpus in packages/sdk-ts/test/
// wimse.test.mjs, and shown live by `make wimse-e2e`.
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { mintWit, signWimseRequest, verifyWimseRequest, wimseIdentifier, trustDomainOf } from "../../packages/sdk-ts/dist/index.js";
import { wimseOnlySign, wimseOnlyVerify } from "./independent.mjs";

const NEGATIVE = process.argv.includes("--negative");
const sdkRequire = createRequire(new URL("../../packages/sdk-ts/package.json", import.meta.url));
const { ed25519 } = await import(pathToFileURL(sdkRequire.resolve("@noble/curves/ed25519")).href);

const NAME = "ainra:registrar-07:acme:invoicing@1.0.0";
const AUD = "https://svcb.example/ledger";
const NOW = Math.floor(Date.now() / 1000);
const enc = new TextEncoder();

async function keypair() {
  const k = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", k.privateKey);
  const d = Buffer.from(jwk.d, "base64url");
  return { jwk, pub: Buffer.from(jwk.x, "base64url"), sign: (m) => ed25519.sign(m, d) };
}
const control = await keypair(), instance = await keypair();
const bundle = { claims: Buffer.from(JSON.stringify({ sub: NAME, exp: NOW + 86_400, keys: [{ ed25519: control.jwk.x }] })).toString("base64url") };
const passportAccepted = { verify: () => ({ verdict: "valid" }) };

const SHAPES = [
  { what: "GET", method: "GET", path: "/ledger", headers: {} },
  { what: "GET with a query", method: "GET", path: "/ledger/entries?since=2026-10-01&limit=5", headers: {} },
  { what: "POST with a body", method: "POST", path: "/ledger/entries", headers: { "content-type": "application/json" }, body: enc.encode('{"invoice":"INV-7","amount":120}') },
];

const flipSig = (v) => v.replace(/=:([A-Za-z0-9+/=]+):/, (_, b) => { const r = Buffer.from(b, "base64"); r[5] ^= 1; return `=:${r.toString("base64")}:`; });
const flipWit = (w) => { const [h, p, s] = w.split("."); const r = Buffer.from(s, "base64url"); r[5] ^= 1; return `${h}.${p}.${r.toString("base64url")}`; };
const TAMPER = NEGATIVE
  ? [["request signature flipped", (h) => ({ ...h, signature: flipSig(h.signature) }), (r) => r],
     ["WIT signature flipped", (h) => ({ ...h, "workload-identity-token": flipWit(h["workload-identity-token"]) }), (r) => r],
     ["method changed", (h) => h, (r) => ({ ...r, method: r.method === "GET" ? "DELETE" : "PUT" })]]
  : [["as sent", (h) => h, (r) => r]];

let bad = 0, n = 0;
const line = (good, msg) => { n++; if (!good) bad = 1; console.log(`  ${good ? "ok  " : "FAIL"} ${msg}`); };

console.log(`A · AINRA signs; the independent WIMSE verifier (jose + http-message-sig) reads${NEGATIVE ? " — tampered" : ""}`);
for (const s of SHAPES) {
  const iid = "i-" + Math.random().toString(16).slice(2, 10);
  const wit = await mintWit({ passportClaimsB64: bundle.claims, iid, instanceEd25519Public: instance.pub, now: NOW, controlSignEd25519: control.sign });
  const req = { method: s.method, authority: "svcb.example", path: s.path, headers: s.headers, body: s.body };
  const signed = await signWimseRequest({ req, wit, audience: AUD, nonce: "n-" + iid, created: NOW, instanceSignEd25519: instance.sign });
  for (const [how, th, tr] of TAMPER) {
    const r = tr(s);
    const request = new Request(`https://svcb.example${s.path}`, { method: r.method, headers: th({ ...s.headers, ...signed }), body: s.body });
    let out;
    try { out = { ok: true, sub: await wimseOnlyVerify(request, { trustDomain: trustDomainOf(NAME), issuerX: control.jwk.x, audience: AUD, now: NOW, body: s.body }) }; }
    catch (e) { out = { ok: false, why: e.cause?.message ?? e.message }; }
    line(NEGATIVE ? !out.ok : out.ok && out.sub === wimseIdentifier(NAME, iid),
      `${s.what.padEnd(17)} ${how.padEnd(26)} → ${out.ok ? `accepted, ${out.sub}` : `refused (${out.why})`}`);
  }
}

console.log(`\nB · the independent libraries sign as any WIMSE workload; AINRA's verifyWimseRequest reads${NEGATIVE ? " — tampered" : ""}`);
for (const s of SHAPES) {
  const iid = "w-" + Math.random().toString(16).slice(2, 10);
  const h = await wimseOnlySign({
    url: `https://svcb.example${s.path}`, method: s.method, headers: s.headers, body: s.body,
    issuerJwkPrivate: control.jwk, workloadJwkPrivate: instance.jwk, sub: wimseIdentifier(NAME, iid), iss: "did:ainra:registrar-07:acme:invoicing",
    audience: AUD, now: NOW, nonce: "n-" + iid,
  });
  const headers = Object.fromEntries(h.entries());
  for (const [how, th, tr] of TAMPER) {
    const r = tr(s);
    const out = verifyWimseRequest({
      req: { method: r.method, authority: "svcb.example", path: s.path, headers: th(headers), body: s.body },
      verifier: passportAccepted, bundle, audience: AUD, now: NOW,
    });
    line(NEGATIVE ? !out.ok : out.ok && out.sub === wimseIdentifier(NAME, iid),
      `${s.what.padEnd(17)} ${how.padEnd(26)} → ${out.ok ? `accepted, ${out.sub}` : `refused (${out.reason})`}`);
  }
}

console.log(bad
  ? `\nWIMSE-CHECK FAILED${NEGATIVE ? " (NEGATIVE)" : ""}`
  : NEGATIVE
    ? `\nWIMSE-CHECK NEGATIVE OK: all ${n} tampered requests were refused, in both directions.`
    : `\nWIMSE-CHECK OK: ${n} requests, both directions — an AINRA running copy's WIT and signature are read by independent WIMSE code, and AINRA reads theirs.`);
// WITNESS: --negative above is this check's negative control; it exits red if any tampered request is accepted.
process.exit(bad);
