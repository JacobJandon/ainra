#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make pilot-e2e — the pilot, live: one command in front of a service, a signature agent's requests through it.
//   1. an upstream service that only echoes what reached it
//   2. the pilot in front of it, link mode, F1, writing a decision log
//   3. a signature agent with two keys in its directory; key A linked to its operator's passport, key B not
//   4. A's request reaches the upstream with x-ainra-operator; B's is refused not_linked and never reaches it
//   5. revoke A's link → after the pilot's status cache (10 s at F1) A is refused revoked
//   6. the decision log verifies under the pilot's key and its last line is the published head
// WITNESS: step 4's negative control (B) and step 5 (A after revocation) must be refused and must not reach the
// upstream; the upstream counts what reached it.
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { sign, HTTP_MESSAGE_SIGNATURES_DIRECTORY } from "web-bot-auth";
import { signerFromJWK } from "web-bot-auth/crypto";
import { appendSignature } from "http-message-sig";
import { jwkThumbprintEd25519, linkPopSigningBytes, verifyDecisionChain } from "../../packages/sdk-ts/dist/index.js";

const REG = process.env.AINRA_REGISTRAR ?? "http://127.0.0.1:4970";
const ART = process.env.AINRA_ARTIFACTS ?? "http://127.0.0.1:8091";
const now = () => Math.floor(Date.now() / 1000);
let bad = 0;
const ok = (m) => console.log(`  ok    ${m}`);
const fail = (m) => { console.error(`  ✗     ${m}`); bad = 1; };
try { await fetch(`${REG}/accreditation`, { signal: AbortSignal.timeout(3000) }); }
catch { console.error(`pilot-e2e: no live registrar at ${REG} — run \`make live-up\` first`); process.exit(2); }
const TOKEN = readFileSync(new URL("../../live/.issue-token", import.meta.url), "utf8").trim(); // header only
const write = async (p, b) => (await fetch(REG + p, { method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" }, body: JSON.stringify(b) })).json();
const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));

// 1 · the upstream
let reached = 0;
const upstream = http.createServer((req, res) => { reached++; res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ operator: req.headers["x-ainra-operator"] ?? null })); });
const upPort = await listen(upstream);

// 3 · the signature agent and its directory
const agentKey = async () => {
  const k = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", k.privateKey);
  return { k, jwk, signer: await signerFromJWK({ ...jwk, alg: "EdDSA" }), tp: jwkThumbprintEd25519(Buffer.from(jwk.x, "base64url")) };
};
const A = await agentKey(), B = await agentKey();
const dirSrv = http.createServer((req, res) => {
  res.setHeader("content-type", "application/http-message-signatures-directory+json");
  res.setHeader("cache-control", "max-age=300");
  res.end(JSON.stringify({ keys: [A, B].map((a) => ({ kty: "OKP", crv: "Ed25519", x: a.jwk.x, use: "sig", nbf: now() - 60, exp: now() + 3600 })) }));
});
const AGENT = `http://127.0.0.1:${await listen(dirSrv)}`;
const passport = await (await fetch(`${REG}/demo/issue`, { method: "POST", body: JSON.stringify({ operator: "specimen", lineage: "pilot" }) })).json();
const nbf = passport.nbf;
const pop = Buffer.from(await crypto.subtle.sign({ name: "Ed25519" }, A.k.privateKey, linkPopSigningBytes(passport.registrar, passport.sub, A.tp, nbf))).toString("base64url");
const linked = await write("/link", { passport: passport.sub, key: A.jwk.x, pop, nbf, exp: Math.min(passport.exp, now() + 3600) });
linked.thumbprint === A.tp ? ok(`key A linked to ${passport.sub}`) : fail(`link: ${JSON.stringify(linked)}`);

// 2 · the pilot
const work = mkdtempSync(join(tmpdir(), "ainra-pilot-"));
writeFileSync(join(work, "directory.json"), await (await fetch(`${ART}/directory.json`)).text());
writeFileSync(join(work, "roots.json"), await (await fetch(`${ART}/roots.json`)).text());
const pilotPort = 20000 + Math.floor(Math.random() * 20000);
const pilot = spawn("node", [new URL("pilot.mjs", import.meta.url).pathname, "--upstream", `http://127.0.0.1:${upPort}`, "--listen", `127.0.0.1:${pilotPort}`,
  "--directory", join(work, "directory.json"), "--roots", join(work, "roots.json"), "--mode", "link", "--registrar", REG, "--freshness", "F1",
  "--decisions", join(work, "decisions.jsonl"), "--gate-key", join(work, "gate.key")], { stdio: ["ignore", "ignore", "inherit"] });
const PILOT = `http://127.0.0.1:${pilotPort}`;
for (let i = 0; i < 100; i++) { try { await fetch(PILOT + "/.well-known/ainra-decisions-head"); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }
ok(`the pilot in front of the upstream: ${PILOT} → 127.0.0.1:${upPort}`);

async function send(a) {
  const url = `${PILOT}/orders`;
  const h = new Headers({ "signature-agent": `sig1="${AGENT}"` });
  const f = await sign(new Request(url, { headers: h }), { signer: a.signer, label: "sig1", expires: new Date((now() + 300) * 1000) });
  const r = await fetch(url, { headers: appendSignature(h, f) });
  return { status: r.status, reason: r.headers.get("x-ainra-reason"), body: await r.json().catch(() => null) };
}

// 4 · A through, B refused
{
  const before = reached;
  const r = await send(A);
  r.status === 200 && r.body?.operator === "specimen" && reached === before + 1 ? ok(`A → 200 from the upstream, which saw x-ainra-operator: ${r.body.operator}`) : fail(`A: ${JSON.stringify(r)}`);
  const rb = await send(B);
  rb.status === 403 && rb.reason === "not_linked" && reached === before + 1 ? ok("B → 403 not_linked, and the upstream never saw it") : fail(`B: ${JSON.stringify(rb)}`);
}
// 5 · revoke A
{
  const rv = await write("/link/revoke", { thumbprint: A.tp, kind: "link" });
  rv.kind === "link" ? ok("A's link revoked") : fail(`revoke: ${JSON.stringify(rv)}`);
  await new Promise((r) => setTimeout(r, 11_000));
  const before = reached;
  const r = await send(A);
  r.status === 403 && r.reason === "revoked" && reached === before ? ok("A after the 10 s status cache → 403 revoked, and the upstream never saw it") : fail(`A after revocation: ${JSON.stringify(r)}`);
}
// 6 · the log
{
  const lines = readFileSync(join(work, "decisions.jsonl"), "utf8").trim().split("\n");
  const head = await (await fetch(PILOT + "/.well-known/ainra-decisions-head")).json();
  const chain = verifyDecisionChain(lines, Buffer.from(head.gate_key, "base64url"));
  const last = createHash("sha256").update(lines.at(-1)).digest("base64url");
  chain.ok && chain.count === 3 && head.head === last
    ? ok(`the decision log: ${chain.count} signed, chained records (${lines.map((l) => JSON.parse(l).reason ?? "valid").join(", ")}); its last line is the published head`)
    : fail(`log: ${JSON.stringify(chain)} head ${head.head} last ${last}`);
}
pilot.kill(); upstream.close(); dirSrv.close();
console.log(bad ? "\nPILOT-E2E FAILED" : "\nPILOT-E2E OK: one command in front of a service; linked keys in, unlinked and revoked keys refused by name, every decision signed");
process.exit(bad);
