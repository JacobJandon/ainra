#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make pilot-e2e — the pilot, live: one command in front of a service, in both of its modes.
//   1. an upstream service that only echoes what reached it
//   2. the pilot in front of it, link mode, F1, writing a decision log
//   3. a signature agent with two keys in its directory; key A linked to its operator's passport, key B not
//   4. A's request reaches the upstream with x-ainra-operator; B's is refused not_linked and never reaches it
//   5. revoke A's link → after the pilot's status cache (10 s at F1) A is refused revoked
//   6. the decision log verifies under the pilot's key and its last line is the published head
// Passport mode, against the same upstream:
//   7. an agent holds its own hybrid key, gets a passport for it, and mints a running copy's instance credential
//   8. a second pilot, passport mode: the copy sends its bundle once, then signs a request (RFC 9421); it reaches the
//      upstream with the operator named and the presentation headers stripped
//   9. unsigned, replayed, and — after the passport is revoked — the post-revocation bundle are refused by name, and
//      none of them reaches the upstream
//  10. that pilot's decision log verifies and its last line is the published head
// WITNESS: step 4's negative control (B), step 5 (A after revocation) and step 9 must be refused and must not reach
// the upstream; the upstream counts what reached it, and step 8 asserts it never sees a presentation header.
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { sign, HTTP_MESSAGE_SIGNATURES_DIRECTORY } from "web-bot-auth";
import { signerFromJWK } from "web-bot-auth/crypto";
import { appendSignature } from "http-message-sig";
import {
  jwkThumbprintEd25519, linkPopSigningBytes, verifyDecisionChain, canonicalize, mintInstanceCredential,
  proveInstancePossession, signPresentation, splitPresentation, PRESENTATION_HEADER, POP_HEADER, PRIME_PATH,
} from "../../packages/sdk-ts/dist/index.js";
import { b64uEncode } from "../../packages/sdk-ts/dist/crypto.js";

// Sign with the SDK's own copies of the libraries, the versions its verifier checks with (as identity-e2e does).
const sdkRequire = createRequire(new URL("../../packages/sdk-ts/package.json", import.meta.url));
const lib = async (m) => import(pathToFileURL(sdkRequire.resolve(m)).href);
const { ml_dsa65 } = await lib("@noble/post-quantum/ml-dsa");
const { ed25519 } = await lib("@noble/curves/ed25519");

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
const upstream = http.createServer((req, res) => {
  reached++;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify({ operator: req.headers["x-ainra-operator"] ?? null, name: req.headers["x-ainra-passport-name"] ?? null,
    presentation: req.headers[PRESENTATION_HEADER] ?? null, pop: req.headers[POP_HEADER] ?? null }));
});
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
pilot.kill();

// 7 · passport mode: the agent's own key, a passport for it, a running copy
console.log("\npassport mode");
const AUD = "https://shop.example";
const edSk = ed25519.utils.randomPrivateKey();
const ml = ml_dsa65.keygen(randomBytes(32));
const holderKey = { ed25519: b64uEncode(ed25519.getPublicKey(edSk)), mldsa65: b64uEncode(ml.publicKey) };
const holderSign = (m) => ({ ed25519: ed25519.sign(m, edSk), mldsa65: ml_dsa65.sign(ml.secretKey, m) });
const registrarId = (await (await fetch(`${REG}/accreditation`)).json()).id ?? "registrar-07";
const hpop = holderSign(new TextEncoder().encode(canonicalize({ holder: holderKey, purpose: "ainra-holder-pop-v1", registrar: registrarId })));
const issued = await (await fetch(`${REG}/demo/issue`, { method: "POST", body: JSON.stringify({ operator: "specimen", lineage: "pilot",
  holder_key: holderKey, holder_pop: { ed25519: b64uEncode(hpop.ed25519), mldsa65: b64uEncode(hpop.mldsa65) } }) })).json();
const psub = issued.sub;
psub ? ok(`a passport for the agent's own key: ${psub}`) : fail(`issue: ${JSON.stringify(issued)}`);
const presentBundle = async () => (await fetch(`${REG}/present?sub=${encodeURIComponent(psub)}&now=${now()}`)).json();
let bundle = await presentBundle();
const iEd = ed25519.utils.randomPrivateKey(), iMl = ml_dsa65.keygen(randomBytes(32));
const instanceSign = (m) => ({ ed25519: ed25519.sign(m, iEd), mldsa65: ml_dsa65.sign(iMl.secretKey, m) });
const ic = await mintInstanceCredential({ passportClaimsB64: bundle.claims, instancePublic: { ed25519: ed25519.getPublicKey(iEd), mldsa65: iMl.publicKey },
  capabilities: ["demo:specimen"], audience: AUD, now: now(), lifetimeSecs: 900, iid: "i-" + randomBytes(4).toString("hex"), controlSign: holderSign });
const wire = (x) => ({ ed25519: b64uEncode(x.ed25519), mldsa65: b64uEncode(x.mldsa65) });
async function presentation(b) {
  const p = await proveInstancePossession({ audience: AUD, credential: ic, nonce: "p-" + randomBytes(6).toString("hex"), now: now(), instanceSign });
  return { ...b, instance: { sub: ic.sub, iid: ic.iid, ikey: wire(ic.ikey), nbf: ic.nbf, exp: ic.exp, capabilities: ic.capabilities, aud: ic.aud,
    passport_leaf: b64uEncode(ic.passportLeaf), sig: wire(ic.sig), pop: { aud: p.aud, nonce: p.nonce, ts: p.ts, sig: wire(p.sig) } } };
}

// 8 · the second pilot, passport mode
const ppPort = 20000 + Math.floor(Math.random() * 20000);
const ppilot = spawn("node", [new URL("pilot.mjs", import.meta.url).pathname, "--upstream", `http://127.0.0.1:${upPort}`, "--listen", `127.0.0.1:${ppPort}`,
  "--directory", join(work, "directory.json"), "--roots", join(work, "roots.json"), "--mode", "passport", "--audience", AUD, "--freshness", "F3",
  "--decisions", join(work, "passport-decisions.jsonl"), "--gate-key", join(work, "passport-gate.key")], { stdio: ["ignore", "ignore", "inherit"] });
const PP = `127.0.0.1:${ppPort}`;
for (let i = 0; i < 100; i++) { try { await fetch(`http://${PP}/.well-known/ainra-decisions-head`); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }
async function primeVia(b) {
  const r = await fetch(`http://${PP}${PRIME_PATH}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(await presentation(b)) });
  return { status: r.status, ref: (await r.json().catch(() => ({}))).ref, reason: r.headers.get("x-ainra-reason") };
}
async function sendSigned({ ref, signIt = true }) {
  const { pop } = splitPresentation(await presentation(bundle));
  const headers = { [PRESENTATION_HEADER]: ref, [POP_HEADER]: Buffer.from(JSON.stringify(pop)).toString("base64url"), host: PP };
  if (signIt) Object.assign(headers, await signPresentation({ req: { method: "POST", authority: PP, path: "/orders", headers }, keyid: ic.iid,
    nonce: "r-" + randomBytes(6).toString("hex"), created: now(), instanceSign }));
  const r = await fetch(`http://${PP}/orders`, { method: "POST", headers });
  return { status: r.status, reason: r.headers.get("x-ainra-reason"), body: await r.json().catch(() => null), headers };
}
let ref;
{
  const before = reached;
  const p = await primeVia(bundle);
  ref = p.ref;
  p.status === 201 && ref && reached === before ? ok(`the running copy sends its bundle once → 201, named by ${ref.slice(0, 22)}…; the upstream never sees it`)
    : fail(`prime: ${JSON.stringify(p)} (upstream saw ${reached - before})`);
}
{
  const before = reached;
  const r = await sendSigned({ ref });
  r.status === 200 && reached === before + 1 && r.body?.operator === "specimen" && r.body?.name === psub && !r.body?.presentation && !r.body?.pop
    ? ok(`a signed request → 200 from the upstream, which saw x-ainra-operator: ${r.body.operator} and no presentation headers`)
    : fail(`signed request: ${JSON.stringify({ status: r.status, reason: r.reason, body: r.body })}`);
}
// 9 · refused by name, never forwarded
{
  const before = reached;
  const u = await sendSigned({ ref, signIt: false });
  u.status === 403 && u.reason === "presentation_unsigned" && reached === before ? ok("unsigned → 403 presentation_unsigned, and the upstream never saw it") : fail(`unsigned: ${u.status} ${u.reason}`);
  const first = await sendSigned({ ref });
  const again = await fetch(`http://${PP}/orders`, { method: "POST", headers: first.headers });
  const reason = again.headers.get("x-ainra-reason");
  first.status === 200 && again.status === 403 && reason === "presentation_replayed" && reached === before + 1
    ? ok("the identical request sent twice → 1st 200, 2nd 403 presentation_replayed, and the replay never reached the upstream")
    : fail(`replay: ${first.status} then ${again.status} ${reason}`);
}
{
  const rv = await fetch(`${REG}/demo/revoke`, { method: "POST", body: JSON.stringify({ sub: psub, now: now() }) });
  rv.status === 200 ? ok("the passport revoked") : fail(`revoke: ${rv.status}`);
  bundle = await presentBundle();
  const before = reached;
  const p = await primeVia(bundle);
  p.status === 403 && p.reason === "revoked" && reached === before ? ok("its post-revocation bundle → 403 revoked; the pilot never stores it") : fail(`after revocation: ${JSON.stringify(p)}`);
}
// 10 · that pilot's log
{
  const lines = readFileSync(join(work, "passport-decisions.jsonl"), "utf8").trim().split("\n");
  const head = await (await fetch(`http://${PP}/.well-known/ainra-decisions-head`)).json();
  const chain = verifyDecisionChain(lines, Buffer.from(head.gate_key, "base64url"));
  const last = createHash("sha256").update(lines.at(-1)).digest("base64url");
  chain.ok && head.head === last && lines.some((l) => JSON.parse(l).reason === "presentation_replayed")
    ? ok(`the decision log: ${chain.count} signed, chained records (${lines.map((l) => JSON.parse(l).reason ?? "valid").join(", ")}); its last line is the published head`)
    : fail(`log: ${JSON.stringify(chain)} head ${head.head} last ${last}`);
}
ppilot.kill(); upstream.close(); dirSrv.close();
console.log(bad ? "\nPILOT-E2E FAILED" : "\nPILOT-E2E OK: one command in front of a service, both modes; linked keys and signed passports in, unlinked, revoked, unsigned and replayed requests refused by name, every decision signed");
process.exit(bad);
