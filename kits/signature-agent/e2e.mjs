#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make signature-agent-e2e — one request, two readers, live (D-070).
//
// An agent operator already signs its agents' requests as a SIGNATURE AGENT: the Web Bot Auth profile, Ed25519 keys
// published in a directory at its origin. Its agent also holds an AINRA passport. This drill puts both signatures on
// the same HTTP request and has each verified by its own reader, at the real clock:
//
//   1. the agent's own key → a passport from the live registrar → an instance credential for one running copy
//   2. the operator publishes its signature-agent directory (a JWKS at the well-known path)
//   3. an origin runs BOTH readers on every request: an independent open-source signature-agent verifier, which
//      fetches the operator's directory, and AINRA's gate (`@ainra/middleware`, or `--edge` for `@ainra/edge`)
//   4. signed by the operator first and the running copy second → both valid
//   5. signed by the running copy first, the operator's outer signature covering AINRA's → both valid
//   6. each reader holds its own line: either signature broken or missing, the other reader's answer does not move
//   7. revocation — the operator's signature on the request still verifies; AINRA refuses the revoked passport at
//      the door. The signature-agent profile defines no revocation: its remedy is removing the key from the directory,
//      which reaches a verifier at its next refresh. Both shown, as they are.
//
// TEST-ROOT, local directory over http on 127.0.0.1 (the profile requires https in deployment). It proves the
// mechanism; it is not evidence that any operator runs it.
//
// WITNESS: could this observe a failure? Yes — every step asserts both readers' answers, and step 4 is the positive
// control for both. Before D-070 every AINRA gate refused step 4 as `presentation_sig_invalid`.

import http from "node:http";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { readFileSync } from "node:fs";
import { sign, verify, parseSignatureAgentHeader, HTTP_MESSAGE_SIGNATURES_DIRECTORY } from "web-bot-auth";
import { signerFromJWK, verifierFromJWK } from "web-bot-auth/crypto";
import { appendSignature, component } from "http-message-sig";
import {
  Verifier, canonicalize, mintInstanceCredential, proveInstancePossession, signPresentation, PRESENTATION_HEADER,
  PRIME_PATH, POP_HEADER, splitPresentation,
} from "../../packages/sdk-ts/dist/index.js";
import { b64uEncode } from "../../packages/sdk-ts/dist/crypto.js";
import { ainraGate, ainraPrime, createPresentationStore } from "../../packages/middleware/dist/index.js";

const EDGE = process.argv.includes("--edge");
const REG = process.env.AINRA_REGISTRAR ?? "http://127.0.0.1:4970";
const ART = process.env.AINRA_ARTIFACTS ?? "http://127.0.0.1:8091";
const AUD = "https://shop.example";
const now = () => Math.floor(Date.now() / 1000);

const sdkRequire = createRequire(new URL("../../packages/sdk-ts/package.json", import.meta.url));
const load = async (m) => import(pathToFileURL(sdkRequire.resolve(m)).href);
const { ml_dsa65 } = await load("@noble/post-quantum/ml-dsa");
const { ed25519 } = await load("@noble/curves/ed25519");

let bad = 0;
const ok = (m) => console.log(`  ok    ${m}`);
const fail = (m) => { console.error(`  ✗     ${m}`); bad = 1; };
const step = (m) => console.log(`\n${m}`);
async function j(url, init) {
  const r = await fetch(url, init);
  const t = await r.text();
  let body; try { body = JSON.parse(t); } catch { body = t; }
  return { status: r.status, body };
}

try { await fetch(`${REG}/accreditation`, { signal: AbortSignal.timeout(3000) }); }
catch { console.error(`signature-agent-e2e: no live registrar at ${REG} — run \`make live-up\` first`); process.exit(2); }

// ── 1 · the agent: its own key, a passport for it, an instance credential for one running copy ────────────────────
step("1 · the agent: its own key → a passport from the live registrar → a credential for one running copy");
const edSk = ed25519.utils.randomPrivateKey();
const ml = ml_dsa65.keygen(randomBytes(32));
const holderKey = { ed25519: b64uEncode(ed25519.getPublicKey(edSk)), mldsa65: b64uEncode(ml.publicKey) };
const holderSign = (msg) => ({ ed25519: ed25519.sign(msg, edSk), mldsa65: ml_dsa65.sign(ml.secretKey, msg) });
const accred = await j(`${REG}/accreditation`);
const registrarId = accred.body?.id ?? accred.body?.registrar ?? "registrar-07";
const popSig = holderSign(new TextEncoder().encode(canonicalize({ holder: holderKey, purpose: "ainra-holder-pop-v1", registrar: registrarId })));
const issued = await j(`${REG}/demo/issue`, {
  method: "POST",
  body: JSON.stringify({ operator: "specimen", lineage: "sigagent", holder_key: holderKey, holder_pop: { ed25519: b64uEncode(popSig.ed25519), mldsa65: b64uEncode(popSig.mldsa65) } }),
});
if (issued.status !== 200) { fail(`issue failed: ${issued.status} ${JSON.stringify(issued.body)}`); process.exit(1); }
const sub = issued.body.sub;
const directory = (await j(`${ART}/directory.json`)).body;
const roots = (await j(`${ART}/roots.json`)).body;
const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F3", false, AUD);
if (!verifier) { fail("could not build a verifier from the published directory"); process.exit(1); }
const bundle = (await j(`${REG}/present?sub=${encodeURIComponent(sub)}&now=${now()}`)).body;
const iEdSk = ed25519.utils.randomPrivateKey();
const iMl = ml_dsa65.keygen(randomBytes(32));
const instanceSign = (msg) => ({ ed25519: ed25519.sign(msg, iEdSk), mldsa65: ml_dsa65.sign(iMl.secretKey, msg) });
const ic = await mintInstanceCredential({
  passportClaimsB64: bundle.claims, instancePublic: { ed25519: ed25519.getPublicKey(iEdSk), mldsa65: iMl.publicKey },
  capabilities: ["demo:specimen"], audience: AUD, now: now(), lifetimeSecs: 900, iid: "i-" + randomBytes(4).toString("hex"),
  controlSign: holderSign,
});
const wireSig = (s) => ({ ed25519: b64uEncode(s.ed25519), mldsa65: b64uEncode(s.mldsa65) });
async function presentationFor(b = bundle) {
  const pop = await proveInstancePossession({ audience: AUD, credential: ic, nonce: "p-" + randomBytes(6).toString("hex"), now: now(), instanceSign });
  return {
    ...b,
    instance: {
      sub: ic.sub, iid: ic.iid, ikey: wireSig(ic.ikey), nbf: ic.nbf, exp: ic.exp, capabilities: ic.capabilities,
      aud: ic.aud, passport_leaf: b64uEncode(ic.passportLeaf), sig: wireSig(ic.sig),
      pop: { aud: pop.aud, nonce: pop.nonce, ts: pop.ts, sig: wireSig(pop.sig) },
    },
  };
}
ok(`${sub} · running copy ${ic.iid}, credential for ${ic.exp - ic.nbf}s`);

// ── 2 · the operator: a signature agent with a published key directory ───────────────────────────────────────────
step("2 · the operator publishes its signature-agent directory");
const opKeys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const opPrivate = await crypto.subtle.exportKey("jwk", opKeys.privateKey);
const opSigner = await signerFromJWK({ ...opPrivate, alg: "EdDSA" }); // WebCrypto exports alg "Ed25519"; JOSE says EdDSA
let published = [{ kty: "OKP", crv: "Ed25519", x: opPrivate.x, use: "sig", nbf: now() - 60, exp: now() + 3600 }];
let directoryServed = 0;
const dirServer = http.createServer((req, res) => {
  if (req.url !== HTTP_MESSAGE_SIGNATURES_DIRECTORY) { res.statusCode = 404; res.end(); return; }
  directoryServed++;
  res.setHeader("content-type", "application/http-message-signatures-directory+json");
  res.setHeader("cache-control", "max-age=300");
  res.end(JSON.stringify({ keys: published }));
});
await new Promise((r) => dirServer.listen(0, "127.0.0.1", r));
const AGENT_URI = `http://127.0.0.1:${dirServer.address().port}`;
ok(`${AGENT_URI}${HTTP_MESSAGE_SIGNATURES_DIRECTORY} · one Ed25519 key, keyid ${opSigner.keyid.slice(0, 16)}…`);

// ── 3 · the origin: both readers on every request ────────────────────────────────────────────────────────────────
step(`3 · an origin reads every request twice: a signature-agent verifier, then AINRA's ${EDGE ? "edge gate (@ainra/edge)" : "gate (@ainra/middleware)"}`);
// The signature-agent reader: an independent open-source implementation of that profile. It resolves keys from the
// operator's directory and caches it as HTTP caching says (max-age=300) — so a key the operator withdraws keeps
// verifying here until the next refresh, exactly as the profile states.
const dirCache = new Map();
async function keysAt(uri) {
  const hit = dirCache.get(uri);
  if (hit && hit.until > now()) return hit.keys;
  const r = await fetch(new URL(HTTP_MESSAGE_SIGNATURES_DIRECTORY, uri));
  const { keys } = await r.json();
  const maxAge = Number(/max-age=(\d+)/.exec(r.headers.get("cache-control") ?? "")?.[1] ?? 0);
  dirCache.set(uri, { keys, until: now() + maxAge });
  return keys;
}
async function readSignatureAgent(request) {
  const header = request.headers.get("signature-agent");
  if (!header) return "absent";
  const out = [];
  for (const { label } of parseSignatureAgentHeader(header).entries) {
    try {
      const res = await verify(request, {
        label,
        resolver: async (profile) => {
          for (const k of await keysAt(profile.signatureAgent.uri)) {
            const v = await verifierFromJWK(k);
            if (v.keyid === profile.keyid && (k.exp === undefined || k.exp > now())) return v;
          }
          throw new Error(`keyid ${profile.keyid.slice(0, 12)}... is not in that directory`);
        },
      });
      out.push(`${label}=valid`);
      void res;
    } catch (e) {
      out.push(`${label}=invalid (${e.cause?.message ?? e.message})`);
    }
  }
  return out.join(", ");
}

const seen = new Set();
const store = createPresentationStore();
const gate = ainraGate(verifier, { now, requireSignature: true, store, seenNonce: (n) => { const had = seen.has(n); seen.add(n); return had; } });
const prime = ainraPrime(verifier, { store, now });
let edgeGate = null;
if (EDGE) {
  const edge = await import("../../packages/edge/src/index.mjs");
  await edge.initAinra(readFileSync(new URL("../../packages/edge/wasm/ainra_wasm_bg.wasm", import.meta.url)));
  edgeGate = await edge.createAinraEdgeGate({ directory, roots, audience: AUD, now });
}
const origin = http.createServer(async (req, res) => {
  const chunks = []; for await (const c of req) chunks.push(c);
  const body = Buffer.concat(chunks);
  const headers = new Headers();
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    const k = req.rawHeaders[i].toLowerCase();
    if (!["host", "connection", "content-length", "transfer-encoding"].includes(k)) headers.append(k, req.rawHeaders[i + 1]);
  }
  const asRequest = () => new Request(`http://${req.headers.host}${req.url}`, { method: req.method, headers, body: body.length ? body : undefined });
  res.setHeader("x-signature-agent", await readSignatureAgent(asRequest()));
  if (EDGE) {
    const g = await edgeGate(asRequest());
    if (g.allow) { res.statusCode = 200; res.end("{}"); return; }
    res.statusCode = g.response.status;
    g.response.headers.forEach((v, k) => res.setHeader(k, v));
    res.end(Buffer.from(await g.response.arrayBuffer()));
    return;
  }
  const shim = {
    status(c) { res.statusCode = c; return shim; },
    json(b) { res.setHeader("content-type", "application/json"); res.end(JSON.stringify(b)); },
    setHeader: (k, v) => res.setHeader(k, v),
  };
  if (req.method === "POST" && req.url === PRIME_PATH) {
    try { req.body = JSON.parse(body.toString("utf8")); } catch { req.body = undefined; }
    prime(req, shim);
    return;
  }
  gate(req, shim, () => { res.statusCode = 200; res.end("{}"); });
});
await new Promise((r) => origin.listen(0, "127.0.0.1", r));
const authority = `127.0.0.1:${origin.address().port}`;
ok(`origin on ${authority}`);

// ── the two signers ──────────────────────────────────────────────────────────────────────────────────────────────
// The operator signs as a signature agent through the same open-source library, and APPENDS to whatever signature
// fields the request already has; AINRA's SDK appends too (D-070). Neither overwrites the other.
async function operatorSigns(url, method, headers, cover = []) {
  const f = await sign(new Request(url, { method, headers }), {
    signer: opSigner, label: "sig1", expires: new Date((now() + 300) * 1000), additionalComponents: cover,
  });
  return appendSignature(headers, f);
}
async function copySigns(method, path, headers) {
  const add = await signPresentation({
    req: { method, authority, path, headers: Object.fromEntries(headers) }, keyid: ic.iid,
    nonce: "r-" + randomBytes(6).toString("hex"), created: now(), instanceSign,
  });
  for (const [k, v] of Object.entries(add)) headers.set(k, v);
  return headers;
}
let REF = null;
async function baseHeaders() {
  const { pop } = splitPresentation(await presentationFor());
  return new Headers({
    "signature-agent": `sig1="${AGENT_URI}"`,
    [PRESENTATION_HEADER]: REF,
    [POP_HEADER]: Buffer.from(JSON.stringify(pop)).toString("base64url"),
  });
}
async function send(path, headers, { method = "GET", pathOnWire } = {}) {
  const r = await fetch(`http://${authority}${pathOnWire ?? path}`, { method, headers });
  return { status: r.status, reason: r.headers.get("x-ainra-reason"), agent: r.headers.get("x-signature-agent") };
}
const both = (r) => `signature agent: ${r.agent} · AINRA: ${r.status}${r.reason ? " " + r.reason : ""}`;

{
  const r = await fetch(`http://${authority}${PRIME_PATH}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(await presentationFor()) });
  REF = (await r.json().catch(() => ({}))).ref;
  r.status === 201 && REF ? ok(`the running copy sends its bundle once → 201 (D-065)`) : fail(`priming failed: ${r.status}`);
}

// ── 4 · operator first, running copy second ──────────────────────────────────────────────────────────────────────
step("4 · the operator signs, then the running copy appends its own signature");
const url = (p) => `http://${authority}${p}`;
{
  const h = await copySigns("GET", "/orders", await operatorSigns(url("/orders"), "GET", await baseHeaders()));
  const members = h.get("signature-input").split(/,\s*(?=[a-z*][a-z0-9_.*-]*=\()/).map((m) => m.split("=")[0]);
  const r = await send("/orders", h);
  r.status === 200 && r.agent === "sig1=valid" && members.join(",") === "sig1,ainra"
    ? ok(`one request, members [${members}] → ${both(r)}`)
    : fail(`both signatures: members [${members}] · ${both(r)}`);
  const total = [...h].reduce((n, [k, v]) => n + k.length + v.length + 4, 0);
  ok(`request headers ${(total / 1024).toFixed(1)} KiB with both signatures — Node's default limit is 16 KiB`);
}

// ── 5 · running copy first, the operator's outer signature covering AINRA's ───────────────────────────────────────
step("5 · the running copy signs first; the operator's outer signature covers AINRA's (the profile's §5.2.2 union)");
{
  const h = await copySigns("GET", "/orders", await baseHeaders());
  const cover = ["@method", "@path", PRESENTATION_HEADER, component("signature-input", { key: "ainra" }), component("signature", { key: "ainra" })];
  const signed = await operatorSigns(url("/orders"), "GET", h, cover);
  const r = await send("/orders", signed);
  r.status === 200 && r.agent === "sig1=valid"
    ? ok(`${both(r)} — the operator's signature is evidence AINRA's was present; AINRA neither needs nor reads it`)
    : fail(`outer signature: ${both(r)}`);
}

// ── 6 · each reader holds its own line ───────────────────────────────────────────────────────────────────────────
step("6 · each signature stands alone");
{
  const h = await operatorSigns(url("/orders"), "GET", await baseHeaders());
  const r = await send("/orders", h);
  r.status === 403 && r.reason === "presentation_unsigned" && r.agent === "sig1=valid"
    ? ok(`only the operator signed → ${both(r)}`) : fail(`operator only: ${both(r)}`);
}
{
  const h = await copySigns("GET", "/orders", await operatorSigns(url("/orders"), "GET", await baseHeaders()));
  h.set("signature", h.get("signature").replace(/sig1=:([A-Za-z0-9+/=]+):/, (_, b) => {
    const raw = Buffer.from(b, "base64"); raw[0] ^= 1; return `sig1=:${raw.toString("base64")}:`;
  }));
  const r = await send("/orders", h);
  r.status === 200 && r.agent?.startsWith("sig1=invalid")
    ? ok(`the operator's signature broken → ${both(r)} — a site that requires both must check both`)
    : fail(`operator signature broken: ${both(r)}`);
}
{
  const h = await copySigns("GET", "/orders", await operatorSigns(url("/orders"), "GET", await baseHeaders()));
  const r = await send("/orders", h, { pathOnWire: "/admin/refunds" });
  r.status === 403 && r.reason === "presentation_sig_invalid" && r.agent === "sig1=valid"
    ? ok(`moved to another path → ${both(r)} — the operator's minimal signature covers @authority, not the path`)
    : fail(`moved: ${both(r)}`);
}

// ── 7 · revocation ───────────────────────────────────────────────────────────────────────────────────────────────
step("7 · revoke the passport; then withdraw the operator's key");
const rv = await j(`${REG}/demo/revoke`, { method: "POST", body: JSON.stringify({ sub, now: now() }) });
if (rv.status !== 200) fail(`revoke failed: ${rv.status} ${JSON.stringify(rv.body)}`);
Object.assign(bundle, (await j(`${REG}/present?sub=${encodeURIComponent(sub)}&now=${now()}`)).body);
{
  // ONE request: the running copy sends its current (post-revocation) bundle, and the operator signs that request.
  const body = JSON.stringify(await presentationFor());
  const h = await operatorSigns(url(PRIME_PATH), "POST", new Headers({ "signature-agent": `sig1="${AGENT_URI}"`, "content-type": "application/json" }));
  const r0 = await fetch(url(PRIME_PATH), { method: "POST", headers: h, body });
  const r = { status: r0.status, reason: r0.headers.get("x-ainra-reason"), agent: r0.headers.get("x-signature-agent") };
  r.status === 403 && r.reason === "revoked" && r.agent === "sig1=valid"
    ? ok(`the revoked passport, on a request the operator signed → ${both(r)} — refused at the door`)
    : fail(`after revocation: ${both(r)}`);
}
{
  // The signature-agent layer's own remedy: take the key out of the directory. A verifier holding the directory in
  // cache keeps accepting it until its next refresh; then it stops.
  published = [];
  const served = directoryServed;
  const h = await operatorSigns(url("/orders"), "GET", await baseHeaders());
  const cached = await send("/orders", h);
  const fromCache = directoryServed === served;
  dirCache.clear(); // the cache entry expires (max-age=300 elapsed)
  const h2 = await operatorSigns(url("/orders"), "GET", await baseHeaders());
  const refreshed = await send("/orders", h2);
  cached.agent === "sig1=valid" && fromCache && refreshed.agent?.startsWith("sig1=invalid") && directoryServed === served + 1
    ? ok(`key withdrawn from the directory → still "valid" from cache, "${refreshed.agent}" after the refresh`)
    : fail(`withdrawn key: cached ${cached.agent}, refreshed ${refreshed.agent}`);
}

origin.close();
dirServer.close();
console.log(bad
  ? "\nSIGNATURE-AGENT-E2E FAILED"
  : `\nSIGNATURE-AGENT-E2E OK${EDGE ? " (EDGE)" : ""}: one request carried a signature agent's signature and a running copy's; an independent signature-agent verifier and AINRA's gate each read their own, in either order, and each held its own line. After revocation the passport was refused at the door while the operator's key still verified. TEST-ROOT.`);
process.exit(bad);
