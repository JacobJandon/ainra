#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// kits/pilot — one command puts an AINRA gate in front of any HTTP service, and keeps a signed record of what it let
// in. For a design partner's first week: nothing in their service changes; the gate sits in front, refuses by name,
// forwards the rest, and every decision lands in a hash-chained log they can hand to an auditor.
//
//   node kits/pilot/pilot.mjs --upstream http://127.0.0.1:3000 --listen 127.0.0.1:8080 \
//     --directory D --roots R --mode link --registrar URL [--freshness F1] [--capability C] \
//     [--decisions decisions.jsonl --gate-key gate.key [--publish-head URL [--head-every N] [--head-seconds T]]]
//
// MODES
//   link      the request is signed by a SIGNATURE AGENT (the Web Bot Auth profile): an independent open-source
//             verifier checks the signature against the operator's published key directory; AINRA Link then says who
//             stands behind that key, from the registrar's link index and signed status list (fetched whole, cached
//             inside the freshness class). Refused: not_linked, revoked, stale_status, … by name.
//   passport  the request carries an AINRA presentation and is signed by the agent's running copy (RFC 9421); the
//             standard @ainra/middleware gate, with send-once and single-use nonces.
// Forwarded requests carry `x-ainra-operator` and `x-ainra-passport-name`. `GET /.well-known/ainra-decisions-head`
// returns the log's current head digest, the gate's public key and the latest registrar receipt.
// HEADS (D-081) `--publish-head URL` hands the log's signed head statement to that registrar's `POST /decision-head`
//   every N decisions (`--head-every`, default 100) or T seconds (`--head-seconds`, default 300), whichever comes
//   first, and keeps the latest receipt in `<decisions>.receipt.json`. Records cut after the latest logged head are
//   the most a log can quietly lose, so the interval is that bound.
// D and R are file paths or URLs (the signed directory and its two root keys). gate.key is created if missing (0600).
import http from "node:http";
import { readFileSync, writeFileSync, appendFileSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { verify, parseSignatureAgentHeader, HTTP_MESSAGE_SIGNATURES_DIRECTORY } from "web-bot-auth";
import { verifierFromJWK } from "web-bot-auth/crypto";
import { Verifier, createDecisionLog } from "../../packages/sdk-ts/dist/index.js";
import { ainraGate, ainraLinkGate, ainraPrime, createPresentationStore, PRIME_PATH } from "../../packages/middleware/dist/index.js";

const sdkRequire = createRequire(new URL("../../packages/sdk-ts/package.json", import.meta.url));
const { ed25519 } = await import(pathToFileURL(sdkRequire.resolve("@noble/curves/ed25519")).href);

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(`--${k}`); return i >= 0 ? args[i + 1] : d; };
const need = (k) => opt(k) ?? (console.error(`missing --${k}`), process.exit(2));
const now = () => Math.floor(Date.now() / 1000);
const load = async (s) => JSON.parse(/^https?:/.test(s) ? await (await fetch(s)).text() : readFileSync(s, "utf8"));

const upstream = new URL(need("upstream"));
const [host, port] = need("listen").split(":");
const mode = opt("mode", "link");
const freshness = opt("freshness", "F2");
const directory = await load(need("directory"));
const roots = await load(need("roots"));
const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, freshness, false, opt("audience", ""));
if (!verifier) { console.error("the directory does not verify against the roots — refusing to start"); process.exit(2); }

// The decision log: one signed, chained line per decision, appended to a file.
let decisions = null, gatePub = null;
if (opt("decisions")) {
  const keyFile = opt("gate-key", "gate.key");
  if (!existsSync(keyFile)) writeFileSync(keyFile, Buffer.from(randomBytes(32)).toString("base64url") + "\n", { mode: 0o600 });
  const secret = Buffer.from(readFileSync(keyFile, "utf8").trim(), "base64url");
  gatePub = ed25519.getPublicKey(secret);
  const file = opt("decisions");
  const lastLine = existsSync(file) ? (readFileSync(file, "utf8").trim().split("\n").filter(Boolean).pop() ?? "") : "";
  decisions = createDecisionLog({ gatePublic: gatePub, sign: (m) => ed25519.sign(m, secret), append: (l) => { appendFileSync(file, l + "\n"); headDue(); }, freshness, audience: opt("audience", ""), lastLine });
}

// D-081: log the head at a registrar on a schedule, and keep the latest receipt beside the log.
const headTo = opt("publish-head");
const headEvery = Number(opt("head-every", "100")), headSeconds = Number(opt("head-seconds", "300"));
let sinceHead = 0, receipt = null, publishing = null;
const receiptFile = opt("decisions") ? opt("decisions") + ".receipt.json" : null;
if (receiptFile && existsSync(receiptFile)) { try { receipt = JSON.parse(readFileSync(receiptFile, "utf8")); } catch { receipt = null; } }
async function publishHead() {
  if (!headTo || !decisions || publishing) return publishing;
  const statement = decisions.statement();
  if (!statement) return null;
  publishing = (async () => {
    try {
      const r = await fetch(`${headTo.replace(/\/$/, "")}/decision-head`, { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ statement, gate_key: Buffer.from(gatePub).toString("base64url") }), signal: AbortSignal.timeout(5000) });
      const body = await r.json();
      if (!r.ok || body.statement !== statement) throw new Error(body.error ?? `HTTP ${r.status}`);
      receipt = body;
      writeFileSync(receiptFile, JSON.stringify(body) + "\n");
      sinceHead = 0;
    } catch (e) {
      console.error(`ainra pilot: head not logged (${e.message}); will retry`); // the next decision or tick retries
    } finally {
      publishing = null;
    }
  })();
  return publishing;
}
function headDue() {
  if (headTo && ++sinceHead >= headEvery) publishHead();
}
if (headTo) setInterval(() => { if (sinceHead > 0) publishHead(); }, headSeconds * 1000).unref();

// Link mode: who signed (the signature-agent profile, independently verified), then who stands behind that key.
const dirCache = new Map();
async function keysAt(uri) {
  const hit = dirCache.get(uri);
  if (hit && hit.until > now()) return hit.keys;
  const r = await fetch(new URL(HTTP_MESSAGE_SIGNATURES_DIRECTORY, uri), { signal: AbortSignal.timeout(5000) });
  const { keys } = await r.json();
  dirCache.set(uri, { keys, until: now() + Number(/max-age=(\d+)/.exec(r.headers.get("cache-control") ?? "")?.[1] ?? 0) });
  return keys;
}
async function signedBy(req) {
  const header = req.headers["signature-agent"];
  if (!header) return null;
  const headers = new Headers();
  for (let i = 0; i < req.rawHeaders.length; i += 2) headers.append(req.rawHeaders[i], req.rawHeaders[i + 1]);
  const request = new Request(`http://${req.headers.host}${req.url}`, { method: req.method, headers });
  for (const { label } of parseSignatureAgentHeader(header).entries) {
    let x = null;
    try {
      await verify(request, { label, resolver: async (profile) => {
        for (const k of await keysAt(profile.signatureAgent.uri)) {
          const v = await verifierFromJWK(k);
          if (v.keyid === profile.keyid && (k.exp === undefined || k.exp > now())) { x = k.x; return v; }
        }
        throw new Error("keyid not in that directory");
      } });
      return Buffer.from(x, "base64url");
    } catch { /* the next label */ }
  }
  return null;
}
const TTL = { F1: 10, F2: 60, F3: 600 }[freshness] ?? 10;
let cached = null;
async function source() {
  if (cached && cached.until > now()) return cached.v;
  const reg = need("registrar");
  const [index, status] = await Promise.all([fetch(`${reg}/links`).then((r) => r.json()), fetch(`${reg}/status-list`).then((r) => r.json())]);
  cached = { v: { index, status }, until: now() + TTL };
  return cached.v;
}

let gate, prime = null;
if (mode === "link") {
  gate = ainraLinkGate(verifier, { verifiedKey: (req) => req.ainraVerifiedKey, source, capability: () => opt("capability"), decisions: decisions ?? undefined });
} else if (mode === "passport") {
  const store = createPresentationStore();
  const seen = new Map();
  gate = ainraGate(verifier, { requireSignature: true, store, decisions: decisions ?? undefined,
    seenNonce: (n) => { const had = seen.has(n); seen.set(n, now()); if (seen.size > 100_000) seen.clear(); return had; } });
  prime = ainraPrime(verifier, { store });
} else { console.error("--mode is link or passport"); process.exit(2); }

const server = http.createServer(async (req, res) => {
  const chunks = []; for await (const c of req) chunks.push(c);
  const body = Buffer.concat(chunks);
  if (req.method === "GET" && req.url.split("?")[0] === "/.well-known/ainra-decisions-head") {
    res.setHeader("content-type", "application/json");
    if (new URL(req.url, "http://x").searchParams.get("flush") === "1") await publishHead(); // log the head now
    return res.end(JSON.stringify({ head: decisions?.head() ?? null, gate_key: gatePub ? Buffer.from(gatePub).toString("base64url") : null, receipt }));
  }
  const shim = {
    status(c) { res.statusCode = c; return shim; },
    json(b) { res.setHeader("content-type", "application/json"); res.end(JSON.stringify(b)); },
    setHeader: (k, v) => res.setHeader(k, v),
  };
  req.rawBody = body;
  if (mode === "passport" && req.method === "POST" && req.url === PRIME_PATH) {
    try { req.body = JSON.parse(body.toString("utf8")); } catch { req.body = undefined; }
    return prime(req, shim);
  }
  if (mode === "link") req.ainraVerifiedKey = await signedBy(req);
  await gate(req, shim, () => {
    // Forward, stripping the AINRA presentation headers and naming who was admitted.
    const a = req.ainraLink ?? null, p = req.ainra?.event ?? null;
    const headers = { ...req.headers, host: upstream.host };
    for (const h of ["x-ainra-passport", "x-ainra-pop", "x-ainra-operator", "x-ainra-passport-name"]) delete headers[h];
    if (a) { headers["x-ainra-operator"] = a.operator; headers["x-ainra-passport-name"] = a.passport; }
    if (p?.name) { headers["x-ainra-passport-name"] = p.name; headers["x-ainra-operator"] = p.name.split(":")[2]; }
    const up = http.request({ hostname: upstream.hostname, port: upstream.port, path: req.url, method: req.method, headers }, (ur) => {
      res.writeHead(ur.statusCode ?? 502, ur.headers);
      ur.pipe(res);
    });
    up.on("error", () => { res.statusCode = 502; res.end(); });
    up.end(body);
  });
});
server.listen(Number(port), host, () => console.log(`ainra pilot (${mode}) on http://${host}:${port} → ${upstream.origin}${decisions ? " · decisions → " + opt("decisions") : ""}`));
