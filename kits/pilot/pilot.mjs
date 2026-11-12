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
// WATCH (D-105) `--watch` puts the gate BESIDE a route: the check never refuses a request and never holds one up. With
//   --upstream every request goes on at once with its header lines as sent (only Host's value is the upstream's, as
//   without --watch); without --upstream the pilot is a mirror target and answers 204 at once. Node's own HTTP limits
//   are raised to what a service may take; the README names those that remain. A copy is checked on a second thread,
//   never in the request's path, and every request appends one JSON line to --observations (default ./watch.jsonl):
//   time, method, path without its query, which signatures it carried, and either what the gate would have decided
//   and why (the operator and passport when admitted, and check_ms) or `unchecked` and why not. Never an address, a
//   query string, a body or any other header, and the file is sent nowhere. `GET /.well-known/ainra-watch` returns the
//   running summary to loopback clients only. A watch signs nothing: --watch with --decisions exits 2.
//   `node kits/pilot/watch-report.mjs FILE` summarises the file.
// D and R are file paths or URLs (the signed directory and its two root keys). gate.key is created if missing (0600).
import http from "node:http";
import { readFileSync, writeFileSync, appendFileSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { pipeline } from "node:stream";
import { pathToFileURL } from "node:url";
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";
import { verify, parseSignatureAgentHeader, HTTP_MESSAGE_SIGNATURES_DIRECTORY } from "web-bot-auth";
import { verifierFromJWK } from "web-bot-auth/crypto";
import { Verifier, createDecisionLog, PRESENTATION_HEADER, POP_HEADER } from "../../packages/sdk-ts/dist/index.js";
import { ainraGate, ainraLinkGate, ainraPrime, createPresentationStore, PRIME_PATH } from "../../packages/middleware/dist/index.js";

const sdkRequire = createRequire(new URL("../../packages/sdk-ts/package.json", import.meta.url));
const { ed25519 } = await import(pathToFileURL(sdkRequire.resolve("@noble/curves/ed25519")).href);

// In watch mode this file also runs as the second thread (below), with the same arguments.
const args = isMainThread ? process.argv.slice(2) : workerData.args;
const opt = (k, d) => { const i = args.indexOf(`--${k}`); return i >= 0 ? args[i + 1] : d; };
const need = (k) => opt(k) ?? (console.error(`missing --${k}`), process.exit(2));
const now = () => Math.floor(Date.now() / 1000);
const load = async (s) => JSON.parse(/^https?:/.test(s) ? await (await fetch(s)).text() : readFileSync(s, "utf8"));

// D-105: a watch serves every request, so it keeps no decision log. Checked before anything is read.
const watch = args.includes("--watch");
if (watch && opt("decisions")) {
  console.error("--watch keeps no decision log: a signed record saying \"refused\" for a request that was in fact served would be false evidence; drop --decisions");
  process.exit(2);
}

const upstream = watch && !args.includes("--upstream") ? null : new URL(need("upstream"));
const [host, port] = need("listen").split(":");
const mode = opt("mode", "link");
const freshness = opt("freshness", "F2");
const directory = isMainThread ? await load(need("directory")) : workerData.directory;
const roots = isMainThread ? await load(need("roots")) : workerData.roots;
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
// A watch (D-105) runs for weeks and any client can name a new directory, so it keeps at most DIRS of them, oldest
// fetched first out, each for at most DIR_AGE seconds whatever max-age it was served with.
const dirCache = new Map(), DIRS = 512, DIR_AGE = 3600;
async function keysAt(uri) {
  const hit = dirCache.get(uri);
  if (hit && hit.until > now()) return hit.keys;
  const r = await fetch(new URL(HTTP_MESSAGE_SIGNATURES_DIRECTORY, uri), { signal: AbortSignal.timeout(5000) });
  const { keys } = await r.json();
  const age = Number(/max-age=(\d+)/.exec(r.headers.get("cache-control") ?? "")?.[1] ?? 0);
  if (watch) { dirCache.delete(uri); while (dirCache.size >= DIRS) dirCache.delete(dirCache.keys().next().value); }
  dirCache.set(uri, { keys, until: now() + (watch ? Math.min(age, DIR_AGE) : age) });
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
let cached = null, fetching = null;
async function source() {
  if (cached && cached.until > now()) return cached.v;
  // A watch can have a thousand checks waiting: they share one fetch, which gives up after 5 s as keysAt's does.
  if (watch) return (fetching ??= fetchSource(AbortSignal.timeout(5000)).finally(() => { fetching = null; }));
  return fetchSource();
}
async function fetchSource(signal) {
  const reg = need("registrar");
  const [index, status] = await Promise.all([fetch(`${reg}/links`, { signal }).then((r) => r.json()), fetch(`${reg}/status-list`, { signal }).then((r) => r.json())]);
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
  prime = ainraPrime(verifier, { store: watch ? inOrder(store) : store });
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
if (isMainThread && !watch) server.listen(Number(port), host, () => console.log(`ainra pilot (${mode}) on http://${host}:${port} → ${upstream.origin}${decisions ? " · decisions → " + opt("decisions") : ""}`));

// ── WATCH (D-105): the gate beside a route, deciding nothing ─────────────────────────────────────────────────────
// Two threads. This one forwards (or answers 204) and never runs a check. The second holds the gate, the passport
// store and the nonce memory; it records a refusal or an admission, writes the observations and keeps the summary.
// When it falls behind, requests still go on at once, and their lines say they were not checked.
const WATCH_PATH = "/.well-known/ainra-watch";
const observations = watch ? resolve(opt("observations") ?? "watch.jsonl") : null;

// The second thread's line: checks in the order their requests arrived, one per turn of its event loop, so the
// summary and the prime path, which do not wait in it, answer between two checks.
const jobs = [];
let draining = false;
function inLine(job) {
  jobs.push(job);
  if (!draining) { draining = true; setImmediate(nextJob); }
}
function nextJob() {
  const job = jobs.shift();
  if (jobs.length) setImmediate(nextJob); else draining = false;
  job();
}
// The prime path answers at once, but the bundle it stores takes its place in that line, so a request that came
// before it is checked against the store as it was when that request came, as without --watch.
function inOrder(store) {
  return { get: (ref, t) => store.get(ref, t), put: (ref, stable, exp) => inLine(() => store.put(ref, stable, exp)) };
}

if (!isMainThread) checkThread();
else if (watch) await watchFront();

async function watchFront() {
  if (mode === "link") need("registrar"); // otherwise a missing one would surface only at the first signed request
  try { appendFileSync(observations, "", { mode: 0o600 }); }
  catch (e) { console.error(`cannot write the observations file ${observations} (${e.code ?? e.message})`); process.exit(2); }
  // Node's own HTTP limits, raised to what a service may take: headers up to 256 KiB (a whole presentation sent in a
  // header is about 64 KB), headers within 60 s, and no deadline for a body. The README names what remains.
  const MAX_HEADERS = 256 << 10;
  // What may wait for the check: copies, and their bytes (headers and body, counted from the first byte copied). Past
  // these a request still goes on, and its line says it was not checked. A body over 1 MiB is not copied at all.
  const MAX_WAITING = 1000, MAX_WAITING_BYTES = 32 << 20, MAX_BODY = 1 << 20;
  let waiting = 0, waitingBytes = 0, asked = 0, serving = false, stopped = false;
  const replies = new Map();
  const second = new Worker(new URL(import.meta.url), { workerData: { args, directory, roots } });
  const halt = (why) => {
    if (!serving) { console.error(`ainra pilot: the watch did not start (${why})`); process.exit(2); }
    if (stopped) return;
    stopped = true;
    console.error(`ainra pilot (watch): the check stopped (${why}); requests still go on, unchecked`);
    for (const reply of replies.values()) reply(null);
    replies.clear();
  };
  // Once requests flow, an error's message may hold what one of them carried, so only its kind is logged.
  second.on("error", (e) => halt(serving ? e.code ?? e.name : e.message));
  second.on("exit", (code) => halt(`exit ${code}`));
  await new Promise((ready) => second.on("message", (m) => {
    if (m.t === "ready") ready();
    else if (m.t === "checked") { waiting--; waitingBytes -= m.bytes; }
    else if (m.t === "reply") { const reply = replies.get(m.id); replies.delete(m.id); reply?.(m); }
  }));
  serving = true;

  // The pilot's own paths, answered by the second thread: the summary, and in passport mode the prime path.
  const ask = (msg, res, transfer = []) => {
    if (stopped) { res.statusCode = 503; return res.end(); }
    const id = ++asked;
    replies.set(id, (m) => {
      if (m) return answer(res, m);
      res.statusCode = 503;
      res.end();
    });
    second.postMessage({ ...msg, id }, transfer);
  };
  // Nothing in the second thread's answer may throw on this thread: a header Node will not send is dropped, and any
  // other failure answers 500.
  const answer = (res, m) => {
    try {
      for (const [k, v] of m.headers) try { res.setHeader(k, v); } catch { /* not sendable: dropped */ }
      res.statusCode = m.status;
      res.end(m.body);
    } catch {
      try { res.statusCode = 500; res.end(); } catch { res.destroy(); }
    }
  };
  async function primeVia(req, res) {
    const chunks = [];
    let size = 0;
    try { for await (const c of req) if ((size += c.length) <= MAX_BODY) chunks.push(c); } catch { return; } // the client went away
    if (size > MAX_BODY) { res.statusCode = 413; return res.end(); } // no presentation is near this size
    const body = new Uint8Array(Buffer.concat(chunks));
    ask({ t: "prime", method: req.method, url: req.url, headers: req.headers, body }, res, [body.buffer]);
  }
  // From this machine, and not relayed by a proxy on it for someone else.
  const loopback = (req) => /^(127\.|::1$|::ffff:127\.)/.test(req.socket.remoteAddress ?? "")
    && !["forwarded", "x-forwarded-for", "x-real-ip"].some((h) => h in req.headers);
  // What a line may say about a request: its path without the query, and which signatures it carried.
  const pathOnly = (u) => { if (u.startsWith("/")) return u.split("?")[0]; try { return new URL(u).pathname; } catch { return "*"; } };
  const carried = (h) => [
    ...(h["signature-agent"] !== undefined ? ["signature-agent"] : []),
    ...(h.signature !== undefined || h["signature-input"] !== undefined ? ["rfc9421"] : []),
    ...(h[PRESENTATION_HEADER] !== undefined || h[POP_HEADER] !== undefined ? ["ainra-presentation"] : []),
  ];

  // Every header line as the client sent it: name, case, order and duplicates. Only Host's value is the service's,
  // as without --watch. The answer comes back the same way. Node adds only what its own connection needs (README).
  const toService = (raw) => {
    const out = [];
    let host = false;
    for (let i = 0; i < raw.length; i += 2) {
      const isHost = raw[i].toLowerCase() === "host";
      host ||= isHost;
      out.push(raw[i], isHost ? upstream.host : raw[i + 1]);
    }
    if (!host) out.push("Host", upstream.host);
    return out;
  };
  function forward(req, res) {
    let up;
    try {
      up = http.request({ hostname: upstream.hostname, port: upstream.port, path: req.url, method: req.method,
        headers: toService(req.rawHeaders), maxHeaderSize: MAX_HEADERS }, (ur) => {
        try { res.writeHead(ur.statusCode ?? 502, ur.statusMessage, ur.rawHeaders); }
        catch { ur.destroy(); res.statusCode = 502; return void res.end(); } // an answer Node will not send on
        pipeline(ur, res, () => {}); // either side failing ends the other, as on one connection
      });
    } catch { res.statusCode = 502; res.end(); return void req.resume(); } // a target this client cannot send on
    up.on("error", () => {
      if (!res.headersSent) { res.statusCode = 502; res.end(); }
      else if (!res.writableEnded) res.destroy();
      req.resume();
    });
    req.pipe(up);
    req.once("close", () => { if (!req.complete) up.destroy(); }); // the client went away mid-body
  }

  const server = http.createServer({ maxHeaderSize: MAX_HEADERS, requestTimeout: 0, headersTimeout: 60_000 }, (req, res) => {
    const at = Date.now();
    if (req.method === "GET" && req.url.split("?")[0] === WATCH_PATH) {
      req.resume();
      if (loopback(req)) return ask({ t: "summary", waiting }, res);
      res.statusCode = 403;
      res.setHeader("content-type", "application/json");
      return res.end(JSON.stringify({ error: "ainra: the watch summary answers on this machine only" }));
    }
    if (mode === "passport" && req.method === "POST" && req.url === PRIME_PATH) return void primeVia(req, res).catch(() => res.destroy());
    // The service's traffic: on its way at once, as it came, and never held for the check.
    if (upstream) forward(req, res);
    else { res.statusCode = 204; res.end(); }
    // A copy for the check, taken as the request streams past. Link mode reads headers only, so it copies no body.
    const seen = { at, method: req.method, path: pathOnly(req.url), signatures: carried(req.headers) };
    let body = mode === "passport" ? [] : null, size = 0, held = 0, why = null;
    const hold = (n) => { if (waitingBytes + n > MAX_WAITING_BYTES) return false; waitingBytes += n; held += n; return true; };
    const release = () => { waitingBytes -= held; held = 0; };
    const skip = (reason) => { why ??= reason; body = null; release(); };
    if (!hold(req.url.length + 2 * req.rawHeaders.reduce((n, s) => n + s.length, 0))) skip("check_busy"); // headers go twice
    if (mode === "passport") req.on("data", (c) => {
      size += c.length;
      if (!body) return;
      if (size > MAX_BODY) skip("body_over_1_mib");
      else if (hold(c.length)) body.push(c);
      else skip("check_busy");
    });
    else if (!upstream) req.resume();
    req.once("close", () => { if (!req.complete) release(); }); // the client went away mid-body: nothing to check
    req.once("end", () => {
      if (stopped) return release();
      if (why === null && waiting >= MAX_WAITING) skip("check_busy");
      if (why !== null) return void second.postMessage({ t: "unchecked", ...seen, why });
      const copy = body ? new Uint8Array(size) : null;
      if (copy) body.reduce((o, c) => (copy.set(c, o), o + c.length), 0);
      waiting++;
      second.postMessage({ t: "check", ...seen, url: req.url, headers: req.headers, rawHeaders: req.rawHeaders, body: copy, bytes: held },
        copy ? [copy.buffer] : []);
    });
  });
  server.listen(Number(port), host, () => console.log(`ainra pilot (${mode}, watch) on http://${host}:${port} → ${upstream ? upstream.origin : "204 to every request (a mirror target)"} · the check refuses nothing · observations → ${observations}`));
}

function checkThread() {
  const since = new Date().toISOString();
  const tally = { requests: 0, signatures: { any: 0, "signature-agent": 0, rfc9421: 0, "ainra-presentation": 0, none: 0 },
    decisions: { admit: 0, refuse: 0 }, refusals: {}, not_checked: { check_busy: 0, body_over_1_mib: 0, check_failed: 0 } };
  const KEEP = 1_000_000; // check times kept for the percentiles: the most recent million
  let times = new Float64Array(1024), timed = 0, unwritable = false;
  // What went wrong, by kind only: an error's message can hold what a request carried (a query string, a Host, a
  // header's text). Each kind is logged once; the file and the summary count every failed check.
  const logged = new Set();
  const complain = (what, e) => {
    const kind = `${what} (${e?.code ?? e?.name ?? "error"})`;
    if (!logged.has(kind)) { logged.add(kind); console.error(`ainra pilot (watch): ${kind}`); }
  };

  function write(line) {
    try { appendFileSync(observations, JSON.stringify(line) + "\n", { mode: 0o600 }); }
    catch (e) { if (!unwritable) console.error(`ainra pilot (watch): cannot write ${observations} (${e.code ?? e.message})`); unwritable = true; }
    tally.requests++;
    tally.signatures[line.signatures.length ? "any" : "none"]++;
    for (const k of line.signatures) tally.signatures[k]++;
  }
  // A request seen and not checked still gets its line, so the file's shares count every request.
  function note(m, why) {
    write({ time: new Date(m.at).toISOString(), method: m.method, path: m.path, signatures: m.signatures, decision: "unchecked", not_checked: why });
    tally.not_checked[why]++;
  }

  // What the gate would have decided, as one line; null when it could not decide.
  async function decideOn(m) {
    const req = { method: m.method, url: m.url, headers: m.headers, rawHeaders: m.rawHeaders };
    if (m.body) req.rawBody = Buffer.from(m.body.buffer, m.body.byteOffset, m.body.length);
    // The gate answers into this, and nothing it writes reaches anyone: its headers are captured, not applied.
    const said = { status: 200, headers: [], body: undefined };
    let decision = null, ms = 0;
    const t0 = performance.now();
    const decide = (d) => { if (decision === null) { decision = d; ms = performance.now() - t0; } };
    const shim = { status(c) { said.status = c; return shim; }, json(b) { said.body = b; decide("refuse"); }, setHeader: (k, v) => { said.headers.push([k, v]); } };
    try {
      if (mode === "link") req.ainraVerifiedKey = await signedBy(req);
      await gate(req, shim, () => decide("admit"));
    } catch (e) { complain("the gate threw", e); }
    if (decision === null) return null;
    const name = mode === "link" ? req.ainraLink?.passport : req.ainra?.event?.name;
    return { time: new Date(m.at).toISOString(), method: m.method, path: m.path, signatures: m.signatures, decision,
      ...(decision === "refuse" ? { status: said.status, reason: said.body?.reason ?? null }
        : { operator: mode === "link" ? req.ainraLink?.operator : name?.split(":")[2], passport: name }),
      check_ms: Math.round(ms * 100) / 100 };
  }
  async function check(m) {
    try {
      const line = await decideOn(m);
      if (!line) return note(m, "check_failed");
      write(line);
      tally.decisions[line.decision]++;
      if (line.decision === "refuse") tally.refusals[line.reason] = (tally.refusals[line.reason] ?? 0) + 1;
      if (timed < KEEP && timed === times.length) { const t = new Float64Array(Math.min(KEEP, times.length * 2)); t.set(times); times = t; }
      times[timed++ % KEEP] = line.check_ms;
    } catch (e) {
      complain("a check failed", e);
    } finally {
      parentPort.postMessage({ t: "checked", bytes: m.bytes });
    }
  }

  // A header the prime handler wrote, as Node will send it. The middleware writes JSON into x-ainra-verdict, with the
  // presenter's name in it, and a name may hold characters no header can; written as \uXXXX they mean the same JSON.
  // Whatever still cannot be sent is dropped.
  const sendable = (k, v) => {
    let s = String(v);
    try { http.validateHeaderValue(k, s); } catch { s = s.replace(/[^\x20-\x7e]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`); }
    try { http.validateHeaderName(k); http.validateHeaderValue(k, s); return [k, s]; } catch { return null; }
  };
  // In passport mode the prime path answers as without --watch: the same handler and store, so the same answer.
  function primeOnce(m) {
    const req = { method: m.method, url: m.url, headers: m.headers, rawBody: Buffer.from(m.body.buffer, m.body.byteOffset, m.body.length) };
    try { req.body = JSON.parse(req.rawBody.toString("utf8")); } catch { req.body = undefined; }
    const out = { status: 200, headers: [], body: "" };
    const shim = { status(c) { out.status = c; return shim; }, json(b) { out.headers.push(["content-type", "application/json"]); out.body = JSON.stringify(b); },
      setHeader: (k, v) => { const h = sendable(k, v); if (h) out.headers.push(h); } };
    try { prime(req, shim); } catch (e) { complain("the prime path threw", e); return { status: 500, headers: [], body: "" }; }
    return out;
  }

  // Nearest-rank percentiles, as watch-report.mjs computes them from the file.
  function summary(m) {
    const n = Math.min(timed, KEEP), sorted = times.slice(0, n).sort();
    const pct = (p) => (n ? sorted[Math.ceil((p * n) / 100) - 1] : null);
    return { mode, since, observations, requests: tally.requests, checked: tally.decisions.admit + tally.decisions.refuse,
      not_checked: tally.not_checked, waiting: m.waiting, signatures: tally.signatures, decisions: tally.decisions,
      refusals: tally.refusals, check_ms: { p50: pct(50), p95: pct(95), p99: pct(99), of: n } };
  }

  // Checks wait in line; a request that was not checked, the summary and the prime path are answered as they come.
  parentPort.on("message", (m) => {
    if (m.t === "check") inLine(() => void check(m));
    else if (m.t === "unchecked") note(m, m.why);
    else if (m.t === "prime") parentPort.postMessage({ t: "reply", id: m.id, ...primeOnce(m) });
    else if (m.t === "summary") parentPort.postMessage({ t: "reply", id: m.id, status: 200, headers: [["content-type", "application/json"]], body: JSON.stringify(summary(m)) });
  });
  parentPort.postMessage({ t: "ready" });
}
