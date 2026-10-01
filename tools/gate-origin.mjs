// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// A standalone origin running the REAL gate, so an agent written in any language can be tested against it (D-071).
//
//   node tools/gate-origin.mjs            the Node gate (@ainra/middleware): send-once + signed requests required
//   node tools/gate-origin.mjs --edge     the edge gate (@ainra/edge): ainra-core in WebAssembly behind a fetch handler
//
// Trust comes from the published directory and roots (AINRA_ARTIFACTS, default the local network's). It listens on
// 127.0.0.1 at PORT (default: any free port) and prints `LISTENING <port>` once it is ready. Every request other than
// the send-once POST must carry a valid presentation and an RFC 9421 signature by the running copy's instance key;
// an allowed request answers 200 `{"ok":true,"as":"<credential name>"}`, a refused one answers with the gate's own
// status and `x-ainra-reason`. Nothing here is simulated, and nothing here is a deployment: TEST-ROOT, loopback.
import http from "node:http";
import { readFileSync } from "node:fs";
import { Verifier, PRIME_PATH } from "../packages/sdk-ts/dist/index.js";
import { ainraGate, ainraPrime, createPresentationStore } from "../packages/middleware/dist/index.js";

const EDGE = process.argv.includes("--edge");
const ART = process.env.AINRA_ARTIFACTS ?? "http://127.0.0.1:8091";
const AUD = process.env.AINRA_AUDIENCE ?? "https://shop.example";
const now = () => Math.floor(Date.now() / 1000);

let directory, roots;
try {
  directory = await (await fetch(`${ART}/directory.json`, { signal: AbortSignal.timeout(3000) })).json();
  roots = await (await fetch(`${ART}/roots.json`, { signal: AbortSignal.timeout(3000) })).json();
} catch {
  console.error(`gate-origin: no published directory at ${ART} — run \`make stage-up\` first`);
  process.exit(2);
}

let serve;
if (EDGE) {
  const edge = await import("../packages/edge/src/index.mjs");
  await edge.initAinra(readFileSync(new URL("../packages/edge/wasm/ainra_wasm_bg.wasm", import.meta.url)));
  const gate = await edge.createAinraEdgeGate({ directory, roots, audience: AUD, now });
  serve = async (req, res, body) => {
    const headers = new Headers();
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const k = req.rawHeaders[i].toLowerCase();
      if (!["host", "connection", "content-length", "transfer-encoding"].includes(k)) headers.append(k, req.rawHeaders[i + 1]);
    }
    const request = new Request(`http://${req.headers.host}${req.url}`, { method: req.method, headers, body: body.length ? body : undefined });
    const g = await gate(request);
    if (g.allow) { res.statusCode = 200; res.end(JSON.stringify({ ok: true, as: g.event?.name })); return; }
    res.statusCode = g.response.status;
    g.response.headers.forEach((v, k) => res.setHeader(k, v));
    res.end(Buffer.from(await g.response.arrayBuffer()));
  };
} else {
  const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F3", false, AUD);
  if (!verifier) { console.error("gate-origin: the published directory does not verify against the roots"); process.exit(1); }
  const seen = new Set();
  const store = createPresentationStore();
  const gate = ainraGate(verifier, { now, requireSignature: true, store, seenNonce: (n) => { const had = seen.has(n); seen.add(n); return had; } });
  const prime = ainraPrime(verifier, { store, now });
  serve = async (req, res, body) => {
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
    // The signature covers the body's digest, so the gate needs the bytes as they arrived, not a re-serialisation.
    if (body.length) req.rawBody = body;
    gate(req, shim, () => { res.statusCode = 200; res.end(JSON.stringify({ ok: true, as: req.ainra.event.name })); });
  };
}

const server = http.createServer(async (req, res) => {
  const chunks = []; for await (const c of req) chunks.push(c);
  serve(req, res, Buffer.concat(chunks)).catch((e) => { res.statusCode = 500; res.end(String(e)); });
});
server.listen(Number(process.env.PORT ?? 0), "127.0.0.1", () => console.log(`LISTENING ${server.address().port}`));
