#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// services/verify — the hosted verifier (D-079). A convenience, not an authority.
//
// It runs the published verifier (@ainra/sdk) against a directory you configure, and every answer is a SIGNED
// decision receipt: a decision record (docs/DECISION-RECORDS.md) that names what was checked, the verdict, and digests
// of the status and checkpoint it relied on, bound to the exact bytes you sent. Anyone can re-check a receipt offline
// with `ainra verify-decisions` and the key `/v1/about` publishes — and anyone can skip this service and verify
// locally with the same result. What it deliberately does NOT do:
//   * no lookup by identifier, no search, no listing of agents or keys — you send what you want checked;
//   * no unsigned verdicts, no soft-fail: anything it cannot decide is a signed refusal;
//   * no request bodies or identifiers in logs; /v1/metrics is aggregate counts only.
//
//   node services/verify/server.mjs --directory D --roots R --key KEYFILE [--port 8787] [--freshness F2]
//                                   [--audience A] [--heads URL]
// KEYFILE holds the verifier's Ed25519 secret key, base64url, 32 bytes (create one with `--new-key KEYFILE`).
import http from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";
import {
  Verifier, signDecision, decisionRequestDigest, jwkThumbprintEd25519, strictB64u,
} from "../../packages/sdk-ts/dist/index.js";

const sdkRequire = createRequire(new URL("../../packages/sdk-ts/package.json", import.meta.url));
const { ed25519 } = await import(pathToFileURL(sdkRequire.resolve("@noble/curves/ed25519")).href);

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(`--${k}`); return i >= 0 ? args[i + 1] : d; };
const b64u = (b) => Buffer.from(b).toString("base64url");

if (opt("new-key")) {
  writeFileSync(opt("new-key"), b64u(randomBytes(32)) + "\n", { mode: 0o600 });
  console.log(`wrote a new verifier key to ${opt("new-key")} (0600)`);
  process.exit(0);
}

const MAX_BODY = 256 * 1024;
const read = (p) => JSON.parse(readFileSync(p, "utf8"));
const directory = read(opt("directory") ?? usage());
const roots = read(opt("roots") ?? usage());
const secret = strictB64u(readFileSync(opt("key") ?? usage(), "utf8").trim());
if (!secret || secret.length !== 32) { console.error("the key file must hold a base64url 32-byte Ed25519 secret"); process.exit(2); }
const pub = ed25519.getPublicKey(secret);
const freshness = opt("freshness", "F2");
const audience = opt("audience", "");
const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, freshness, false, audience);
if (!verifier) { console.error("the directory does not verify against the roots — refusing to start"); process.exit(2); }
const sha = (s) => createHash("sha256").update(s).digest("base64url");
const build = (() => { try { return execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8", cwd: new URL("../..", import.meta.url).pathname }).trim(); } catch { return process.env.AINRA_BUILD ?? "unknown"; } })();
const about = {
  service: "ainra-verify",
  build,
  verifier_key: b64u(pub),
  gate: jwkThumbprintEd25519(pub),
  freshness,
  audience: audience || null,
  trust: { directory: sha(JSON.stringify(directory)), roots: sha(JSON.stringify(roots)) },
  note: "A convenience, not an authority: every answer is a signed receipt you can re-check offline, and the same check runs locally with @ainra/sdk.",
};

function usage() {
  console.error("usage: node services/verify/server.mjs --directory D --roots R --key KEYFILE [--port 8787] [--freshness F2] [--audience A] [--heads URL]");
  process.exit(2);
}

// Aggregate counters only: no identifiers, no timestamps per request.
const metrics = { verifications: 0, accepted: 0, refused: 0, by_reason: {} };
const count = (decision, reason) => {
  metrics.verifications++;
  if (decision === "accept") metrics.accepted++;
  else { metrics.refused++; metrics.by_reason[reason] = (metrics.by_reason[reason] ?? 0) + 1; }
};

// `--now T` pins the clock — for fixtures and tests only; a deployment never passes it.
const now = opt("now") ? (() => Number(opt("now"))) : () => Math.floor(Date.now() / 1000);
const relied = (src) => ({
  ...(src && typeof src.status_uri === "string" && Number.isSafeInteger(src.status_issued_at) && typeof src.status_list === "string"
    ? { status: { uri: src.status_uri, issued_at: src.status_issued_at, list: sha(src.status_list) } } : {}),
  ...(src?.checkpoint && typeof src.checkpoint.origin === "string" && Number.isSafeInteger(src.checkpoint.size) && typeof src.checkpoint.root === "string"
    ? { checkpoint: { origin: src.checkpoint.origin, size: src.checkpoint.size, root: src.checkpoint.root } } : {}),
});

/** One decision → its signed receipt (a standalone, seq-0 decision record). `null` when nothing names a subject. */
function receipt(rec, bodyText) {
  try {
    return signDecision(
      { ...rec, request: decisionRequestDigest({ method: "POST", authority: "ainra-verify", path: "/v1/verify", contentDigest: `sha-256=:${createHash("sha256").update(bodyText).digest("base64")}:` }), policy: { freshness, audience } },
      pub, "", (m) => ed25519.sign(m, secret),
    );
  } catch { return null; }
}

function decide(body, bodyText) {
  const t = now();
  if (body && typeof body === "object" && body.passport && typeof body.passport === "object") {
    const v = verifier.verify(body.passport, t);
    let name = null;
    try { name = JSON.parse(Buffer.from(body.passport.claims, "base64url").toString("utf8")).sub ?? null; } catch { /* unnamed */ }
    const decision = v.verdict === "valid" ? "accept" : "refuse";
    const operator = decision === "accept" && typeof name === "string" ? name.split(":")[2] : undefined;
    const rec = typeof name === "string"
      ? receipt({ at: t, kind: "passport", subject: name, ...(operator ? { operator } : {}), verdict: v.verdict, ...(v.verdict === "valid" ? {} : { reason: v.reason }), ...relied(body.passport) }, bodyText)
      : null;
    return { decision, reason: v.verdict === "valid" ? null : v.reason, subject: name, operator: operator ?? null, receipt: rec };
  }
  if (body && typeof body === "object" && body.link && typeof body.key === "string") {
    const key = strictB64u(body.key);
    if (!key || key.length !== 32) return { decision: "refuse", reason: "schema_violation", receipt: null };
    const v = verifier.verifyLink(body.link, key, t, typeof body.capability === "string" ? body.capability : undefined);
    const tp = jwkThumbprintEd25519(key);
    const rec = receipt({ at: t, kind: "link", subject: tp, ...(v.verdict === "valid" ? { passport: v.passport, operator: v.operator } : {}), verdict: v.verdict, ...(v.verdict === "valid" ? {} : { reason: v.reason }), ...relied(body.link) }, bodyText);
    return v.verdict === "valid"
      ? { decision: "accept", operator: v.operator, passport: v.passport, registrar: v.registrar, scope: v.scope, receipt: rec }
      : { decision: "refuse", reason: v.reason, receipt: rec };
  }
  return { decision: "refuse", reason: "schema_violation", receipt: null };
}

// The doorbell (optional): poll a static heads.json and announce changes. Receivers must still pull and verify.
const listeners = new Set();
let lastHeads = null;
if (opt("heads")) {
  const poll = async () => {
    try {
      const h = await (await fetch(opt("heads"), { signal: AbortSignal.timeout(5000) })).text();
      if (h !== lastHeads) {
        lastHeads = h;
        const msg = `event: heads\ndata: ${JSON.stringify({ digest: sha(h) })}\n\n`;
        for (const res of listeners) res.write(msg);
      }
    } catch { /* the next poll tries again; the doorbell never carries state */ }
  };
  poll();
  setInterval(poll, 15_000).unref();
}

const send = (res, code, obj) => {
  res.writeHead(code, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(obj));
};
export const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  if (req.method === "GET" && url.pathname === "/v1/about") return send(res, 200, about);
  if (req.method === "GET" && url.pathname === "/v1/metrics") return send(res, 200, metrics);
  if (req.method === "GET" && url.pathname === "/v1/events" && opt("heads")) {
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store" });
    res.write(": ainra doorbell — announces new heads; pull and verify them yourself\n\n");
    listeners.add(res);
    req.on("close", () => listeners.delete(res));
    return;
  }
  if (req.method === "POST" && url.pathname === "/v1/verify") {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => { size += c.length; if (size <= MAX_BODY) chunks.push(c); });
    req.on("end", () => {
      if (size > MAX_BODY) { count("refuse", "schema_violation"); return send(res, 413, { decision: "refuse", reason: "schema_violation", receipt: null }); }
      const text = Buffer.concat(chunks).toString("utf8");
      let body = null;
      try { body = JSON.parse(text); } catch { body = null; }
      const r = decide(body, text);
      count(r.decision, r.reason);
      send(res, 200, r);
    });
    return;
  }
  send(res, 404, { error: "not found", note: "This service answers POST /v1/verify only. There is no lookup by identifier, by design." });
});

if (process.argv[1] && new URL(import.meta.url).pathname === process.argv[1]) {
  const port = Number(opt("port", "8787"));
  server.listen(port, opt("bind", "127.0.0.1"), () => console.log(`ainra-verify on http://${opt("bind", "127.0.0.1")}:${port} · gate ${about.gate} · build ${build.slice(0, 12)}`));
}
