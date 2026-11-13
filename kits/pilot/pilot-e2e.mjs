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
//  11. its head, logged at the registrar (D-081): the receipt verifies against the published directory, the log
//      reaches it — and with its last record cut, the chain alone still holds while the receipt says `truncated`
// Watch mode (`--watch`, D-105): the gate beside a route, refusing nothing, against the same upstream. Its requests
// are sent with exact header lines (duplicates, case, Connection) and the upstream echoes the lines that reached it:
//  W1. passport mode, between steps 8 and 9: the prime path answers as without --watch (201, the same ref); a signed
//      request and an unsigned one, each with a query string and a body, reach the upstream with every header line
//      as sent but Host's value, and neither answer carries x-ainra-reason or x-ainra-verdict; a bundle naming a
//      subject with U+20AC, sent to the prime path, is answered 403 and the next request still goes on; a body over
//      1 MiB and a whole bundle in one header go on; the observations say admit (operator, passport),
//      presentation_unsigned, schema_violation and unchecked, and hold no address, query, body or header value. Then a
//      fresh watch: with 40 checks in line the prime path answers at once, and the requests that named the bundle
//      before it came are still checked without it (presentation_unknown); the one sent after it is admitted
//  W2. link mode, after step 11, with key C linked to a fresh passport: C's request, B's (unlinked) and an unsigned one
//      reach the upstream as in W1, and the upstream's two X-Echo lines come back as two; a Signature-Agent the
//      verifier cannot parse is served, written `unchecked` (check_failed), and nothing of it reaches the pilot's
//      stderr; the observations say admit, not_linked, sig_invalid and unchecked and hold no address, query string or
//      header value; the summary answers on loopback, and gets 403 when relayed by a proxy or asked from a
//      non-loopback address of this machine
//  W3. link mode with a registrar that accepts connections and never answers: signed requests reach the upstream
//      within 1 s while their checks wait; the checks share one registrar fetch, which gives up after 5 s, and end
//      not_linked
//  W4. link mode as a mirror target (no --upstream): a request gets 204, the upstream count does not move, and the
//      request is observed
//  W5. watch-report.mjs prints W2's counts from the file, gets a file of known values right (percentiles, unchecked
//      lines, a line over 1 MiB skipped), and exits 2 on a missing file
//  W6. --watch with --decisions exits 2 with one line, and writes no log and no key
// WITNESS: step 4's negative control (B), step 5 (A after revocation) and step 9 must be refused and must not reach
// the upstream; the upstream counts what reached it, and step 8 asserts it never sees a presentation header.
// WITNESS (watch): in watch mode a request the gate would refuse must still reach the upstream (W1's unsigned
// request, W2's B and unsigned request); in normal mode it must not (step 4's B, step 9). A watch that held requests
// for the check fails W3's 1 s; one that added or merged a header line fails W1/W2's comparison; one that answered a
// non-loopback client fails W2; one that wrote a body, a query or a header value fails W1/W2's file checks; one whose
// prime path waited behind the checks, or stored a bundle ahead of requests that came before it, fails W1's last part.
import http from "node:http";
import net from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { networkInterfaces, tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { sign, HTTP_MESSAGE_SIGNATURES_DIRECTORY } from "web-bot-auth";
import { signerFromJWK } from "web-bot-auth/crypto";
import { appendSignature } from "http-message-sig";
import {
  jwkThumbprintEd25519, linkPopSigningBytes, verifyDecisionChain, verifyDecisionChainToHead, Verifier, canonicalize,
  mintInstanceCredential,
  proveInstancePossession, signPresentation, splitPresentation, PRESENTATION_HEADER, POP_HEADER, PRIME_PATH,
} from "../../packages/sdk-ts/dist/index.js";
import { b64uEncode } from "../../packages/sdk-ts/dist/crypto.js";

// Sign with the SDK's own copies of the libraries, the versions its verifier checks with (as identity-e2e does).
const sdkRequire = createRequire(new URL("../../packages/sdk-ts/package.json", import.meta.url));
const lib = async (m) => import(pathToFileURL(sdkRequire.resolve(m)).href);
const { ml_dsa65 } = await lib("@noble/post-quantum/ml-dsa");
const { ed25519 } = await lib("@noble/curves/ed25519");

const REG = process.env.AINRA_REGISTRAR ?? "http://127.0.0.1:4970";
const ART = process.env.AINRA_ARTIFACTS ?? "http://127.0.0.1:8093";
const now = () => Math.floor(Date.now() / 1000);
let bad = 0;
const ok = (m) => console.log(`  ok    ${m}`);
const fail = (m) => { console.error(`  ✗     ${m}`); bad = 1; };
try { await fetch(`${REG}/accreditation`, { signal: AbortSignal.timeout(3000) }); }
catch { console.error(`pilot-e2e: no live registrar at ${REG} — run \`make live-up\` first`); process.exit(2); }
const TOKEN = readFileSync(new URL("../../live/.issue-token", import.meta.url), "utf8").trim(); // header only
const write = async (p, b) => (await fetch(REG + p, { method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" }, body: JSON.stringify(b) })).json();
const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
// A specimen passport from the public demo door. The door takes 30 writes a minute, shared by everyone using this
// registrar, so a refusal there stops the run with exit 2 (not ready) rather than a failed step.
async function demoIssue(body) {
  const r = await fetch(`${REG}/demo/issue`, { method: "POST", body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (typeof j.sub !== "string") { console.error(`pilot-e2e: the registrar's demo door issued nothing (HTTP ${r.status}: ${j.error ?? "no passport"}); try again in a minute`); process.exit(2); }
  return j;
}

// 1 · the upstream: it echoes what reached it, every header line as it came and the body's size, and answers with
// one header line twice (watch mode hands both back). It takes headers up to 256 KiB, as a service may.
let reached = 0;
const upstream = http.createServer({ maxHeaderSize: 256 << 10 }, (req, res) => {
  reached++;
  let bytes = 0;
  req.on("data", (c) => { bytes += c.length; });
  req.on("end", () => {
    res.setHeader("content-type", "application/json");
    res.setHeader("X-Echo", ["one", "two"]);
    res.end(JSON.stringify({ operator: req.headers["x-ainra-operator"] ?? null, name: req.headers["x-ainra-passport-name"] ?? null,
      presentation: req.headers[PRESENTATION_HEADER] ?? null, pop: req.headers[POP_HEADER] ?? null,
      agent: req.headers["signature-agent"] ?? null, sig: req.headers.signature ?? null, sigInput: req.headers["signature-input"] ?? null,
      raw: req.rawHeaders, bytes }));
  });
});
const upPort = await listen(upstream);

// 3 · the signature agent and its directory
const agentKey = async () => {
  const k = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", k.privateKey);
  return { k, jwk, signer: await signerFromJWK({ ...jwk, alg: "EdDSA" }), tp: jwkThumbprintEd25519(Buffer.from(jwk.x, "base64url")) };
};
const A = await agentKey(), B = await agentKey();
const more = []; // keys added to the directory later (watch mode's C)
const dirSrv = http.createServer((req, res) => {
  res.setHeader("content-type", "application/http-message-signatures-directory+json");
  res.setHeader("cache-control", "max-age=300");
  res.end(JSON.stringify({ keys: [A, B, ...more].map((a) => ({ kty: "OKP", crv: "Ed25519", x: a.jwk.x, use: "sig", nbf: now() - 60, exp: now() + 3600 })) }));
});
const AGENT = `http://127.0.0.1:${await listen(dirSrv)}`;
const passport = await demoIssue({ operator: "specimen", lineage: "pilot" });
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

async function send(a, base = PILOT) {
  const url = `${base}/orders`;
  const h = new Headers({ "signature-agent": `sig1="${AGENT}"` });
  const f = await sign(new Request(url, { headers: h }), { signer: a.signer, label: "sig1", expires: new Date((now() + 300) * 1000) });
  const sent = appendSignature(h, f);
  const r = await fetch(url, { headers: sent });
  return { status: r.status, reason: r.headers.get("x-ainra-reason"), body: await r.json().catch(() => null), sent };
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
  "--decisions", join(work, "passport-decisions.jsonl"), "--gate-key", join(work, "passport-gate.key"),
  "--publish-head", REG, "--head-every", "1000"], { stdio: ["ignore", "ignore", "inherit"] });
const PP = `127.0.0.1:${ppPort}`;
for (let i = 0; i < 100; i++) { try { await fetch(`http://${PP}/.well-known/ainra-decisions-head`); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }
async function primeVia(b) {
  const r = await fetch(`http://${PP}${PRIME_PATH}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(await presentation(b)) });
  return { status: r.status, ref: (await r.json().catch(() => ({}))).ref, reason: r.headers.get("x-ainra-reason") };
}
async function sendSigned({ ref, signIt = true, at = PP }) {
  const { pop } = splitPresentation(await presentation(bundle));
  const headers = { [PRESENTATION_HEADER]: ref, [POP_HEADER]: Buffer.from(JSON.stringify(pop)).toString("base64url"), host: at };
  if (signIt) Object.assign(headers, await signPresentation({ req: { method: "POST", authority: at, path: "/orders", headers }, keyid: ic.iid,
    nonce: "r-" + randomBytes(6).toString("hex"), created: now(), instanceSign }));
  const r = await fetch(`http://${at}/orders`, { method: "POST", headers });
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

// Watch mode (D-105). A watch pilot is up when its summary answers. Its checks finish after the request has gone on,
// so wait until the summary has counted n of them before reading the file. Its stderr is kept, to be searched.
const PILOT_JS = new URL("pilot.mjs", import.meta.url).pathname;
const watchPilot = (port, extra) => {
  const p = spawn("node", [PILOT_JS, "--watch", "--listen", `127.0.0.1:${port}`,
    "--directory", join(work, "directory.json"), "--roots", join(work, "roots.json"), ...extra], { stdio: ["ignore", "ignore", "pipe"] });
  p.err = "";
  p.stderr.on("data", (d) => { p.err += d; process.stderr.write(d); });
  return p;
};
async function watchUp(base) {
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(`${base}/.well-known/ainra-watch`)).ok) return; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
}
async function observed(base, file, n) {
  for (let i = 0; i < 100; i++) {
    const s = await fetch(`${base}/.well-known/ainra-watch`).then((r) => r.json()).catch(() => ({}));
    if ((s.requests ?? 0) >= n) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  return readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
}
// Send exactly these header lines, in this order and case. Connection is always among them, and Content-Length with a
// body, so Node adds no line of its own. The answer comes back with its header lines as they came.
function exact(at, method, path, lines, body) {
  const [hostname, port] = at.split(":");
  const t0 = performance.now();
  return new Promise((done) => {
    const q = http.request({ hostname, port, method, path, headers: lines.flat() }, (r) => {
      const chunks = [];
      r.on("data", (c) => chunks.push(c));
      r.on("end", () => {
        let json = null;
        try { json = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { /* not JSON */ }
        done({ status: r.statusCode, headers: r.headers, raw: r.rawHeaders, body: json, ms: performance.now() - t0 });
      });
    });
    q.on("error", (e) => done({ status: 0, error: e.code, headers: {}, raw: [], body: null, ms: performance.now() - t0 }));
    q.end(body);
  });
}
// The upstream saw the lines that were sent, in order and case, with Host's value set to its own and nothing added.
const pairsOf = (raw) => (raw ?? []).flatMap((v, i) => (i % 2 ? [] : [[v, raw[i + 1]]]));
const butHost = (lines) => JSON.stringify(lines.filter(([k]) => k.toLowerCase() !== "host"));
const asSent = (lines, seen) => butHost(lines) === butHost(pairsOf(seen))
  && pairsOf(seen).filter(([k]) => k.toLowerCase() === "host").map(([, v]) => v).join() === `127.0.0.1:${upPort}`;
// The gate's own headers never reach a client in watch mode.
const noVerdict = (r) => !("x-ainra-reason" in r.headers) && !("x-ainra-verdict" in r.headers);
// Text that must never reach an observations file or the pilot's log.
const MARK = Object.fromEntries(["query", "body", "ua", "dup", "err"].map((k) => [k, `${k}-${randomBytes(6).toString("hex")}`]));
const markLines = () => [["User-Agent", MARK.ua], ["X-Dup", `${MARK.dup}-1`], ["x-dup", `${MARK.dup}-2`], ["Connection", "close"]];
// The running copy's POST to `at`, as the header lines to send: the bundle's ref, a fresh proof of possession and,
// when signed, the request's own signature (RFC 9421), which covers the body's digest when there is a body.
async function copyLines(at, path, { body, signIt = true } = {}) {
  const { pop } = splitPresentation(await presentation(bundle));
  const h = { [PRESENTATION_HEADER]: ref, [POP_HEADER]: Buffer.from(JSON.stringify(pop)).toString("base64url"), host: at };
  const signed = signIt ? await signPresentation({ req: { method: "POST", authority: at, path, headers: h, ...(body ? { body } : {}) }, keyid: ic.iid,
    nonce: "r-" + randomBytes(6).toString("hex"), created: now(), instanceSign }) : {};
  return [["Host", at], ["X-Ainra-Passport", ref], ["X-Ainra-Pop", h[POP_HEADER]], ...Object.entries(signed),
    ...(body ? [["Content-Type", "application/json"]] : []), ["Content-Length", String(body?.length ?? 0)], ...markLines()];
}
// A signature agent's request to `at`, as the header lines to send.
async function agentLines(a, at, path) {
  const h = new Headers({ "signature-agent": `sig1="${AGENT}"` });
  const f = await sign(new Request(`http://${at}${path}`, { headers: h }), { signer: a.signer, label: "sig1", expires: new Date((now() + 300) * 1000) });
  return [["Host", at], ...appendSignature(h, f), ...markLines()];
}
const leaks = (text, values) => values.filter((v) => v && text.includes(v));

// W1 · watch mode, passport: the same running copy, through a pilot that only watches
{
  const port = 20000 + Math.floor(Math.random() * 20000);
  const obs = join(work, "watch-passport.jsonl");
  const w = watchPilot(port, ["--upstream", `http://127.0.0.1:${upPort}`, "--mode", "passport", "--audience", AUD, "--freshness", "F3", "--observations", obs]);
  const W = `127.0.0.1:${port}`;
  await watchUp(`http://${W}`);
  const before = reached;
  const p = await fetch(`http://${W}${PRIME_PATH}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(await presentation(bundle)) });
  const pb = await p.json().catch(() => ({}));
  p.status === 201 && pb.ref === ref && p.headers.get("x-ainra-verdict") && reached === before
    ? ok("W1 watch, passport: the prime path answers as it does without --watch (201, the same ref), and the upstream never sees it")
    : fail(`W1 prime: ${p.status} ${JSON.stringify(pb)} (upstream saw ${reached - before})`);
  // A signed request and an unsigned one, each with a query string, a body, and header lines a forwarder could merge.
  const path = `/orders?q=${MARK.query}`, body = Buffer.from(JSON.stringify({ note: MARK.body }));
  const sl = await copyLines(W, path, { body }), ul = await copyLines(W, path, { body, signIt: false });
  const s = await exact(W, "POST", path, sl, body), u = await exact(W, "POST", path, ul, body);
  s.status === 200 && u.status === 200 && reached === before + 2 && asSent(sl, s.body?.raw) && asSent(ul, u.body?.raw)
    && s.body?.bytes === body.length && u.body?.bytes === body.length && noVerdict(s) && noVerdict(u)
    ? ok("W1 a signed request and an unsigned one, with a query and a body, reach the upstream: every header line as sent but Host's value, nothing added, the body whole; neither answer carries x-ainra-reason or x-ainra-verdict")
    : fail(`W1 forwarded: ${JSON.stringify({ s: [s.status, s.headers, s.body], u: [u.status, u.headers, u.body], reached: reached - before, sent: [sl, ul] })}`);
  // A presenter's name no header can hold, sent to the prime path: answered, and the watch goes on.
  const euro = "ainra:r:\u20ac:x@1.0.1";
  const e = await fetch(`http://${W}${PRIME_PATH}`, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ claims: Buffer.from(JSON.stringify({ sub: euro })).toString("base64url") }) }).catch((x) => ({ error: x.cause?.code ?? x.message }));
  let verdict = null;
  try { verdict = JSON.parse(e.headers.get("x-ainra-verdict")); } catch { /* no answer, or no verdict */ }
  const next = await exact(W, "GET", "/after", [["Host", W], ["Connection", "close"]]);
  e.status === 403 && e.headers.get("x-ainra-reason") && verdict?.name === euro && next.status === 200 && reached === before + 3
    ? ok(`W1 a bundle whose subject holds U+20AC, sent to the prime path → 403 ${e.headers.get("x-ainra-reason")} with the name escaped in x-ainra-verdict; the next request still reaches the upstream`)
    : fail(`W1 U+20AC: ${e.error ? `no answer (${e.error})` : `${e.status} ${e.headers.get("x-ainra-reason")} ${JSON.stringify(verdict)}`}; next ${next.status} ${next.error ?? ""}`);
  // A body over 1 MiB is served and not copied for the check.
  const big = Buffer.alloc((1 << 20) + 4096, 97);
  const g = await exact(W, "POST", "/upload", [["Host", W], ["X-Ainra-Passport", pb.ref], ["Content-Length", String(big.length)], ["Connection", "close"]], big);
  g.status === 200 && g.body?.bytes === big.length && reached === before + 4
    ? ok(`W1 a body over 1 MiB (${big.length} bytes) reaches the upstream whole`)
    : fail(`W1 big body: ${g.status} ${JSON.stringify(g.body)} (upstream saw ${reached - before})`);
  // The whole bundle in one header, which a server at Node's default limits refuses with 431 (PRESENTATION.md).
  const whole = Buffer.from(JSON.stringify(await presentation(bundle))).toString("base64url");
  const wh = await exact(W, "GET", "/whole", [["Host", W], ["X-Ainra-Passport", whole], ["Connection", "close"]]);
  wh.status === 200 && reached === before + 5
    ? ok(`W1 the whole bundle in one header (${whole.length} bytes) reaches the upstream`)
    : fail(`W1 whole bundle in a header: ${wh.status} ${wh.error ?? ""} (upstream saw ${reached - before})`);
  const rows = await observed(`http://${W}`, obs, 5);
  const a = rows.find((r) => r.decision === "admit"), x = rows.find((r) => r.reason === "presentation_unsigned" && r.path === "/orders");
  const after = rows.find((r) => r.path === "/after"), over = rows.find((r) => r.decision === "unchecked"), wl = rows.find((r) => r.path === "/whole");
  rows.length === 5 && a?.operator === "specimen" && a.passport === psub && a.signatures.join() === "rfc9421,ainra-presentation" && a.path === "/orders"
    && x?.decision === "refuse" && x.signatures.join() === "ainra-presentation"
    && after?.decision === "refuse" && after.reason === "schema_violation"
    && over?.not_checked === "body_over_1_mib" && over.path === "/upload" && over.signatures.join() === "ainra-presentation" && !("check_ms" in over)
    && wl?.decision === "refuse" && wl.reason === "presentation_unsigned"
    ? ok(`W1 the observations: admit (${a.operator}, ${a.passport}), refuse presentation_unsigned, schema_violation and presentation_unsigned (the whole bundle, unsigned), and unchecked body_over_1_mib`)
    : fail(`W1 observations: ${JSON.stringify(rows)}`);
  const text = readFileSync(obs, "utf8");
  const found = leaks(text, ["127.0.0.1", "q=", MARK.query, MARK.body, MARK.ua, MARK.dup, pb.ref, whole.slice(0, 64), sl.find(([k]) => k === "signature")?.[1],
    sl.find(([k]) => k === "content-digest")?.[1], sl.find(([k]) => k === "X-Ainra-Pop")?.[1]]);
  found.length === 0 ? ok("W1 the file holds no address, query string, body or header value") : fail(`W1 the file holds: ${found.join(", ")}`);
  w.kill();
}
// W1 · the prime path while checks wait. A fresh watch gets 30 requests with the whole bundle in a header (each check
// verifies it in full, so they make a line of real work), then 10 signed requests naming the bundle by a ref it does
// not hold yet, then the bundle. The prime path answers while checks still wait; the 10 are still checked without the
// bundle (presentation_unknown, as without --watch); a request sent after it is checked with it.
{
  const port = 20000 + Math.floor(Math.random() * 20000);
  const obs = join(work, "watch-prime.jsonl");
  const w = watchPilot(port, ["--upstream", `http://127.0.0.1:${upPort}`, "--mode", "passport", "--audience", AUD, "--freshness", "F3", "--observations", obs]);
  const W = `127.0.0.1:${port}`;
  await watchUp(`http://${W}`);
  const E = 30, N = 10, before = reached, heavy = [], early = [];
  for (let i = 0; i < E; i++) heavy.push([["Host", W], ["X-Ainra-Passport", Buffer.from(JSON.stringify(await presentation(bundle))).toString("base64url")], ["Connection", "close"]]);
  for (let i = 0; i < N; i++) early.push(await copyLines(W, "/orders"));
  const primeBody = JSON.stringify(await presentation(bundle));
  const hs = await Promise.all(heavy.map((l) => exact(W, "GET", "/heavy", l)));
  const es = await Promise.all(early.map((l) => exact(W, "POST", "/orders", l)));
  const p = await fetch(`http://${W}${PRIME_PATH}`, { method: "POST", headers: { "content-type": "application/json" }, body: primeBody });
  const pj = await p.json().catch(() => ({}));
  const mid = await (await fetch(`http://${W}/.well-known/ainra-watch`)).json();
  const late = await exact(W, "POST", "/orders", await copyLines(W, "/orders"));
  [...hs, ...es, late].every((r) => r.status === 200) && reached === before + E + N + 1 && p.status === 201 && pj.ref === ref && mid.waiting > 0
    ? ok(`W1 with ${E + N} checks in line, the prime path still answers at once (201, the same ref) while ${mid.waiting} of them wait`)
    : fail(`W1 prime under load: ${p.status} ${JSON.stringify(pj)}; waiting then ${mid.waiting}; statuses ${JSON.stringify([...new Set([...hs, ...es].map((r) => r.status))])}, late ${late.status} (upstream saw ${reached - before})`);
  const rows = await observed(`http://${W}`, obs, E + N + 1);
  const count = (f) => rows.filter(f).length;
  const whole = count((r) => r.path === "/heavy" && r.reason === "presentation_unsigned");
  const unknown = count((r) => r.path === "/orders" && r.reason === "presentation_unknown" && r.status === 428);
  const admitted = count((r) => r.decision === "admit");
  rows.length === E + N + 1 && whole === E && unknown === N && admitted === 1
    ? ok(`W1 and the ${N} requests that named the bundle before it was sent are checked without it (428 presentation_unknown, as without --watch); the one sent after it is admitted`)
    : fail(`W1 order: ${rows.length} lines; ${whole} whole-bundle presentation_unsigned, ${unknown} presentation_unknown, ${admitted} admitted`);
  w.kill();
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
// 11 · the head, logged at the registrar — and the cut it now shows
{
  const lines = readFileSync(join(work, "passport-decisions.jsonl"), "utf8").trim().split("\n");
  const h = await (await fetch(`http://${PP}/.well-known/ainra-decisions-head?flush=1`)).json();
  const gateKey = Buffer.from(h.gate_key, "base64url");
  const gate = Verifier.fromDirectoryB64(JSON.parse(readFileSync(join(work, "directory.json"), "utf8")),
    ...(({ root_ed25519, root_slh }) => [root_ed25519, root_slh])(JSON.parse(readFileSync(join(work, "roots.json"), "utf8"))), "F3");
  const hv = h.receipt ? gate.verifyHeadReceipt(h.receipt, gateKey, now()) : { verdict: "invalid", reason: "no receipt" };
  hv.verdict === "valid" && hv.statement.seq === lines.length - 1
    ? ok(`the pilot logged its head at the registrar: leaf ${h.receipt.leaf_index}, seq ${hv.statement.seq}; the receipt verifies against the published directory`)
    : fail(`head receipt: ${JSON.stringify(hv)}`);
  if (hv.verdict === "valid") {
    const whole = verifyDecisionChainToHead(lines, gateKey, null, hv.statement);
    const cut = lines.slice(0, -1);
    const alone = verifyDecisionChain(cut, gateKey);
    const against = verifyDecisionChainToHead(cut, gateKey, null, hv.statement);
    whole.ok && alone.ok && !against.ok && against.problem === "truncated"
      ? ok(`the last record cut: the chain alone still holds (${alone.count}), against the logged head it reads truncated`)
      : fail(`cut: whole ${JSON.stringify(whole)} alone ${JSON.stringify(alone)} against ${JSON.stringify(against)}`);
  }
}

// Watch mode, link (D-105): the gate beside a route
console.log("\nwatch mode");
// W2 · key C, linked to a fresh passport (step 9 revoked the lineage A's passport is in); B stays unlinked
const wpass = await demoIssue({ operator: "specimen", lineage: "pilot-watch" });
const C = await agentKey();
more.push(C);
{
  const cpop = Buffer.from(await crypto.subtle.sign({ name: "Ed25519" }, C.k.privateKey, linkPopSigningBytes(wpass.registrar, wpass.sub, C.tp, wpass.nbf))).toString("base64url");
  const lc = await write("/link", { passport: wpass.sub, key: C.jwk.x, pop: cpop, nbf: wpass.nbf, exp: Math.min(wpass.exp, now() + 3600) });
  lc.thumbprint === C.tp ? ok(`key C linked to ${wpass.sub}`) : fail(`link C: ${JSON.stringify(lc)}`);
}
const watchLink = join(work, "watch-link.jsonl");
{
  const port = 20000 + Math.floor(Math.random() * 20000);
  const w = watchPilot(port, ["--upstream", `http://127.0.0.1:${upPort}`, "--mode", "link", "--registrar", REG, "--freshness", "F1", "--observations", watchLink]);
  const W = `127.0.0.1:${port}`;
  await watchUp(`http://${W}`);
  const before = reached;
  const path = `/orders?card=${MARK.query}`;
  const cl = await agentLines(C, W, path), bl = await agentLines(B, W, path), ul = [["Host", W], ...markLines()];
  const c = await exact(W, "GET", path, cl), b = await exact(W, "GET", path, bl), u = await exact(W, "GET", path, ul);
  const sent = [[c, cl], [b, bl], [u, ul]];
  sent.every(([r]) => r.status === 200) && reached === before + 3 && sent.every(([r, l]) => asSent(l, r.body?.raw) && noVerdict(r))
    && JSON.stringify(pairsOf(c.raw).filter(([k]) => k === "X-Echo")) === JSON.stringify([["X-Echo", "one"], ["X-Echo", "two"]])
    ? ok("W2 watch, link: the linked key, the unlinked key and an unsigned request reach the upstream with every header line as sent but Host's value, nothing added; no answer carries x-ainra-reason or x-ainra-verdict, and the upstream's two X-Echo lines come back as two")
    : fail(`W2 forwarded: ${JSON.stringify({ c: [c.status, c.raw, c.body], b: [b.status, b.body], u: [u.status, u.body], reached: reached - before })}`);
  // A Signature-Agent the verifier cannot parse, with text of the client's own in it.
  const m = await exact(W, "GET", path, [["Host", W], ["Signature-Agent", `sig1="${AGENT}";type=${MARK.err}`], ["Connection", "close"]]);
  const rows = await observed(`http://${W}`, watchLink, 4);
  m.status === 200 && reached === before + 4 && w.err.includes("the gate threw") && leaks(w.err, [MARK.err, MARK.query, "card=", "127.0.0.1"]).length === 0
    ? ok(`W2 a Signature-Agent the verifier cannot parse is served; the pilot logs only the kind of failure: ${JSON.stringify(w.err.trim().split("\n").at(-1))}`)
    : fail(`W2 unparsable Signature-Agent: ${m.status} (upstream saw ${reached - before}); stderr ${JSON.stringify(w.err)}`);
  const admit = rows.find((r) => r.decision === "admit"), nl = rows.find((r) => r.reason === "not_linked");
  const si = rows.find((r) => r.reason === "sig_invalid"), un = rows.find((r) => r.decision === "unchecked");
  rows.length === 4 && admit?.operator === "specimen" && admit.passport === wpass.sub && admit.signatures.join() === "signature-agent,rfc9421"
    && nl?.decision === "refuse" && nl.status === 403 && si?.decision === "refuse" && si.signatures.length === 0 && si.path === "/orders"
    && un?.not_checked === "check_failed" && un.signatures.join() === "signature-agent" && un.path === "/orders"
    ? ok(`W2 the observations: admit (${admit.operator}, ${admit.passport}), refuse not_linked, refuse sig_invalid for the unsigned one, unchecked check_failed for the unparsable one`)
    : fail(`W2 observations: ${JSON.stringify(rows)}`);
  const found = leaks(readFileSync(watchLink, "utf8"), ["127.0.0.1", "card=", MARK.query, MARK.ua, MARK.dup, MARK.err,
    cl.find(([k]) => k === "signature")?.[1], cl.find(([k]) => k === "signature-input")?.[1]]);
  found.length === 0 ? ok("W2 the file holds no address, no query string and no header value") : fail(`W2 the file holds: ${found.join(", ")}`);
  const sum = await (await fetch(`http://${W}/.well-known/ainra-watch`)).json();
  const relayed = await fetch(`http://${W}/.well-known/ainra-watch`, { headers: { "x-forwarded-for": "203.0.113.9" } });
  sum.requests === 4 && sum.checked === 3 && sum.not_checked.check_failed === 1 && sum.decisions.admit === 1 && sum.decisions.refuse === 2
    && sum.refusals.not_linked === 1 && sum.refusals.sig_invalid === 1 && sum.signatures.any === 3 && sum.signatures.none === 1
    && typeof sum.check_ms.p99 === "number" && relayed.status === 403
    ? ok(`W2 the summary, on loopback: 4 seen, 3 checked (1 would be admitted, 2 refused), 1 not checked; check p50 ${sum.check_ms.p50} ms, p99 ${sum.check_ms.p99} ms on this machine; relayed by a proxy → 403`)
    : fail(`W2 summary: ${JSON.stringify(sum)}, relayed → ${relayed.status}`);
  // A client that is not on loopback: one of this machine's own non-loopback addresses as the source, so no port opens
  // to the network.
  const lan = Object.values(networkInterfaces()).flat().find((a) => a && !a.internal && a.family === "IPv4")?.address;
  if (lan) {
    const far = await new Promise((done) => {
      const q = http.request({ hostname: "127.0.0.1", port, path: "/.well-known/ainra-watch", localAddress: lan }, (r) => { r.resume(); done(r.statusCode); });
      q.on("error", (e) => done(e.code));
      q.end();
    });
    far === 403 ? ok(`W2 the summary asked from ${lan}, not loopback → 403`) : fail(`W2 the summary asked from ${lan} → ${far}`);
  } else console.log("  skip  W2 this machine has no non-loopback IPv4 address, so a far client was not tried");
  w.kill();
}
// W3 · a registrar that accepts connections and never answers
{
  let asked = 0; // requests the registrar received (the HTTP client may also open idle connections it never uses)
  const hung = net.createServer((s) => { s.on("data", (d) => { asked += (d.toString("latin1").match(/^GET \//gm) ?? []).length; }); s.on("error", () => {}); });
  await new Promise((r) => hung.listen(0, "127.0.0.1", r));
  const port = 20000 + Math.floor(Math.random() * 20000);
  const obs = join(work, "watch-hung.jsonl");
  const w = watchPilot(port, ["--upstream", `http://127.0.0.1:${upPort}`, "--mode", "link", "--registrar", `http://127.0.0.1:${hung.address().port}`,
    "--freshness", "F1", "--observations", obs]);
  const W = `127.0.0.1:${port}`;
  await watchUp(`http://${W}`);
  const before = reached, N = 10;
  const sent = await Promise.all(Array.from({ length: N }, async () => exact(W, "GET", "/orders", await agentLines(C, W, "/orders"))));
  const slowest = Math.max(...sent.map((r) => r.ms));
  const early = await (await fetch(`http://${W}/.well-known/ainra-watch`)).json();
  sent.every((r) => r.status === 200) && reached === before + N && slowest < 1000 && early.waiting >= 1 && asked <= 2
    ? ok(`W3 a registrar that never answers: ${N} signed requests reach the upstream at once (the slowest in ${slowest.toFixed(0)} ms) while ${early.waiting} checks wait for it`)
    : fail(`W3 forwarding: ${JSON.stringify(sent.map((r) => [r.status, Math.round(r.ms)]))} (upstream saw ${reached - before}); waiting ${early.waiting}; registrar asked ${asked}`);
  const rows = await observed(`http://${W}`, obs, N);
  const later = await (await fetch(`http://${W}/.well-known/ainra-watch`)).json();
  rows.length === N && rows.every((r) => r.decision === "refuse" && r.reason === "not_linked") && later.waiting === 0 && asked === 2
    ? ok(`W3 the shared fetch gave up after 5 s: every check ended not_linked, none is waiting, and the registrar was asked ${asked} times in all, not ${2 * N}`)
    : fail(`W3 after the timeout: ${JSON.stringify(rows)}; waiting ${later.waiting}; registrar asked ${asked}`);
  w.kill();
  hung.close();
}
// W4 · a mirror target: no --upstream
{
  const port = 20000 + Math.floor(Math.random() * 20000);
  const obs = join(work, "watch-mirror.jsonl");
  const w = watchPilot(port, ["--mode", "link", "--registrar", REG, "--freshness", "F1", "--observations", obs]);
  const W = `http://127.0.0.1:${port}`;
  await watchUp(W);
  const before = reached;
  const r = await send(C, W);
  const rows = await observed(W, obs, 1);
  r.status === 204 && r.reason === null && reached === before && rows.length === 1 && rows[0].decision === "admit" && rows[0].operator === "specimen"
    ? ok("W4 watch as a mirror target: 204 at once, the upstream count unchanged, and the request observed (admit)")
    : fail(`W4: ${r.status} (upstream saw ${reached - before}) ${JSON.stringify(rows)}`);
  w.kill();
}
// W5 · the report
{
  const REPORT = new URL("watch-report.mjs", import.meta.url).pathname;
  const rep = spawnSync("node", [REPORT, watchLink], { encoding: "utf8" });
  const want = [/: 4 requests seen/, /carrying any signature\s+3 of 4/, /Signature-Agent header\s+3 of 4/, /RFC 9421 signature\s+2 of 4/,
    /AINRA presentation\s+0 of 4/, /\n {2}checked\s+3\n/, /would admit\s+1\n/, /would refuse\s+2\n/, /not_linked\s+1\n/, /sig_invalid\s+1\n/, /of which no signature at all\s+1\n/,
    /not checked\s+1\n/, /check_failed\s+1\n/, /p50 [\d.]+ ms · p95 [\d.]+ ms · p99 [\d.]+ ms \(3 checks\)/];
  const missed = want.filter((re) => !re.test(rep.stdout));
  rep.status === 0 && missed.length === 0
    ? ok(`W5 watch-report.mjs on W2's file:\n${rep.stdout.trimEnd().split("\n").map((l) => "        " + l).join("\n")}`)
    : fail(`W5 report (exit ${rep.status}) missed ${missed.join(" ")}:\n${rep.stdout}${rep.stderr}`);
  // A file whose answers are known: check times 1..100 in random order, two unchecked lines, a line that is not JSON,
  // a 1.5 MiB line read in many pieces, and no newline at the end.
  const known = join(work, "watch-known.jsonl");
  const line = (r) => JSON.stringify({ time: "2026-11-12T09:00:00.000Z", method: "GET", path: "/k", ...r });
  const checks = Array.from({ length: 100 }, (_, i) => i + 1).sort(() => Math.random() - 0.5)
    .map((ms, i) => line({ signatures: i % 2 ? ["rfc9421"] : [], decision: i % 4 ? "refuse" : "admit", ...(i % 4 ? { status: 403, reason: "not_linked" } : {}), check_ms: ms }));
  writeFileSync(known, [...checks.slice(0, 50), "x".repeat(3 << 19), line({ signatures: ["rfc9421"], decision: "unchecked", not_checked: "check_busy" }),
    "not json", line({ signatures: [], decision: "unchecked", not_checked: "body_over_1_mib" }), ...checks.slice(50)].join("\n"));
  const k = spawnSync("node", [REPORT, known], { encoding: "utf8" });
  const wantK = [/: 102 requests seen/, /\(2 lines skipped: not an observation\)/, /carrying any signature\s+51 of 102/, /\n {2}checked\s+100\n/,
    /would admit\s+25\n/, /would refuse\s+75\n/, /not checked\s+2\n/, /check_busy\s+1\n/, /body_over_1_mib\s+1\n/,
    /p50 50\.00 ms · p95 95\.00 ms · p99 99\.00 ms \(100 checks\)/];
  const missedK = wantK.filter((re) => !re.test(k.stdout));
  k.status === 0 && missedK.length === 0
    ? ok("W5 on a file of known values: 102 requests, 100 checked (p50 50, p95 95, p99 99 ms), 2 unchecked by reason, and the line that is not JSON and the 1.5 MiB line skipped")
    : fail(`W5 known file (exit ${k.status}) missed ${missedK.join(" ")}:\n${k.stdout}${k.stderr}`);
  const gone = spawnSync("node", [REPORT, join(work, "no-such-file.jsonl")], { encoding: "utf8" });
  gone.status === 2 ? ok("W5 and on a missing file it exits 2") : fail(`W5 missing file: exit ${gone.status}`);
}
// W6 · a watch signs nothing
{
  const log = join(work, "watch-decisions.jsonl"), key = join(work, "watch-gate.key");
  const d = spawnSync("node", [PILOT_JS, "--watch", "--decisions", log, "--gate-key", key, "--upstream", `http://127.0.0.1:${upPort}`,
    "--listen", "127.0.0.1:1", "--directory", join(work, "directory.json"), "--roots", join(work, "roots.json"), "--mode", "link", "--registrar", REG], { encoding: "utf8" });
  const msg = d.stderr.trim();
  d.status === 2 && msg && !msg.includes("\n") && !existsSync(log) && !existsSync(key)
    ? ok(`W6 --watch with --decisions exits 2 and writes no log and no key: ${msg}`)
    : fail(`W6: exit ${d.status}, stderr ${JSON.stringify(d.stderr)}, log ${existsSync(log)}, key ${existsSync(key)}`);
}
ppilot.kill(); upstream.close(); dirSrv.close();
console.log(bad ? "\nPILOT-E2E FAILED" : "\nPILOT-E2E OK: one command in front of a service, both modes; linked keys and signed passports in, unlinked, revoked, unsigned and replayed requests refused by name, every decision signed, and a cut tail caught by the head the registrar logged; in watch mode every request reached the service as it was sent, refused or not, checked or not, without waiting for the check, and only what the gate would have decided was written down");
process.exit(bad);
