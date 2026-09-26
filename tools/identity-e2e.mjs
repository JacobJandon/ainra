// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// STATUS: passes against the wall-clock live registrar (`make live-up`, M35). It FAILS against the pinned staging
// network, correctly — that world is fixed at 2026-04-21 and says so.
//
// make identity-e2e — the whole working identity, end to end, the way a stranger's agent would do it.
//
//   1. the AGENT generates its own hybrid key; nothing ever sees the secret          (D-063)
//   2. it asks the registrar's PUBLIC door for a passport, proving it holds the key  (D-063)
//   3. it mints an instance credential for one running copy, under that key          (ADR-019)
//   4. the running copy sends its bundle ONCE, then names it by digest               (D-065)
//   5. it SIGNS each HTTP request with its instance key; the real gate lets it in    (D-062)
//      — on a server with Node's DEFAULT header limit, every header under 8 KiB
//   6. the same request moved, replayed, unsigned, or after revocation is refused — each by name
//
// Nothing here is simulated. The registrar is the live staging daemon, the server is node:http, the gate is the
// shipped `@ainra/middleware`, and every verdict is the real verifier's. It needs the staging network: `make
// stage-up`. It is TEST-ROOT, and says so — this proves the mechanism, not that anyone outside has used it.
//
// WITNESS: could this observe a failure? Yes — each refusal is asserted by status AND reason, and step 5 is the
// positive control that makes the refusals mean something. Drop `requireSignature` and step 6a allows; drop the
// holder proof on the registrar and step 2 still issues but step 3's credential no longer verifies.

import http from "node:http";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import {
  Verifier, canonicalize, mintInstanceCredential, proveInstancePossession, signPresentation, PRESENTATION_HEADER,
  PRIME_PATH, POP_HEADER, splitPresentation,
} from "../packages/sdk-ts/dist/index.js";
import { b64uEncode } from "../packages/sdk-ts/dist/crypto.js";
import { ainraGate, ainraPrime, createPresentationStore } from "../packages/middleware/dist/index.js";

// The limits a request has to survive on the way to a real server. Apache refuses one header line over 8190 bytes
// (LimitRequestFieldSize) and nginx over 8 KiB (large_client_header_buffers); Node refuses 16 KiB in total.
const HEADER_LINE_MAX = 8190;
const HEADERS_TOTAL_MAX = 16 * 1024;

// Sign with the SDK's own copies of the libraries — the exact versions the verifier checks with — rather than
// whatever a repo-root install happens to hold. They are resolved from the SDK, not from here.
const sdkRequire = createRequire(new URL("../packages/sdk-ts/package.json", import.meta.url));
const load = async (m) => import(pathToFileURL(sdkRequire.resolve(m)).href);
const { ml_dsa65 } = await load("@noble/post-quantum/ml-dsa");
const { ed25519 } = await load("@noble/curves/ed25519");

const REG = process.env.AINRA_REGISTRAR ?? "http://127.0.0.1:4970";   // the wall-clock live registrar (make live-up)
const ART = process.env.AINRA_ARTIFACTS ?? "http://127.0.0.1:8091";
const AUD = "https://shop.example";
const now = () => Math.floor(Date.now() / 1000);

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

// ── preflight: the live network must be there ────────────────────────────────────────────────────────────────────
try { await fetch(`${ART}/directory.json`, { signal: AbortSignal.timeout(3000) }); }
catch { console.error(`identity-e2e: no staging network at ${ART} — run \`make stage-up\` first`); process.exit(2); }

// ── 1 · the agent's own key ──────────────────────────────────────────────────────────────────────────────────────
step("1 · the agent generates its own hybrid key");
const edSk = ed25519.utils.randomPrivateKey();
const ml = ml_dsa65.keygen(randomBytes(32));
const holderKey = { ed25519: b64uEncode(ed25519.getPublicKey(edSk)), mldsa65: b64uEncode(ml.publicKey) };
const holderSign = (msg) => ({ ed25519: ed25519.sign(msg, edSk), mldsa65: ml_dsa65.sign(ml.secretKey, msg) });
ok(`generated locally · ed25519 + ml-dsa-65 · secret never leaves this process`);

// ── 2 · a passport from the public door, bound to THAT key ───────────────────────────────────────────────────────
step("2 · the registrar's public door issues a passport bound to it");
const accred = await j(`${REG}/accreditation`);
const registrarId = accred.body?.id ?? accred.body?.registrar ?? "registrar-07";
const popMsg = new TextEncoder().encode(canonicalize({ holder: holderKey, purpose: "ainra-holder-pop-v1", registrar: registrarId }));
const popSig = holderSign(popMsg);
const holderPop = { ed25519: b64uEncode(popSig.ed25519), mldsa65: b64uEncode(popSig.mldsa65) };

const refused = await j(`${REG}/demo/issue`, { method: "POST", body: JSON.stringify({ lineage: "e2e", holder_key: holderKey }) });
if (refused.status === 200) fail("the door certified a key with no proof of possession");
else ok(`a key WITHOUT a proof is refused (${refused.status})`);

const issued = await j(`${REG}/demo/issue`, {
  method: "POST",
  body: JSON.stringify({ operator: "specimen", lineage: "e2e", holder_key: holderKey, holder_pop: holderPop }),
});
if (issued.status !== 200) { fail(`issue failed: ${issued.status} ${JSON.stringify(issued.body)}`); process.exit(1); }
const sub = issued.body.sub;
const claims = JSON.parse(issued.body.claims);
if (claims.keys?.[0]?.ed25519 !== holderKey.ed25519 || claims.keys?.[0]?.mldsa65 !== holderKey.mldsa65)
  fail("the passport does not carry the agent's own key");
else ok(`issued ${sub} · carries the AGENT's key, not one the registrar generated`);

// ── the verifier's side: trust anchors from the published artifacts ──────────────────────────────────────────────
const directory = (await j(`${ART}/directory.json`)).body;
const roots = (await j(`${ART}/roots.json`)).body;
const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F3", false, AUD);
if (!verifier) { fail("could not build a verifier from the published directory"); process.exit(1); }

// ── 3 · an instance credential for one running copy, minted under the agent's key ────────────────────────────────
step("3 · the agent mints an instance credential for one running copy");
const bundle = (await j(`${REG}/present?sub=${encodeURIComponent(sub)}&now=${now()}`)).body;
const iEdSk = ed25519.utils.randomPrivateKey();
const iMl = ml_dsa65.keygen(randomBytes(32));
const instancePublic = { ed25519: ed25519.getPublicKey(iEdSk), mldsa65: iMl.publicKey };
const instanceSign = (msg) => ({ ed25519: ed25519.sign(msg, iEdSk), mldsa65: ml_dsa65.sign(iMl.secretKey, msg) });
const t0 = now();
const ic = await mintInstanceCredential({
  passportClaimsB64: bundle.claims, instancePublic, capabilities: ["demo:specimen"], audience: AUD,
  now: t0, lifetimeSecs: 900, iid: "i-" + randomBytes(4).toString("hex"), controlSign: holderSign,
});
ok(`${ic.iid} · ${ic.exp - ic.nbf}s · audience ${ic.aud} · minted with the passport key, which stays outside`);

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

// ── 5 · a real server, the real gate ─────────────────────────────────────────────────────────────────────────────
const seen = new Set();
const store = createPresentationStore();
const gate = ainraGate(verifier, {
  now, requireSignature: true, store,
  seenNonce: (n) => { const had = seen.has(n); seen.add(n); return had; },
});
const prime = ainraPrime(verifier, { store, now });
// Node's DEFAULT header limit (16 KiB). Until M36 this server had to be told to accept 256 KiB, because the whole
// bundle rode in one header — which no ordinary front end in the path would have let through.
const server = http.createServer((req, res) => {
  const shim = {
    status(c) { res.statusCode = c; return shim; },
    json(b) { res.setHeader("content-type", "application/json"); res.end(JSON.stringify(b)); },
    setHeader: (k, v) => res.setHeader(k, v),
  };
  if (req.method === "POST" && req.url === PRIME_PATH) {
    let raw = ""; req.on("data", (c) => { raw += c; });
    req.on("end", () => { try { req.body = JSON.parse(raw); } catch { req.body = undefined; } prime(req, shim); });
    return;
  }
  gate(req, shim, () => { res.statusCode = 200; res.end(JSON.stringify({ ok: true, as: req.ainra.event.name })); });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;
const authority = `127.0.0.1:${port}`;

// Send the bundle once. The gate verifies it in full and answers with the digest every request will name.
async function primeBundle(b = bundle) {
  const r = await fetch(`http://${authority}${PRIME_PATH}`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(await presentationFor(b)),
  });
  const body = await r.json().catch(() => ({}));
  return { status: r.status, ref: body.ref, reason: r.headers.get("x-ainra-reason") };
}
const sizes = (h) => ({ total: Object.entries(h).reduce((n, [k, v]) => n + k.length + String(v).length + 4, 0),
                        line: Math.max(...Object.entries(h).map(([k, v]) => k.length + String(v).length + 2)) });

let REF = null;
async function send({ path = "/orders", method = "POST", sign = true, pathOnWire, headersOverride, ref }) {
  const { pop } = splitPresentation(await presentationFor());
  const headers = {
    [PRESENTATION_HEADER]: ref ?? REF, [POP_HEADER]: Buffer.from(JSON.stringify(pop)).toString("base64url"), host: authority,
  };
  if (sign) Object.assign(headers, await signPresentation({
    req: { method, authority, path, headers }, keyid: ic.iid, nonce: "r-" + randomBytes(6).toString("hex"), created: now(), instanceSign,
  }));
  Object.assign(headers, headersOverride ?? {});
  const r = await fetch(`http://${authority}${pathOnWire ?? path}`, { method, headers });
  return { status: r.status, reason: r.headers.get("x-ainra-reason"), ...sizes(headers), headers };
}

step("4 · the old way first: the whole bundle in one header, against a server on default limits");
{
  const whole = Buffer.from(JSON.stringify(await presentationFor())).toString("base64url");
  let status;
  try { status = (await fetch(`http://${authority}/orders`, { method: "POST", headers: { [PRESENTATION_HEADER]: whole } })).status; }
  catch { status = "connection refused"; }
  status === 431
    ? ok(`${(whole.length / 1024).toFixed(1)} KiB in one header → ${status} Request Header Fields Too Large — why M36 exists`)
    : fail(`expected 431 for a ${(whole.length / 1024).toFixed(1)} KiB header, got ${status}`);
}
{
  const p = await primeBundle();
  REF = p.ref;
  p.status === 201 && REF
    ? ok(`sent once to ${PRIME_PATH} → 201, named from now on by ${REF.slice(0, 22)}…`)
    : fail(`priming failed: ${p.status} ${p.reason}`);
}

step("5 · the running copy signs each request; the real gate lets it in");
const good = await send({});
if (good.status !== 200) fail(`a correctly signed request was refused: ${good.status} ${good.reason}`);
else if (good.line > HEADER_LINE_MAX || good.total > HEADERS_TOTAL_MAX)
  fail(`allowed, but too big for a real front end: largest header ${good.line} B, total ${good.total} B`);
else ok(`200 · allowed · request headers ${(good.total / 1024).toFixed(1)} KiB, largest ${(good.line / 1024).toFixed(1)} KiB — under every common limit`);
{
  const r = await send({ ref: "sha-256=:" + Buffer.alloc(32).toString("base64") + ":" });
  r.status === 428 && r.reason === "presentation_unknown"
    ? ok(`a digest this gate was never sent → 428 ${r.reason} (send it, then retry)`) : fail(`unknown digest: ${r.status} ${r.reason}`);
}

step("6 · every way of misusing it is refused, by name");
{
  const r = await send({ pathOnWire: "/admin/refunds" });
  r.status === 403 && r.reason === "presentation_sig_invalid"
    ? ok(`moved to another path → 403 ${r.reason}`) : fail(`moved path: ${r.status} ${r.reason}`);
}
{
  const r = await send({ sign: false });
  r.status === 403 && r.reason === "presentation_unsigned"
    ? ok(`unsigned → 403 ${r.reason}`) : fail(`unsigned: ${r.status} ${r.reason}`);
}
{
  // Replay: send the EXACT headers of a request that was already accepted.
  const first = await send({});
  const again = await fetch(`http://${authority}/orders`, { method: "POST", headers: first.headers });
  const reason = again.headers.get("x-ainra-reason");
  first.status === 200 && again.status === 403 && reason === "presentation_replayed"
    ? ok(`the identical request sent twice → 1st 200, 2nd 403 ${reason}`) : fail(`replay: ${first.status} then ${again.status} ${reason}`);
}

step("7 · revoke the passport — every running copy dies with it");
const rv = await j(`${REG}/demo/revoke`, { method: "POST", body: JSON.stringify({ sub, now: now() }) });
if (rv.status !== 200) fail(`revoke failed: ${rv.status} ${JSON.stringify(rv.body)}`);
const fresh = (await j(`${REG}/present?sub=${encodeURIComponent(sub)}&now=${now()}`)).body;
const before = { ...bundle };
Object.assign(bundle, fresh);                      // the post-revocation status list
{
  // An honest copy sends the bundle it now holds. The gate refuses to store a revoked credential at all.
  const p = await primeBundle();
  p.status === 403 && p.reason === "revoked"
    ? ok(`sending the post-revocation bundle → 403 ${p.reason} — a revoked credential is never stored`)
    : fail(`priming after revoke: ${p.status} ${p.reason}`);
}
{
  // A copy that keeps naming the bundle it sent BEFORE revocation is judged exactly as if it had re-sent that old
  // bundle in full: caching changes nothing about the status-freshness bound. Assert the equivalence, not a hope.
  const viaRef = await send({});
  const { checkRequest } = await import("../packages/middleware/dist/index.js");
  const direct = checkRequest(verifier, await presentationFor(before), { now });
  (viaRef.status === 200) === direct.allow
    ? ok(`naming the pre-revocation bundle → ${viaRef.status}${viaRef.reason ? " " + viaRef.reason : ""}, the same answer as re-sending it in full (${direct.allow ? "allowed until its status list ages out — the freshness bound, unchanged by M36" : "refused"})`)
    : fail(`the cached bundle and the same bundle sent in full disagree: ${viaRef.status} vs allow=${direct.allow}`);
}

server.close();
console.log(bad
  ? "\nIDENTITY-E2E FAILED"
  : "\nIDENTITY-E2E OK: an agent held its own key, got a passport for it, signed a request with a running copy's key, and the gate let it in — then refused it moved, unsigned, replayed and revoked. TEST-ROOT.");
process.exit(bad);
