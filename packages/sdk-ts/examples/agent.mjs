// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// An agent written in TypeScript/JavaScript, end to end — the same journey as packages/sdk-py/examples/agent.py, step
// for step, against an origin you name (D-072). `make identity-e2e` is the deeper drill; this is the one to copy from.
//
//   1. the agent generates its own hybrid key; the secret never leaves this process
//   2. it asks the registrar's public door for a passport, proving it holds that key
//   3. it mints an instance credential for one running copy
//   4. the running copy sends its bundle ONCE, then names it by digest
//   5. it SIGNS each HTTP request with its instance key; a real gate lets it in
//   6. the same request moved, unsigned or replayed is refused, each by name
//   7. after revocation the gate refuses the passport
//
// Usage:  node examples/agent.mjs http://127.0.0.1:<port>     (an origin from tools/gate-origin.mjs or gate-origin.py)
import { randomBytes } from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { ed25519 } from "@noble/curves/ed25519";
import {
  canonicalize, mintInstanceCredential, proveInstancePossession, signPresentation, presentationRef,
  PRESENTATION_HEADER, PRIME_PATH, POP_HEADER,
} from "../dist/index.js";

const REG = process.env.AINRA_REGISTRAR ?? "http://127.0.0.1:4970";
const AUD = process.env.AINRA_AUDIENCE ?? "https://shop.example";
const origin = (process.argv[2] ?? "").replace(/\/$/, "");
if (!origin) { console.error("usage: node examples/agent.mjs http://127.0.0.1:<port>"); process.exit(2); }
const authority = new URL(origin).host;
const now = () => Math.floor(Date.now() / 1000);
const b64u = (u) => Buffer.from(u).toString("base64url");
let bad = 0;
const ok = (m) => console.log(`  ok    ${m}`);
const fail = (m) => { console.error(`  FAIL  ${m}`); bad = 1; };
const step = (m) => console.log(`\n${m}`);

/** Ed25519 + ML-DSA-65, held by the caller. The SDK only ever sees `sign`, a callback. */
function hybridKey() {
  const edSk = ed25519.utils.randomPrivateKey();
  const ml = ml_dsa65.keygen(randomBytes(32));
  return {
    raw: { ed25519: ed25519.getPublicKey(edSk), mldsa65: ml.publicKey },
    wire: { ed25519: b64u(ed25519.getPublicKey(edSk)), mldsa65: b64u(ml.publicKey) },
    sign: (msg) => ({ ed25519: ed25519.sign(msg, edSk), mldsa65: ml_dsa65.sign(ml.secretKey, msg) }),
  };
}
const wireSig = (s) => ({ ed25519: b64u(s.ed25519), mldsa65: b64u(s.mldsa65) });

/** { status, reason, body } — a refusal is an answer, not an exception. A 429 is "wait": the registrar's public
 *  door allows 30 writes a minute, so this waits its turn (up to 70 s) rather than reporting a failure. */
async function call(method, url, headers = {}, body) {
  let r = await fetch(url, { method, headers, body });
  for (let attempt = 0; r.status === 429 && attempt < 14; attempt++) {
    await new Promise((ok) => setTimeout(ok, 5000));
    r = await fetch(url, { method, headers, body });
  }
  const text = await r.text();
  let parsed = null; try { parsed = JSON.parse(text); } catch { /* not JSON */ }
  return { status: r.status, reason: r.headers.get("x-ainra-reason"), body: parsed };
}

let accred;
try { accred = await call("GET", `${REG}/accreditation`); }
catch { console.error(`agent.mjs: no live registrar at ${REG} — run \`make live-up\` first`); process.exit(2); }

step("1 · the agent generates its own hybrid key");
const holder = hybridKey(), instance = hybridKey();
ok("generated locally · ed25519 + ml-dsa-65 · the secret never leaves this process");

step("2 · the registrar's public door issues a passport bound to it");
const registrar = accred.body?.id ?? accred.body?.registrar ?? "registrar-07";
const spec = { operator: "specimen", lineage: "tsagent", holder_key: holder.wire };
{
  const r = await call("POST", `${REG}/demo/issue`, {}, JSON.stringify(spec));
  r.status !== 200 ? ok(`a key WITHOUT a proof is refused (${r.status})`) : fail("the door certified a key with no proof");
}
const proof = wireSig(holder.sign(new TextEncoder().encode(canonicalize({ holder: holder.wire, purpose: "ainra-holder-pop-v1", registrar }))));
const issued = await call("POST", `${REG}/demo/issue`, {}, JSON.stringify({ ...spec, holder_pop: proof }));
if (issued.status !== 200) { fail(`issue failed: ${issued.status} ${JSON.stringify(issued.body)}`); process.exit(1); }
const sub = issued.body.sub;
const carried = JSON.parse(issued.body.claims).keys?.[0];
carried?.ed25519 === holder.wire.ed25519 && carried?.mldsa65 === holder.wire.mldsa65
  ? ok(`issued ${sub} · carries the AGENT's key`) : fail("the passport carries another key");

step("3 · the agent mints an instance credential for one running copy");
const present = `${REG}/present?sub=${encodeURIComponent(sub)}&now=`;
const bundle = (await call("GET", present + now())).body;
const ic = await mintInstanceCredential({
  passportClaimsB64: bundle.claims, instancePublic: instance.raw, capabilities: ["demo:specimen"], audience: AUD,
  now: now(), lifetimeSecs: 900, iid: "i-" + randomBytes(4).toString("hex"), controlSign: holder.sign,
});
ok(`${ic.iid} · ${ic.exp - ic.nbf}s · audience ${ic.aud} · minted with the passport key`);
async function presentation(b = bundle) {
  const pop = await proveInstancePossession({ audience: AUD, credential: ic, nonce: "p-" + randomBytes(6).toString("hex"), now: now(), instanceSign: instance.sign });
  return {
    ...b,
    instance: {
      sub: ic.sub, iid: ic.iid, ikey: wireSig(ic.ikey), nbf: ic.nbf, exp: ic.exp, capabilities: ic.capabilities,
      aud: ic.aud, passport_leaf: b64u(ic.passportLeaf), sig: wireSig(ic.sig),
      pop: { aud: pop.aud, nonce: pop.nonce, ts: pop.ts, sig: wireSig(pop.sig) },
    },
  };
}

step("4 · the running copy sends its bundle once");
const full = await presentation();
const primed = await call("POST", origin + PRIME_PATH, { "content-type": "application/json" }, JSON.stringify(full));
const ref = primed.body?.ref;
if (primed.status === 201 && ref === presentationRef(full)) ok(`201 · named from now on by ${ref.slice(0, 22)}… — the digest this SDK computes for the same bundle`);
else { fail(`priming: ${primed.status} ${primed.reason} · gate ref ${ref} · ours ${presentationRef(full)}`); process.exit(1); }

async function send({ method = "GET", path = "/orders", body, sign = true, wirePath, name } = {}) {
  const pop = (await presentation()).instance.pop;
  const headers = { [PRESENTATION_HEADER]: name ?? ref, [POP_HEADER]: b64u(JSON.stringify(pop)) };
  if (sign) Object.assign(headers, await signPresentation({
    req: { method, authority, path, headers, body }, keyid: ic.iid, nonce: "r-" + randomBytes(6).toString("hex"), created: now(), instanceSign: instance.sign,
  }));
  const r = await call(method, origin + (wirePath ?? path), headers, body);
  return { ...r, headers };
}

step("5 · the running copy signs each request; the real gate lets it in");
{
  const r = await send();
  const size = Object.entries(r.headers).reduce((n, [k, v]) => n + k.length + v.length + 4, 0);
  r.status === 200 ? ok(`GET → 200 · request headers ${(size / 1024).toFixed(1)} KiB`) : fail(`signed GET: ${r.status} ${r.reason}`);
  const p = await send({ method: "POST", body: new TextEncoder().encode('{"sku":"A-1","qty":2}') });
  p.status === 200 ? ok("POST with a body → 200 · the body is covered by its digest") : fail(`signed POST: ${p.status} ${p.reason}`);
}

step("6 · every way of misusing it is refused, by name");
for (const [label, wantStatus, wantReason, args] of [
  ["moved to another path", 403, "presentation_sig_invalid", { wirePath: "/admin/refunds" }],
  ["unsigned", 403, "presentation_unsigned", { sign: false }],
  ["a digest this gate was never sent", 428, "presentation_unknown", { name: `sha-256=:${Buffer.alloc(32).toString("base64")}:` }],
]) {
  const r = await send(args);
  r.status === wantStatus && r.reason === wantReason ? ok(`${label} → ${r.status} ${r.reason}`) : fail(`${label}: ${r.status} ${r.reason}`);
}
{
  const first = await send();
  const again = await call("GET", origin + "/orders", first.headers);
  first.status === 200 && again.status === 403 && again.reason === "presentation_replayed"
    ? ok(`the identical request sent twice → 1st 200, 2nd 403 ${again.reason}`) : fail(`replay: ${first.status} then ${again.status} ${again.reason}`);
}

step("7 · revoke the passport");
{
  const rv = await call("POST", `${REG}/demo/revoke`, {}, JSON.stringify({ sub, now: now() }));
  if (rv.status !== 200) fail(`revoke failed: ${rv.status} ${JSON.stringify(rv.body)}`);
  const fresh = (await call("GET", present + now())).body;
  const r = await call("POST", origin + PRIME_PATH, { "content-type": "application/json" }, JSON.stringify(await presentation(fresh)));
  r.status === 403 && r.reason === "revoked"
    ? ok(`sending the post-revocation bundle → 403 ${r.reason} — a revoked credential is never stored`) : fail(`priming after revoke: ${r.status} ${r.reason}`);
}

console.log(bad ? "\nTS-AGENT-E2E FAILED"
  : "\nTS-AGENT-E2E OK: an agent written in TypeScript held its own key, got a passport for it, minted a credential for a running copy, signed its requests, and the gate let it in — then refused it moved, unsigned, replayed and revoked. TEST-ROOT.");
process.exit(bad);
