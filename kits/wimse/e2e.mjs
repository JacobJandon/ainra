#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make wimse-e2e — an AINRA running copy as a WIMSE workload, live (D-076).
//
// The IETF's agent-identity work (draft-ietf-wimse-aims) gives a workload a short-lived Workload Identity Token and
// has it sign each request (draft-ietf-wimse-http-signature). It has no revocation: "a short expiration is the primary
// mitigation". This drill runs, at the real clock, against the live registrar:
//
//   1. the agent's own key → a passport → a WIT for one running copy, signed by the passport's key
//   2. an origin that reads every request twice: a WIMSE-only verifier built from independent open-source libraries
//      (kits/wimse/independent.mjs: jose + http-message-sig — it trusts the passport's key as the trust domain's
//      issuer key, configured once, out of band), and AINRA's `verifyWimseRequest` (the passport too: registrar,
//      log, registrar-signed status list, at the F1 freshness class)
//   3. signed GET and POST → both readers accept
//   4. moved to another path → both refuse; the same nonce twice → AINRA refuses the replay
//   5. revoke. The copy's current passport → refused at the door, `revoked`. The copy keeps presenting its OLD
//      all-clear snapshot instead: AINRA accepts it only until that snapshot is older than F1 (30 s), then refuses
//      `stale_status`. The WIMSE-only verifier accepts every one of these requests: nothing in WIMSE can tell it.
//
// TEST-ROOT, http on 127.0.0.1. It proves the mechanism; it is not evidence that anyone deploys it.
//
// WITNESS: could this observe a failure? Yes — every step asserts both readers' answers, step 3 is the positive
// control for both, and step 5 fails if AINRA accepts the old snapshot past its freshness bound.
import http from "node:http";
import { randomBytes } from "node:crypto";
import { liveAgent, now, REG } from "../../tools/lib/live-agent.mjs";
import {
  Verifier, mintWit, signWimseRequest, verifyWimseRequest, trustDomainOf, presentationRef, PRIME_PATH,
} from "../../packages/sdk-ts/dist/index.js";
import { wimseOnlyVerify } from "./independent.mjs";

const ART = process.env.AINRA_ARTIFACTS ?? "http://127.0.0.1:8091";
const AUD = "https://ledger.example/entries";
const REF_HEADER = "x-ainra-passport";
let bad = 0;
const ok = (m) => console.log(`  ok    ${m}`);
const fail = (m) => { console.error(`  ✗     ${m}`); bad = 1; };
const step = (m) => console.log(`\n${m}`);
const sleep = (s) => new Promise((r) => setTimeout(r, s * 1000));

try { await fetch(`${REG}/accreditation`, { signal: AbortSignal.timeout(3000) }); }
catch { console.error(`wimse-e2e: no live registrar at ${REG} — run \`make live-up\` first`); process.exit(2); }

// ── 1 ────────────────────────────────────────────────────────────────────────────────────────────────────────────
step("1 · the agent: its own key → a passport → a WIT for one running copy, signed by the passport's key");
const agent = await liveAgent({ lineage: "wimse", audience: AUD });
const iid = "i-" + randomBytes(4).toString("hex");
const wit = await mintWit({
  passportClaimsB64: agent.bundle.claims, iid, instanceEd25519Public: agent.instance.raw.ed25519, now: now(),
  controlSignEd25519: (m) => agent.holder.sign(m).ed25519,
});
const witClaims = JSON.parse(Buffer.from(wit.split(".")[1], "base64url"));
ok(`${agent.sub} → ${witClaims.sub}, WIT valid ${witClaims.exp - witClaims.iat}s`);

// ── 2 ────────────────────────────────────────────────────────────────────────────────────────────────────────────
step("2 · an origin reads every request twice: a WIMSE-only verifier (independent libraries), then AINRA");
const directory = await (await fetch(`${ART}/directory.json`)).json();
const roots = await (await fetch(`${ART}/roots.json`)).json();
const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F1", false, AUD);
if (!verifier) { fail("could not build a verifier from the published directory"); process.exit(1); }
// What the WIMSE-only side is configured with, once: this trust domain, and its authorized issuer key.
const passportKey = JSON.parse(Buffer.from(agent.bundle.claims, "base64url")).keys[0].ed25519;
const wimseConfig = { trustDomain: trustDomainOf(agent.sub), issuerX: passportKey, audience: AUD };
const store = new Map(); // passports this origin has verified, by digest (D-065)
const seen = new Set();

const origin = http.createServer(async (req, res) => {
  const chunks = []; for await (const c of req) chunks.push(c);
  const body = Buffer.concat(chunks);
  res.setHeader("content-type", "application/json");
  if (req.method === "POST" && req.url === PRIME_PATH) {
    const bundle = JSON.parse(body.toString("utf8"));
    const v = verifier.verify(bundle, now());
    if (v.verdict !== "valid") { res.statusCode = 403; res.end(JSON.stringify({ reason: v.reason })); return; }
    const ref = presentationRef(bundle);
    store.set(ref, bundle);
    res.statusCode = 201; res.end(JSON.stringify({ ref })); return;
  }
  const headers = {};
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    const k = req.rawHeaders[i].toLowerCase();
    headers[k] = headers[k] === undefined ? req.rawHeaders[i + 1] : [].concat(headers[k], req.rawHeaders[i + 1]);
  }
  const fwd = new Headers();
  for (const [k, v] of Object.entries(headers)) if (!["host", "connection", "content-length"].includes(k)) for (const x of [].concat(v)) fwd.append(k, x);
  let wimse;
  try {
    await wimseOnlyVerify(new Request(`http://${req.headers.host}${req.url}`, { method: req.method, headers: fwd, body: body.length ? body : undefined }),
      { ...wimseConfig, now: now(), body });
    wimse = "valid";
  } catch (e) { wimse = `invalid (${e.cause?.message ?? e.message})`; }
  const bundle = store.get(headers[REF_HEADER]);
  const a = bundle
    ? verifyWimseRequest({
        req: { method: req.method, authority: req.headers.host, path: req.url, headers, body },
        verifier, bundle, audience: AUD, now: now(), seenNonce: (n) => { const had = seen.has(n); seen.add(n); return had; },
      })
    : { ok: false, reason: "presentation_unknown" };
  res.statusCode = 200;
  res.end(JSON.stringify({ wimse, ainra: a.ok ? "valid" : a.reason }));
});
await new Promise((r) => origin.listen(0, "127.0.0.1", r));
const BASE = `http://127.0.0.1:${origin.address().port}`;
ok(`origin at ${BASE} · WIMSE-only trusts ${wimseConfig.trustDomain} · AINRA gate at F1 (30 s)`);

async function prime(bundle) {
  const r = await fetch(BASE + PRIME_PATH, { method: "POST", body: JSON.stringify(bundle) });
  return { status: r.status, ...(await r.json()) };
}
async function send({ method = "GET", path = "/ledger", body, ref, sentPath = path, nonce = "n-" + randomBytes(6).toString("hex") }) {
  const headers = body ? { "content-type": "application/json" } : {};
  const h = await signWimseRequest({
    req: { method, authority: new URL(BASE).host, path, headers, body }, wit, audience: AUD, nonce, created: now(),
    instanceSignEd25519: (m) => agent.instance.sign(m).ed25519,
  });
  const r = await fetch(BASE + sentPath, { method, headers: { ...headers, ...h, [REF_HEADER]: ref }, body });
  return { ...(await r.json()), nonce };
}
const both = (r) => `WIMSE-only ${r.wimse} · AINRA ${r.ainra}`;

// ── 3 ────────────────────────────────────────────────────────────────────────────────────────────────────────────
step("3 · signed requests from the running copy");
const p0 = await prime(agent.bundle);
p0.status === 201 ? ok(`passport primed once → ${p0.ref.slice(0, 20)}…`) : fail(`prime refused: ${JSON.stringify(p0)}`);
const ref = p0.ref;
for (const [what, r] of [
  ["GET /ledger", await send({ ref })],
  ["POST /ledger/entries with a body", await send({ method: "POST", path: "/ledger/entries?dry=0", body: '{"invoice":"INV-7","amount":120}', ref })],
]) r.wimse === "valid" && r.ainra === "valid" ? ok(`${what} → ${both(r)}`) : fail(`${what} → ${both(r)}`);

// ── 4 ────────────────────────────────────────────────────────────────────────────────────────────────────────────
step("4 · each reader holds its line");
{
  const moved = await send({ path: "/ledger", sentPath: "/ledger/void", ref });
  moved.wimse.startsWith("invalid") && moved.ainra === "presentation_sig_invalid"
    ? ok(`signed for /ledger, sent to /ledger/void → ${both(moved)}`) : fail(`moved: ${both(moved)}`);
  const first = await send({ ref });
  const again = await send({ ref, nonce: first.nonce });
  again.ainra === "presentation_replayed"
    ? ok(`the same nonce twice → AINRA ${again.ainra} (the WIMSE-only verifier here keeps no nonce cache: ${again.wimse})`)
    : fail(`replay: ${both(again)}`);
}

// ── 5 ────────────────────────────────────────────────────────────────────────────────────────────────────────────
step("5 · revoke the passport");
const rv = await agent.revoke();
rv.status === 200 ? ok(`revoked at the registrar`) : fail(`revoke failed: ${rv.status} ${JSON.stringify(rv.body)}`);
const current = await agent.fetchBundle();
const p1 = await prime(current);
p1.status === 403 && p1.reason === "revoked"
  ? ok(`the copy's current passport → refused at the door, ${p1.reason}`) : fail(`current passport after revocation: ${JSON.stringify(p1)}`);
{
  const r = await send({ ref });
  const age = now() - agent.bundle.status_issued_at;
  r.wimse === "valid" && r.ainra === "valid"
    ? ok(`the OLD all-clear snapshot (${age}s old) → ${both(r)} — inside F1, as documented`)
    : r.wimse === "valid" && r.ainra === "stale_status"
      ? ok(`the OLD all-clear snapshot (${age}s old) → ${both(r)} — already past F1`)
      : fail(`old snapshot, inside the bound: ${both(r)}`);
  const wait = Math.max(0, agent.bundle.status_issued_at + 30 - now() + 2);
  console.log(`        waiting ${wait}s for that snapshot to pass F1…`);
  await sleep(wait);
  const late = await send({ ref });
  late.wimse === "valid" && late.ainra === "stale_status"
    ? ok(`the OLD snapshot, ${now() - agent.bundle.status_issued_at}s old → ${both(late)}`)
    : fail(`old snapshot past F1: ${both(late)}`);
  console.log(`        the WIMSE-only verifier accepts this copy's requests until its WIT expires, in ${witClaims.exp - now()}s`);
}

origin.close();
console.log(bad
  ? "\nWIMSE-E2E FAILED"
  : "\nWIMSE-E2E OK: a running copy presented as a standard WIMSE workload — its WIT and request signatures accepted by independent WIMSE code and by AINRA. After revocation AINRA refused its current passport at once and its old snapshot within F1; the WIMSE-only verifier, which has no revocation, kept accepting. TEST-ROOT.");
process.exit(bad);
