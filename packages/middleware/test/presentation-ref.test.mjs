// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// M36 / D-065 — the gate's side of "send the bundle once, name it by digest after that".
//
// What must hold: a digest opens nothing on its own (only a bundle that verified when it was sent is ever stored),
// a digest names one bundle and no other, the store is bounded and forgets, and a gate that does not hold the
// bundle says so in a way a client can act on — 428 and where to send it — rather than refusing the agent.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  Verifier, checkRequest, ainraGate, ainraPrime, createPresentationStore, presentationRef, PRIME_PATH,
} from "../dist/index.js";

const F = new URL("./fixtures/", import.meta.url);
const load = (f) => JSON.parse(readFileSync(new URL(f, F), "utf8"));
const roots = load("roots.json");
const verifier = Verifier.fromDirectoryB64(load("directory.json"), roots.root_ed25519, roots.root_slh);
const bundle = load("bundle-valid.json");
const T = load("meta.json").now;
const now = () => T;

function fakeRes() {
  const r = { statusCode: 0, headers: {}, body: undefined };
  r.status = (c) => { r.statusCode = c; return r; };
  r.json = (b) => { r.body = b; return r; };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  return r;
}
function prime(store, body) {
  const res = fakeRes();
  ainraPrime(verifier, { store, now })({ method: "POST", headers: {}, body }, res);
  return res;
}

test("a digest the gate has never been sent is refused as unknown — not as an invalid agent", () => {
  const r = checkRequest(verifier, presentationRef(bundle), { now, store: createPresentationStore() });
  assert.equal(r.allow, false);
  assert.equal(r.reason, "presentation_unknown");
});

test("THE POINT: send the bundle once, then its digest opens the gate with the full verdict", () => {
  const store = createPresentationStore();
  const res = prime(store, bundle);
  assert.equal(res.statusCode, 201, JSON.stringify(res.body));
  assert.equal(res.body.ref, presentationRef(bundle));
  const r = checkRequest(verifier, res.body.ref, { now, store });
  assert.equal(r.allow, true, r.reason);
  assert.equal(r.verdict.verdict, "valid");
  assert.equal(r.event.name, checkRequest(verifier, bundle, { now }).event.name, "same agent, same event, either way");
});

test("a bundle that does not verify is never stored — sending one opens nothing", () => {
  const store = createPresentationStore();
  const forged = { ...bundle, status_list: bundle.status_list.slice(0, -2) + "AA" };
  const res = prime(store, forged);
  assert.equal(res.statusCode, 403);
  assert.ok(res.body.reason && res.body.reason !== "presentation_unknown", `named refusal, got ${res.body.reason}`);
  assert.equal(checkRequest(verifier, presentationRef(forged), { now, store }).reason, "presentation_unknown");
});

test("a digest names one bundle: a different bundle's digest stays unknown after the real one is sent", () => {
  const store = createPresentationStore();
  prime(store, bundle);
  const other = presentationRef({ ...bundle, status_issued_at: bundle.status_issued_at + 1 });
  assert.equal(checkRequest(verifier, other, { now, store }).reason, "presentation_unknown");
});

test("every use re-verifies: a stored bundle checked at a time it is no longer valid is refused", () => {
  const store = createPresentationStore();
  const { body } = prime(store, bundle);
  const later = () => T + 400 * 24 * 3600;   // past the passport's own validity
  const stale = store.get(body.ref, T);
  assert.ok(stale, "still held");
  const r = checkRequest(verifier, body.ref, { now: later, store: { get: () => stale, put() {} } });
  assert.equal(r.allow, false, "the store holds bytes, never a verdict");
});

test("the store is bounded, forgets the idlest first, and nothing outlives its expiry", () => {
  const s = createPresentationStore({ max: 2 });
  s.put("a", { n: 1 }, T + 10); s.put("b", { n: 2 }, T + 10);
  s.get("a", T);                       // a is now the most recently used
  s.put("c", { n: 3 }, T + 10);
  assert.equal(s.get("b", T), undefined, "the idlest entry is the one evicted");
  assert.ok(s.get("a", T) && s.get("c", T));
  assert.equal(s.get("a", T + 10), undefined, "expired at its expiry, not after");
});

test("the gate answers 428 with where to send the bundle, so a client re-sends instead of giving up", () => {
  const res = fakeRes();
  let nexted = false;
  ainraGate(verifier, { now, store: createPresentationStore() })(
    { headers: { "x-ainra-passport": presentationRef(bundle) } }, res, () => { nexted = true; });
  assert.equal(nexted, false);
  assert.equal(res.statusCode, 428);
  assert.equal(res.headers["x-ainra-reason"], "presentation_unknown");
  assert.equal(res.headers["link"], `<${PRIME_PATH}>; rel="ainra-prime"`);
});

test("without a store, a digest is refused rather than silently treated as a bundle", () => {
  const r = checkRequest(verifier, presentationRef(bundle), { now });
  assert.equal(r.allow, false);
  assert.equal(r.reason, "presentation_unknown");
});

test("the full bundle in the header still works exactly as before", () => {
  const b64 = Buffer.from(JSON.stringify(bundle)).toString("base64url");
  assert.equal(checkRequest(verifier, b64, { now }).allow, true);
});
