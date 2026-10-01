// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// PLAN-M34 Task 5 — the edge gate, hermetically, with web-standard Request objects.
//
// What these prove: the engine IS the core (every request-signature vector, answered by the WASM build); the gate
// trusts only a directory that verifies against both roots; every credential verdict equals what @ainra/sdk — an
// independently written verifier — gives the same bundle at the same time; the PRESENTER cannot choose its own
// freshness class (D-068); send-once stores only what verified and names it by the digest the TS SDK computes; a
// gate that lacks the bundle says 428; the stores are bounded. The SIGNED positive path needs an instance key no
// fixture publishes — `make edge-e2e` proves it against the live registrar.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { initAinra, createAinraEdgeGate, createStore, createNonceCache, runPresentationVector, PRIME_PATH } from "../src/index.mjs";
import { Verifier, checkRequest } from "../../middleware/dist/index.js";
import { presentationRef } from "../../sdk-ts/dist/index.js";

const ROOT = new URL("../../../", import.meta.url);
await initAinra(readFileSync(new URL("../wasm/ainra_wasm_bg.wasm", import.meta.url)));

const F = new URL("packages/middleware/test/fixtures/", ROOT);
const load = (f) => JSON.parse(readFileSync(new URL(f, F), "utf8"));
const directory = load("directory.json"), roots = load("roots.json");
const valid = load("bundle-valid.json"), revoked = load("bundle-revoked.json");
const T = load("meta.json").now;
const AUD = "https://api.example";
const tsVerifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh);
const make = (o = {}) => createAinraEdgeGate({ directory, roots, audience: AUD, now: () => T, ...o });
const b64u = (s) => Buffer.from(s).toString("base64url");
const req = (path, init = {}) => new Request(`https://api.example${path}`, init);
const present = (b) => req("/orders", { headers: { "x-ainra-passport": b64u(JSON.stringify(b)) } });

test("THE ENGINE IS THE CORE: all request-signature vectors answered by the WASM build as the core recorded them", () => {
  const dir = new URL("vectors/v1-presentation/", ROOT);
  const files = readdirSync(dir).filter((f) => f !== "manifest.json");
  assert.ok(files.length >= 33);
  const st = (o) => JSON.stringify(o, Object.keys(o).sort());
  for (const f of files) {
    const v = JSON.parse(readFileSync(new URL(f, dir), "utf8"));
    assert.equal(st(runPresentationVector(v)), st(v.expect), v.name);
  }
});

test("the gate refuses to exist on a directory that does not verify against the roots", async () => {
  const forged = { ...directory, epoch: directory.epoch + 1 };
  await assert.rejects(make({ directory: forged }), /does not verify/);
  const wrongRoots = { ...roots, root_ed25519: b64u("x".repeat(32)) };
  await assert.rejects(make({ roots: wrongRoots }), /does not verify/);
});

test("every credential verdict equals the independently written TS verifier's, on the same bundle and clock", async () => {
  for (const [name, b, at] of [["valid", valid, T], ["revoked", revoked, T], ["valid, an hour later", valid, T + 3600]]) {
    const g = await make({ now: () => at });
    const edge = await g(present(b));
    const ts = checkRequest(tsVerifier, b, { now: () => at });
    assert.equal(edge.event.status, ts.verdict.verdict, `${name}: status`);
    assert.equal(edge.event.reason ?? null, ts.verdict.verdict === "valid" ? null : ts.verdict.reason, `${name}: reason`);
  }
});

test("D-068: the presenter cannot choose its own freshness — an F3 bundle an hour later is stale under the gate's F2", async () => {
  assert.equal(valid.freshness, "F3", "the fixture declares the loosest class, which is the point");
  const g = await make({ now: () => T + 3600 });
  const r = await g(present(valid));
  assert.equal(r.allow, false);
  assert.equal(r.reason, "stale_status", "the wire said F3 (24 h); the gate's policy is F2 (5 min), and the gate decides");
  const lax = await make({ now: () => T + 3600, freshness: "F3" });
  assert.equal((await lax(present(valid))).event.status, "valid", "an operator who chooses F3 gets F3 — by choice, not by the presenter's");
});

test("a valid credential on an UNSIGNED request is refused by name — its own verdict still reads valid", async () => {
  const g = await make();
  const r = await g(present(valid));
  assert.equal(r.reason, "presentation_unsigned");
  assert.equal(r.event.status, "valid", "the credential is fine; the refusal is about the request");
  assert.equal(r.response.status, 403);
  assert.equal(r.response.headers.get("x-ainra-reason"), "presentation_unsigned");
});

test("send once: the gate stores a bundle that verifies and names it by the TS SDK's digest", async () => {
  const g = await make({ store: createStore() });
  const p = await g(req(PRIME_PATH, { method: "POST", body: JSON.stringify(valid) }));
  assert.equal(p.response.status, 201);
  const { ref } = await p.response.json();
  assert.equal(ref, presentationRef(valid), "WASM (core canon) and TS name a bundle by the same digest");
  const r = await g(req("/orders", { headers: { "x-ainra-passport": ref } }));
  assert.equal(r.reason, "presentation_unsigned", "the named bundle verifies; only the missing signature stops it");
  assert.equal(r.event.status, "valid");
});

test("a revoked or forged bundle is never stored — naming it afterwards is 428, not access", async () => {
  const g = await make({ store: createStore() });
  for (const bad of [revoked, { ...valid, status_list: valid.status_list.slice(0, -2) + "AA" }]) {
    const p = await g(req(PRIME_PATH, { method: "POST", body: JSON.stringify(bad) }));
    assert.equal(p.response.status, 403);
    const r = await g(req("/orders", { headers: { "x-ainra-passport": presentationRef(bad) } }));
    assert.equal(r.response.status, 428);
    assert.equal(r.response.headers.get("link"), `<${PRIME_PATH}>; rel="ainra-prime"`);
  }
});

test("D-072: the gate believes only status the registrar signed — every edit a presenter can make reads stale_status", async () => {
  // Before D-072 the Rust path did not look at the status signature at all. The only "forged" bundle this file
  // tried was one whose edit happened to break the list's compression, so it was refused for the wrong reason and
  // the test never asked which. Each edit here leaves a bundle that still DECODES; only the signature can refuse it.
  const g = await make();
  const without = (b, ...keys) => Object.fromEntries(Object.entries(b).filter(([k]) => !keys.includes(k)));
  const edits = {
    "the issue time moved": { ...valid, status_issued_at: valid.status_issued_at + 1 },
    "a byte appended to the list": { ...valid, status_list: valid.status_list + "A" },
    "the signature removed": without(valid, "status_sig_ed25519", "status_sig_mldsa65"),
    "one half of the signature removed": without(valid, "status_sig_mldsa65"),
    "published under another URI": { ...valid, status_uri: "status://someone-else/1" },
    "REVOKED, with an all-clear list of its own, issued now": { ...revoked, status_list: "eJztwAEBAAAAQCD_VxtCsDIBAgAAAQ", status_issued_at: T },
    "REVOKED, re-dating the list it was revoked in": { ...revoked, status_issued_at: T },
  };
  for (const [what, b] of Object.entries(edits)) {
    const edge = await g(present(b));
    const ts = checkRequest(tsVerifier, b, { now: () => T });
    assert.equal(edge.allow, false, what);
    assert.equal(edge.event.reason, "stale_status", `${what}: the edge gate`);
    assert.equal(ts.verdict.reason, "stale_status", `${what}: @ainra/sdk, on the same bundle`);
  }
  // and none of them can be sent once and named afterwards
  const s = await make({ store: createStore() });
  for (const b of Object.values(edits)) {
    const p = await s(req(PRIME_PATH, { method: "POST", body: JSON.stringify(b) }));
    assert.equal(p.response.status, 403);
    assert.equal(p.response.headers.get("x-ainra-reason"), "stale_status");
  }
});

test("no presentation is refused; a gate without an audience or with an unknown class refuses to exist", async () => {
  assert.equal((await (await make())(req("/orders"))).response.status, 403);
  await assert.rejects(createAinraEdgeGate({ directory, roots }), /audience/);
  await assert.rejects(make({ freshness: "F9" }), /freshness/);
});

test("the stores are bounded and forget", () => {
  const s = createStore({ max: 2 });
  s.put("a", { n: 1 }, T + 10); s.put("b", { n: 2 }, T + 10); s.get("a", T); s.put("c", { n: 3 }, T + 10);
  assert.equal(s.get("b", T), undefined, "the idlest goes first");
  assert.equal(s.get("a", T + 10), undefined, "nothing outlives its expiry");
  const n = createNonceCache({ max: 2 });
  assert.equal(n.seen("x", T), false);
  assert.equal(n.seen("x", T), true, "a nonce is single use");
  assert.equal(n.seen("x", T + 400), false, "past the acceptance window it cannot verify anyway, so it is forgotten");
});
