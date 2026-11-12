// SPDX-License-Identifier: Apache-2.0 OR MIT
// A presenter writes the passport name the gate echoes in `x-ainra-verdict`, also on a refusal. A name with a character
// no header can hold (outside printable ASCII) made Node's setHeader throw: a refusal became a 500 in a framework that
// catches, and a server whose async handler did not catch stopped (2026-11-12). These run the gate and the prime
// handler against a real http.ServerResponse, so the header is validated exactly as in production.
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { readFileSync } from "node:fs";
import { Verifier } from "@ainra/sdk";
import { ainraGate, ainraPrime, createPresentationStore, serializeVerdictEvent, verdictHeaderValue, verdictEvent } from "../dist/index.js";

const fx = (f) => JSON.parse(readFileSync(new URL("fixtures/" + f, import.meta.url), "utf8"));
const roots = fx("roots.json");
const verifier = Verifier.fromDirectoryB64(fx("directory.json"), roots.root_ed25519, roots.root_slh);
const bundle = fx("bundle-valid.json");
const NOW = fx("meta.json").now;

const withSub = (sub) => {
  const c = JSON.parse(Buffer.from(bundle.claims, "base64url").toString("utf8"));
  c.sub = sub;
  return { ...bundle, claims: Buffer.from(JSON.stringify(c)).toString("base64url") };
};
const response = () => {
  const res = new http.ServerResponse(new http.IncomingMessage(null));
  res.status = (c) => { res.statusCode = c; return res; };
  res.json = (b) => { res.body = b; return res; };
  return res;
};
const NAMES = ["ainra:registrar-07:acme:invoicing€@1.0.0", "ainra:registrar-07:acme:invoicing\u007f@1.0.0", "ainra:registrar-07:acme:\u{1F600}@1.0.0"];

test("the gate refuses a name no header can hold, by name, without throwing", () => {
  for (const sub of NAMES) {
    const gate = ainraGate(verifier, { now: () => NOW });
    const res = response();
    let passed = false;
    assert.doesNotThrow(() => gate({ headers: { "x-ainra-passport": Buffer.from(JSON.stringify(withSub(sub))).toString("base64url") } }, res, () => { passed = true; }), JSON.stringify(sub));
    assert.equal(passed, false, "an edited name must not be let in");
    assert.equal(res.statusCode, 403);
    const h = res.getHeader("x-ainra-verdict");
    assert.match(h, /^[\x20-\x7e]*$/, "the header is printable ASCII");
    assert.equal(JSON.parse(h).status, "invalid");
  }
});

test("the prime handler refuses the same names without throwing", () => {
  for (const sub of NAMES) {
    const prime = ainraPrime(verifier, { store: createPresentationStore(), now: () => NOW });
    const res = response();
    assert.doesNotThrow(() => prime({ method: "POST", headers: {}, body: withSub(sub) }, res), JSON.stringify(sub));
    assert.equal(res.statusCode, 403);
    assert.match(res.getHeader("x-ainra-verdict"), /^[\x20-\x7e]*$/);
  }
});

test("the header value parses to exactly the event, and is unchanged for an ASCII name", () => {
  for (const sub of [...NAMES, "ainra:registrar-07:acme:invoicing@1.0.0"]) {
    const e = verdictEvent(withSub(sub), { verdict: "invalid", reason: "sig_invalid" }, NOW);
    assert.deepEqual(JSON.parse(verdictHeaderValue(e)), JSON.parse(serializeVerdictEvent(e)));
    if (/^[\x20-\x7e]*$/.test(sub)) assert.equal(verdictHeaderValue(e), serializeVerdictEvent(e));
  }
});
