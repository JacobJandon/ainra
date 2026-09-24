// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// M34 / D-062 — the gate's side of the request binding.
//
// The signature logic itself is proven in `@ainra/sdk`'s presentation tests, with real hybrid keys and a positive
// case that makes the refusals mean something. What is proven HERE is the gate's policy: that turning the
// requirement on changes the answer, that leaving it off changes nothing for existing integrators, and that each
// way of failing is named rather than collapsed into one.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Verifier, checkRequest } from "../dist/index.js";

const F = new URL("./fixtures/", import.meta.url);
const load = (f) => JSON.parse(readFileSync(new URL(f, F), "utf8"));
const roots = load("roots.json");
const verifier = Verifier.fromDirectoryB64(load("directory.json"), roots.root_ed25519, roots.root_slh);
const bundle = load("bundle-valid.json");
const now = () => load("meta.json").now;

const req = (over = {}) => ({
  method: "POST",
  authority: "shop.example",
  path: "/orders",
  headers: { "x-ainra-passport": "…" },
  ...over,
});

test("off by default: an existing integrator's behaviour does not change", () => {
  const r = checkRequest(verifier, bundle, { now });
  assert.equal(r.allow, true, "a valid credential with no signature still passes when nothing was required");
});

test("THE POINT: the same valid credential is refused once the request must be signed", () => {
  const r = checkRequest(verifier, bundle, { now, requireSignature: true, binding: req() });
  assert.equal(r.allow, false, "a credential that says nothing about this request must not open it");
  assert.equal(r.reason, "presentation_unsigned");
});

test("the credential's own verdict is still reported as valid — the refusal is about the request", () => {
  const r = checkRequest(verifier, bundle, { now, requireSignature: true, binding: req() });
  assert.equal(r.verdict.verdict, "valid", "the passport is fine; what failed is the binding, and the two must not be confused");
  assert.notEqual(r.reason, "sig_invalid", "sig_invalid would send an integrator to the registrar, which is not where the fault is");
});

test("requiring a signature with nothing to check it over is refused, not waved through", () => {
  const r = checkRequest(verifier, bundle, { now, requireSignature: true });
  assert.equal(r.allow, false);
  assert.equal(r.reason, "schema_violation");
});

test("a signed-request header alone proves nothing without an instance credential", () => {
  const r = checkRequest(verifier, bundle, {
    now,
    requireSignature: true,
    binding: req({ headers: { "x-ainra-passport": "…", "signature-input": 'ainra=("@method");created=1;keyid="x";alg="ainra-hybrid-v1";nonce="n"', signature: "ainra=:AAAA:" } }),
  });
  assert.equal(r.allow, false);
  assert.ok(["presentation_unsigned", "presentation_sig_invalid"].includes(r.reason), `named refusal, got ${r.reason}`);
});

test("the verdict event still has the one shape, whichever way the request failed", () => {
  const r = checkRequest(verifier, bundle, { now, requireSignature: true, binding: req() });
  for (const k of ["status", "reason", "name", "number", "tier"]) assert.ok(k in r.event, `event must keep ${k}`);
});
