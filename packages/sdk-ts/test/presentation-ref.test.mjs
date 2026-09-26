// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// M36 / D-065. A bundle is sent once and named by digest after that. The digest is what the request signature
// covers, so it has to name exactly one bundle: any change to what the verifier checks must change it, and the
// only thing allowed NOT to change it is the per-request proof of possession, which is sent with every request.

import test from "node:test";
import assert from "node:assert/strict";
import {
  presentationRef, splitPresentation, joinPresentation, isPresentationRef, PRIME_PATH, POP_HEADER,
} from "../dist/presentation.js";

const pop = (n) => ({ aud: "shop.example", nonce: `p-${n}`, ts: 1790000000 + n, sig: { ed25519: "AA", mldsa65: "BB" } });
const bundle = (over = {}) => ({
  claims: "eyJzdWIiOiJhaW5yYTpyZWdpc3RyYXItMDc6YWNtZTpib3RAMS4wLjAifQ",
  issuer_sig: { ed25519: "e1", mldsa65: "m1" },
  status_list: "H4sI",
  status_issued_at: 1790000000,
  checkpoint: { origin: "o", size: 7, root: "r" },
  instance: { sub: "s", iid: "i-1", ikey: { ed25519: "k", mldsa65: "K" }, nbf: 1, exp: 901, aud: "shop.example", pop: pop(1) },
  ...over,
});

test("the digest has the RFC 9530 shape, and the recogniser accepts only that shape", () => {
  const ref = presentationRef(bundle());
  assert.ok(isPresentationRef(ref), ref);
  assert.ok(!isPresentationRef("sha-256=:short=:"), "a truncated digest is not a reference");
  assert.ok(!isPresentationRef(Buffer.from(JSON.stringify(bundle())).toString("base64url")), "a bundle is not a reference");
});

test("THE POINT: a fresh proof of possession does not change the digest — it is sent on every request", () => {
  assert.equal(presentationRef(bundle()), presentationRef(bundle({ instance: { ...bundle().instance, pop: pop(2) } })));
});

test("key order and whitespace do not change it: the digest is over canonical JSON", () => {
  const b = bundle();
  const reordered = Object.fromEntries(Object.entries(b).reverse());
  assert.equal(presentationRef(b), presentationRef(reordered));
});

test("anything the verifier checks DOES change it", () => {
  const base = presentationRef(bundle());
  const moved = [
    bundle({ status_list: "H4sJ" }),
    bundle({ status_issued_at: 1790000001 }),
    bundle({ claims: bundle().claims + "A" }),
    bundle({ instance: { ...bundle().instance, exp: 902 } }),
    bundle({ instance: { ...bundle().instance, aud: "evil.example" } }),
    bundle({ checkpoint: { origin: "o", size: 8, root: "r" } }),
  ];
  for (const m of moved) assert.notEqual(presentationRef(m), base);
});

test("split then join gives back the bundle the verifier would have seen", () => {
  const b = bundle();
  const { stable, pop: p } = splitPresentation(b);
  assert.ok(!("pop" in stable.instance), "the stable part carries no proof of possession");
  assert.deepEqual(joinPresentation(stable, p), b);
  assert.ok("pop" in b.instance, "the input is not modified");
});

test("a passport presented directly (no running copy) splits with no proof of possession", () => {
  const { instance, ...passportOnly } = bundle();
  const { stable, pop: p } = splitPresentation(passportOnly);
  assert.equal(p, null);
  assert.deepEqual(stable, passportOnly);
  assert.deepEqual(joinPresentation(stable, null), passportOnly);
});

test("the conventions are stated once", () => {
  assert.equal(PRIME_PATH, "/.well-known/ainra-presentation");
  assert.equal(POP_HEADER, "x-ainra-pop");
});
