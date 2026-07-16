// SPDX-License-Identifier: Apache-2.0 OR MIT
// The middleware is a security boundary — an allow/deny gate. These tests prove it FAILS CLOSED: any input that is
// not a presentation bundle verifying VALID against the trusted directory is denied, and NOTHING ever throws.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Verifier } from "@ainra/sdk";
import { checkRequest, ainraGate } from "../dist/index.js";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const dv = JSON.parse(readFileSync(root + "vectors/v1-directory/directory-valid-2.json", "utf8"));
const verifier = Verifier.fromDirectoryB64(dv.directory, dv.root_ed25519, dv.root_slh);

test("a valid directory builds a Verifier; a tampered one does not (fail closed)", () => {
  assert.ok(verifier, "directory-valid-2 must trust-anchor");
  const bad = JSON.parse(readFileSync(root + "vectors/v1-directory/directory-tampered-entry.json", "utf8"));
  assert.equal(Verifier.fromDirectoryB64(bad.directory, bad.root_ed25519, bad.root_slh), null);
  assert.equal(Verifier.fromDirectoryB64(dv.directory, "!!not-base64!!", dv.root_slh), null);
});

test("every malformed bundle is DENIED and nothing throws", () => {
  const denials = [
    undefined,
    null,
    42,
    "",
    "not json at all",
    "{",
    "{}", // valid JSON, missing every field
    JSON.stringify({ claims: "AAAA" }), // partial
    { claims: "AAAA" }, // partial object
    { claims: 123 }, // wrong type
    "eyJ4IjoxfQ", // base64url of {"x":1} — decodes but is not a bundle
    Buffer.alloc(1_000_000).toString("base64url"), // large garbage
  ];
  for (const b of denials) {
    let r;
    assert.doesNotThrow(() => {
      r = checkRequest(verifier, b, { now: () => 1_776_729_600 });
    }, `checkRequest must not throw on ${typeof b}`);
    assert.equal(r.allow, false, `must deny: ${JSON.stringify(b)?.slice(0, 40)}`);
    assert.equal(r.verdict.verdict, "invalid");
    assert.ok(r.reason, "a deny must carry a machine-readable reason");
  }
});

test("ainraGate denies (403 + reason header) when the header is absent — fail closed by default", () => {
  const gate = ainraGate(verifier, { now: () => 1_776_729_600 });
  let status = 0,
    headers = {},
    nexted = false;
  const req = { headers: {} };
  const res = {
    status(c) {
      status = c;
      return this;
    },
    json(b) {
      this.body = b;
      return b;
    },
    setHeader(k, v) {
      headers[k] = v;
    },
  };
  gate(req, res, () => {
    nexted = true;
  });
  assert.equal(nexted, false, "must NOT call next() without a valid passport");
  assert.equal(status, 403);
  assert.equal(headers["x-ainra-reason"], "schema_violation");
  assert.equal(req.ainra.allow, false);
});

test("ainraGate denies a garbage passport header, never calls next()", () => {
  const gate = ainraGate(verifier, { now: () => 1_776_729_600 });
  let nexted = false,
    status = 0;
  const req = { headers: { "x-ainra-passport": "totally-bogus" } };
  const res = { status(c) { status = c; return this; }, json(b) { return b; }, setHeader() {} };
  gate(req, res, () => { nexted = true; });
  assert.equal(nexted, false);
  assert.equal(status, 403);
});
