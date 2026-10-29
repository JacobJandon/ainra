// SPDX-License-Identifier: Apache-2.0 OR MIT
// D-078 — the Node gate in link mode: the request's key is verified by the caller's own signature check; the gate
// says who stands behind it. Real link vectors (vectors/v1-link), served as a registrar would serve them.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { Verifier, createDecisionLog, verifyDecisionChain } from "@ainra/sdk";
import { ainraLinkGate } from "../dist/index.js";

const vec = (n) => JSON.parse(readFileSync(new URL(`../../../vectors/v1-link/${n}.json`, import.meta.url), "utf8"));
const b64 = (s) => Buffer.from(s, "base64url");
// What GET /links and GET /status-list would have served for this vector's link.
const served = (v) => {
  const l = v.link;
  const claims = JSON.parse(b64(l.claims).toString("utf8"));
  return {
    index: { registrar: claims.registrar, checkpoint: l.checkpoint, checkpoint_sig: l.checkpoint_sig,
             links: [{ thumbprint: claims.subject.thumbprint, claims: l.claims, registrar_sig: l.registrar_sig, leaf_index: l.leaf_index, inclusion_proof: l.inclusion_proof }] },
    status: { uri: l.status_uri, status_list_b64: l.status_list, bit_len: l.status_len, issued_at: l.status_issued_at, sig_ed25519: l.status_sig_ed25519, sig_mldsa65: l.status_sig_mldsa65 },
  };
};
function call(gate, key, path = "/orders") {
  return new Promise((resolve) => {
    const req = { method: "GET", url: path, headers: { host: "shop.example" }, key };
    let status = 200;
    const res = { status(c) { status = c; return res; }, json(b) { resolve({ status, body: b, req }); }, setHeader() {} };
    gate(req, res, () => resolve({ status: 200, req }));
  });
}
function gateFor(v, extra = {}) {
  const verifier = Verifier.fromDirectoryB64(v.directory, v.roots.root_ed25519, v.roots.root_slh, v.freshness);
  return ainraLinkGate(verifier, { verifiedKey: (req) => req.key, source: () => served(v), now: () => v.now, ...extra });
}

test("a linked key passes and names the operator; a revoked or out-of-scope link is refused by name", async () => {
  const ok = vec("l01-valid");
  const r = await call(gateFor(ok), b64(ok.presented_key));
  assert.equal(r.status, 200);
  assert.equal(r.req.ainraLink.operator, "acme");
  const rev = vec("l05-link-revoked");
  assert.equal((await call(gateFor(rev), b64(rev.presented_key))).body.reason, "revoked");
  const narrow = vec("l13-outside-scope");
  assert.equal((await call(gateFor(narrow, { capability: () => narrow.capability }), b64(narrow.presented_key))).body.reason, "ceiling_exceeded");
});

test("a key the registrar never linked is not_linked; a request whose signature did not verify is refused", async () => {
  const ok = vec("l01-valid");
  assert.equal((await call(gateFor(ok), Buffer.alloc(32, 3))).body.reason, "not_linked");
  assert.equal((await call(gateFor(ok), null)).body.reason, "sig_invalid");
});

test("D-079: link decisions are recorded, signed and chained", async () => {
  const sdkRequire = createRequire(new URL("../../sdk-ts/package.json", import.meta.url));
  const { ed25519 } = await import(pathToFileURL(sdkRequire.resolve("@noble/curves/ed25519")).href);
  const secret = ed25519.utils.randomPrivateKey(), pub = ed25519.getPublicKey(secret);
  const lines = [];
  const decisions = createDecisionLog({ gatePublic: pub, sign: (m) => ed25519.sign(m, secret), append: (l) => lines.push(l), freshness: "F2" });
  const ok = vec("l01-valid");
  await call(gateFor(ok, { decisions }), b64(ok.presented_key));
  await call(gateFor(ok, { decisions }), Buffer.alloc(32, 3));
  assert.deepEqual(verifyDecisionChain(lines, pub), { ok: true, count: 2 });
  const [a, b] = lines.map((l) => JSON.parse(l));
  assert.equal(a.kind, "link");
  assert.equal(a.operator, "acme");
  assert.equal(b.reason, "not_linked");
  assert.equal(b.operator, undefined);
});
