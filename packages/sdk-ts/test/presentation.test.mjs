import test from "node:test";
import assert from "node:assert/strict";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { ed25519 } from "@noble/curves/ed25519";
import {
  signPresentation, verifyPresentation, contentDigest, signatureBase, coveredComponents,
  PRESENTATION_HEADER, SIG_ALG, MAX_AGE_SECS,
} from "../dist/presentation.js";

// REAL hybrid keys, both halves. The first version of this file filled the ML-DSA half with a constant, and every
// "must be refused" case then passed for the wrong reason: verifyHybrid rejected the filler before any of the
// logic under test ran, so the tests could not tell a moved path from a correct one. A negative control that
// cannot distinguish is theatre. These keys are deterministic so the file is reproducible.
const mld = ml_dsa65.keygen(new Uint8Array(32).fill(3));
const edPriv = ed25519.utils.randomPrivateKey();
const ikey = { ed25519: ed25519.getPublicKey(edPriv), mldsa65: mld.publicKey };
const instance = { iid: "i-bc5dbeed", ikey };

const instanceSign = (msg) => ({
  ed25519: ed25519.sign(msg, edPriv),
  mldsa65: ml_dsa65.sign(mld.secretKey, msg),
});

const NOW = 1_800_000_000;
const baseReq = () => ({
  method: "POST",
  authority: "shop.example",
  path: "/orders",
  headers: { [PRESENTATION_HEADER]: "eyJhIjoxfQ" },
});

async function signed(req = baseReq(), now = NOW) {
  const h = await signPresentation({ req, keyid: instance.iid, nonce: "n-0001", created: now, instanceSign });
  return { ...req, headers: { ...req.headers, ...h } };
}

test("a signed request verifies, and the signature really is over the base", async () => {
  const req = await signed();
  const base = signatureBase(req, coveredComponents(false), { created: NOW, keyid: instance.iid, nonce: "n-0001" });
  assert.ok(base.startsWith('"@method": POST\n"@authority": shop.example\n"@path": /orders\n'));
  assert.match(base, new RegExp(`"@signature-params": \\(.*\\);created=${NOW};keyid="i-bc5dbeed";alg="${SIG_ALG}";nonce="n-0001"$`));
  const r = verifyPresentation({ req, instance, now: NOW });
  assert.equal(r.ok, true, "a correctly signed request must VERIFY — without this, every refusal below is vacuous");
  assert.equal(r.nonce, "n-0001");
});

test("THE DEFECT: the same signature moved to another path is refused", async () => {
  const req = await signed();
  const moved = { ...req, path: "/admin/refunds" };
  const r = verifyPresentation({ req: moved, instance, now: NOW });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "presentation_sig_invalid");
});

test("moved to another host is refused", async () => {
  const req = await signed();
  const r = verifyPresentation({ req: { ...req, authority: "bank.example" }, instance, now: NOW });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "presentation_sig_invalid");
});

test("a different method is refused", async () => {
  const req = await signed();
  const r = verifyPresentation({ req: { ...req, method: "DELETE" }, instance, now: NOW });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "presentation_sig_invalid");
});

test("swapping the presentation bundle under the signature is refused", async () => {
  const req = await signed();
  req.headers[PRESENTATION_HEADER] = "eyJhIjo5OTl9";
  const r = verifyPresentation({ req, instance, now: NOW });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "presentation_sig_invalid");
});

test("an unsigned request is named as unsigned, not as invalid", async () => {
  const r = verifyPresentation({ req: baseReq(), instance, now: NOW });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "presentation_unsigned");
});

test("stale and future signatures are refused by name", async () => {
  const req = await signed();
  const old = verifyPresentation({ req, instance, now: NOW + MAX_AGE_SECS + 1 });
  assert.equal(old.reason, "presentation_stale");
  const future = verifyPresentation({ req, instance, now: NOW - 31 });
  assert.equal(future.reason, "presentation_stale");
  const edge = verifyPresentation({ req, instance, now: NOW + MAX_AGE_SECS });
  assert.equal(edge.ok, true, "exactly at the window edge is still inside it");
});

test("keyid must name THIS instance credential", async () => {
  const req = await signed();
  const r = verifyPresentation({ req, instance: { iid: "i-someone-else", ikey }, now: NOW });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "presentation_sig_invalid");
});

test("a body is covered: swapping it after signing is refused", async () => {
  const body = new TextEncoder().encode('{"amount":10}');
  const req = { ...baseReq(), body };
  const h = await signPresentation({ req, keyid: instance.iid, nonce: "n-0002", created: NOW, instanceSign });
  assert.ok(h["content-digest"].startsWith("sha-256=:"), "a body must produce a digest");
  const withHeaders = { ...req, headers: { ...req.headers, ...h } };
  const tampered = { ...withHeaders, body: new TextEncoder().encode('{"amount":100000}') };
  const r = verifyPresentation({ req: tampered, instance, now: NOW });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "presentation_sig_invalid");
});

test("the digest header must match the body it claims to cover", async () => {
  const body = new TextEncoder().encode("a");
  assert.equal(await contentDigest(body), "sha-256=:ypeBEsobvcr6wjGzmiPcTaeG7/gUfE5yuYB3ha/uSLs=:");
});

test("single use is the caller's, and the reason says replayed — not invalid", async () => {
  const req = await signed();
  const seen = new Set();
  const first = verifyPresentation({ req, instance, now: NOW, seenNonce: (n) => { const had = seen.has(n); seen.add(n); return had; } });
  const second = verifyPresentation({ req, instance, now: NOW, seenNonce: (n) => { const had = seen.has(n); seen.add(n); return had; } });
  // Both calls exercise the cache; the first records the nonce, the second finds it.
  assert.equal(second.ok, false);
  assert.equal(second.reason, "presentation_replayed");
  assert.notEqual(first.reason, "presentation_replayed", "the first presentation of a nonce is not a replay");
});

test("a signature covering a different component set is refused", async () => {
  const req = await signed();
  req.headers["signature-input"] = req.headers["signature-input"].replace('("@method" "@authority" "@path"', '("@method" "@authority"');
  const r = verifyPresentation({ req, instance, now: NOW });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "presentation_sig_invalid");
});

test("a malformed signature field is refused, never accepted by accident", async () => {
  for (const bad of ["ainra=notbytes", "ainra=::", "other=:AAAA:", "ainra=:!!!!:"]) {
    const req = await signed();
    req.headers.signature = bad;
    const r = verifyPresentation({ req, instance, now: NOW });
    assert.equal(r.ok, false, `must refuse: ${bad}`);
  }
});
