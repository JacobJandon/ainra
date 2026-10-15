// SPDX-License-Identifier: Apache-2.0 OR MIT
// D-076: an AINRA running copy as a WIMSE workload (draft-ietf-wimse-workload-creds + draft-ietf-wimse-http-signature).
//
// WITNESS — could these assertions fail? Each negative below starts from the one request the positive test accepts and
// changes exactly one thing, so deleting any single check in `verifyWimseRequest` turns exactly that test red. The
// passport step is held to REAL gate vectors through the GA Verifier: g02 is a revoked passport, and a request that is
// otherwise perfect must still be refused with `revoked` — the check WIMSE itself has no way to make.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import {
  Verifier, mintWit, signWimseRequest, verifyWimseRequest, trustDomainOf, wimseIdentifier, WIT_HEADER,
} from "../dist/index.js";

const { ed25519 } = createRequire(import.meta.url)("@noble/curves/ed25519");
const b64u = (u) => Buffer.from(u).toString("base64url");
const enc = new TextEncoder();
const NAME = "ainra:registrar-01:acme:invoicing@1.0.0";
const NOW = 1_800_000_000;
const AUD = "https://svcb.example/ledger";

function keypair() {
  const sk = ed25519.utils.randomPrivateKey();
  return { pub: ed25519.getPublicKey(sk), sign: (m) => ed25519.sign(m, sk) };
}
const control = keypair(), instance = keypair(), stranger = keypair();
const claims = (over = {}) => ({ sub: NAME, exp: NOW + 86_400, keys: [{ ed25519: b64u(control.pub), mldsa65: "AA" }], ...over });
const bundleOf = (c) => ({ claims: b64u(JSON.stringify(c)) });
const BUNDLE = bundleOf(claims());
const accepts = { verify: () => ({ verdict: "valid" }) };

const wit = (over = {}) => mintWit({
  passportClaimsB64: BUNDLE.claims, iid: "i-0f3a2b71", instanceEd25519Public: instance.pub, now: NOW,
  controlSignEd25519: control.sign, ...over,
});

const BODY = enc.encode('{"invoice":"INV-7","amount":120}');
const baseReq = () => ({
  method: "POST", authority: "svcb.example", path: "/ledger/entries?dry=0",
  headers: { "content-type": "application/json" }, body: BODY,
});
async function signed({ req = baseReq(), w, audience = AUD, nonce = "n-12345678", created = NOW, key = instance } = {}) {
  const h = await signWimseRequest({ req, wit: w ?? await wit(), audience, nonce, created, instanceSignEd25519: key.sign });
  return { ...req, headers: { ...req.headers, ...h } };
}
/** An independent signature base (RFC 9421 §2.5, written out here rather than imported), so a test can sign what
 *  `signWimseRequest` refuses to produce — a keyid, a missing component — with the RIGHT key. Without a valid
 *  signature, a rule's test would pass on the signature failing instead of on the rule. */
function resign(req, components, params, key = instance) {
  const [path, q] = req.path.includes("?") ? [req.path.slice(0, req.path.indexOf("?")), req.path.slice(req.path.indexOf("?"))] : [req.path, "?"];
  const val = (c) => (c === "@method" ? req.method : c === "@path" ? path : c === "@query" ? q : req.headers[c]);
  const inner = `(${components.map((c) => `"${c}"`).join(" ")})${params}`;
  const base = [...components.map((c) => `"${c}": ${val(c)}`), `"@signature-params": ${inner}`].join("\n");
  return { ...req, headers: { ...req.headers, "signature-input": `wimse=${inner}`,
    signature: `wimse=:${Buffer.from(key.sign(enc.encode(base))).toString("base64")}:` } };
}
const PARAMS = `;created=${NOW};expires=${NOW + 120};nonce="n-12345678";tag="wimse-workload-to-workload";wimse-aud="${AUD}"`;
const ALL = ["@method", "@path", "@query", "content-type", "content-digest", "workload-identity-token"];

const verify = (req, over = {}) =>
  verifyWimseRequest({ req, verifier: accepts, bundle: BUNDLE, audience: AUD, now: NOW + 5, ...over });

/** Re-sign a WIT's header and payload with `key`, after `edit` — the attacker's tool. */
function forge(token, edit, key = control) {
  const [h, p] = token.split(".");
  const header = JSON.parse(Buffer.from(h, "base64url")), payload = JSON.parse(Buffer.from(p, "base64url"));
  edit(header, payload);
  const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  return `${input}.${b64u(key.sign(enc.encode(input)))}`;
}

test("a passport's lineage is a WIMSE trust domain, and a running copy is a workload in it", () => {
  assert.equal(trustDomainOf(NAME), "invoicing.acme.registrar-01.ainra.org");
  assert.equal(wimseIdentifier(NAME, "i-0f3a2b71"), "wimse://invoicing.acme.registrar-01.ainra.org/i-0f3a2b71");
  assert.equal(wimseIdentifier(NAME, "a/b"), null, "an instance id is one path segment");
  assert.equal(wimseIdentifier(NAME, ""), null);
  assert.equal(trustDomainOf("did:web:example.com"), null, "only AINRA names map");
});

test("the WIT is a standard one: wit+jwt, EdDSA, sub, exp, cnf.jwk with alg, at most an hour", async () => {
  const [h, p] = (await wit({ lifetimeSecs: 99_999 })).split(".");
  assert.deepEqual(JSON.parse(Buffer.from(h, "base64url")), { alg: "EdDSA", typ: "wit+jwt" });
  const c = JSON.parse(Buffer.from(p, "base64url"));
  assert.equal(c.sub, "wimse://invoicing.acme.registrar-01.ainra.org/i-0f3a2b71");
  assert.equal(c.exp - c.iat, 3600, "capped at the instance ceiling, whatever was asked");
  assert.deepEqual(c.cnf.jwk, { kty: "OKP", crv: "Ed25519", x: b64u(instance.pub), alg: "EdDSA" });
  const short = JSON.parse(Buffer.from((await mintWit({
    passportClaimsB64: bundleOf(claims({ exp: NOW + 60 })).claims, iid: "i-1", instanceEd25519Public: instance.pub,
    now: NOW, controlSignEd25519: control.sign,
  })).split(".")[1], "base64url"));
  assert.equal(short.exp, NOW + 60, "never outlives the passport");
});

test("the request signature is the draft's profile: tagged, covering the listed parts, no keyid or alg", async () => {
  const r = await signed();
  const input = r.headers["signature-input"];
  assert.match(input, /^wimse=\("@method" "@path" "@query" "content-type" "content-digest" "workload-identity-token"\)/);
  assert.match(input, /;created=1800000000;expires=1800000120;nonce="n-12345678";tag="wimse-workload-to-workload";wimse-aud="https:\/\/svcb.example\/ledger"$/);
  assert.doesNotMatch(input, /keyid|alg=/);
});

test("an AINRA-backed WIMSE request is accepted", async () => {
  assert.deepEqual(verify(await signed()), { ok: true, sub: "wimse://invoicing.acme.registrar-01.ainra.org/i-0f3a2b71", nonce: "n-12345678" });
  const get = await signed({ req: { method: "GET", authority: "svcb.example", path: "/ledger", headers: {} } });
  assert.equal(verify(get).ok, true, "no body, no query: @query is '?', and no content-digest is required");
});

test("THE POINT: a revoked passport's workload is refused, though its WIT and signature are perfect", async () => {
  const g = JSON.parse(readFileSync(new URL("../../../vectors/v1-gate/g02-revoked.json", import.meta.url), "utf8"));
  const gate = Verifier.fromDirectoryB64(g.directory, g.roots.root_ed25519, g.roots.root_slh, g.freshness, false, g.audience);
  assert.ok(gate, "the gate vector's directory must verify");
  const r = await signed();
  // A WIMSE verifier that trusts this passport's key accepts this request until the WIT expires.
  assert.equal(verify(r).ok, true, "the control: everything below the passport is valid");
  assert.deepEqual(verify(r, { verifier: gate, bundle: g.bundle, now: g.now }), { ok: false, reason: "revoked" });
  const ok = JSON.parse(readFileSync(new URL("../../../vectors/v1-gate/g01-valid.json", import.meta.url), "utf8"));
  const gate1 = Verifier.fromDirectoryB64(ok.directory, ok.roots.root_ed25519, ok.roots.root_slh, ok.freshness, false, ok.audience);
  assert.deepEqual(verify(r, { verifier: gate1, bundle: ok.bundle, now: ok.now }), { ok: false, reason: "instance_sig_invalid" },
    "the unrevoked passport passes, and THEN its key is the only one that can sign a WIT — this one was not");
});

test("one thing changed, one refusal", async () => {
  const good = await signed();
  const w = await wit();
  const cases = [
    ["moved to another path", { ...good, path: "/ledger/void?dry=0" }, "presentation_sig_invalid"],
    ["query changed", { ...good, path: "/ledger/entries?dry=1" }, "presentation_sig_invalid"],
    ["method changed", { ...good, method: "PUT" }, "presentation_sig_invalid"],
    ["body changed", { ...good, body: enc.encode('{"invoice":"INV-7","amount":9120}') }, "presentation_sig_invalid"],
    ["content-type changed", { ...good, headers: { ...good.headers, "content-type": "text/plain" } }, "presentation_sig_invalid"],
    ["no WIT", { ...good, headers: { ...good.headers, [WIT_HEADER]: undefined } }, "presentation_unsigned"],
    ["no signature", { ...good, headers: { ...good.headers, signature: undefined, "signature-input": undefined } }, "presentation_unsigned"],
    ["another audience", await signed({ audience: "https://svcc.example/" }), "presentation_sig_invalid"],
    ["signed by a key the WIT does not bind", await signed({ key: stranger }), "presentation_sig_invalid"],
    ["WIT signed by a stranger", await signed({ w: forge(w, () => {}, stranger) }), "instance_sig_invalid"],
    ["WIT names another trust domain", await signed({ w: forge(w, (_, c) => { c.sub = "wimse://payroll.acme.registrar-01.ainra.org/i-1"; }) }), "instance_sig_invalid"],
    ["WIT typ is a plain JWT", await signed({ w: forge(w, (h) => { h.typ = "JWT"; }) }), "instance_sig_invalid"],
    ["WIT lives a day", await signed({ w: forge(w, (_, c) => { c.exp = c.iat + 86_400; }) }), "instance_sig_invalid"],
    ["WIT binds an RSA-shaped key", await signed({ w: forge(w, (_, c) => { c.cnf.jwk.kty = "RSA"; }) }), "instance_sig_invalid"],
    ["WIT expired", await signed({ w: forge(w, (_, c) => { c.iat = NOW - 600; c.exp = NOW; }) }), "instance_expired"],
    ["signature from the future", await signed({ created: NOW + 600 }), "presentation_stale"],
  ];
  for (const [what, req, reason] of cases) assert.deepEqual(verify(req), { ok: false, reason }, what);
  assert.deepEqual(verify(good, { now: NOW + 121 }), { ok: false, reason: "presentation_stale" }, "past `expires`");
  assert.deepEqual(verify(good, { seenNonce: () => true }), { ok: false, reason: "presentation_replayed" }, "replayed");
});

test("the profile's own rules: keyid/alg prohibited, one tagged signature, found by its tag", async () => {
  const good = await signed();
  assert.equal(verify(resign(good, ALL, PARAMS)).ok, true, "the control: the independent base agrees with ours");
  assert.deepEqual(verify(resign(good, ALL, PARAMS + ';keyid="k"')), { ok: false, reason: "presentation_sig_invalid" }, "keyid");
  assert.deepEqual(verify(resign(good, ALL, PARAMS + ';alg="ed25519"')), { ok: false, reason: "presentation_sig_invalid" }, "alg");
  for (const left of ["@query", "content-type", "content-digest", "workload-identity-token"])
    assert.deepEqual(verify(resign(good, ALL.filter((c) => c !== left), PARAMS)), { ok: false, reason: "presentation_sig_invalid" },
      `a signature that leaves out ${left} binds less than the profile requires`);
  assert.deepEqual(verify(resign(good, ALL, PARAMS.replace(NOW + 120 + "", NOW + 3600 + ""))), { ok: false, reason: "presentation_sig_invalid" },
    "an hour-long request signature is not minutes");
  const second = good.headers["signature-input"].replace(/^wimse=/, "again=");
  const twice = { ...good, headers: { ...good.headers,
    "signature-input": `${good.headers["signature-input"]}, ${second}`,
    signature: `${good.headers.signature}, ${good.headers.signature.replace(/^wimse=/, "again=")}` } };
  assert.deepEqual(verify(twice), { ok: false, reason: "presentation_sig_invalid" }, "the draft: reject if more than one is tagged");
  // D-070 beside another signer: their member stays, ours is found by its tag.
  const other = { ...baseReq(), headers: { ...baseReq().headers, "signature-input": 'sig1=("@authority");created=1;keyid="x";tag="web-bot-auth"', signature: "sig1=:AAAA:" } };
  const both = await signed({ req: other });
  assert.match(both.headers["signature-input"], /^sig1=.*, wimse=/);
  assert.equal(verify(both).ok, true);
  await assert.rejects(signed({ req: { ...baseReq(), headers: { "signature-input": "wimse=()", signature: "wimse=:AA:" } } }), /already carries/);
});
