// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// D-066 — the personhood kit, offline. The registry itself is exercised against the real chain by `live-drill.mjs`;
// here the RPC is a stub so every refusal can be forced and named, and the Ethereum primitives are checked against
// vectors produced by OTHER implementations, so this is not a kit agreeing with itself.

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  selector, checksumAddress, personalMessageHash, recoverSigner, signPersonal, addressFromPrivateKey,
  lookupHuman, bindingMessage, provePersonhood, holderThumbprint, SOURCES, PURPOSE, BINDING_MAX_AGE_SECS,
} from "../personhood.mjs";

const hex = (b) => Buffer.from(b).toString("hex");
const SRC = SOURCES["agentbook-worldchain"];

// ── independent vectors ──────────────────────────────────────────────────────────────────────────────────────────

test("EIP-55 checksums match the spec's own examples", () => {
  for (const a of ["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                   "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"])
    assert.equal(checksumAddress(a.toLowerCase()), a);
});

test("selectors match the well-known ERC-20 ones (same keccak, same encoding)", () => {
  assert.equal(hex(selector("transfer(address,uint256)")), "a9059cbb");
  assert.equal(hex(selector("balanceOf(address)")), "70a08231");
});

test("EIP-191 hashing and recovery agree with web3.js's documented example", () => {
  // web3.eth.accounts.sign('Some data', '0x4c0883a6…2318') — the example in the web3.js documentation.
  const key = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
  assert.equal(hex(personalMessageHash("Some data")), "1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655");
  const sig = "0xb91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c";
  assert.equal(addressFromPrivateKey(key), "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23");
  assert.equal(recoverSigner("Some data", sig), "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23");
  assert.equal(signPersonal("Some data", key), sig, "deterministic (RFC 6979) signing reproduces the same bytes");
});

test("a malformed or malleable signature recovers nobody", () => {
  const key = randomBytes(32);
  const sig = signPersonal("x", key);
  assert.equal(recoverSigner("x", sig.slice(0, -2)), null, "truncated");
  assert.equal(recoverSigner("x", "0x" + "00".repeat(65)), null, "zero");
  assert.equal(recoverSigner("x", sig.slice(0, -2) + "1f"), null, "bad recovery byte");
});

// ── the binding, with a stub registry ────────────────────────────────────────────────────────────────────────────

const holderKey = { ed25519: Buffer.alloc(32, 7).toString("base64url"), mldsa65: Buffer.alloc(1952, 9).toString("base64url") };
const HOLDER = holderThumbprint(holderKey);
const REG = "registrar-07";
const NOW = 1790300000;

/** A JSON-RPC stub that answers like a real node: the right chain, a block number, and `humanId` for any call. */
function stubRpc({ humanId = 7n, chainId = SRC.chainId, fail = null } = {}) {
  const calls = [];
  const f = async (_url, init) => {
    const { method, params } = JSON.parse(init.body);
    calls.push({ method, params });
    if (fail === method) return { ok: false, status: 503, json: async () => ({}) };
    const result = method === "eth_chainId" ? "0x" + chainId.toString(16)
      : method === "eth_blockNumber" ? "0x21e7a2b"
      : "0x" + humanId.toString(16).padStart(64, "0");
    return { ok: true, status: 200, json: async () => ({ jsonrpc: "2.0", id: 1, result }) };
  };
  f.calls = calls;
  return f;
}

function binding(over = {}) {
  const key = over.key ?? randomBytes(32);
  const wallet = over.wallet ?? addressFromPrivateKey(key);
  const message = bindingMessage({ registrar: REG, holder: HOLDER, address: wallet, chainId: SRC.chainId, issuedAt: NOW, nonce: "n-1", ...over.fields });
  return { key, wallet, message, signature: signPersonal(message, key) };
}
const prove = (b, over = {}) => provePersonhood({ message: b.message, signature: b.signature, registrar: REG, holder: HOLDER, now: NOW, fetchImpl: stubRpc(), ...over });

test("THE POINT: a wallet the registry backs, bound by its own signature, yields an opaque principal proof", async () => {
  const b = binding();
  const r = await prove(b);
  assert.equal(r.ok, true, r.reason);
  assert.match(r.principal_proof, /^[0-9a-f]{64}$/, "opaque hex — no identifier on the wire");
  assert.ok(!r.principal_proof.includes(b.wallet.slice(2).toLowerCase()), "the wallet does not appear in it");
  assert.equal(r.evidence.wallet, b.wallet);
  assert.equal(r.evidence.block, 0x21e7a2b, "the evidence names the block the answer came from");
  assert.equal(r.auth_class_hint, "A1");
});

test("the lookup is made AT the block it read, on the chain it expects", async () => {
  const f = stubRpc();
  await lookupHuman(addressFromPrivateKey(randomBytes(32)), SRC, { fetchImpl: f });
  assert.deepEqual(f.calls.map((c) => c.method), ["eth_chainId", "eth_blockNumber", "eth_call"]);
  assert.equal(f.calls[2].params[1], "0x21e7a2b", "eth_call is pinned to the block, not 'latest'");
  assert.equal(f.calls[2].params[0].data.slice(0, 10), "0x" + hex(selector("lookupHuman(address)")));
});

test("a wallet the registry does not back is refused as not_human_backed", async () => {
  assert.equal((await prove(binding(), { fetchImpl: stubRpc({ humanId: 0n }) })).reason, "not_human_backed");
});

test("a lookup that fails is lookup_failed — never mistaken for 'not registered'", async () => {
  assert.equal((await prove(binding(), { fetchImpl: stubRpc({ fail: "eth_call" }) })).reason, "lookup_failed");
  assert.equal((await prove(binding(), { fetchImpl: stubRpc({ chainId: 1 }) })).reason, "lookup_failed", "wrong chain");
  const down = async () => { throw new Error("ECONNREFUSED"); };
  assert.equal((await prove(binding(), { fetchImpl: down })).reason, "lookup_failed");
});

test("naming a human-backed wallet you do not control is refused — the signer must be the wallet", async () => {
  const victim = addressFromPrivateKey(randomBytes(32));
  const b = binding({ wallet: victim });            // message names the victim, signed by someone else's key
  assert.equal((await prove(b)).reason, "binding_invalid");
});

test("a binding for another registrar, another agent key or another chain is worthless here", async () => {
  assert.equal((await prove(binding({ fields: { registrar: "registrar-11" } }))).reason, "binding_mismatch");
  assert.equal((await prove(binding({ fields: { holder: "00".repeat(32) } }))).reason, "binding_mismatch");
  assert.equal((await prove(binding({ fields: { chainId: 1 } }))).reason, "binding_mismatch");
});

test("a binding outside its window is stale", async () => {
  assert.equal((await prove(binding({ fields: { issuedAt: NOW - BINDING_MAX_AGE_SECS - 1 } }))).reason, "binding_stale");
  assert.equal((await prove(binding({ fields: { issuedAt: NOW + 3600 } }))).reason, "binding_stale");
});

test("an edited message breaks the signature; a malformed one is refused by name", async () => {
  const b = binding();
  assert.equal((await prove({ ...b, message: b.message.replace("n-1", "n-2") })).reason, "binding_invalid");
  assert.equal((await prove({ ...b, message: "hello" })).reason, "binding_malformed");
  assert.ok(b.message.includes(`purpose: ${PURPOSE}`));
});

test("the principal proof is reproducible from the evidence, and changes with it", async () => {
  const b = binding();
  const r1 = await prove(b), r2 = await prove(b);
  assert.equal(r1.principal_proof, r2.principal_proof, "same evidence, same proof");
  const r3 = await prove(b, { fetchImpl: stubRpc({ humanId: 8n }) });
  assert.notEqual(r3.principal_proof, r1.principal_proof, "a different human is a different proof");
});

test("the holder thumbprint takes only a real hybrid public key", () => {
  assert.match(HOLDER, /^[0-9a-f]{64}$/);
  assert.throws(() => holderThumbprint({ ed25519: "AAAA", mldsa65: "AAAA" }));
});
