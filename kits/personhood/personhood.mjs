#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// AINRA personhood kit — a REGISTRAR-SIDE principal proof from an on-chain proof-of-personhood registry (D-066).
//
// WHAT IT ANSWERS. "Does a unique, verified human stand behind the wallet this applicant controls?" — and it turns
// the answer into what an AINRA registrar already accepts: an opaque `principal_proof` for the passport's authority
// block, with the evidence kept at the registrar (Standard §4: evidence lives at the registrar, never on the wire).
//
// WHERE IT SITS. Outside the root and outside the core. The root issues nothing and sees none of this; a registrar
// MAY use it as one way to establish an A1 (human-delegated) principal, next to any other. The registry is
// configuration — an EVM chain, a contract, a `lookup(address) → uint256` view — not code, so no one registry is
// built in. The first configured source is the AgentBook contract on World Chain, because it is the one that exists.
//
// WHAT AINRA ADDS ON TOP, which the registry does not have: the AgentBook contract has no revoke, no unregister and
// no expiry (read in the deployed, verified contract, 2026-09-26) — a wallet stays "human-backed" forever once
// registered. An AINRA passport built on it expires, can be revoked in one bit, names its operator and capabilities,
// and verifies offline.
//
// THE CHAIN OF EVIDENCE.  human ──(ZK proof, on chain)──▶ agent wallet ──(EIP-191 signature)──▶ AINRA holder key
//   1. the registry says the wallet is backed by a unique human (a lookup, pinned to a block number);
//   2. the wallet signs a binding message naming THIS registrar, THIS holder key, a time and a nonce;
//   3. the kit recovers the signer, checks every field, and only then emits a principal proof.
//
// FAILS CLOSED, AND SAYS WHY. Every refusal is a named reason. A failed lookup is `lookup_failed` — never folded into
// "not registered", which is the ambiguity the registry's own SDK documents and this kit refuses to inherit.

import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** Known registries. Configuration, not code: a registrar can pass its own `source` object instead. */
export const SOURCES = Object.freeze({
  "agentbook-worldchain": Object.freeze({
    id: "agentbook-worldchain",
    chainId: 480,
    rpc: "https://worldchain-mainnet.g.alchemy.com/public",
    contract: "0xA23aB2712eA7BBa896930544C7d6636a96b944dA",
    lookup: "lookupHuman(address)",
  }),
});

export const PURPOSE = "ainra-personhood-binding-v1";
/** How old a binding signature may be when the registrar checks it. It is a one-time proof made during issuance,
 *  so minutes, not days — a captured one is useless after this and useless at any other registrar. */
export const BINDING_MAX_AGE_SECS = 600;
export const BINDING_MAX_FUTURE_SECS = 60;

// ── Ethereum primitives, small and exact ──────────────────────────────────────────────────────────────────────────

const hex0x = (b) => "0x" + bytesToHex(b);
const strip0x = (h) => (h.startsWith("0x") || h.startsWith("0X") ? h.slice(2) : h);

/** The 4-byte selector of a function signature. */
export function selector(signature) {
  return keccak_256(utf8ToBytes(signature)).slice(0, 4);
}

/** EIP-55 mixed-case checksum address. Throws on anything that is not 20 bytes of hex. */
export function checksumAddress(address) {
  const a = strip0x(address).toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(a)) throw new Error(`not an address: ${address}`);
  const h = bytesToHex(keccak_256(utf8ToBytes(a)));
  let out = "0x";
  for (let i = 0; i < 40; i++) out += parseInt(h[i], 16) >= 8 ? a[i].toUpperCase() : a[i];
  return out;
}

/** The address of a secp256k1 public key (uncompressed, 65 bytes). */
function addressOf(pubUncompressed) {
  return checksumAddress(hex0x(keccak_256(pubUncompressed.slice(1)).slice(12)));
}

/** EIP-191 `personal_sign` hash: keccak256("\x19Ethereum Signed Message:\n" + len(message) + message). */
export function personalMessageHash(message) {
  const m = utf8ToBytes(message);
  const prefix = utf8ToBytes(`\x19Ethereum Signed Message:\n${m.length}`);
  const buf = new Uint8Array(prefix.length + m.length);
  buf.set(prefix, 0); buf.set(m, prefix.length);
  return keccak_256(buf);
}

/** Recover the signer of an EIP-191 message from a 65-byte r‖s‖v signature. Returns null for anything malformed. */
export function recoverSigner(message, signatureHex) {
  let raw;
  try { raw = hexToBytes(strip0x(signatureHex)); } catch { return null; }
  if (raw.length !== 65) return null;
  let v = raw[64];
  if (v >= 27) v -= 27;
  if (v !== 0 && v !== 1) return null;
  try {
    const sig = secp256k1.Signature.fromCompact(raw.slice(0, 64)).addRecoveryBit(v);
    if (sig.hasHighS()) return null;                     // EIP-2: a malleable twin is not a second valid signature
    const pub = sig.recoverPublicKey(personalMessageHash(message)).toRawBytes(false);
    return addressOf(pub);
  } catch { return null; }
}

/** Sign an EIP-191 message (tests and the binding CLI use this; a real wallet does it in its own UI). */
export function signPersonal(message, privateKey) {
  const sig = secp256k1.sign(personalMessageHash(message), privateKey);
  const out = new Uint8Array(65);
  out.set(sig.toCompactRawBytes(), 0);
  out[64] = 27 + sig.recovery;
  return hex0x(out);
}

export function addressFromPrivateKey(privateKey) {
  return addressOf(secp256k1.getPublicKey(privateKey, false));
}

// ── the registry lookup — pinned to a block, and never confusing "no" with "could not ask" ───────────────────────

export class LookupError extends Error {}

async function rpc(source, method, params, fetchImpl) {
  let r;
  try {
    r = await fetchImpl(source.rpc, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: AbortSignal.timeout(15000),
    });
  } catch (e) { throw new LookupError(`rpc unreachable: ${e.message}`); }
  if (!r.ok) throw new LookupError(`rpc http ${r.status}`);
  let body;
  try { body = await r.json(); } catch { throw new LookupError("rpc returned non-JSON"); }
  if (body.error) throw new LookupError(`rpc error: ${body.error.message ?? JSON.stringify(body.error)}`);
  if (typeof body.result !== "string") throw new LookupError("rpc returned no result");
  return body.result;
}

/** Ask the registry who backs `address`. Returns `{ humanId: bigint, block: number }` — `humanId === 0n` means "not
 *  registered", and ANY failure to ask throws `LookupError`. The block is read first and the call is made AT it, so
 *  the evidence names the exact chain state the answer came from. */
export async function lookupHuman(address, source = SOURCES["agentbook-worldchain"], { fetchImpl = fetch } = {}) {
  const addr = checksumAddress(address);
  const chain = await rpc(source, "eth_chainId", [], fetchImpl);
  if (Number(BigInt(chain)) !== source.chainId) throw new LookupError(`rpc serves chain ${BigInt(chain)}, expected ${source.chainId}`);
  const blockHex = await rpc(source, "eth_blockNumber", [], fetchImpl);
  const data = hex0x(selector(source.lookup)) + strip0x(addr).toLowerCase().padStart(64, "0");
  const out = await rpc(source, "eth_call", [{ to: source.contract, data }, blockHex], fetchImpl);
  const word = strip0x(out);
  if (!/^[0-9a-fA-F]{64}$/.test(word)) throw new LookupError(`unexpected return data (${word.length / 2} bytes)`);
  return { humanId: BigInt("0x" + word), block: Number(BigInt(blockHex)) };
}

// ── the binding message: wallet → this registrar, this holder key, now ──────────────────────────────────────────

/** A line-oriented message a person can read in their wallet before signing. Every field is checked on the way in. */
export function bindingMessage({ registrar, holder, address, chainId, issuedAt, nonce }) {
  return [
    "AINRA passport — bind this wallet to an agent key",
    `purpose: ${PURPOSE}`,
    `registrar: ${registrar}`,
    `holder: ${holder}`,
    `wallet: ${checksumAddress(address)}`,
    `chain: ${chainId}`,
    `issued-at: ${issuedAt}`,
    `nonce: ${nonce}`,
  ].join("\n");
}

function parseBinding(message) {
  const lines = message.split("\n");
  if (lines[0] !== "AINRA passport — bind this wallet to an agent key" || lines.length !== 8) return null;
  const f = {};
  for (const l of lines.slice(1)) {
    const i = l.indexOf(": ");
    if (i < 0) return null;
    f[l.slice(0, i)] = l.slice(i + 2);
  }
  const want = ["purpose", "registrar", "holder", "wallet", "chain", "issued-at", "nonce"];
  if (want.some((k) => typeof f[k] !== "string" || !f[k].length)) return null;
  if (!/^\d{1,12}$/.test(f["issued-at"]) || !/^\d{1,12}$/.test(f.chain)) return null;
  return { purpose: f.purpose, registrar: f.registrar, holder: f.holder, wallet: f.wallet, chainId: Number(f.chain), issuedAt: Number(f["issued-at"]), nonce: f.nonce };
}

/** The AINRA holder key's thumbprint, as the binding names it: SHA-256 over ed25519 ‖ ml-dsa-65 public keys. */
export function holderThumbprint(holderKey) {
  const ed = Buffer.from(holderKey.ed25519, "base64url"), ml = Buffer.from(holderKey.mldsa65, "base64url");
  if (ed.length !== 32 || ml.length !== 1952) throw new Error("holder key must be a hybrid public key (ed25519 32 B, ml-dsa-65 1952 B)");
  return bytesToHex(sha256(Buffer.concat([ed, ml])));
}

function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
  return JSON.stringify(v);
}

/**
 * Check a binding end to end and, only if every step holds, return the principal proof.
 *
 *   { ok: true,  principal_proof, evidence, auth_class_hint: "A1" }
 *   { ok: false, reason }   reason ∈ binding_malformed · binding_invalid · binding_mismatch · binding_stale ·
 *                                    not_human_backed · lookup_failed
 *
 * `principal_proof` is SHA-256 over the canonical evidence: opaque, carries no identifier, and anyone holding the
 * evidence can recompute it. The evidence stays with the registrar.
 */
export async function provePersonhood({ message, signature, registrar, holder, now, source = SOURCES["agentbook-worldchain"], fetchImpl = fetch }) {
  const b = parseBinding(message);
  if (!b || b.purpose !== PURPOSE) return { ok: false, reason: "binding_malformed" };
  let wallet;
  try { wallet = checksumAddress(b.wallet); } catch { return { ok: false, reason: "binding_malformed" }; }
  // The signer must be the wallet the message names — otherwise anyone could name a human-backed wallet they do
  // not control.
  const signer = recoverSigner(message, signature);
  if (!signer || signer !== wallet) return { ok: false, reason: "binding_invalid" };
  // Bound to THIS registrar, THIS agent key and THIS chain: a proof shown elsewhere, or for another key, is worthless.
  if (b.registrar !== registrar || b.holder !== holder || b.chainId !== source.chainId) return { ok: false, reason: "binding_mismatch" };
  if (now - b.issuedAt > BINDING_MAX_AGE_SECS || b.issuedAt - now > BINDING_MAX_FUTURE_SECS) return { ok: false, reason: "binding_stale" };
  let looked;
  try { looked = await lookupHuman(wallet, source, { fetchImpl }); }
  catch { return { ok: false, reason: "lookup_failed" }; }
  if (looked.humanId === 0n) return { ok: false, reason: "not_human_backed" };
  const evidence = {
    kind: "ainra/personhood-evidence/v1",
    source: { id: source.id, chain_id: source.chainId, contract: checksumAddress(source.contract), lookup: source.lookup },
    block: looked.block,
    wallet,
    human_id: looked.humanId.toString(10),
    binding: { message, signature },
    checked_at: now,
  };
  return { ok: true, principal_proof: bytesToHex(sha256(utf8ToBytes(canonical(evidence)))), evidence, auth_class_hint: "A1" };
}

// ── CLI ─────────────────────────────────────────────────────────────────────────────────────────────────────────

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [cmd, ...rest] = process.argv.slice(2);
  const arg = (n) => { const i = rest.indexOf(`--${n}`); return i >= 0 ? rest[i + 1] : undefined; };
  const nowSecs = Math.floor(Date.now() / 1000);
  if (cmd === "check" && rest[0]) {
    try {
      const { humanId, block } = await lookupHuman(rest[0]);
      console.log(humanId === 0n
        ? `${checksumAddress(rest[0])}: NOT human-backed (block ${block})`
        : `${checksumAddress(rest[0])}: human-backed — a unique verified human stands behind it (block ${block})`);
      process.exit(humanId === 0n ? 1 : 0);
    } catch (e) { console.error(`lookup_failed: ${e.message}`); process.exit(2); }
  } else if (cmd === "prove") {
    const message = readFileSync(arg("message-file"), "utf8");
    const r = await provePersonhood({ message, signature: arg("signature"), registrar: arg("registrar"), holder: arg("holder"), now: nowSecs });
    console.log(JSON.stringify(r, null, 2));
    process.exit(r.ok ? 0 : 1);
  } else {
    console.error("usage: personhood.mjs check <address>\n       personhood.mjs prove --message-file <f> --signature <0x…> --registrar <id> --holder <thumbprint>");
    process.exit(2);
  }
}
