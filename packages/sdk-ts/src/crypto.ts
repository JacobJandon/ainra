// SPDX-License-Identifier: Apache-2.0 OR MIT
// Crypto mirror — audited libraries only (@noble/curves, @noble/post-quantum, @noble/hashes). No bespoke crypto.
//
// Interop with ainra-core (RustCrypto) is empirically pinned (see the diff-harness): Ed25519 and ML-DSA-65 verify
// the raw message; SLH-DSA-SHA2-128s needs the FIPS-205 empty-context frame `0x00 0x00` prepended (RustCrypto's
// Signer uses the external ctx="" interface; @noble's slh verify does not auto-frame).

import { ed25519 } from "@noble/curves/ed25519";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { slh_dsa_sha2_128s } from "@noble/post-quantum/slh-dsa";
import { sha256 } from "@noble/hashes/sha256";

// Exact FIPS sizes — a decoded key/sig of the wrong length is a downgrade/forgery, not a crash.
export const ED25519_PK = 32;
export const ED25519_SIG = 64;
export const MLDSA65_PK = 1952;
export const MLDSA65_SIG = 3309;
export const SLHDSA128S_PK = 32;
export const SLHDSA128S_SIG = 7856;

export function b64uDecode(s: string): Uint8Array {
  // base64url (unpadded) → bytes
  const b = s.replace(/-/g, "+").replace(/_/g, "/");
  return new Uint8Array(Buffer.from(b, "base64"));
}
export function b64uEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export interface HybridPublic {
  ed25519: Uint8Array; // 32
  mldsa65: Uint8Array; // 1952
}
export interface HybridSig {
  ed25519: Uint8Array; // 64
  mldsa65: Uint8Array; // 3309
}

/** Result of a hybrid verify: null = OK, else the closed reason string (mirrors ainra-core). */
export type HybridResult = null | "alg_downgrade" | "sig_invalid";

/**
 * Both-signatures-or-invalid. Fixed order matching ainra-core: (1) length/presence → alg_downgrade;
 * (2) Ed25519; (3) ML-DSA-65. Any failure after the downgrade gate is sig_invalid.
 */
export function verifyHybrid(pk: HybridPublic, msg: Uint8Array, sig: HybridSig): HybridResult {
  if (sig.ed25519.length !== ED25519_SIG || sig.mldsa65.length !== MLDSA65_SIG) return "alg_downgrade";
  if (pk.ed25519.length !== ED25519_PK || pk.mldsa65.length !== MLDSA65_PK) return "sig_invalid";
  let ok: boolean;
  try {
    ok = ed25519.verify(sig.ed25519, msg, pk.ed25519);
  } catch {
    return "sig_invalid";
  }
  if (!ok) return "sig_invalid";
  try {
    if (!ml_dsa65.verify(pk.mldsa65, msg, sig.mldsa65)) return "sig_invalid";
  } catch {
    return "sig_invalid";
  }
  return null;
}

/** Plain Ed25519 verify (ADR-002 delegate checkpoints). Fails closed. */
export function ed25519Verify(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  if (pk.length !== ED25519_PK || sig.length !== ED25519_SIG) return false;
  try {
    return ed25519.verify(sig, msg, pk);
  } catch {
    return false;
  }
}

/** SLH-DSA-SHA2-128s verify with the FIPS-205 empty-context frame. Fails closed on any error. */
export function slhVerify(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  if (pk.length !== SLHDSA128S_PK || sig.length !== SLHDSA128S_SIG) return false;
  const framed = new Uint8Array(2 + msg.length);
  framed[0] = 0x00; // context-string interface: 0x00 || len(ctx)=0 || ctx(empty) || M
  framed[1] = 0x00;
  framed.set(msg, 2);
  try {
    return slh_dsa_sha2_128s.verify(pk, framed, sig);
  } catch {
    return false;
  }
}

// ── RFC 6962 Merkle (SHA-256, 0x00 leaf / 0x01 node prefixes) ──────────────────────────────────────────────────

export function hashLeaf(data: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + data.length);
  buf[0] = 0x00;
  buf.set(data, 1);
  return sha256(buf);
}
function hashNode(l: Uint8Array, r: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + 32 + 32);
  buf[0] = 0x01;
  buf.set(l, 1);
  buf.set(r, 33);
  return sha256(buf);
}
function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** RFC 6962 §2.1.1 inclusion-path verification. Mirrors ainra-core::merkle::verify_inclusion. Fails closed. */
export function verifyInclusion(
  leaf: Uint8Array,
  index: number,
  treeSize: number,
  proof: Uint8Array[],
  root: Uint8Array,
): boolean {
  if (index >= treeSize) return false;
  let fn = index;
  let sn = treeSize - 1;
  let r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      r = hashNode(p, r);
      if ((fn & 1) === 0) {
        while ((fn & 1) === 0 && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      r = hashNode(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && eq(r, root);
}

export { sha256 };
