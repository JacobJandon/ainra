// SPDX-License-Identifier: Apache-2.0 OR MIT
// AINRA verify-only SDK — a faithful mirror of ainra-core (independent implementation #2 for the diff-harness).
// The nine verify steps, their fixed order, and the 15 frozen reason strings match crates/ainra-core/src/verify.rs.
//
// Validity (ADR-017): the IDENTITY (lineage + AINRA Number) is permanent; the CREDENTIAL defaults to 366 days and
// renews invisibly (T−30 d reissue, overlap issuance, a logged `prev_leaf` continuity chain). The window check is
// exact — nbf inclusive, exp exclusive, no skew, no grace period. Long credentials are safe here because
// revocation fails closed in <60 s; short certificates are what you need when it doesn't.

import { inflateSync } from "node:zlib";
import { canonicalize } from "./canon.js";
import {
  b64uDecode,
  b64uEncode,
  ed25519Verify,
  hashLeaf,
  sha256,
  slhVerify,
  verifyHybrid,
  verifyInclusion,
  type HybridPublic,
  type HybridSig,
} from "./crypto.js";

export { canonicalize } from "./canon.js";

// ── Verdicts + the 15 frozen reasons ───────────────────────────────────────────────────────────────────────────
export type Reason =
  | "sig_invalid"
  | "alg_downgrade"
  | "expired"
  | "not_yet_valid"
  | "revoked"
  | "mandate_revoked"
  | "chain_widening"
  | "chain_expired"
  | "not_logged"
  | "checkpoint_invalid"
  | "stale_status"
  | "name_malformed"
  | "ceiling_exceeded"
  | "unknown_registrar"
  | "schema_violation";

export type Verdict = { verdict: "valid" } | { verdict: "invalid"; reason: Reason };

const VALID: Verdict = { verdict: "valid" };
const invalid = (reason: Reason): Verdict => ({ verdict: "invalid", reason });

/** Thrown internally to short-circuit to an INVALID verdict with a reason. */
class Reject extends Error {
  constructor(public reason: Reason) {
    super(reason);
  }
}

// ── Name grammar (mirror name.rs) ──────────────────────────────────────────────────────────────────────────────
function validateLabel(s: string): boolean {
  if (s.length < 1 || s.length > 63) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const ok = (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) || c === 0x2d; // a-z 0-9 -
    if (!ok) return false;
  }
  return s[0] !== "-" && s[s.length - 1] !== "-";
}
function validateVersion(s: string): boolean {
  const parts = s.split(".");
  if (parts.length < 1 || parts.length > 3) return false;
  for (const p of parts) {
    if (p.length === 0) return false;
    if (!/^[0-9]+$/.test(p)) return false;
    if (p.length > 1 && p[0] === "0") return false; // no leading zeros (except "0")
  }
  return true;
}
/** ainra:{registrar}:{operator}:{lineage}@{version} */
function parseName(s: string): boolean {
  const at = s.split("@");
  if (at.length !== 2) return false;
  if (!validateVersion(at[1])) return false;
  const p = at[0].split(":");
  if (p.length !== 4 || p[0] !== "ainra") return false;
  return validateLabel(p[1]) && validateLabel(p[2]) && validateLabel(p[3]);
}
/** did:ainra:{registrar}:{operator}:{lineage} → returns registrar id, or null if malformed. */
function parseDidRegistrar(s: string): string | null {
  const p = s.split(":");
  if (p.length !== 5 || p[0] !== "did" || p[1] !== "ainra") return null;
  if (!validateLabel(p[2]) || !validateLabel(p[3]) || !validateLabel(p[4])) return null;
  return p[2];
}

// ── Passport schema gate (mirror passport.rs) ──────────────────────────────────────────────────────────────────
const FORBIDDEN_KEYS = new Set([
  "email", "phone", "name", "full_name", "given_name", "family_name", "surname", "address", "street", "city",
  "postcode", "zip", "ssn", "national_id", "dob", "birthdate", "gender", "photo", "ip", "geolocation",
  "score", "trust_score", "reputation", "rating", "ranking", "karma", "credit_score",
  "price", "amount", "fee", "cost", "payment", "balance", "invoice_total", "currency", "wallet", "iban",
]);
const ALLOWED_TOP = new Set([
  "vct", "iss", "sub", "nbf", "exp", "authority", "tier", "capabilities", "scope_ceiling", "keys", "cnf",
  "status", "log", "act_chain", "mandates", "mandates_root", "mandates_size", "transfer_history", "prev_leaf",
]);
// Nested deny-unknown-fields sets — mirror each Rust struct's #[serde(deny_unknown_fields)] (review finding #7).
const ALLOWED_AUTHORITY = new Set(["class", "principal_proof"]);
const ALLOWED_KEY = new Set(["ed25519", "mldsa65"]);
const ALLOWED_STATUS = new Set(["status_list"]);
const ALLOWED_STATUSREF = new Set(["idx", "uri"]);
const ALLOWED_LOG = new Set(["leaf", "root", "checkpoint"]);
const ALLOWED_HOP = new Set(["from", "to", "granted", "exp", "sig_ed25519", "sig_mldsa65", "sig_child_ed25519", "sig_child_mldsa65", "log_leaf"]);
const ALLOWED_MANDATE = new Set(["id", "parent"]);
const VCT = "ainra/passport/v1";

/** Reject any key not in `allowed` on a plain object (mirror deny_unknown_fields). */
function denyUnknown(o: unknown, allowed: Set<string>): void {
  if (o === null || typeof o !== "object" || Array.isArray(o)) throw new Reject("schema_violation");
  for (const k of Object.keys(o as object)) if (!allowed.has(k)) throw new Reject("schema_violation");
}
function reqString(v: unknown): string {
  if (typeof v !== "string") throw new Reject("schema_violation");
  return v;
}
function reqStringArray(v: unknown): string[] {
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) throw new Reject("schema_violation");
  return v as string[];
}

function scanForbidden(v: unknown): void {
  if (Array.isArray(v)) {
    for (const it of v) scanForbidden(it);
  } else if (v !== null && typeof v === "object") {
    for (const [k, child] of Object.entries(v as object)) {
      if (FORBIDDEN_KEYS.has(k.toLowerCase())) throw new Reject("schema_violation");
      scanForbidden(child);
    }
  }
}

interface MandateNode {
  id: string;
  parent: string | null;
}
interface ActLink {
  from: string;
  to: string;
  granted: string[];
  exp: number;
  sig_ed25519: string;
  sig_mldsa65: string;
  sig_child_ed25519: string;
  sig_child_mldsa65: string;
  log_leaf: string;
}
interface Passport {
  iss: string;
  sub: string;
  nbf: number;
  exp: number;
  capabilities: string[];
  scope_ceiling: string[];
  statusIdx: number;
  /** The status-list URI this passport points to (`status.status_list.uri`). The GA {@link Verifier} binds it to the
   *  registrar's directory-published status URI and to the signed publication's URI, so a presenter cannot splice in
   *  a different (all-clear) registrar's list (D-020). */
  statusUri: string;
  logLeaf: string;
  act_chain: ActLink[];
  mandates: MandateNode[];
}

function parseChecked(claims: Uint8Array): Passport {
  let raw: unknown;
  try {
    raw = JSON.parse(Buffer.from(claims).toString("utf8"));
  } catch {
    throw new Reject("schema_violation");
  }
  scanForbidden(raw);
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) throw new Reject("schema_violation");
  const o = raw as Record<string, unknown>;
  for (const k of Object.keys(o)) if (!ALLOWED_TOP.has(k)) throw new Reject("schema_violation");
  if (o.vct !== VCT) throw new Reject("schema_violation");
  if (typeof o.sub !== "string" || !parseName(o.sub)) throw new Reject("name_malformed");
  if (typeof o.iss !== "string" || parseDidRegistrar(o.iss) === null) throw new Reject("name_malformed");
  // authority (nested deny_unknown_fields + required fields)
  denyUnknown(o.authority, ALLOWED_AUTHORITY);
  reqString((o.authority as Record<string, unknown>).class);
  reqString((o.authority as Record<string, unknown>).principal_proof);
  // keys — at least one; each carries BOTH algorithms as non-empty strings; no stray fields
  const keys = o.keys;
  if (!Array.isArray(keys) || keys.length === 0) throw new Reject("schema_violation");
  for (const k of keys) {
    denyUnknown(k, ALLOWED_KEY);
    const ke = k as Record<string, unknown>;
    if (typeof ke.ed25519 !== "string" || ke.ed25519.length === 0) throw new Reject("schema_violation");
    if (typeof ke.mldsa65 !== "string" || ke.mldsa65.length === 0) throw new Reject("schema_violation");
  }
  if (typeof o.nbf !== "number" || typeof o.exp !== "number" || o.exp <= o.nbf) throw new Reject("schema_violation");
  // capabilities + scope_ceiling are REQUIRED string arrays (Rust has no serde default — review #10)
  const capabilities = reqStringArray(o.capabilities);
  const scope_ceiling = reqStringArray(o.scope_ceiling);
  // status + log shape (mirror the Rust serde structs — review #5)
  denyUnknown(o.status, ALLOWED_STATUS);
  const sl = (o.status as Record<string, unknown>).status_list;
  denyUnknown(sl, ALLOWED_STATUSREF);
  const idx = (sl as { idx: unknown }).idx;
  // idx MUST be a non-negative integer (Rust parses it as u64 — a negative/fractional idx fails there, so it must
  // fail here too, else a negative index would read `statusBits[-1] === undefined` as not-revoked = a bypass).
  if (typeof idx !== "number" || !Number.isInteger(idx) || idx < 0) throw new Reject("schema_violation");
  const statusUri = reqString((sl as Record<string, unknown>).uri);
  denyUnknown(o.log, ALLOWED_LOG);
  const logLeaf = reqString((o.log as Record<string, unknown>).leaf);
  reqString((o.log as Record<string, unknown>).root);
  reqString((o.log as Record<string, unknown>).checkpoint);
  // act_chain: nested deny-unknown + dual-sig + log_leaf presence + structural linkage (D-012)
  if (o.act_chain !== undefined && !Array.isArray(o.act_chain)) throw new Reject("schema_violation");
  const act_chain = (o.act_chain as ActLink[]) ?? [];
  for (const hop of act_chain) {
    denyUnknown(hop, ALLOWED_HOP);
    if (!reqString(hop.from) || !parseName(hop.from)) throw new Reject("name_malformed");
    if (!reqString(hop.to) || !parseName(hop.to)) throw new Reject("name_malformed");
    reqStringArray(hop.granted);
    if (typeof hop.exp !== "number") throw new Reject("schema_violation");
    if (!hop.sig_ed25519 || !hop.sig_mldsa65 || !hop.sig_child_ed25519 || !hop.sig_child_mldsa65 || !hop.log_leaf)
      throw new Reject("schema_violation");
  }
  for (let i = 1; i < act_chain.length; i++) {
    if (act_chain[i].from !== act_chain[i - 1].to) throw new Reject("schema_violation");
  }
  if (act_chain.length > 0 && act_chain[act_chain.length - 1].to !== o.sub) throw new Reject("schema_violation");
  // Static mandates: nested deny-unknown; DYNAMIC (mandates_root/size) is M3 — fail closed (D-013 revised, review #1/#4)
  const mandates = (o.mandates as MandateNode[]) ?? [];
  if (o.mandates !== undefined && !Array.isArray(o.mandates)) throw new Reject("schema_violation");
  for (const n of mandates) denyUnknown(n, ALLOWED_MANDATE);
  if (o.mandates_root !== undefined || o.mandates_size !== undefined) throw new Reject("schema_violation");
  // ADR-017 renewal continuity: `prev_leaf` present ⇒ a REISSUE; it must strictly decode to a 32-byte leaf hash
  // (mirrors Rust's `b64::decode_array::<32>` gate — a malformed link would make the renewal chain unwalkable
  // while still looking like a renewal, so it fails closed here). Two parity subtleties with the Rust side:
  //   * Rust's `Option<String>` maps a JSON `null` to `None` (= absent, first issuance), so `null` is NOT an
  //     error here either — treat null exactly like a missing field;
  //   * Rust decodes with base64ct (STRICT, unpadded) which rejects a non-canonical last char (nonzero trailing
  //     bits), whereas Node's `Buffer.from(_, "base64")` silently accepts it. So a canonical round-trip
  //     (`b64uEncode(decode(s)) === s`) is REQUIRED — without it a 43-char non-canonical link is accepted here
  //     and rejected by Rust, a fail-open verdict split in the SDK.
  if (o.prev_leaf !== undefined && o.prev_leaf !== null) {
    if (typeof o.prev_leaf !== "string") throw new Reject("schema_violation");
    const pl = strictB64u(o.prev_leaf);
    if (pl === null || pl.length !== 32 || b64uEncode(pl) !== o.prev_leaf) throw new Reject("schema_violation");
  }
  return {
    iss: o.iss as string,
    sub: o.sub as string,
    nbf: o.nbf as number,
    exp: o.exp as number,
    capabilities,
    scope_ceiling,
    statusIdx: idx,
    statusUri,
    logLeaf,
    act_chain,
    mandates,
  };
}

// ── Status list + freshness (mirror status.rs) ─────────────────────────────────────────────────────────────────
// Null-prototype lookup so a presenter-supplied freshness label of "__proto__"/"constructor" resolves to `undefined`
// (fail closed at step 7), never to an inherited Object.prototype member that would defeat the freshness gate.
const FRESHNESS_MAX: Record<string, number> = Object.assign(Object.create(null), { F1: 30, F2: 300, F3: 86400 });

/** Hard cap on a status list's declared length: 2^24 lineages (~2 MiB PACKED bitmap, since {@link unpackStatus}
 *  keeps the list packed and never expands it to a `boolean[]`). A larger `bit_len` is rejected (fail closed) so a
 *  hostile bundle can neither pre-allocate an enormous bitmap nor drive an unbounded inflate. Mirrors the Rust
 *  `StatusList::decode` cap (kept byte-parity by regenerating with the same bound). */
const MAX_STATUS_BITS = 1 << 24;

/** Decompress a status list to its PACKED bytes (LSB-first, `ceil(bitLen/8)` bytes) — never expanded to a
 *  `boolean[]`. A `boolean[]` of `bitLen` entries costs ~180× the packed bytes in V8 (a status_len at the 2^24 cap
 *  would be ~360 MB, an unauthenticated compression-amplification OOM); the packed `Uint8Array` is ≤ 2 MiB at the
 *  cap. Read individual bits with {@link statusBit}. */
function unpackStatus(compressed: Uint8Array, bitLen: number): Uint8Array {
  // Bound the declared length BEFORE touching the allocator (review: unbounded status_len → OOM).
  if (!Number.isInteger(bitLen) || bitLen < 0 || bitLen > MAX_STATUS_BITS) throw new Reject("stale_status");
  const need = Math.ceil(bitLen / 8);
  let packed: Uint8Array;
  try {
    // Cap the decompressed size to exactly what the declared length needs (+ a little slack). A zlib bomb that would
    // inflate past this throws RangeError → mapped to stale_status (status unavailable ⇒ fail closed).
    packed = new Uint8Array(inflateSync(compressed, { maxOutputLength: need + 8 }));
  } catch {
    throw new Reject("stale_status");
  }
  // Fail closed on a truncated list — mirror Rust StatusList::decode's length guard (review #3): a blob shorter
  // than the declared length must NOT be read past its end as 0 (valid).
  if (packed.length < need) throw new Reject("stale_status");
  return packed;
}

/** Resolve one lineage's status from a packed list. **Fail closed**: an index at/beyond `bitLen` is `revoked`
 *  (`true`), never valid — mirrors Rust `StatusList::status_of`. */
function statusBit(packed: Uint8Array, bitLen: number, idx: number): boolean {
  if (idx < 0 || idx >= bitLen) return true;
  return ((packed[idx >> 3] >> (idx & 7)) & 1) === 1;
}

// ── Delegation chain (mirror chain.rs) ─────────────────────────────────────────────────────────────────────────
function subset(a: string[], b: string[]): boolean {
  return a.every((x) => b.includes(x));
}
function hopSigningBytes(h: ActLink): Uint8Array {
  return new TextEncoder().encode(canonicalize({ from: h.from, to: h.to, granted: h.granted, exp: h.exp }));
}
function hopLeaf(h: ActLink): Uint8Array {
  return hashLeaf(hopSigningBytes(h));
}

// ── Mandate (mirror mandate.rs) ────────────────────────────────────────────────────────────────────────────────
function checkMandatePath(path: MandateNode[], revoked: Set<string>): void {
  if (path.length === 0) return;
  if (path[0].parent !== null && path[0].parent !== undefined) throw new Reject("schema_violation");
  for (let i = 1; i < path.length; i++) {
    if (path[i].parent !== path[i - 1].id) throw new Reject("schema_violation");
  }
  if (path.some((n) => revoked.has(n.id))) throw new Reject("mandate_revoked");
}

// ── The verify inputs ──────────────────────────────────────────────────────────────────────────────────────────
export interface RegistrarInfo {
  issuerKey: HybridPublic;
  logRootKey: Uint8Array;
  /** The registrar's status-list-signing hybrid key (from the directory). The GA {@link Verifier} authenticates a
   *  presented status list against this before trusting a single bit — so a presenter cannot forge an all-clear
   *  status to bypass revocation (D-020). Absent when anchors are hand-built (raw `runVector` conformance path). */
  statusKey?: HybridPublic;
  /** The registrar's directory-published status-list URI. The signed publication in the bundle AND the passport's
   *  own claimed status URI must both equal this — a triple binding that stops a presenter splicing another
   *  registrar's list. Present iff {@link statusKey} is. */
  statusUri?: string;
}
export type TrustAnchors = Record<string, RegistrarInfo>;

export interface HopLogProof {
  leafIndex: number;
  proof: Uint8Array[];
}
/** ADR-002 delegate certificate + delegate signature. */
export interface DelegateCert {
  delegateEd25519: Uint8Array;
  scopes: string[];
  nbf: number;
  exp: number;
  sigSlh: Uint8Array;
}
export type CheckpointSig =
  | { mode: "root"; slh: Uint8Array }
  | { mode: "delegate"; cert: DelegateCert; sigEd25519: Uint8Array };

export interface MandateInclusion {
  leafIndex: number;
  proof: Uint8Array[];
}

export interface Presentation {
  claims: Uint8Array;
  issuerSig: HybridSig;
  now: number;
  chainKeys: HybridPublic[];
  hopProofs: HopLogProof[];
  /** The status list as PACKED bytes (LSB-first) — never a `boolean[]` (see {@link unpackStatus}). Read a lineage
   *  with {@link statusBit}. */
  statusBits: Uint8Array;
  /** The declared bit length of {@link statusBits} (an index ≥ this is fail-closed `revoked`). */
  statusBitLen: number;
  statusIssuedAt: number;
  freshness: string;
  checkpoint: { origin: string; size: number; root: Uint8Array; rootB64: string };
  checkpointSig: CheckpointSig;
  leafIndex: number;
  inclusionProof: Uint8Array[];
  mandatePath: MandateNode[];
  mandateProofs: MandateInclusion[];
  mandateRevocations: Set<string>;
  /** Revoked delegate-cert fingerprints (base64url SHA-256), M4 — from the dual-root-signed directory. A checkpoint
   *  signed by a revoked delegate is `checkpoint_invalid`. Empty = no delegate revocations known (M1–M3 behaviour). */
  revokedDelegates: Set<string>;
}

const SCOPE_CHECKPOINT = "checkpoint-daily";
/** ≤ 92-day delegate-cert cap (ADR-002) — mirrors `ainra_core::consts::DELEGATE_CERT_MAX_SECS`. */
const DELEGATE_CERT_MAX_SECS = 92 * 24 * 60 * 60;

/** Default passport validity — 366 days (ADR-017). Mirrors `ainra_core::consts::PASSPORT_VALIDITY_DEFAULT_SECS`.
 *  Identity (the lineage + AINRA Number) is eternal; the CREDENTIAL is bounded. Long validity is affordable
 *  because revocation fails closed (<60 s) — short certs are what you need when it doesn't. */
export const PASSPORT_VALIDITY_DEFAULT_SECS = 366 * 24 * 60 * 60;
/** Renewal lead — REISSUE at T−30 d (ADR-017). Mirrors `ainra_core::consts::RENEWAL_LEAD_SECS`. */
export const RENEWAL_LEAD_SECS = 30 * 24 * 60 * 60;
/** True once a credential has entered its ADR-017 renewal window (now ≥ exp − 30 d). A scheduling hint for
 *  holders — the verifier's window check is unaffected (no grace period anywhere; expiry is expiry). */
export function renewalDue(exp: number, now: number): boolean {
  return now >= exp - RENEWAL_LEAD_SECS;
}

/** SHA-256 fingerprint of a delegate cert = hash of its canonical signing bytes (mirrors DelegateCert::fingerprint).
 *  Returned base64url so it compares directly against the wire/directory `revoked_delegates` list. */
function certFingerprintB64(c: DelegateCert): string {
  const bytes = new TextEncoder().encode(
    canonicalize({ delegate: b64uEncode(c.delegateEd25519), exp: c.exp, nbf: c.nbf, scopes: c.scopes }),
  );
  return b64uEncode(sha256(bytes));
}

/** STRICT unpadded base64url decode: returns null on any character outside the base64url alphabet (Node's
 *  `Buffer.from(x,'base64')` silently drops invalid chars; Rust's `b64::decode` rejects them — this restores
 *  parity). Empty string → empty array (valid). */
function strictB64u(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
  try {
    return b64uDecode(s);
  } catch {
    return null;
  }
}

/** Decode + length-check a list of base64url SHA-256 fingerprints, returning a canonical-b64 array — or null if
 *  ANY is malformed (not valid base64url, or not 32 bytes). Mirrors `Directory::accredit`, which decodes each
 *  fingerprint to `[u8;32]` and fails closed (`unknown_registrar`) on a bad one; re-encoding canonicalises so the
 *  set compares byte-for-byte against `certFingerprintB64` regardless of the wire form (review parity fix). */
function decodeFingerprints(list: string[]): string[] | null {
  const out: string[] = [];
  for (const s of list) {
    const b = strictB64u(s);
    if (b === null || b.length !== 32) return null;
    out.push(b64uEncode(b));
  }
  return out;
}

/** Verify a checkpoint signature in either ADR-002 mode. Fail closed → false. Mirrors checkpoint.rs verify_sig_mode. */
function verifyCheckpointSig(
  logRootKey: Uint8Array,
  cp: { origin: string; rootB64: string; size: number },
  sig: CheckpointSig,
  now: number,
): boolean {
  const cpMsg = new TextEncoder().encode(canonicalize({ origin: cp.origin, root: cp.rootB64, size: cp.size }));
  if (sig.mode === "root") return slhVerify(logRootKey, cpMsg, sig.slh);
  // delegate mode: (1) cert root-signature, (2) ≤92-day lifetime, (3) window, (4) scope, (5) delegate signature
  const c = sig.cert;
  const certMsg = new TextEncoder().encode(
    canonicalize({ delegate: b64uEncode(c.delegateEd25519), exp: c.exp, nbf: c.nbf, scopes: c.scopes }),
  );
  if (!slhVerify(logRootKey, certMsg, c.sigSlh)) return false;
  if (c.exp <= c.nbf || c.exp - c.nbf > DELEGATE_CERT_MAX_SECS) return false; // lifetime out of range (review #9)
  if (now < c.nbf || now >= c.exp) return false;
  if (!c.scopes.includes(SCOPE_CHECKPOINT)) return false;
  return ed25519Verify(c.delegateEd25519, cpMsg, sig.sigEd25519);
}

// ── Signed status deltas + fresh head (mirror status.rs StatusDelta / FreshHead) ───────────────────────────────
const SCOPE_DELTA = "delta-countersign";
const SCOPE_FRESH_HEAD = "fresh-head";

/** Verify an ADR-002 delegate cert for a given scope. Fail closed → false. Mirrors DelegateCert::verify. */
function verifyDelegateCert(cert: DelegateCert, rootKey: Uint8Array, now: number, scope: string): boolean {
  const certMsg = new TextEncoder().encode(
    canonicalize({ delegate: b64uEncode(cert.delegateEd25519), exp: cert.exp, nbf: cert.nbf, scopes: cert.scopes }),
  );
  if (!slhVerify(rootKey, certMsg, cert.sigSlh)) return false;
  if (cert.exp <= cert.nbf || cert.exp - cert.nbf > DELEGATE_CERT_MAX_SECS) return false;
  if (now < cert.nbf || now >= cert.exp) return false;
  if (!cert.scopes.includes(scope)) return false;
  return true;
}

/** Fail-closed freshness (mirror status.rs Freshness::check): future-dated, older than the class, OR an
 *  unrecognized class ⇒ stale. In Rust `Freshness` is a closed enum so an unknown class cannot exist; here it
 *  arrives as a string, so an unrecognized value must fail CLOSED (stale), never accept. */
function freshnessStale(freshness: string, now: number, issuedAt: number): boolean {
  const max = FRESHNESS_MAX[freshness];
  if (max === undefined) return true; // unknown class → fail closed (review #7)
  if (issuedAt > now) return true; // future-dated → suspect → stale
  return now - issuedAt > max;
}

export interface StatusDelta {
  uri: string;
  fromSeq: number;
  seq: number;
  ts: number;
  idx: number[];
  newStatus: boolean;
  sigRegistrar: HybridSig;
  countersigDelegate: Uint8Array;
}
export interface FreshHead {
  uri: string;
  seq: number;
  ts: number;
  statusHash: Uint8Array;
  sigDelegate: Uint8Array;
}

function deltaSigningBytes(d: StatusDelta): Uint8Array {
  return new TextEncoder().encode(
    canonicalize({ from_seq: d.fromSeq, idx: d.idx, new_status: d.newStatus, seq: d.seq, ts: d.ts, uri: d.uri }),
  );
}
function freshHeadSigningBytes(h: FreshHead): Uint8Array {
  return new TextEncoder().encode(
    canonicalize({ seq: h.seq, status_hash: b64uEncode(h.statusHash), ts: h.ts, uri: h.uri }),
  );
}

/**
 * Verify a signed status delta. Returns null (accept) or the closed Reason (reject), in the SAME fixed order as
 * ainra-core StatusDelta::verify: structure → registrar hybrid sig → delegate cert → delegate countersig.
 */
export function verifyDelta(
  d: StatusDelta,
  registrarPub: HybridPublic,
  rootKey: Uint8Array,
  cert: DelegateCert,
  now: number,
): Reason | null {
  // (1) structure: single-step monotonic advance, strictly-ascending indices.
  if (d.seq !== d.fromSeq + 1 || d.seq === 0) return "stale_status";
  for (let i = 1; i < d.idx.length; i++) if (!(d.idx[i - 1] < d.idx[i])) return "stale_status";
  // canonicalization can reject an out-of-JS-range / non-integer signed field; Rust maps that signing-bytes error
  // to stale_status (status unavailable). Mirror it here instead of throwing (review #6).
  let msg: Uint8Array;
  try {
    msg = deltaSigningBytes(d);
  } catch {
    return "stale_status";
  }
  // (2) registrar hybrid signature (both-or-invalid).
  const h = verifyHybrid(registrarPub, msg, d.sigRegistrar);
  if (h) return h;
  // (3) delegate cert authorizes deltas, and (4) the countersignature verifies.
  if (!verifyDelegateCert(cert, rootKey, now, SCOPE_DELTA)) return "checkpoint_invalid";
  return ed25519Verify(cert.delegateEd25519, msg, d.countersigDelegate) ? null : "checkpoint_invalid";
}

/**
 * Verify a delegate-signed fresh head. Returns null (accept) or the Reason. Mirrors FreshHead::verify: cert (scope
 * fresh-head) → delegate signature → freshness. Does NOT bind to a held list (caller compares statusHash separately).
 */
export function verifyFreshHead(
  head: FreshHead,
  rootKey: Uint8Array,
  cert: DelegateCert,
  now: number,
  freshness: string,
): Reason | null {
  if (!verifyDelegateCert(cert, rootKey, now, SCOPE_FRESH_HEAD)) return "checkpoint_invalid";
  // Rust maps a fresh-head signing-bytes canon error to checkpoint_invalid; mirror it rather than throw (review #6).
  let msg: Uint8Array;
  try {
    msg = freshHeadSigningBytes(head);
  } catch {
    return "checkpoint_invalid";
  }
  if (!ed25519Verify(cert.delegateEd25519, msg, head.sigDelegate)) return "checkpoint_invalid";
  return freshnessStale(freshness, now, head.ts) ? "stale_status" : null;
}

/** SHA-256 head identity — mirrors StatusList::head_hash (canonical {bit_len, status_list, uri}). */
export function headHash(uri: string, bitLen: number, statusListB64: string): Uint8Array {
  return sha256(new TextEncoder().encode(canonicalize({ bit_len: bitLen, status_list: statusListB64, uri })));
}

/** The AINRA verify orchestrator — mirrors ainra-core::verify::verify step for step. Never throws; returns a Verdict. */
export function verify(pres: Presentation, anchors: TrustAnchors): Verdict {
  try {
    verifyInner(pres, anchors);
    return VALID;
  } catch (e) {
    if (e instanceof Reject) return invalid(e.reason);
    throw e;
  }
}

function verifyInner(pres: Presentation, anchors: TrustAnchors): void {
  // 1. schema gate
  const p = parseChecked(pres.claims);

  // 2. issuer registrar is accredited. `Object.hasOwn` (not truthiness) so an inherited member — e.g. the grammar-
  //    valid label "constructor" resolving to Object.prototype.constructor — can never masquerade as an anchor.
  const registrar = parseDidRegistrar(p.iss);
  if (registrar === null) throw new Reject("name_malformed");
  if (!Object.hasOwn(anchors, registrar)) throw new Reject("unknown_registrar");
  const reg = anchors[registrar];

  // 3. validity window
  if (pres.now < p.nbf) throw new Reject("not_yet_valid");
  if (pres.now >= p.exp) throw new Reject("expired");

  // 4. issuer hybrid signature
  const h = verifyHybrid(reg.issuerKey, pres.claims, pres.issuerSig);
  if (h) throw new Reject(h);

  // 5. scope ceiling
  if (!subset(p.capabilities, p.scope_ceiling)) throw new Reject("ceiling_exceeded");

  // 6. delegation chain: every hop DUAL-signed (delegator + delegatee, D-012), then monotone ∩-narrowing.
  if (p.act_chain.length > 0) {
    if (pres.chainKeys.length !== p.act_chain.length + 1) throw new Reject("schema_violation");
    if (pres.hopProofs.length !== p.act_chain.length) throw new Reject("schema_violation");
    for (let i = 0; i < p.act_chain.length; i++) {
      const hop = p.act_chain[i];
      const msg = hopSigningBytes(hop);
      const parent: HybridSig = { ed25519: b64uDecode(hop.sig_ed25519), mldsa65: b64uDecode(hop.sig_mldsa65) };
      const rp = verifyHybrid(pres.chainKeys[i], msg, parent);
      if (rp) throw new Reject(rp);
      const child: HybridSig = { ed25519: b64uDecode(hop.sig_child_ed25519), mldsa65: b64uDecode(hop.sig_child_mldsa65) };
      const rc = verifyHybrid(pres.chainKeys[i + 1], msg, child);
      if (rc) throw new Reject(rc);
    }
    let effCaps = p.act_chain[0].granted;
    let effExp = p.act_chain[0].exp;
    for (let i = 1; i < p.act_chain.length; i++) {
      const hop = p.act_chain[i];
      if (!subset(hop.granted, effCaps)) throw new Reject("chain_widening");
      if (hop.exp > effExp) throw new Reject("chain_expired");
      effCaps = hop.granted;
      effExp = hop.exp;
    }
    if (!subset(p.capabilities, effCaps)) throw new Reject("chain_widening");
    if (p.exp > effExp) throw new Reject("chain_expired");
  } else if (pres.chainKeys.length > 0 || pres.hopProofs.length > 0) {
    throw new Reject("schema_violation");
  }

  // 7. status: freshness then revocation
  const maxAge = FRESHNESS_MAX[pres.freshness];
  if (maxAge === undefined) throw new Reject("stale_status");
  if (pres.statusIssuedAt > pres.now || pres.now - pres.statusIssuedAt > maxAge) throw new Reject("stale_status");
  const idx = p.statusIdx;
  const revoked = statusBit(pres.statusBits, pres.statusBitLen, idx); // fail closed past the end
  if (revoked) throw new Reject("revoked");

  // 8. mandate subtree — the STATIC authenticated path in the signed passport. Dynamic (mandates_root) is M3 and is
  //    already rejected at the schema gate (D-013 revised), so no presenter-supplied path is honoured — must be empty.
  if (pres.mandatePath.length > 0 || pres.mandateProofs.length > 0) throw new Reject("schema_violation");
  checkMandatePath(p.mandates, pres.mandateRevocations);

  // 9. logged-before-valid: checkpoint sig (root/delegate), credential leaf binding+inclusion, then EVERY hop's
  //    log_leaf binding+inclusion.
  if (!verifyCheckpointSig(reg.logRootKey, pres.checkpoint, pres.checkpointSig, pres.now))
    throw new Reject("checkpoint_invalid");
  // Delegate revocation (M4): a checkpoint signed by a revoked delegate is checkpoint_invalid even though the cert
  // itself still verifies. Mirrors verify.rs — the revoked set comes from the dual-root-signed directory.
  if (pres.checkpointSig.mode === "delegate" && pres.revokedDelegates.has(certFingerprintB64(pres.checkpointSig.cert)))
    throw new Reject("checkpoint_invalid");
  const expectedLeaf = prelogLeaf(pres.claims);
  const claimedLeaf = b64uDecode(p.logLeaf);
  if (claimedLeaf.length !== 32 || !eqBytes(claimedLeaf, expectedLeaf)) throw new Reject("not_logged");
  if (!verifyInclusion(claimedLeaf, pres.leafIndex, pres.checkpoint.size, pres.inclusionProof, pres.checkpoint.root)) {
    throw new Reject("not_logged");
  }
  for (let i = 0; i < p.act_chain.length; i++) {
    const hop = p.act_chain[i];
    const anchored = b64uDecode(hop.log_leaf);
    const recomputed = hopLeaf(hop);
    if (anchored.length !== 32 || !eqBytes(anchored, recomputed)) throw new Reject("not_logged");
    const hp = pres.hopProofs[i];
    if (!verifyInclusion(anchored, hp.leafIndex, pres.checkpoint.size, hp.proof, pres.checkpoint.root))
      throw new Reject("not_logged");
  }
}

function prelogLeaf(claims: Uint8Array): Uint8Array {
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(Buffer.from(claims).toString("utf8")) as Record<string, unknown>;
  } catch {
    throw new Reject("schema_violation");
  }
  delete body.log;
  return hashLeaf(new TextEncoder().encode(canonicalize(body)));
}

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// ── Wire-vector runner (mirror tools/vector-gen run()) ─────────────────────────────────────────────────────────
interface WireKey {
  ed25519: string;
  mldsa65: string;
}
interface WireCheckpointSig {
  mode: string;
  slh?: string;
  cert?: { delegate_ed25519: string; scopes: string[]; nbf: number; exp: number; sig_slh: string };
  sig_ed25519?: string;
}
export interface WireVector {
  name: string;
  expect: { verdict: string; reason?: string };
  anchors: Record<string, { issuer_key: WireKey; log_root_key: string }>;
  presentation: {
    claims: string;
    issuer_sig: WireKey;
    now: number;
    chain_keys: WireKey[];
    hop_proofs: { leaf_index: number; proof: string[] }[];
    status_list: string;
    status_len: number;
    status_issued_at: number;
    freshness: string;
    // The registrar's SIGNED status publication (D-020). Present in a real `/present` bundle; optional here because
    // the self-contained conformance corpus (runVector) does not carry it — only the GA {@link Verifier} authenticates
    // it, against the directory's status key. `status_uri` is the URI the publication was signed over.
    status_uri?: string;
    status_sig_ed25519?: string;
    status_sig_mldsa65?: string;
    // The delegate-signed FRESH HEAD + its cert (D-021, M6). A currency-mode {@link Verifier} verifies the head,
    // binds it to the presented list by head-hash, and enforces its monotonic `seq` — closing genuine-snapshot
    // replay. Optional (absent in the conformance corpus and for default verifiers).
    fresh_head?: { uri: string; seq: number; ts: number; status_hash: string; sig_delegate: string };
    status_delegate_cert?: { delegate_ed25519: string; scopes: string[]; nbf: number; exp: number; sig_slh: string };
    checkpoint: { origin: string; size: number; root: string };
    checkpoint_sig: WireCheckpointSig;
    leaf_index: number;
    inclusion_proof: string[];
    mandate_revocations: string[];
    revoked_delegates?: string[];
  };
}

function decodeCheckpointSig(w: WireCheckpointSig): CheckpointSig {
  if (w.mode === "root") return { mode: "root", slh: b64uDecode(w.slh ?? "") };
  const c = w.cert!;
  return {
    mode: "delegate",
    cert: {
      delegateEd25519: b64uDecode(c.delegate_ed25519),
      scopes: c.scopes,
      nbf: c.nbf,
      exp: c.exp,
      sigSlh: b64uDecode(c.sig_slh),
    },
    sigEd25519: b64uDecode(w.sig_ed25519 ?? ""),
  };
}

/** A self-contained presentation the verifier checks: exactly a `WireVector`'s `presentation` block (no anchors —
 * those come from the trusted directory; and `now`/`revoked_delegates` on the wire are IGNORED by the GA
 * {@link Verifier}, which supplies its own clock + the directory's revocation set). */
export type PresentationBundle = WireVector["presentation"];

/** Decode a wire presentation into verify inputs. `now` and `revoked` are supplied by the CALLER (the verifier's
 * own clock + the trusted directory's revoked-delegate set) — a presenter cannot dictate either. Throws `Reject`
 * on a malformed status list (fail closed); other decode errors propagate for the caller's try/catch. */
function decodePresentation(pr: PresentationBundle, revoked: Set<string>, now: number): Presentation {
  return {
    claims: b64uDecode(pr.claims),
    issuerSig: { ed25519: b64uDecode(pr.issuer_sig.ed25519), mldsa65: b64uDecode(pr.issuer_sig.mldsa65) },
    now,
    chainKeys: pr.chain_keys.map((k) => ({ ed25519: b64uDecode(k.ed25519), mldsa65: b64uDecode(k.mldsa65) })),
    hopProofs: pr.hop_proofs.map((hp) => ({ leafIndex: hp.leaf_index, proof: hp.proof.map(b64uDecode) })),
    statusBits: unpackStatus(b64uDecode(pr.status_list), pr.status_len),
    statusBitLen: pr.status_len,
    statusIssuedAt: pr.status_issued_at,
    freshness: pr.freshness,
    checkpoint: { origin: pr.checkpoint.origin, size: pr.checkpoint.size, root: b64uDecode(pr.checkpoint.root), rootB64: pr.checkpoint.root },
    checkpointSig: decodeCheckpointSig(pr.checkpoint_sig),
    leafIndex: pr.leaf_index,
    inclusionProof: pr.inclusion_proof.map(b64uDecode),
    mandatePath: [],
    mandateProofs: [],
    mandateRevocations: new Set(pr.mandate_revocations),
    revokedDelegates: revoked,
  };
}

/** Reconstruct a wire vector into verify inputs and produce the verdict. A Reject thrown while DECODING the
 * presentation (e.g. a truncated status list — review #3) fails closed to that reason, never a crash. The vector
 * carries its own `now` + `revoked_delegates` (the conformance corpus is self-contained). */
export function runVector(v: WireVector): Verdict {
  try {
    const pr = v.presentation;
    const anchors: TrustAnchors = Object.create(null);
    for (const [id, r] of Object.entries(v.anchors)) {
      anchors[id] = {
        issuerKey: { ed25519: b64uDecode(r.issuer_key.ed25519), mldsa65: b64uDecode(r.issuer_key.mldsa65) },
        logRootKey: b64uDecode(r.log_root_key),
      };
    }
    // Canonicalise the trusted revoked-delegate fingerprints so the byte-set comparison against
    // `certFingerprintB64` is exact regardless of the wire encoding (review parity fix).
    const revoked = new Set(decodeFingerprints(pr.revoked_delegates ?? []) ?? (pr.revoked_delegates ?? []));
    return verify(decodePresentation(pr, revoked, pr.now), anchors);
  } catch (e) {
    if (e instanceof Reject) return invalid(e.reason);
    throw e;
  }
}

// ── The GA Verifier — the 5-line wedge (load a signed directory once, verify presentations against it) ───────────

/** A verifier's freshness policy — the maximum age it tolerates for a status publication. The VERIFIER chooses this
 *  (default F2 = 5 min); a presenter cannot downgrade it by advertising a laxer class in the bundle. */
export type FreshnessClass = "F1" | "F2" | "F3";

/**
 * Authenticate a presented status list against the registrar's directory-published status key (D-020). The presenter
 * supplies the compressed bitmap + `issued_at`, but they mean nothing until this proves the registrar signed *exactly*
 * those bytes. Three bindings, all fail-closed to `stale_status` (status unauthenticated ⇒ unavailable ⇒ fail closed):
 *   (a) the bundle carries a hybrid status signature (`status_sig_ed25519` + `status_sig_mldsa65`) and a `status_uri`;
 *   (b) the passport's claimed status URI, the bundle's signed URI, and the directory's published URI all agree —
 *       so a presenter cannot splice in another registrar's (all-clear) list;
 *   (c) the hybrid signature verifies over the canonical `{bit_len, issued_at, status_list, uri}` (mirrors the Rust
 *       `StatusSigning` body) under the registrar's status key.
 */
function authenticateStatus(info: RegistrarInfo, claimedUri: string, bundle: PresentationBundle): void {
  const uri = bundle.status_uri;
  const sigEd = bundle.status_sig_ed25519;
  const sigMl = bundle.status_sig_mldsa65;
  if (typeof uri !== "string" || typeof sigEd !== "string" || typeof sigMl !== "string")
    throw new Reject("stale_status"); // (a) no signed publication ⇒ cannot authenticate ⇒ fail closed
  // (b) triple URI binding (info.statusUri is guaranteed present when info.statusKey is).
  if (uri !== info.statusUri || claimedUri !== info.statusUri) throw new Reject("stale_status");
  const ed = strictB64u(sigEd);
  const ml = strictB64u(sigMl);
  if (ed === null || ml === null) throw new Reject("stale_status");
  let signing: Uint8Array;
  try {
    signing = new TextEncoder().encode(
      canonicalize({ bit_len: bundle.status_len, issued_at: bundle.status_issued_at, status_list: bundle.status_list, uri }),
    );
  } catch {
    throw new Reject("stale_status");
  }
  // (c) any hybrid-verify failure (bad sig or algorithm downgrade) ⇒ status unauthenticated ⇒ fail closed.
  if (verifyHybrid(info.statusKey as HybridPublic, signing, { ed25519: ed, mldsa65: ml })) throw new Reject("stale_status");
}

/**
 * Currency check (D-021, M6 — **currency mode only**). Authenticating the status list proves the registrar signed it
 * and bounds its age; this additionally proves it is the CURRENT head, closing genuine-snapshot **replay**. It
 * verifies the bundle's delegate-signed **fresh head** (cert → the registrar's log root, delegate signature, F1
 * recency), binds the head to the presented list by **head-hash**, and enforces a **monotonic `seq`** across
 * presentations — a seq lower than one already observed for this uri is a replay of a superseded head.
 *
 * HONEST LIMIT: the monotonic-seq check closes replay only for a verifier that OBSERVES the head advance — one that
 * has already verified a newer presentation (e.g. a shared gateway where some party presents the current head), or
 * that independently polls the registrar's fresh head. A purely passive verifier only ever shown the stale head
 * cannot know a newer one exists; the F1 (≤30 s) freshness still bounds that residual window. All failures fail
 * closed to `stale_status`.
 */
function authenticateCurrency(
  info: RegistrarInfo,
  bundle: PresentationBundle,
  now: number,
  seqSeen: Map<string, number>,
): void {
  const fh = bundle.fresh_head;
  const wc = bundle.status_delegate_cert;
  if (!fh || !wc) throw new Reject("stale_status"); // currency mode REQUIRES a fresh head (an absent one can't downgrade)
  const statusHash = strictB64u(fh.status_hash);
  const sigDelegate = strictB64u(fh.sig_delegate);
  const dEd = strictB64u(wc.delegate_ed25519);
  const dSlh = strictB64u(wc.sig_slh);
  if (statusHash === null || sigDelegate === null || dEd === null || dSlh === null) throw new Reject("stale_status");
  if (
    typeof fh.uri !== "string" ||
    !Number.isInteger(fh.seq) || fh.seq < 0 ||
    !Number.isInteger(fh.ts) ||
    !Number.isInteger(wc.nbf) || !Number.isInteger(wc.exp) ||
    !Array.isArray(wc.scopes) || wc.scopes.some((s) => typeof s !== "string")
  ) {
    throw new Reject("stale_status");
  }
  const head: FreshHead = { uri: fh.uri, seq: fh.seq, ts: fh.ts, statusHash, sigDelegate };
  const cert: DelegateCert = { delegateEd25519: dEd, scopes: wc.scopes, nbf: wc.nbf, exp: wc.exp, sigSlh: dSlh };
  // (1) fresh head verifies to the registrar's log root, F1-recent (cert scope fresh-head, delegate sig, ts window).
  if (verifyFreshHead(head, info.logRootKey, cert, now, "F1")) throw new Reject("stale_status");
  // (2) the head names THIS registrar's status uri (already bound to info.statusUri via authenticateStatus).
  if (head.uri !== info.statusUri) throw new Reject("stale_status");
  // (3) head-hash binding: the fresh head must name the EXACT list being presented (bit_len + compressed bytes + uri).
  if (!eqBytes(headHash(head.uri, bundle.status_len, bundle.status_list), statusHash)) throw new Reject("stale_status");
  // (4) monotonic seq: a lower seq than one already observed for this uri is a replay of a superseded head.
  const seen = seqSeen.get(head.uri);
  if (seen !== undefined && head.seq < seen) throw new Reject("stale_status");
  seqSeen.set(head.uri, seen === undefined ? head.seq : Math.max(seen, head.seq));
}


/**
 * A ready-to-use AINRA verifier. Build it once from a **dual-root-signed directory** (which supplies the trust
 * anchors + the revoked-delegate set), then `.verify(bundle, now)` any number of presentations. Everything is
 * local, offline, and fail-closed: a malformed directory yields `null` from {@link fromDirectory}; a malformed or
 * failing presentation yields an `invalid` Verdict, never a throw, never a wrong `valid`.
 *
 * ```ts
 * import { Verifier } from "@ainra/sdk";
 * const verifier = Verifier.fromDirectory(directory, rootEd25519, rootSlh);   // 1. trust, once
 * if (!verifier) throw new Error("untrusted directory");                      // 2. fail closed
 * const verdict = verifier.verify(bundle, Math.floor(Date.now() / 1000));     // 3. verify, per request
 * if (verdict.verdict !== "valid") deny(verdict.reason);                      // 4. act
 * ```
 *
 * The verifier — never the presenter — owns three trust inputs: its own **clock** (`now`), the directory's
 * **revoked-delegate** set, and its **freshness policy**. It also authenticates the presented **status list**
 * against the registrar's directory-published status key before trusting a single revocation bit (D-020), and
 * ignores any presenter-supplied mandate-revocation set. A presenter therefore cannot **forge** an all-clear status,
 * downgrade freshness, or drop a mandate revocation to make a dead passport verify.
 *
 * **Freshness bounds revocation LATENCY, not currency.** The status list is a stapled, registrar-signed *snapshot*;
 * the verifier proves its signature and that it is no older than the freshness class, but not that it is the *latest*
 * one. So a presenter CAN replay a genuine snapshot taken *before* its lineage was revoked, and it will verify VALID
 * until that snapshot ages out of the window (F1 ≤30 s · F2 ≤5 min · F3 ≤24 h) — the same replay-within-validity that
 * OCSP stapling has. Pick **F1** for hot revocation paths. **Currency mode** (`currency: true`) goes further: it
 * requires the bundle's delegate-signed **fresh head**, binds it to the presented list by head-hash, and enforces a
 * **monotonic head sequence** — so once this verifier has observed a newer head (from any presentation, or an
 * out-of-band poll), a replayed superseded snapshot is rejected. It is stateful (keeps a per-uri max seq).
 */
export class Verifier {
  readonly anchors: TrustAnchors;
  readonly revokedDelegates: Set<string>;
  readonly epoch: number;
  /** The verifier's freshness policy (default F2 = 5 min). The presenter's advertised class is ignored. */
  readonly freshness: FreshnessClass;
  /** Currency mode: require + verify + head-hash-bind the fresh head and enforce a monotonic seq (D-021, M6). */
  readonly currency: boolean;
  /** Per-uri highest fresh-head `seq` this verifier has observed (currency mode). A lower seq is a replay. */
  private readonly seqSeen: Map<string, number> = new Map();
  private constructor(acc: AccreditedSet, freshness: FreshnessClass, currency: boolean) {
    this.anchors = acc.anchors;
    this.revokedDelegates = acc.revokedDelegates;
    this.epoch = acc.epoch;
    this.freshness = freshness;
    this.currency = currency;
  }
  /** Verify the dual-root-signed directory and build a Verifier; `null` if the directory is not authentic.
   *  `freshness` sets the verifier's own status-freshness policy (default `"F2"` = 5 min). `currency` (default
   *  `false`) enables the fresh-head + monotonic-seq replay defence (see the class docs). */
  static fromDirectory(
    d: WireDirectory,
    rootEd25519: Uint8Array,
    rootSlh: Uint8Array,
    freshness: FreshnessClass = "F2",
    currency = false,
  ): Verifier | null {
    const acc = verifyDirectory(d, rootEd25519, rootSlh);
    return acc === null ? null : new Verifier(acc, freshness, currency);
  }
  /** Convenience: build from a directory + the ceremony's base64url root keys (as published in `roots.json`). */
  static fromDirectoryB64(
    d: WireDirectory,
    rootEd25519B64: string,
    rootSlhB64: string,
    freshness: FreshnessClass = "F2",
    currency = false,
  ): Verifier | null {
    let ed: Uint8Array, slh: Uint8Array;
    try {
      ed = b64uDecode(rootEd25519B64);
      slh = b64uDecode(rootSlhB64);
    } catch {
      return null;
    }
    return Verifier.fromDirectory(d, ed, slh, freshness, currency);
  }
  /** Verify one presentation at the verifier's own `now` (unix seconds). The verifier supplies the clock, the
   * directory's revoked-delegate set, its own freshness policy, and an EMPTY mandate-revocation set; and it
   * authenticates the presented status list against the registrar's directory status key before trusting any bit.
   * The presenter cannot dictate any of these. Never throws. */
  verify(bundle: PresentationBundle, now: number): Verdict {
    try {
      // Steps 1–2 up front, on CHEAP inputs only — decode the small claims blob, resolve the registrar, and
      // AUTHENTICATE the status signature over the *compressed* bytes (a signature over the b64 string; no inflate).
      // Doing this before decodePresentation means an unauthenticated presenter fails here, BEFORE the status list is
      // ever decompressed — so a compression-amplification DoS (a tiny blob that inflates to a huge bitmap) can never
      // allocate. Only a list the registrar genuinely signed is decompressed (and even then bounded, see unpackStatus).
      const p = parseChecked(b64uDecode(bundle.claims)); // throws Reject (correct reason) on a malformed passport
      const registrar = parseDidRegistrar(p.iss);
      if (registrar === null) throw new Reject("name_malformed");
      if (!Object.hasOwn(this.anchors, registrar)) throw new Reject("unknown_registrar");
      const info = this.anchors[registrar];
      // An accredited registrar with no status key cannot have its revocations authenticated → fail closed. Every
      // real directory entry carries a status key, so this only bites a malformed/legacy directory.
      if (!info.statusKey) throw new Reject("stale_status");
      authenticateStatus(info, p.statusUri, bundle); // over compressed bytes — no decompression yet
      // Currency mode (D-021): additionally require+verify the fresh head, bind it to this list, enforce monotonic
      // seq — closing genuine-snapshot replay. Also cheap (no decompression). Fails closed to stale_status.
      if (this.currency) authenticateCurrency(info, bundle, now, this.seqSeen);

      // The status list is now proven to be exactly what the registrar signed; decompress it and run full verify.
      const pres = decodePresentation(bundle, this.revokedDelegates, now);
      // Presenter-controlled fields the verifier MUST override (fail-safe defaults, not the bundle's word):
      //  · mandate revocations — a presenter must not be able to drop a revocation; M5 GA has no dynamic mandate
      //    feed, so the authenticated set is empty (static mandates in the signed passport are still enforced).
      pres.mandateRevocations = new Set();
      //  · freshness class — the verifier's policy, so a presenter cannot advertise a laxer class to dodge staleness.
      //    NOTE: freshness bounds revocation LATENCY (a genuine, registrar-signed status is trusted until it ages out
      //    of this class); it does not prove currency. A presenter can replay a genuine pre-revocation snapshot until
      //    it exceeds the window — that is the stapled-snapshot model's inherent latency, closed to sub-window by the
      //    (M6) fresh-head binding. Choose F1 for hot revocation paths.
      pres.freshness = this.freshness;
      return verify(pres, this.anchors);
    } catch (e) {
      if (e instanceof Reject) return invalid(e.reason);
      // A structurally-broken bundle (missing field, bad base64) fails closed, never a crash or a wrong valid.
      return invalid("schema_violation");
    }
  }
}

/** The expected verdict recorded in a wire vector, as a comparable Verdict. */
export function expectedVerdict(v: WireVector): Verdict {
  return v.expect.verdict === "valid" ? VALID : invalid(v.expect.reason as Reason);
}

// ── Delta / fresh-head conformance vectors (mirror tools/vector-gen delta corpus) ───────────────────────────────
interface WireDeltaCert {
  delegate_ed25519: string;
  scopes: string[];
  nbf: number;
  exp: number;
  sig_slh: string;
}
function decodeDeltaCert(c: WireDeltaCert): DelegateCert {
  return {
    delegateEd25519: b64uDecode(c.delegate_ed25519),
    scopes: c.scopes,
    nbf: c.nbf,
    exp: c.exp,
    sigSlh: b64uDecode(c.sig_slh),
  };
}
export interface WireDeltaVector {
  name: string;
  kind: "delta" | "fresh_head";
  expect: { accept: boolean; reason?: string };
  root_pub_slh: string;
  cert: WireDeltaCert;
  now: number;
  // delta fields
  registrar_pub?: WireKey;
  uri?: string;
  from_seq?: number;
  seq?: number;
  ts?: number;
  idx?: number[];
  new_status?: boolean;
  sig_registrar?: WireKey;
  countersig_delegate?: string;
  // fresh-head fields
  status_hash?: string;
  sig_delegate?: string;
  freshness?: string;
}

/** The accept/reason a delta or fresh-head vector reduces to under the sdk-ts verifier — the diff-harness compares
 *  this to the ainra-core-baked `expect`. */
export function runDeltaVector(v: WireDeltaVector): { accept: boolean; reason?: string } {
  const rootKey = b64uDecode(v.root_pub_slh);
  const cert = decodeDeltaCert(v.cert);
  let r: Reason | null;
  if (v.kind === "delta") {
    const delta: StatusDelta = {
      uri: v.uri!,
      fromSeq: v.from_seq!,
      seq: v.seq!,
      ts: v.ts!,
      idx: v.idx!,
      newStatus: v.new_status!,
      sigRegistrar: { ed25519: b64uDecode(v.sig_registrar!.ed25519), mldsa65: b64uDecode(v.sig_registrar!.mldsa65) },
      countersigDelegate: b64uDecode(v.countersig_delegate!),
    };
    const registrarPub: HybridPublic = {
      ed25519: b64uDecode(v.registrar_pub!.ed25519),
      mldsa65: b64uDecode(v.registrar_pub!.mldsa65),
    };
    r = verifyDelta(delta, registrarPub, rootKey, cert, v.now);
  } else {
    const head: FreshHead = {
      uri: v.uri!,
      seq: v.seq!,
      ts: v.ts!,
      statusHash: b64uDecode(v.status_hash!),
      sigDelegate: b64uDecode(v.sig_delegate!),
    };
    r = verifyFreshHead(head, rootKey, cert, v.now, v.freshness ?? "F1");
  }
  return r === null ? { accept: true } : { accept: false, reason: r };
}

// ── Signed registrar directory (mirror ainra-core::directory) ───────────────────────────────────────────────────
export interface WireDirectoryEntry {
  registrar: string;
  issuer_ed25519: string;
  issuer_mldsa65: string;
  log_root_slh: string;
  /** base64url status-signing hybrid public key (D-020). `#[serde(default)]` on the Rust side ⇒ may be "" (a legacy
   *  entry with no status authentication); such a registrar's passports fail closed in the GA {@link Verifier}. */
  status_ed25519?: string;
  status_mldsa65?: string;
  status_uri: string;
}
export interface WireDirectory {
  epoch: number;
  issued_at: number;
  entries: WireDirectoryEntry[];
  revoked_delegates?: string[];
  sig_root_ed25519: string;
  sig_root_slh: string;
}

/** The authenticated result of verifying a directory: trust anchors + the revoked-delegate fingerprint set. */
export interface AccreditedSet {
  anchors: TrustAnchors;
  revokedDelegates: Set<string>;
  epoch: number;
}

/**
 * Verify a directory against BOTH ceremony root public keys (FROST-Ed25519 group key + SLH-DSA root) and turn it
 * into trust anchors + a revoked-delegate set. Returns null on any failure (the caller maps that to
 * `unknown_registrar`: no authentic directory ⇒ no registrar known). Mirrors `Directory::accredit` step for step:
 * (1) FROST/Ed25519 root sig, (2) SLH-DSA root sig — both required, (3) entries strictly sorted+unique.
 */
export function verifyDirectory(d: WireDirectory, rootEd25519: Uint8Array, rootSlh: Uint8Array): AccreditedSet | null {
  const revoked = d.revoked_delegates ?? [];
  // canonicalize can throw on an out-of-JS-range signed field (e.g. epoch > 2^53); Rust maps that signing-bytes
  // error to unknown_registrar (reject). Mirror it — never throw.
  let msg: Uint8Array;
  try {
    msg = new TextEncoder().encode(
      canonicalize({ entries: d.entries, epoch: d.epoch, issued_at: d.issued_at, revoked_delegates: revoked }),
    );
  } catch {
    return null;
  }
  // (1) FROST/Ed25519 root signature.
  let edSig: Uint8Array;
  try {
    edSig = b64uDecode(d.sig_root_ed25519);
  } catch {
    return null;
  }
  if (edSig.length !== 64 || !ed25519Verify(rootEd25519, msg, edSig)) return null;
  // (2) SLH-DSA root signature — BOTH must verify.
  let slhSig: Uint8Array;
  try {
    slhSig = b64uDecode(d.sig_root_slh);
  } catch {
    return null;
  }
  if (!slhVerify(rootSlh, msg, slhSig)) return null;
  // (3) registrar ids MUST be ASCII (parity: Rust's UTF-8 String Ord vs JS UTF-16 order agree only on ASCII), then
  // strictly sorted + unique.
  for (const e of d.entries) if (e.registrar.length === 0 || !/^[\x00-\x7f]*$/.test(e.registrar)) return null;
  for (let i = 1; i < d.entries.length; i++) {
    if (d.entries[i - 1].registrar >= d.entries[i].registrar) return null;
  }
  const anchors: TrustAnchors = Object.create(null);
  for (const e of d.entries) {
    // STRICT base64url (Rust `b64::decode` rejects any non-alphabet char; Node's Buffer.from is lenient — parity).
    const ed = strictB64u(e.issuer_ed25519);
    const ml = strictB64u(e.issuer_mldsa65);
    const lr = strictB64u(e.log_root_slh);
    if (ed === null || ml === null || lr === null) return null;
    if (ed.length !== 32) return null;
    const info: RegistrarInfo = { issuerKey: { ed25519: ed, mldsa65: ml }, logRootKey: lr };
    // Status-signing key (D-020) — extracted opportunistically. It does NOT participate in the directory-accept
    // decision (Rust `Directory::accredit` ignores these fields entirely, so phase-E accept/reject stays byte-parity);
    // a status key is set ONLY when both halves decode to a well-formed key AND a non-empty URI binds it. Anything
    // else leaves it unset → the GA Verifier fails that registrar's passports closed (`stale_status`), never open.
    const sEd = strictB64u(e.status_ed25519 ?? "");
    const sMl = strictB64u(e.status_mldsa65 ?? "");
    if (sEd !== null && sEd.length === 32 && sMl !== null && sMl.length > 0 && e.status_uri.length > 0) {
      info.statusKey = { ed25519: sEd, mldsa65: sMl };
      info.statusUri = e.status_uri;
    }
    anchors[e.registrar] = info;
  }
  // (4) revoked-delegate fingerprints: decode + length-check each, fail closed on a malformed one (Rust parity).
  const revNorm = decodeFingerprints(revoked);
  if (revNorm === null) return null;
  return { anchors, revokedDelegates: new Set(revNorm), epoch: d.epoch };
}

/** Directory conformance vector (mirror the vector-gen directory corpus): accept + registrar count, or reject. */
export interface WireDirectoryVector {
  name: string;
  expect: { accept: boolean; registrars?: number };
  directory: WireDirectory;
  root_ed25519: string;
  root_slh: string;
}
export function runDirectoryVector(v: WireDirectoryVector): { accept: boolean; registrars?: number } {
  const acc = verifyDirectory(v.directory, b64uDecode(v.root_ed25519), b64uDecode(v.root_slh));
  if (acc === null) return { accept: false };
  return { accept: true, registrars: Object.keys(acc.anchors).length };
}
