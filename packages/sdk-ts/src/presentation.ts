// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// RFC 9421 HTTP Message Signatures for an AINRA presentation (D-062, PLAN-M34).
//
// WHY THIS EXISTS. Until now a presentation was a bundle in a header, and a header is a bearer token: the same
// captured bundle verified three times out of three against the shipped middleware, with nothing in the verdict
// naming a method, an authority, a path, a nonce or a time. The threat model has named that gap since it was
// written — T-P3, replay of presentation, mitigation "RFC 9421 nonce+created, 5-min window, nonce cache" — and
// nothing implemented it.
//
// WHO SIGNS (D-062). The RUNNING COPY's instance key signs, and `keyid` names the instance credential, which names
// the passport. The passport's control key never enters a container (ADR-019), so it cannot be the key that signs
// production traffic; the Standard said otherwise and was amended (docs/AMENDMENTS.md, 2026-09-23).
//
// WHAT IT BUYS, AND WHAT IT DOES NOT. Binding covers one method, one authority, one path and — when there is a
// body — its digest, inside a five-minute window. It does NOT eliminate replay: inside that window, against that
// exact target, a captured signature is still usable by whoever captured it. `seenNonce` lets a caller close the
// window completely; `ainra-core` is N7 and holds no state, so the cache cannot live here. This is the same honest
// limit ADR-019 records for the instance PoP nonce, and it is said out loud rather than left to be inferred.
//
// STRICTNESS. This parses exactly the profile AINRA emits and refuses everything else, rather than implementing
// all of RFC 8941. A permissive parser at the front door of a trust root is a liability, and a narrow one that
// fails closed is honest about what it accepts. Widening it to other producers is a later decision with its own
// vectors, not a quiet relaxation here.

import { b64uEncode, b64uDecode, verifyHybrid, sha256, ED25519_SIG, MLDSA65_SIG } from "./crypto.js";
import type { HybridPublic, HybridSig } from "./crypto.js";
import { canonicalize } from "./canon.js";

/** The failure names this layer can return. Distinct from the frozen credential reasons on purpose: telling an
 *  integrator `sig_invalid` when the registrar's signature is fine and the REQUEST signature was merely moved to
 *  another path sends them to the wrong half of the system (the D-047 rule — a reason string is a contract). */
export type PresentationReason =
  | "presentation_unsigned"
  | "presentation_sig_invalid"
  | "presentation_stale"
  | "presentation_replayed"
  /** M36 (D-065): the request named a bundle by digest that this gate does not hold — never sent, evicted, or
   *  expired. Not a judgement of the agent: the answer is to send the bundle again, not to distrust anyone. */
  | "presentation_unknown";

export type PresentationCheck = { ok: true; nonce: string; created: number } | { ok: false; reason: PresentationReason };

/** The label AINRA signs under. RFC 9421 allows several signatures on one message; this one is ours. */
export const SIG_LABEL = "ainra";
/** Private-use algorithm name: both signatures, concatenated at fixed lengths. No registered identifier covers a
 *  hybrid, and naming it `ed25519` would describe half of what was verified. */
export const SIG_ALG = "ainra-hybrid-v1";
/** The header a presentation bundle travels in — covered by the signature, so the bundle cannot be swapped. */
export const PRESENTATION_HEADER = "x-ainra-passport";
// ── M36 (D-065): the bundle is sent once, and named by digest after that ─────────────────────────────────────────
//
// A full bundle is ~60 KiB — post-quantum signatures, delegate certificates, a log proof, a status list — and it
// rode in one request header. `make identity-e2e` measured 66.7 KiB of headers per request; common front ends
// refuse a single header line over 8 KiB (Apache's LimitRequestFieldSize, nginx's large_client_header_buffers) and
// Node refuses 16 KiB in total. The protocol worked only on a server told to accept 256 KiB.
//
// So the part of the bundle that stays the same for the credential's lifetime is sent ONCE, to PRIME_PATH, where
// the gate verifies it in full and keeps it; each request then carries its digest in PRESENTATION_HEADER, the
// per-request proof of possession in POP_HEADER, and the RFC 9421 signature. The signature still covers
// PRESENTATION_HEADER, and a SHA-256 digest names exactly one bundle, so binding the digest binds the bundle.
// The gate reassembles the full bundle and runs every check it always ran: nothing is verified less.

/** Where a running copy sends its bundle once. */
export const PRIME_PATH = "/.well-known/ainra-presentation";
/** The per-request proof of possession. Its freshness window is 30 s (POP_MAX_SKEW_SECS), so it cannot be sent once
 *  with the rest; it is small (one hybrid signature) and travels on its own. */
export const POP_HEADER = "x-ainra-pop";

const REF_RE = /^sha-256=:[A-Za-z0-9+/]{43}=:$/;

/** Is this header value a digest reference (`sha-256=:<base64>:`, RFC 9530 syntax) rather than a bundle? */
export function isPresentationRef(v: string): boolean {
  return REF_RE.test(v.trim());
}

type Bundle = Record<string, unknown> & { instance?: Record<string, unknown> };

/** Split a bundle into the part that holds for the credential's lifetime and the per-request proof of possession.
 *  Neither input is modified. `pop` is null for a passport presented directly (no running-copy credential). */
export function splitPresentation(bundle: Bundle): { stable: Bundle; pop: unknown | null } {
  if (!bundle.instance || typeof bundle.instance !== "object") return { stable: { ...bundle }, pop: null };
  const { pop, ...instance } = bundle.instance as Record<string, unknown>;
  return { stable: { ...bundle, instance }, pop: pop ?? null };
}

/** The inverse of `splitPresentation`: the full bundle the verifier checks. */
export function joinPresentation(stable: Bundle, pop: unknown | null): Bundle {
  if (pop === null || pop === undefined || !stable.instance) return { ...stable };
  return { ...stable, instance: { ...stable.instance, pop } };
}

/** The digest that names a bundle's stable part — over its canonical JSON, so key order and whitespace do not
 *  matter, and with the proof of possession excluded, so it stays the same from one request to the next. */
export function presentationRef(bundle: Bundle): string {
  const { stable } = splitPresentation(bundle);
  return `sha-256=:${b64std(sha256(enc.encode(canonicalize(stable))))}:`;
}

/** Acceptance window (MTS T-P3). A signature older than this is stale however valid it is. */
export const MAX_AGE_SECS = 300;
/** Tolerance for a signer whose clock runs ahead — the freshness tolerance of ADR-016, never a validity window. */
export const MAX_FUTURE_SECS = 30;

/** The request, reduced to what gets signed. Deliberately not a framework type: the middleware, an edge worker and
 *  a test all have different request objects, and all of them can produce these five fields. */
export interface SignableRequest {
  method: string;
  /** host, or host:port — never a scheme, never a path. */
  authority: string;
  /** Path with its query, exactly as sent. */
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body?: Uint8Array;
}

const enc = new TextEncoder();

function headerValue(h: SignableRequest["headers"], name: string): string | null {
  for (const k of Object.keys(h)) {
    if (k.toLowerCase() !== name) continue;
    const v = h[k];
    if (v === undefined) return null;
    // RFC 9421 §2.1: multiple field lines combine with ", "; values are trimmed of leading/trailing whitespace.
    return (Array.isArray(v) ? v.join(", ") : String(v)).trim();
  }
  return null;
}

/** Standard base64, which is what an RFC 8941 byte sequence carries — not the base64url used everywhere else in
 *  this SDK. Derived from the url-safe encoder so there is one encoder, not two. */
function b64std(bytes: Uint8Array): string {
  const u = b64uEncode(bytes).replace(/-/g, "+").replace(/_/g, "/");
  return u + "=".repeat((4 - (u.length % 4)) % 4);
}
function b64stdDecode(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return null;
  try { return b64uDecode(s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")); } catch { return null; }
}

/** `sha-256=:<base64>:` — RFC 9530, the digest a signature covers so a body cannot be swapped under it.
 *  Synchronous, like every other hash in this SDK: a verifier that must be awaited is awkward at an edge gate,
 *  and `sha256` here is the same implementation the log proofs use. */
export function contentDigest(body: Uint8Array): string {
  return `sha-256=:${b64std(sha256(body))}:`;
}

/** The components AINRA covers, in order. `content-digest` is included only when there is a body — a signature
 *  that claims to cover a digest of nothing is worse than one that says it covered nothing. */
export function coveredComponents(hasBody: boolean): string[] {
  return hasBody
    ? ["@method", "@authority", "@path", "content-digest", PRESENTATION_HEADER]
    : ["@method", "@authority", "@path", PRESENTATION_HEADER];
}

export interface SigParams { created: number; keyid: string; nonce: string }

/** RFC 9421 §2.5. Every covered component on its own line, `@signature-params` last and with no trailing newline.
 *  Returns null when a covered component is absent from the request — an unsignable request, not a signable one. */
export function signatureBase(req: SignableRequest, components: string[], p: SigParams): string | null {
  const lines: string[] = [];
  for (const c of components) {
    let v: string | null;
    if (c === "@method") v = req.method.toUpperCase();
    else if (c === "@authority") v = req.authority.toLowerCase();
    else if (c === "@path") v = req.path;
    else if (c.startsWith("@")) return null;            // no other derived component is in the profile
    else v = headerValue(req.headers, c);
    if (v === null) return null;
    lines.push(`"${c}": ${v}`);
  }
  const list = components.map((c) => `"${c}"`).join(" ");
  lines.push(`"@signature-params": (${list});created=${p.created};keyid="${p.keyid}";alg="${SIG_ALG}";nonce="${p.nonce}"`);
  return lines.join("\n");
}

/** Sign a request with the running copy's instance key.
 *
 *  `keyid` is the instance credential's `iid`: the signature names the credential, the credential names the
 *  passport, and the verifier walks the chain it already walks. `nonce` must be fresh per request — this binds it
 *  so single use CAN be enforced, and enforces nothing itself. */
export async function signPresentation(args: {
  req: SignableRequest;
  keyid: string;
  nonce: string;
  created: number;
  instanceSign: (msg: Uint8Array) => Promise<HybridSig> | HybridSig;
}): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  const headers = { ...args.req.headers };
  if (args.req.body && args.req.body.length) {
    out["content-digest"] = contentDigest(args.req.body);
    headers["content-digest"] = out["content-digest"];
  }
  const components = coveredComponents(Boolean(args.req.body && args.req.body.length));
  const p: SigParams = { created: args.created, keyid: args.keyid, nonce: args.nonce };
  const base = signatureBase({ ...args.req, headers }, components, p);
  if (base === null) throw new Error(`cannot sign: a covered component is missing (${components.join(", ")})`);
  const sig = await args.instanceSign(enc.encode(base));
  if (sig.ed25519.length !== ED25519_SIG || sig.mldsa65.length !== MLDSA65_SIG)
    throw new Error("instanceSign returned a non-hybrid signature — both halves are mandatory (D-047)");
  const joined = new Uint8Array(ED25519_SIG + MLDSA65_SIG);
  joined.set(sig.ed25519, 0);
  joined.set(sig.mldsa65, ED25519_SIG);
  out["signature-input"] = `${SIG_LABEL}=(${components.map((c) => `"${c}"`).join(" ")});created=${p.created};keyid="${p.keyid}";alg="${SIG_ALG}";nonce="${p.nonce}"`;
  out["signature"] = `${SIG_LABEL}=:${b64std(joined)}:`;
  return out;
}

/** The exact shape this profile emits, and nothing else. A looser parser here would accept signatures this
 *  implementation cannot reason about. */
const INPUT_RE = new RegExp(
  `^${SIG_LABEL}=\\(([^)]*)\\);created=(\\d{1,15});keyid="([^"]{1,64})";alg="([^"]{1,32})";nonce="([A-Za-z0-9._~-]{1,128})"$`,
);

/** Verify the signature over a request.
 *
 *  Returns the nonce and `created` on success so a caller can keep the replay cache this layer deliberately does
 *  not keep. Pass `seenNonce` and single use is enforced; omit it and a captured signature remains replayable
 *  against the same target inside the window. */
export function verifyPresentation(args: {
  req: SignableRequest;
  /** The instance credential the presentation carries — its `iid` must be what `keyid` names, and its public key
   *  is what verifies the signature. */
  instance: { iid: string; ikey: HybridPublic };
  now: number;
  maxAgeSecs?: number;
  seenNonce?: (nonce: string) => boolean;
}): PresentationCheck {
  const input = headerValue(args.req.headers, "signature-input");
  const signature = headerValue(args.req.headers, "signature");
  if (input === null || signature === null) return { ok: false, reason: "presentation_unsigned" };

  const m = INPUT_RE.exec(input);
  if (!m) return { ok: false, reason: "presentation_sig_invalid" };
  const [, listRaw, createdRaw, keyid, alg, nonce] = m;
  if (alg !== SIG_ALG) return { ok: false, reason: "presentation_sig_invalid" };
  if (keyid !== args.instance.iid) return { ok: false, reason: "presentation_sig_invalid" };

  const components = listRaw.length ? listRaw.split(" ").map((s) => s.replace(/^"|"$/g, "")) : [];
  const hasBody = Boolean(args.req.body && args.req.body.length);
  const required = coveredComponents(hasBody);
  // Exact set AND order: a signature that covers a different set is not a weaker signature over this request, it
  // is a signature over a different message.
  if (components.length !== required.length || components.some((c, i) => c !== required[i]))
    return { ok: false, reason: "presentation_sig_invalid" };

  const created = Number(createdRaw);
  const age = args.now - created;
  if (age > (args.maxAgeSecs ?? MAX_AGE_SECS) || -age > MAX_FUTURE_SECS) return { ok: false, reason: "presentation_stale" };

  if (hasBody) {
    const expected = contentDigest(args.req.body as Uint8Array);
    if (headerValue(args.req.headers, "content-digest") !== expected)
      return { ok: false, reason: "presentation_sig_invalid" };
  }

  const sigField = new RegExp(`^${SIG_LABEL}=:([A-Za-z0-9+/]+={0,2}):$`).exec(signature);
  if (!sigField) return { ok: false, reason: "presentation_sig_invalid" };
  const raw = b64stdDecode(sigField[1]);
  if (!raw || raw.length !== ED25519_SIG + MLDSA65_SIG) return { ok: false, reason: "presentation_sig_invalid" };

  const base = signatureBase(args.req, components, { created, keyid, nonce });
  if (base === null) return { ok: false, reason: "presentation_sig_invalid" };
  const sig: HybridSig = { ed25519: raw.slice(0, ED25519_SIG), mldsa65: raw.slice(ED25519_SIG) };
  if (verifyHybrid(args.instance.ikey, enc.encode(base), sig) !== null)
    return { ok: false, reason: "presentation_sig_invalid" };

  // Last, and only after the signature is known good: a nonce check before verification would let an unauthenticated
  // caller fill someone else's cache.
  if (args.seenNonce && args.seenNonce(nonce)) return { ok: false, reason: "presentation_replayed" };
  return { ok: true, nonce, created };
}
