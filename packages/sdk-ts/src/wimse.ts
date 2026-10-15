// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// WIMSE beside AINRA (D-076) — an AINRA running copy as a standard IETF workload, plus the one thing WIMSE lacks.
//
// The IETF's agent-identity work (draft-ietf-wimse-aims, built on draft-ietf-wimse-workload-creds and
// draft-ietf-wimse-http-signature) gives a workload a short-lived Workload Identity Token (WIT) that binds its key, and
// has it sign each HTTP request with RFC 9421. It defines no way to revoke either: "a short expiration is the primary
// mitigation". And it requires every consumer to bind each trust domain to its authorized issuer keys "via a secure
// out-of-band mechanism", without saying what that mechanism is.
//
// An AINRA passport is exactly that mechanism. Here:
//   * a passport's lineage IS a WIMSE trust domain:  <lineage>.<operator>.<registrar>.ainra.org
//   * its authorized issuer key IS the passport's own key — registrar-certified, logged, and revocable;
//   * a running copy gets a standard WIT, signed with that key, whose `sub` names the copy:
//       wimse://invoicing.acme.registrar-07.ainra.org/i-0f3a2b71
//   * it signs requests exactly as draft-ietf-wimse-http-signature says (tag "wimse-workload-to-workload").
// So a plain WIMSE verifier, given the passport's key as its trust anchor, accepts the request as it would any other.
// An AINRA-aware verifier (`verifyWimseRequest`) also verifies the passport itself — registrar signature, log
// inclusion, and the registrar-signed status list — so a revoked passport's workloads are refused within the
// verifier's freshness class, not whenever their tokens happen to expire.
//
// SAID PLAINLY: WIMSE's JOSE world has no hybrid post-quantum signature, so the WIT and the request signature here are
// Ed25519 only, signed with the Ed25519 half of the passport's hybrid key. The passport chain beneath stays hybrid.
// The AINRA-native instance credential (ADR-019) remains the post-quantum path.

import { b64uDecode, b64uEncode, ed25519Verify } from "./crypto.js";
import { contentDigest, headerValue, members, memberKey } from "./presentation.js";
import type { PresentationBundle, Verdict } from "./index.js";

export const WIT_HEADER = "workload-identity-token";
export const WIT_TYP = "wit+jwt";
export const WIMSE_TAG = "wimse-workload-to-workload";
/** draft-ietf-wimse-workload-creds: WITs are short-lived, "on the order of hours". AINRA's instance ceiling is one. */
export const WIT_MAX_SECS = 3600;
/** draft-ietf-wimse-http-signature: request signature expiry "on the order of minutes". */
export const WIMSE_SIG_MAX_SECS = 300;
const SKEW = 30;

export type WimseReason =
  | "presentation_unsigned" | "presentation_sig_invalid" | "presentation_stale" | "presentation_replayed"
  | "instance_sig_invalid" | "instance_expired";

const enc = new TextEncoder();
const strict = (s: unknown): Uint8Array | null => {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]+$/.test(s)) return null;
  try { const b = b64uDecode(s); return b64uEncode(b) === s ? b : null; } catch { return null; }
};

/** The passport's name → its WIMSE trust domain: `<lineage>.<operator>.<registrar>.ainra.org`. AINRA labels are
 *  already DNS-LDH (1–63 of [a-z0-9-], no edge hyphens), so the result is a valid host name. */
export function trustDomainOf(name: string): string | null {
  const m = /^(?:ainra|did:ainra):([a-z0-9-]+):([a-z0-9-]+):([a-z0-9-]+)(?:@.*)?$/.exec(name);
  return m ? `${m[3]}.${m[2]}.${m[1]}.ainra.org` : null;
}
/** The WIMSE identifier of one running copy of the passport `name`. */
export function wimseIdentifier(name: string, iid: string): string | null {
  const td = trustDomainOf(name);
  return td && /^[A-Za-z0-9._~-]{1,64}$/.test(iid) ? `wimse://${td}/${iid}` : null;
}

function passportOf(bundle: PresentationBundle): { sub: string; ed25519: Uint8Array } | null {
  try {
    const claims = JSON.parse(Buffer.from(b64uDecode(bundle.claims)).toString("utf8"));
    const ed = strict(claims?.keys?.[0]?.ed25519);
    return typeof claims.sub === "string" && ed && ed.length === 32 ? { sub: claims.sub, ed25519: ed } : null;
  } catch { return null; }
}

/** Mint a WIT for one running copy. Run this where the passport key lives — never in the container — exactly like
 *  an AINRA instance credential. `controlSignEd25519` signs with the Ed25519 half of the passport's key. */
export async function mintWit(args: {
  passportClaimsB64: string;
  iid: string;
  instanceEd25519Public: Uint8Array;
  now: number;
  lifetimeSecs?: number;
  controlSignEd25519: (msg: Uint8Array) => Promise<Uint8Array> | Uint8Array;
}): Promise<string> {
  const claims = JSON.parse(Buffer.from(b64uDecode(args.passportClaimsB64)).toString("utf8"));
  const sub = wimseIdentifier(claims.sub, args.iid);
  if (!sub) throw new Error("cannot mint a WIT: the passport name or the instance id does not form a WIMSE identifier");
  if (args.instanceEd25519Public.length !== 32) throw new Error("cannot mint a WIT: the instance key must be Ed25519");
  const life = Math.min(args.lifetimeSecs ?? WIT_MAX_SECS, WIT_MAX_SECS);
  const exp = Math.min(args.now + life, claims.exp);
  const header = { alg: "EdDSA", typ: WIT_TYP };
  const payload = {
    iss: claims.sub.replace(/@.*$/, "").replace(/^ainra:/, "did:ainra:"),
    sub,
    iat: args.now,
    exp,
    jti: args.iid,
    cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: b64uEncode(args.instanceEd25519Public), alg: "EdDSA" } },
  };
  const input = `${b64uEncode(enc.encode(JSON.stringify(header)))}.${b64uEncode(enc.encode(JSON.stringify(payload)))}`;
  const sig = await args.controlSignEd25519(enc.encode(input));
  if (sig.length !== 64) throw new Error("controlSignEd25519 must return a 64-byte Ed25519 signature");
  return `${input}.${b64uEncode(sig)}`;
}

/** Split a request's path into RFC 9421 `@path` and `@query` (the query always starts with "?"). */
function pathAndQuery(target: string): [string, string] {
  const i = target.indexOf("?");
  return i < 0 ? [target, "?"] : [target.slice(0, i), target.slice(i)];
}

interface WimseRequest {
  method: string;
  authority: string;
  /** path with its query, exactly as sent */
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body?: Uint8Array;
}

/** The headers draft-ietf-wimse-http-signature covers "when they exist", in its order. */
const COVERED_IF_PRESENT = ["content-type", "content-digest", "authorization", "txn-token", WIT_HEADER];

function signatureBase(req: WimseRequest, components: string[], params: string): string | null {
  const [p, q] = pathAndQuery(req.path);
  const lines: string[] = [];
  for (const c of components) {
    let v: string | null;
    if (c === "@method") v = req.method.toUpperCase();
    else if (c === "@path") v = p;
    else if (c === "@query") v = q;
    else if (c === "@authority") v = req.authority.toLowerCase();
    else if (c.startsWith("@")) return null;
    else v = headerValue(req.headers, c);
    if (v === null) return null;
    lines.push(`"${c}": ${v}`);
  }
  lines.push(`"@signature-params": ${params}`);
  return lines.join("\n");
}

/** Sign a request as draft-ietf-wimse-http-signature describes: the WIT travels in `Workload-Identity-Token`, the
 *  signature is by the WIT's `cnf` key, tag `wimse-workload-to-workload`, and `wimse-aud` names the recipient. Returns
 *  the headers to SET. Another signer's members in the signature fields are kept (D-070). */
export async function signWimseRequest(args: {
  req: WimseRequest;
  wit: string;
  audience: string;
  nonce: string;
  created: number;
  expiresInSecs?: number;
  instanceSignEd25519: (msg: Uint8Array) => Promise<Uint8Array> | Uint8Array;
}): Promise<Record<string, string>> {
  if (!/^[A-Za-z0-9._~-]{8,128}$/.test(args.nonce)) throw new Error("cannot sign: nonce must be 8-128 of A-Z a-z 0-9 . _ ~ -");
  if (/["\\]/.test(args.audience) || !args.audience) throw new Error("cannot sign: audience must be a non-empty string without quotes");
  const out: Record<string, string> = { [WIT_HEADER]: args.wit };
  const headers: WimseRequest["headers"] = { ...args.req.headers, [WIT_HEADER]: args.wit };
  if (args.req.body && args.req.body.length) {
    out["content-digest"] = contentDigest(args.req.body);
    headers["content-digest"] = out["content-digest"];
  }
  const components = ["@method", "@path", "@query", ...COVERED_IF_PRESENT.filter((h) => headerValue(headers, h) !== null)];
  const expires = args.created + Math.min(args.expiresInSecs ?? 120, WIMSE_SIG_MAX_SECS);
  const params = `(${components.map((c) => `"${c}"`).join(" ")});created=${args.created};expires=${expires};nonce="${args.nonce}";tag="${WIMSE_TAG}";wimse-aud="${args.audience}"`;
  const base = signatureBase({ ...args.req, headers }, components, params);
  if (base === null) throw new Error("cannot sign: a covered component is missing");
  const sig = await args.instanceSignEd25519(enc.encode(base));
  if (sig.length !== 64) throw new Error("instanceSignEd25519 must return a 64-byte Ed25519 signature");
  const priorInput = headerValue(args.req.headers, "signature-input");
  const priorSig = headerValue(args.req.headers, "signature");
  const label = "wimse";
  if (priorInput && (members(priorInput) ?? []).some((m) => memberKey(m) === label))
    throw new Error(`cannot sign: the request already carries a "${label}" signature`);
  const input = `${label}=${params}`;
  const signature = `${label}=:${Buffer.from(sig).toString("base64")}:`;
  out["signature-input"] = priorInput ? `${priorInput}, ${input}` : input;
  out["signature"] = priorSig ? `${priorSig}, ${signature}` : signature;
  return out;
}

/** Parse the parameters after an inner list: `;k=v` with v an integer, a quoted string, or absent (boolean true). */
function params(rest: string): Map<string, string | number | true> | null {
  const out = new Map<string, string | number | true>();
  const re = /^;([a-z*][a-z0-9_.*-]*)(?:=(?:(\d{1,15})|"((?:[^"\\]|\\.)*)"))?/;
  let s = rest;
  while (s.length) {
    const m = re.exec(s);
    if (!m || out.has(m[1])) return null;
    out.set(m[1], m[2] !== undefined ? Number(m[2]) : m[3] !== undefined ? m[3] : true);
    s = s.slice(m[0].length);
  }
  return out;
}

/** Verify a WIMSE request whose workload is backed by an AINRA passport.
 *
 *  1. the PASSPORT verifies under the verifier's own policy — registrar signature, log inclusion, the registrar-signed
 *     status list, the verifier's clock and freshness class. A revoked passport stops here, whatever its WIT says.
 *  2. the WIT: `wit+jwt`, EdDSA, signed by the passport's own key, its `sub` inside the passport's trust domain,
 *     unexpired, at most an hour long.
 *  3. the request signature, exactly as draft-ietf-wimse-http-signature requires — found by its tag, covering
 *     @method @path @query and every listed header present, `wimse-aud` equal to this verifier's audience, short-lived,
 *     by the WIT's `cnf` key, no `keyid` or `alg`.
 *  4. the nonce, last, and only once everything else holds. */
export function verifyWimseRequest(args: {
  req: WimseRequest;
  verifier: { verify(bundle: PresentationBundle, now: number): Verdict };
  bundle: PresentationBundle;
  audience: string;
  now: number;
  seenNonce?: (nonce: string) => boolean;
}): { ok: true; sub: string; nonce: string } | { ok: false; reason: string } {
  // 1 · the passport
  const v = args.verifier.verify(args.bundle, args.now);
  if (v.verdict !== "valid") return { ok: false, reason: v.reason };
  const passport = passportOf(args.bundle); // keys[0], the key ADR-019 signs instance credentials with
  if (!passport) return { ok: false, reason: "instance_sig_invalid" };

  // 2 · the WIT
  const wit = headerValue(args.req.headers, WIT_HEADER);
  if (wit === null) return { ok: false, reason: "presentation_unsigned" };
  const parts = wit.split(".");
  if (parts.length !== 3) return { ok: false, reason: "instance_sig_invalid" };
  let header: Record<string, unknown>, claims: Record<string, unknown>;
  try {
    const h = strict(parts[0]), c = strict(parts[1]);
    if (!h || !c) return { ok: false, reason: "instance_sig_invalid" };
    header = JSON.parse(Buffer.from(h).toString("utf8"));
    claims = JSON.parse(Buffer.from(c).toString("utf8"));
  } catch { return { ok: false, reason: "instance_sig_invalid" }; }
  const witSig = strict(parts[2]);
  if (header.typ !== WIT_TYP || header.alg !== "EdDSA" || !witSig ||
      !ed25519Verify(passport.ed25519, enc.encode(`${parts[0]}.${parts[1]}`), witSig))
    return { ok: false, reason: "instance_sig_invalid" };
  const td = trustDomainOf(passport.sub);
  const sub = typeof claims.sub === "string" ? claims.sub : "";
  if (!td || !sub.startsWith(`wimse://${td}/`)) return { ok: false, reason: "instance_sig_invalid" };
  const exp = claims.exp, iat = claims.iat;
  if (typeof exp !== "number" || typeof iat !== "number" || exp - iat > WIT_MAX_SECS || iat > args.now + SKEW)
    return { ok: false, reason: "instance_sig_invalid" };
  if (args.now >= exp) return { ok: false, reason: "instance_expired" };
  const jwk = (claims.cnf as { jwk?: Record<string, unknown> } | undefined)?.jwk;
  const ikey = strict(jwk?.x);
  if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || jwk.alg !== "EdDSA" || !ikey || ikey.length !== 32)
    return { ok: false, reason: "instance_sig_invalid" };

  // 3 · the request signature, found by its tag
  const inputField = headerValue(args.req.headers, "signature-input");
  const sigField = headerValue(args.req.headers, "signature");
  if (inputField === null || sigField === null) return { ok: false, reason: "presentation_unsigned" };
  const inputs = members(inputField), sigs = members(sigField);
  if (!inputs || !sigs) return { ok: false, reason: "presentation_sig_invalid" };
  const tagged = inputs.filter((m) => /;tag="wimse-workload-to-workload"(;|$)/.test(m));
  if (tagged.length === 0) return { ok: false, reason: "presentation_unsigned" };
  if (tagged.length > 1) return { ok: false, reason: "presentation_sig_invalid" }; // the draft: MUST reject
  const label = memberKey(tagged[0]);
  const m = /^[a-z*][a-z0-9_.*-]*=\(([^)]*)\)(.*)$/.exec(tagged[0]);
  const ownSig = sigs.filter((x) => memberKey(x) === label);
  if (!m || ownSig.length !== 1) return { ok: false, reason: "presentation_sig_invalid" };
  const components = m[1].length ? m[1].split(" ").map((c) => (/^"[^"]+"$/.test(c) ? c.slice(1, -1) : "\u0000")) : [];
  const p = params(m[2]);
  if (!p || components.includes("\u0000") || p.has("keyid") || p.has("alg")) return { ok: false, reason: "presentation_sig_invalid" };
  const need = ["@method", "@path", "@query", ...COVERED_IF_PRESENT.filter((h) => headerValue(args.req.headers, h) !== null)];
  if (need.some((c) => !components.includes(c))) return { ok: false, reason: "presentation_sig_invalid" };
  const created = p.get("created"), expires = p.get("expires"), nonce = p.get("nonce");
  if (typeof created !== "number" || typeof expires !== "number" || typeof nonce !== "string" || !nonce ||
      p.get("wimse-aud") !== args.audience || expires - created > WIMSE_SIG_MAX_SECS || expires < created)
    return { ok: false, reason: "presentation_sig_invalid" };
  if (args.now > expires || created > args.now + SKEW) return { ok: false, reason: "presentation_stale" };
  if (args.req.body && args.req.body.length && headerValue(args.req.headers, "content-digest") !== contentDigest(args.req.body))
    return { ok: false, reason: "presentation_sig_invalid" };
  const sm = /^[a-z*][a-z0-9_.*-]*=:([A-Za-z0-9+/]+={0,2}):$/.exec(ownSig[0]);
  if (!sm) return { ok: false, reason: "presentation_sig_invalid" };
  const raw = new Uint8Array(Buffer.from(sm[1], "base64"));
  if (Buffer.from(raw).toString("base64") !== sm[1]) return { ok: false, reason: "presentation_sig_invalid" };
  const base = signatureBase(args.req, components, `(${m[1]})${m[2]}`);
  if (base === null || !ed25519Verify(ikey, enc.encode(base), raw)) return { ok: false, reason: "presentation_sig_invalid" };

  // 4 · single use, last
  if (args.seenNonce && args.seenNonce(nonce)) return { ok: false, reason: "presentation_replayed" };
  return { ok: true, sub, nonce };
}

