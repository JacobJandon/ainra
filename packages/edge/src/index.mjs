// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// @ainra/edge — the AINRA gate for the edge (PLAN-M34 Task 5).
//
// Agents are classified at the CDN edge, which is where most traffic is decided. This gate runs there: a function
// from a standard `Request` to a decision, on web-standard APIs only (Request, Response, URL, atob, WebAssembly — no
// Node Buffer, no filesystem), so the same file runs in a Worker, in Deno, and in Node's fetch server.
//
// WHAT ANSWERS. Not a re-implementation: `ainra-core` itself, compiled to WebAssembly — the Rust verify path that
// generates the conformance corpus, held to all 1153 passport vectors in the browser (`make wasm-diff`) and to the
// request-signature corpus here. The only JavaScript is what must be stateful, which the core cannot be (N7):
//   * the send-once store (D-065) — bundles sent to PRIME_PATH, verified in full, named by digest;
//   * the nonce cache — single use, checked only AFTER the signature holds (D-062).
// Both are bounded, and both live per isolate. Behind several isolates, pass shared ones.
//
//   import { initAinra, createAinraEdgeGate } from "@ainra/edge";
//   await initAinra(wasmModule);                                  // the bundled wasm/ainra_wasm_bg.wasm
//   const gate = await createAinraEdgeGate({ directory, roots, audience: "https://shop.example" });
//   export default { async fetch(req) { const g = await gate(req); return g.allow ? fetch(req) : g.response; } };
//
// TRUST IS THE VERIFIER'S. The directory must verify against BOTH ceremony roots, once, when the gate is created —
// or the gate refuses to exist. The freshness class (default F2, five minutes, as in @ainra/sdk) and the revoked
// delegates come from the gate and its directory, never from the presenter (D-068).

import init, * as core from "../wasm/ainra_wasm.js";

export const PRIME_PATH = "/.well-known/ainra-presentation";
export const PRESENTATION_HEADER = "x-ainra-passport";
export const POP_HEADER = "x-ainra-pop";
/** The RFC 9421 acceptance window plus the future-skew tolerance: a nonce older than this can never verify again,
 *  so the cache need not remember it. */
const NONCE_TTL_SECS = 300 + 30;
const REF_RE = /^sha-256=:[A-Za-z0-9+/]{43}=:$/;
const DIRECT_PASSPORT_TTL_SECS = 300;

let ready = null;
/** Load the core once per isolate. `wasm` is whatever the runtime hands you for the module: a WebAssembly.Module
 *  (Workers), the bytes (Node), or a URL/Response (browsers, Deno). */
export function initAinra(wasm) {
  ready ??= init({ module_or_path: wasm });
  return ready;
}

/** The send-once store (D-065): bounded, idle-first eviction, nothing outlives its credential. Only bundles that
 *  verified when they arrived are ever put here, and every request re-verifies what it names. */
export function createStore({ max = 1024 } = {}) {
  const m = new Map();
  return {
    get(ref, now) {
      const e = m.get(ref);
      if (!e) return undefined;
      if (now >= e.exp) { m.delete(ref); return undefined; }
      m.delete(ref); m.set(ref, e);
      return e.stable;
    },
    put(ref, stable, exp) {
      m.delete(ref); m.set(ref, { stable, exp });
      while (m.size > max) m.delete(m.keys().next().value);
    },
  };
}

/** Single use for request nonces. `seen(nonce, now)` records and answers "was this used before?". Bounded; an
 *  entry older than the acceptance window is forgotten, because a signature that old is refused as stale anyway. */
export function createNonceCache({ max = 100_000 } = {}) {
  const m = new Map();
  return {
    seen(nonce, now) {
      for (const [k, t] of m) { if (now - t > NONCE_TTL_SECS) m.delete(k); else break; }
      if (m.has(nonce)) return true;
      m.set(nonce, now);
      while (m.size > max) m.delete(m.keys().next().value);
      return false;
    },
  };
}

// ── web-standard base64url (no Buffer) ───────────────────────────────────────────────────────────────────────────
function b64uToBytes(s) {
  const b = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b + "=".repeat((4 - (b.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64u(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const utf8 = new TextDecoder("utf-8", { fatal: true });
function decodeBundle(v) {
  const t = v.trim();
  return JSON.parse(t.startsWith("{") ? t : utf8.decode(b64uToBytes(t)));
}

function deny(status, reason, event, extra = {}) {
  const headers = { "content-type": "application/json", "x-ainra-reason": reason, ...extra };
  return { allow: false, reason, event, response: new Response(JSON.stringify({ error: "ainra: request refused", reason }), { status, headers }) };
}

/**
 * Create the gate. Resolves to a function from a `Request` to `{ allow: true, event, nonce }` — forward the
 * request — or `{ allow: false, reason, response }` — return `response`. A request to PRIME_PATH is answered by the
 * gate itself (201 with the digest, or 403).
 *
 * Options: `directory` + `roots` (the published, root-signed directory and the two ceremony root keys), `audience`
 * (who THIS service is — ADR-019; never taken from the request), `freshness` ("F1" | "F2" | "F3", default "F2"),
 * `now` (seconds), `store`, `nonces`, `primePath`, `maxPrimeBytes`. Rejects if the directory does not verify.
 */
export async function createAinraEdgeGate({ directory, roots, audience, freshness = "F2",
  now = () => Math.floor(Date.now() / 1000), store = createStore(), nonces = createNonceCache(),
  primePath = PRIME_PATH, maxPrimeBytes = 256 * 1024, decisions = null } = {}) {
  if (typeof audience !== "string" || !audience) throw new Error("createAinraEdgeGate: `audience` is required — the gate must know who it is (ADR-019)");
  if (!["F1", "F2", "F3"].includes(freshness)) throw new Error(`createAinraEdgeGate: freshness must be F1, F2 or F3, not ${freshness}`);
  if (!ready) throw new Error("@ainra/edge: call initAinra(wasm) before creating a gate");
  await ready;
  const str = (x) => (typeof x === "string" ? x : JSON.stringify(x));
  const acc = JSON.parse(core.accredit(str(directory), str(roots)));
  if (!acc.ok) throw new Error("createAinraEdgeGate: the directory does not verify against the roots — refusing to start");
  const trust = JSON.stringify(acc.trust);

  // D-079: with `decisions` (a log from `createDecisionLog` in @ainra/sdk), every decision about a named passport is
  // recorded, signed and chained. Recording never changes the decision; a log that cannot be written is the
  // operator's alarm, not the agent's refusal.
  const sha256b64u = async (text) => bytesToB64u(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))));
  const record = async (request, url, bundle, g, t) => {
    if (!decisions) return g;
    try {
      const sub = g.event?.name;
      if (typeof sub !== "string" || sub === "") return g;
      const valid = g.allow === true;
      decisions.record({
        at: t,
        kind: "passport",
        subject: sub,
        ...(valid ? { operator: sub.split(":")[2] } : {}),
        verdict: valid ? "valid" : "invalid",
        ...(valid ? {} : { reason: g.reason ?? "schema_violation" }),
        request: core.decision_request_digest(request.method, url.host, url.pathname + url.search, request.headers.get("content-digest") ?? ""),
        ...(bundle && typeof bundle.status_uri === "string" && Number.isSafeInteger(bundle.status_issued_at) && typeof bundle.status_list === "string"
          ? { status: { uri: bundle.status_uri, issued_at: bundle.status_issued_at, list: await sha256b64u(bundle.status_list) } } : {}),
        ...(bundle?.checkpoint && typeof bundle.checkpoint.origin === "string" && Number.isSafeInteger(bundle.checkpoint.size) && typeof bundle.checkpoint.root === "string"
          ? { checkpoint: { origin: bundle.checkpoint.origin, size: bundle.checkpoint.size, root: bundle.checkpoint.root } } : {}),
      });
    } catch (e) {
      console.error(`@ainra/edge: decision not recorded: ${e?.message ?? e}`);
    }
    return g;
  };

  return async function gate(request) {
    const t = now();
    const url = new URL(request.url);

    // ── send once (D-065): verify in full, keep the stable part, answer with its digest ─────────────────────────
    if (request.method === "POST" && url.pathname === primePath) {
      const text = await request.text();
      if (text.length > maxPrimeBytes) return deny(413, "schema_violation", null);
      let bundle;
      try { bundle = JSON.parse(text); } catch { return deny(403, "schema_violation", null); }
      if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) return deny(403, "schema_violation", null);
      const bundleJson = JSON.stringify(bundle);
      const event = JSON.parse(core.credential(bundleJson, trust, t, audience, freshness));
      if (event.status !== "valid") return deny(403, event.reason ?? "schema_violation", event);
      const ref = core.presentation_ref(bundleJson);
      if (!ref) return deny(403, "schema_violation", event);
      const stable = bundle.instance ? { ...bundle, instance: { ...bundle.instance } } : { ...bundle };
      if (stable.instance) delete stable.instance.pop;
      const exp = typeof bundle.instance?.exp === "number" ? bundle.instance.exp : t + DIRECT_PASSPORT_TTL_SECS;
      store.put(ref, stable, exp);
      return { allow: false, reason: null, event, response: new Response(JSON.stringify({ ref, expires: exp }), { status: 201, headers: { "content-type": "application/json" } }) };
    }

    // ── every other request: the credential, then the request it arrived on ─────────────────────────────────────
    const raw = request.headers.get(PRESENTATION_HEADER);
    if (!raw) return deny(403, "schema_violation", null);
    let bundle;
    if (REF_RE.test(raw.trim())) {
      const stable = store.get(raw.trim(), t);
      if (!stable) return deny(428, "presentation_unknown", null, { link: `<${primePath}>; rel="ainra-prime"` });
      const popRaw = request.headers.get(POP_HEADER);
      let pop = null;
      if (popRaw) { try { pop = decodeBundle(popRaw); } catch { return deny(403, "schema_violation", null); } }
      bundle = pop && stable.instance ? { ...stable, instance: { ...stable.instance, pop } } : stable;
    } else {
      try { bundle = decodeBundle(raw); } catch { return deny(403, "schema_violation", null); }
    }
    let body = null;
    if (request.method !== "GET" && request.method !== "HEAD" && request.body) {
      const bytes = new Uint8Array(await request.clone().arrayBuffer());
      if (bytes.length) body = bytesToB64u(bytes);
    }
    const req = { method: request.method, authority: url.host, path: url.pathname + url.search, headers: [...request.headers], body_b64u: body };
    const r = JSON.parse(core.gate(JSON.stringify(bundle), trust, JSON.stringify(req), t, audience, freshness));
    if (!r.allow) return record(request, url, bundle, deny(403, r.reason ?? "schema_violation", r.event), t);
    // Last, and only now that the signature holds: a nonce check before it would let anyone fill this cache.
    if (nonces.seen(r.nonce, t)) return record(request, url, bundle, deny(403, "presentation_replayed", r.event), t);
    return record(request, url, bundle, { allow: true, event: r.event, nonce: r.nonce }, t);
  };
}

/** The same corpus entry the core runs — so a deployment can prove which engine answers it. */
export function runPresentationVector(vector) {
  if (!ready) throw new Error("@ainra/edge: call initAinra(wasm) first");
  return JSON.parse(core.run_presentation_vector(JSON.stringify(vector)));
}
/** One `vectors/v1-gate` entry, answered by the core (D-073): the directory against its roots, then the bundle under
 *  the gate's policy. `{verdict:"no_gate"}` when the directory does not verify. */
export function runGateVector(vector) {
  if (!ready) throw new Error("@ainra/edge: call initAinra(wasm) first");
  return JSON.parse(core.run_gate_vector(JSON.stringify(vector)));
}
// ── AINRA Link (D-078) ────────────────────────────────────────────────────────────────────────────────────────────

/** Assemble the link for one key from a registrar's link index (`GET /links`) and its signed status publication
 *  (`GET /status-list`). `null` means the key is not linked there. Assembling trusts nothing; the check does. */
export function linkFromIndex(index, publication, thumbprint) {
  const e = (index?.links ?? []).find((l) => l.thumbprint === thumbprint);
  if (!e) return null;
  return {
    claims: e.claims, registrar_sig: e.registrar_sig, leaf_index: e.leaf_index, inclusion_proof: e.inclusion_proof,
    checkpoint: index.checkpoint, checkpoint_sig: index.checkpoint_sig,
    status_list: publication.status_list_b64, status_len: publication.bit_len, status_issued_at: publication.issued_at,
    status_uri: publication.uri, status_sig_ed25519: publication.sig_ed25519, status_sig_mldsa65: publication.sig_mldsa65,
  };
}

/** A link checker built from a root-signed directory, once (like the gate). Resolves to
 *  `check(link, presentedKeyB64u, capability?)` → `{verdict:"valid", registrar, operator, passport, scope}` or
 *  `{verdict:"invalid", reason}`. `presentedKeyB64u` is the Ed25519 key the host ALREADY verified the request with. */
export async function createAinraLinkCheck({ directory, roots, freshness = "F2", now = () => Math.floor(Date.now() / 1000) } = {}) {
  if (!["F1", "F2", "F3"].includes(freshness)) throw new Error(`createAinraLinkCheck: freshness must be F1, F2 or F3, not ${freshness}`);
  if (!ready) throw new Error("@ainra/edge: call initAinra(wasm) before creating a link check");
  await ready;
  const str = (x) => (typeof x === "string" ? x : JSON.stringify(x));
  const acc = JSON.parse(core.accredit(str(directory), str(roots)));
  if (!acc.ok) throw new Error("createAinraLinkCheck: the directory does not verify against the roots — refusing to start");
  const trust = JSON.stringify(acc.trust);
  return (link, presentedKeyB64u, capability = "") =>
    JSON.parse(core.link_check(JSON.stringify(link), trust, presentedKeyB64u, now(), freshness, capability ?? ""));
}

/** One `vectors/v1-link` entry, answered by the core. */
export function runLinkVector(vector) {
  if (!ready) throw new Error("@ainra/edge: call initAinra(wasm) first");
  return JSON.parse(core.run_link_vector(JSON.stringify(vector)));
}

// ── Decision records (D-079) ──────────────────────────────────────────────────────────────────────────────────────

/** Check a gate's decision log against its Ed25519 public key (base64url): `{ok, count}` or `{ok:false, index,
 *  problem}`. `anchor` is the record a segment continues from, or null. */
export function verifyDecisionChain(lines, gateKeyB64u, anchor = null) {
  if (!ready) throw new Error("@ainra/edge: call initAinra(wasm) first");
  return JSON.parse(core.decision_chain(gateKeyB64u, JSON.stringify(lines), JSON.stringify(anchor)));
}
/** One `vectors/v1-decision` entry, answered by the core. */
export function runDecisionVector(vector) {
  if (!ready) throw new Error("@ainra/edge: call initAinra(wasm) first");
  return JSON.parse(core.run_decision_vector(JSON.stringify(vector)));
}

export const version = () => core.version();
