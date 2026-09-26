// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `@ainra/middleware` — the verifier wedge: a fail-closed gate that checks an AINRA passport presented on a
//! request and allows or denies it, in ~5 lines of integration. Pure over `@ainra/sdk`'s `Verifier`: no network,
//! no state, no telemetry — a request either carries a presentation bundle that verifies against the trusted
//! directory, or it is denied with a machine-readable reason.
//!
//! Two surfaces:
//!   * `ainraGate(verifier, opts)` → Connect/Express `(req, res, next)` middleware.
//!   * `checkRequest(verifier, bundle, opts)` → framework-agnostic `{ allow, reason?, verdict }` (edge/fetch).

import {
  Verifier, verdictEvent, serializeVerdictEvent, decodeInstance, verifyPresentation,
  isPresentationRef, splitPresentation, joinPresentation, presentationRef, POP_HEADER, PRIME_PATH,
  type PresentationBundle, type Verdict, type VerdictEvent, type PresentationReason,
} from "@ainra/sdk";

// ── M36 (D-065): bundles sent once, named by digest after that ───────────────────────────────────────────────────

/** Where the gate keeps bundles a running copy has sent once. Only bundles that verified VALID when they arrived
 *  are ever stored, the key is the SHA-256 of the content, and every request re-verifies what it names — so the
 *  store can lose entries (the client just sends again) but cannot make anything pass that would not. */
export interface PresentationStore {
  get(ref: string, now: number): Record<string, unknown> | undefined;
  put(ref: string, stable: Record<string, unknown>, expiresAt: number): void;
}

/** The default store: in memory, bounded, oldest-first eviction, and nothing outlives the credential it holds.
 *  Bounded because whoever can mint valid bundles can otherwise fill it; eviction costs them nothing but costs an
 *  honest client one re-send, which is the right way round. One process only — behind several, share a store. */
export function createPresentationStore(opts: { max?: number } = {}): PresentationStore {
  const max = Math.max(1, opts.max ?? 1024);
  const m = new Map<string, { stable: Record<string, unknown>; exp: number }>();
  return {
    get(ref, now) {
      const e = m.get(ref);
      if (!e) return undefined;
      if (now >= e.exp) { m.delete(ref); return undefined; }
      m.delete(ref); m.set(ref, e);            // most recently used last, so eviction takes the idlest
      return e.stable;
    },
    put(ref, stable, exp) {
      m.delete(ref);
      m.set(ref, { stable, exp });
      while (m.size > max) m.delete(m.keys().next().value as string);
    },
  };
}

/** How long a stored bundle may be named. A running copy's credential expires on its own (ADR-019, ≤ 1 h); a
 *  passport presented directly carries a status list whose freshness is what matters, so it is kept briefly and
 *  re-sent. Every use re-verifies at the current time regardless — this bounds memory, not trust. */
const DIRECT_PASSPORT_TTL_SECS = 300;

export interface GateOptions {
  /** Verifier's clock, unix seconds. Default: `Date.now()/1000`. Pass a fixed value for a demo/test window. */
  now?: () => number;
  /** Header the presentation bundle (JSON, or base64url-of-JSON) arrives in. Default `x-ainra-passport`. */
  header?: string;
  /** Called on deny (before the 403 is sent) — for logging. Never receives secrets. */
  onDeny?: (reason: string) => void;
  /** Require the REQUEST itself to be signed by the running copy's instance key (RFC 9421, D-062).
   *
   *  Off by default, and that default is a compatibility choice rather than a security opinion: turning it on
   *  silently would reject every integrator who upgraded this package without changing a line of their agent.
   *  Leave it off and a captured presentation replays against any route on this host until the credential
   *  expires — which is what `docs/PLAN-M34.md` probed and found. Turn it on and the presentation is bound to one
   *  method, one authority, one path and, when there is a body, that body.
   *
   *  Requires the bundle to carry an instance credential: there is no key to check a signature against without
   *  one, so a passport-only presentation is refused rather than waved through. */
  requireSignature?: boolean;
  /** Close the replay window completely. Return true if this nonce has been seen before.
   *
   *  Without it, a captured signature stays usable against that exact target for five minutes. The cache cannot
   *  live in the SDK (`ainra-core` is N7 — no state), so it lives with the caller who has somewhere to put it. */
  seenNonce?: (nonce: string) => boolean;
  /** M36 (D-065): where bundles sent to PRIME_PATH are kept, so requests can name them by digest. Pass the SAME
   *  store to `ainraPrime`. Without one, a request that names a bundle by digest is refused `presentation_unknown`. */
  store?: PresentationStore;
  /** Header the per-request proof of possession arrives in when the bundle is named by digest. Default `x-ainra-pop`. */
  popHeader?: string;
}

/** What `requireSignature` needs from the request, beyond the bundle. A framework-agnostic shape so an edge
 *  worker, a Node server and a test can all produce it. */
export interface RequestBinding {
  method: string;
  /** host or host:port — no scheme, no path. */
  authority: string;
  /** path, including any query string, exactly as sent */
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body?: Uint8Array;
}

export interface GateResult {
  allow: boolean;
  reason?: string;
  verdict: Verdict;
  /** The canonical verdict event (docs/PRESENTATION.md) — identical shape across CLI, MCP, and this middleware. */
  event: VerdictEvent;
}

const DENY_SCHEMA: Verdict = { verdict: "invalid", reason: "schema_violation" };

/** Returns null when the request is bound to this presentation, or the reason it is not.
 *
 *  Presentation reasons are a SEPARATE vocabulary from the frozen credential reasons, on purpose: `sig_invalid`
 *  means the registrar's signature is broken and sends an integrator to the wrong half of the system, when what
 *  actually happened is that a perfectly good credential arrived on a request it was not signed for. */
function checkBinding(
  parsed: PresentationBundle,
  opts: GateOptions & { binding?: RequestBinding },
  now: number,
): PresentationReason | "schema_violation" | null {
  const req = opts.binding;
  if (!req) return "schema_violation";          // asked to require a signature with nothing to check it over
  if (!parsed.instance) return "presentation_unsigned";  // no instance key to verify against
  let ic;
  try { ({ ic } = decodeInstance(parsed.instance)); } catch { return "schema_violation"; }
  const r = verifyPresentation({
    req: { method: req.method, authority: req.authority, path: req.path, headers: req.headers, body: req.body },
    instance: { iid: ic.iid, ikey: ic.ikey },
    now,
    seenNonce: opts.seenNonce,
  });
  return r.ok ? null : r.reason;
}

/** Verify one presentation bundle. FAIL CLOSED: anything that isn't a bundle that verifies VALID → `allow:false`.
 * Never throws. `bundle` may be a decoded object or a base64url-of-JSON string (what a header carries). */
export function checkRequest(
  verifier: Verifier,
  bundle: unknown,
  opts: GateOptions & { binding?: RequestBinding; pop?: string } = {},
): GateResult {
  const now = (opts.now ?? (() => Math.floor(Date.now() / 1000)))();
  let parsed: PresentationBundle;
  // M36 (D-065): the request names a bundle it sent earlier. Look it up and put the per-request proof of possession
  // back where the verifier expects it — from here on it is the same bundle, checked the same way.
  if (typeof bundle === "string" && isPresentationRef(bundle)) {
    const stable = opts.store?.get(bundle.trim(), now);
    if (!stable)
      return { allow: false, reason: "presentation_unknown", verdict: DENY_SCHEMA, event: verdictEvent({}, DENY_SCHEMA, now) };
    let pop: unknown = null;
    if (opts.pop !== undefined) {
      try { pop = JSON.parse(Buffer.from(opts.pop.trim(), "base64url").toString("utf8")); }
      catch { return { allow: false, reason: "schema_violation", verdict: DENY_SCHEMA, event: verdictEvent({}, DENY_SCHEMA, now) }; }
    }
    bundle = joinPresentation(stable, pop);
  }
  try {
    if (typeof bundle === "string") {
      // Accept raw JSON or base64url(JSON) — a header is easiest as the latter.
      const text = bundle.trim().startsWith("{") ? bundle : Buffer.from(bundle, "base64url").toString("utf8");
      parsed = JSON.parse(text) as PresentationBundle;
    } else if (bundle && typeof bundle === "object") {
      parsed = bundle as PresentationBundle;
    } else {
      return { allow: false, reason: "schema_violation", verdict: DENY_SCHEMA, event: verdictEvent({}, DENY_SCHEMA, now) };
    }
  } catch {
    return { allow: false, reason: "schema_violation", verdict: DENY_SCHEMA, event: verdictEvent({}, DENY_SCHEMA, now) };
  }
  const verdict = verifier.verify(parsed, now); // never throws; invalid on any failure
  let allow = verdict.verdict === "valid";
  let reason: string | undefined = verdict.verdict === "valid" ? undefined : verdict.reason;

  // The credential is good. That says an agent exists and is entitled — it says nothing about THIS request, which
  // is the gap PLAN-M34 probed: the same bundle verified three times over with nothing naming a method, a host or
  // a path. When the caller asks for it, bind the two together before allowing anything.
  if (allow && opts.requireSignature) {
    const bound = checkBinding(parsed, opts, now);
    if (bound !== null) { allow = false; reason = bound; }
  }
  return { allow, reason, verdict, event: verdictEvent(parsed, verdict, now) };
}

// Minimal structural types so we don't depend on Express at build time.
interface ReqLike {
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  /** Present on any Node/Express request; needed only when `requireSignature` is on. */
  method?: string;
  url?: string;
  originalUrl?: string;
  /** The RAW request body. A parsed body cannot be re-serialised back to the bytes that were signed, so when a
   *  signer covered `content-digest` and this is absent, the gate refuses rather than guessing — capture it with
   *  body-parser's `verify` hook (`(req, _res, buf) => { req.rawBody = buf; }`). */
  rawBody?: Uint8Array;
  ainra?: GateResult;
}
interface ResLike {
  status(code: number): ResLike;
  json(body: unknown): unknown;
  setHeader(name: string, value: string): void;
}
type Next = () => void;

/** Build the signed-over view of an Express/Node request. `authority` comes from the Host header, which is what
 *  the client addressed and therefore what it signed. */
function bindingFromReq(req: ReqLike): RequestBinding {
  const host = Array.isArray(req.headers.host) ? req.headers.host[0] : req.headers.host;
  return {
    method: req.method ?? "GET",
    authority: host ?? "",
    path: req.originalUrl ?? req.url ?? "/",
    headers: req.headers,
    body: req.rawBody,
  };
}

/**
 * Connect/Express middleware. Reads the presentation from the configured header (or `req.body.ainra_passport`),
 * verifies it, and either calls `next()` (attaching `req.ainra`) or responds **403 fail-closed** with the reason.
 *
 * ```ts
 * const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh)!;
 * app.use("/agent", ainraGate(verifier));   // every /agent request must carry a valid passport
 * ```
 */
export function ainraGate(verifier: Verifier, opts: GateOptions = {}) {
  const header = (opts.header ?? "x-ainra-passport").toLowerCase();
  const popHeader = (opts.popHeader ?? POP_HEADER).toLowerCase();
  return (req: ReqLike, res: ResLike, next: Next): void => {
    const raw = req.headers[header] ?? (req.body as { ainra_passport?: unknown } | undefined)?.ainra_passport;
    const popRaw = req.headers[popHeader];
    const result: GateResult =
      raw === undefined
        ? { allow: false, reason: "schema_violation", verdict: DENY_SCHEMA, event: verdictEvent({}, DENY_SCHEMA, (opts.now ?? (() => Math.floor(Date.now() / 1000)))()) }
        : checkRequest(verifier, Array.isArray(raw) ? raw[0] : raw, {
            ...opts,
            binding: opts.requireSignature ? bindingFromReq(req) : undefined,
            pop: Array.isArray(popRaw) ? popRaw[0] : popRaw,
          });
    req.ainra = result;
    // Emit the canonical verdict event on every request (allow or deny) — one event shape everywhere (PRESENTATION.md).
    res.setHeader("x-ainra-verdict", serializeVerdictEvent(result.event));
    if (result.allow) {
      next();
      return;
    }
    if (opts.onDeny) opts.onDeny(result.reason ?? "schema_violation");
    res.setHeader("x-ainra-reason", result.reason ?? "schema_violation");
    if (result.reason === "presentation_unknown") {
      // Not a refusal of the agent: this gate simply does not hold the bundle the request names. 428 tells a client
      // to send it (again) and retry, rather than to give up.
      res.setHeader("link", `<${PRIME_PATH}>; rel="ainra-prime"`);
      res.status(428).json({ error: "ainra: send the presentation first", reason: result.reason, prime: PRIME_PATH });
      return;
    }
    res.status(403).json({ error: "ainra: passport not valid", reason: result.reason });
  };
}

/**
 * M36 (D-065): the handler a running copy sends its bundle to, once. Mount it at `PRIME_PATH` with the same store
 * as the gate. It verifies the bundle IN FULL — proof of possession included — and keeps only bundles that verify
 * VALID, keyed by the digest of their stable part; it answers 201 with that digest. Sending a bundle grants nothing
 * by itself: every request that names it must still verify, and, with `requireSignature`, be signed.
 *
 * ```ts
 * const store = createPresentationStore();
 * app.post(PRIME_PATH, express.json({ limit: "256kb" }), ainraPrime(verifier, { store }));
 * app.use("/agent", ainraGate(verifier, { store, requireSignature: true, seenNonce }));
 * ```
 */
export function ainraPrime(verifier: Verifier, opts: { store: PresentationStore; now?: () => number; onDeny?: (reason: string) => void }) {
  return (req: ReqLike, res: ResLike): void => {
    const now = (opts.now ?? (() => Math.floor(Date.now() / 1000)))();
    let body: unknown = req.body;
    if ((body === undefined || typeof body !== "object") && req.rawBody) {
      try { body = JSON.parse(Buffer.from(req.rawBody).toString("utf8")); } catch { body = undefined; }
    }
    const deny = (reason: string) => {
      if (opts.onDeny) opts.onDeny(reason);
      res.setHeader("x-ainra-reason", reason);
      res.status(403).json({ error: "ainra: presentation not stored", reason });
    };
    if (!body || typeof body !== "object" || Array.isArray(body)) return deny("schema_violation");
    if ((req.method ?? "POST").toUpperCase() !== "POST") return deny("schema_violation");
    const result = checkRequest(verifier, body, { now: () => now });
    res.setHeader("x-ainra-verdict", serializeVerdictEvent(result.event));
    if (!result.allow) return deny(result.reason ?? "schema_violation");
    const bundle = body as Record<string, unknown> & { instance?: { exp?: unknown } };
    const { stable } = splitPresentation(bundle);
    const iexp = typeof bundle.instance?.exp === "number" ? bundle.instance.exp : undefined;
    const expiresAt = iexp ?? now + DIRECT_PASSPORT_TTL_SECS;
    const ref = presentationRef(bundle);
    opts.store.put(ref, stable, expiresAt);
    res.status(201).json({ ref, expires: expiresAt });
  };
}

export { Verifier, verdictEvent, serializeVerdictEvent, type VerdictEvent } from "@ainra/sdk";
export { PRIME_PATH, POP_HEADER, presentationRef, isPresentationRef } from "@ainra/sdk";
