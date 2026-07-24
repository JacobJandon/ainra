// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `@ainra/middleware` — the verifier wedge: a fail-closed gate that checks an AINRA passport presented on a
//! request and allows or denies it, in ~5 lines of integration. Pure over `@ainra/sdk`'s `Verifier`: no network,
//! no state, no telemetry — a request either carries a presentation bundle that verifies against the trusted
//! directory, or it is denied with a machine-readable reason.
//!
//! Two surfaces:
//!   * `ainraGate(verifier, opts)` → Connect/Express `(req, res, next)` middleware.
//!   * `checkRequest(verifier, bundle, opts)` → framework-agnostic `{ allow, reason?, verdict }` (edge/fetch).

import { Verifier, verdictEvent, serializeVerdictEvent, type PresentationBundle, type Verdict, type VerdictEvent } from "@ainra/sdk";

export interface GateOptions {
  /** Verifier's clock, unix seconds. Default: `Date.now()/1000`. Pass a fixed value for a demo/test window. */
  now?: () => number;
  /** Header the presentation bundle (JSON, or base64url-of-JSON) arrives in. Default `x-ainra-passport`. */
  header?: string;
  /** Called on deny (before the 403 is sent) — for logging. Never receives secrets. */
  onDeny?: (reason: string) => void;
}

export interface GateResult {
  allow: boolean;
  reason?: string;
  verdict: Verdict;
  /** The canonical verdict event (docs/PRESENTATION.md) — identical shape across CLI, MCP, and this middleware. */
  event: VerdictEvent;
}

const DENY_SCHEMA: Verdict = { verdict: "invalid", reason: "schema_violation" };

/** Verify one presentation bundle. FAIL CLOSED: anything that isn't a bundle that verifies VALID → `allow:false`.
 * Never throws. `bundle` may be a decoded object or a base64url-of-JSON string (what a header carries). */
export function checkRequest(
  verifier: Verifier,
  bundle: unknown,
  opts: GateOptions = {},
): GateResult {
  const now = (opts.now ?? (() => Math.floor(Date.now() / 1000)))();
  let parsed: PresentationBundle;
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
  const allow = verdict.verdict === "valid";
  return { allow, reason: allow ? undefined : verdict.reason, verdict, event: verdictEvent(parsed, verdict, now) };
}

// Minimal structural types so we don't depend on Express at build time.
interface ReqLike {
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  ainra?: GateResult;
}
interface ResLike {
  status(code: number): ResLike;
  json(body: unknown): unknown;
  setHeader(name: string, value: string): void;
}
type Next = () => void;

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
  return (req: ReqLike, res: ResLike, next: Next): void => {
    const raw = req.headers[header] ?? (req.body as { ainra_passport?: unknown } | undefined)?.ainra_passport;
    const result: GateResult =
      raw === undefined
        ? { allow: false, reason: "schema_violation", verdict: DENY_SCHEMA, event: verdictEvent({}, DENY_SCHEMA, (opts.now ?? (() => Math.floor(Date.now() / 1000)))()) }
        : checkRequest(verifier, Array.isArray(raw) ? raw[0] : raw, opts);
    req.ainra = result;
    // Emit the canonical verdict event on every request (allow or deny) — one event shape everywhere (PRESENTATION.md).
    res.setHeader("x-ainra-verdict", serializeVerdictEvent(result.event));
    if (result.allow) {
      next();
      return;
    }
    if (opts.onDeny) opts.onDeny(result.reason ?? "schema_violation");
    res.setHeader("x-ainra-reason", result.reason ?? "schema_violation");
    res.status(403).json({ error: "ainra: passport not valid", reason: result.reason });
  };
}

export { Verifier, verdictEvent, serializeVerdictEvent, type VerdictEvent } from "@ainra/sdk";
