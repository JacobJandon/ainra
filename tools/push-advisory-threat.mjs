// SPDX-License-Identifier: Apache-2.0 OR MIT
// ADR-018 threat proof (M23 Task 5) — PUSH IS ADVISORY, PULL IS SOVEREIGN.
//
// A push channel (SSE/webhook) may ANNOUNCE that a new status head/delta exists, but it carries no trust: the
// verifier still PULLS the signed head/delta and validates it (delegate signature + freshness), exactly as if there
// were no push at all. This proves the two attacks a push layer could tempt, using the REAL sdk-ts verifier over
// REAL conformance vectors — nothing mocked:
//
//   SUPPRESSION — an attacker withholds the push so the verifier "never hears" about a fresh head. It changes
//     nothing: the verifier's scheduled pull enforces FRESHNESS, so a head that isn't refreshed past its window
//     fails closed (`stale_status`). Push can accelerate revocation; it can never be REQUIRED for safety.
//   FORGERY — an attacker forges a push announcing a rosy new head/delta. It changes nothing: the announced bytes
//     are validated on pull, and a forged signature is rejected (`checkpoint_invalid`). The forgery is ignored.
//
// The "subscriber" is just the normal refresh: on any hint (real or forged), it calls `runDeltaVector` — the same
// validation the pull path always runs. There is no trusted push-only code path.
import { runDeltaVector } from "../packages/sdk-ts/dist/index.js";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const load = (f) => JSON.parse(readFileSync(resolve(ROOT, "vectors/v1-delta", f), "utf8"));
const clone = (o) => JSON.parse(JSON.stringify(o));
// flip the last base64 char of a signature so it stays well-formed but no longer verifies (a forged announcement).
const tamper = (b64) => b64.slice(0, -2) + (b64.slice(-2, -1) === "A" ? "B" : "A") + b64.slice(-1);

let fails = 0;
const expect = (label, got, wantAccept, wantReason) => {
  const ok = got.accept === wantAccept && (wantReason === undefined || got.reason === wantReason);
  if (ok) console.log(`  ✓ ${label.padEnd(52)} accept=${got.accept} reason=${got.reason ?? "·"}`);
  else { fails++; console.error(`  ✗ ${label} → accept=${got.accept} reason=${got.reason} (wanted accept=${wantAccept} reason=${wantReason ?? "·"})`); }
};

console.log("ADR-018 — push is advisory, pull is sovereign\n");

// ── baseline: the real signed head + delta validate on pull ─────────────────────────────────────────────────────
const head = load("head-ok-f2.json");   // fresh_head, freshness F2 (max 300 s), ts 1_000_000, now 1_000_100
const delta = load("delta-valid-batch.json");
expect("baseline: signed fresh head validates", runDeltaVector(head), true);
expect("baseline: signed delta validates", runDeltaVector(delta), true);

// ── SUPPRESSION: no push fires, so the head is never refreshed → it ages past its freshness window → fail closed ──
const suppressed = clone(head);
suppressed.now = head.ts + 301;          // one second past the F2 window (300 s) — the scheduled pull sees a stale head
expect("suppression: un-refreshed head fails closed", runDeltaVector(suppressed), false, "stale_status");
const wellInside = clone(head);
wellInside.now = head.ts + 299;          // still inside the window → valid (push only had to be timely, not present)
expect("suppression: within-window head still valid", runDeltaVector(wellInside), true);

// ── FORGERY: a forged push announces a rosy head/delta, but its signature does not verify on pull → ignored ──────
const forgedHead = clone(head);
forgedHead.sig_delegate = tamper(forgedHead.sig_delegate);
expect("forgery: forged fresh head is rejected", runDeltaVector(forgedHead), false, "checkpoint_invalid");
const forgedDelta = clone(delta);
forgedDelta.countersig_delegate = tamper(forgedDelta.countersig_delegate);
expect("forgery: forged delta countersig is rejected", runDeltaVector(forgedDelta), false, "checkpoint_invalid");

console.log(`\n${fails ? "✗" : "✓"} ${fails ? fails + " failed" : "all threat cases hold"} — suppression fails closed (stale_status); forgery ignored (checkpoint_invalid).`);
console.log("  Push accelerates revocation; it can never subvert it. The signed pull is sovereign.");
process.exit(fails ? 1 : 0);
