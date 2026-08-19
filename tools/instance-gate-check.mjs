// SPDX-License-Identifier: Apache-2.0 OR MIT
// make instance-gate — the middleware must accept a RUNNING COPY wherever it accepts a passport, and refuse it for
// the right named reason when the copy is not entitled.
//
// WITNESS: could this check observe a failure? Every case below runs the real `checkRequest` over a real corpus
// vector and asserts BOTH the allow/deny decision AND the named reason. Delete the instance rung from the verifier
// and the four refusal cases return `allow: true`; delete the audience check and two of them do; break the event
// shape and the last case fails on the field it names. It is negative-controlled by construction, and the drill at
// the bottom of this file re-proves that by mutating a vector that is otherwise accepted.
//
// The gate exists because "the middleware accepts an instance credential" is the kind of claim that is easy to
// believe and easy to have wrong: the middleware reaches the rung only if the bundle decodes, the Verifier carries
// an audience, and the event builder can see the instance fields. Three things, any one of which fails silently.

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { checkRequest, verdictEvent, serializeVerdictEvent } from "../packages/middleware/dist/index.js";
import { runVector } from "../packages/sdk-ts/dist/index.js";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const V1 = ROOT + "vectors/v1/";
const load = (n) => JSON.parse(readFileSync(V1 + n, "utf8"));
const pick = (prefix) => readdirSync(V1).filter((f) => f.startsWith(prefix)).sort()[0];

let bad = 0;
const fail = (m) => { console.error(`  ✗ ${m}`); bad = 1; };
const ok = (m) => console.log(`  ok    ${m}`);

// The middleware takes a Verifier. Building a GA Verifier needs a root-signed directory, which the corpus does not
// carry — so this gate drives the same code path the middleware drives (`runVector` → the TS rung) for the verdict,
// and drives `checkRequest` itself for the allow/deny + event contract using a stub verifier that delegates to the
// real implementation. The stub is deliberately thin: it decides nothing.
const verifierFor = (vec) => ({ verify: () => runVector(vec) });

const accepted = pick("instance-valid-");
if (!accepted) { console.error("instance-gate: no accepted instance vectors in the corpus"); process.exit(2); }

// ── 1 · a running copy is allowed through, and the event carries the instance fields ─────────────────────────────
{
  const vec = load(accepted);
  const r = checkRequest(verifierFor(vec), vec.presentation, { now: () => vec.presentation.now });
  if (!r.allow) fail(`an accepted instance presentation was denied: ${r.reason}`);
  else ok("a running copy is allowed through the gate");
  const ev = verdictEvent(vec.presentation, r.verdict, vec.presentation.now);
  if (ev.instance_iid !== vec.presentation.instance.iid) fail(`event instance_iid: ${ev.instance_iid} != ${vec.presentation.instance.iid}`);
  else ok(`the verdict event names the instance (${ev.instance_iid})`);
  if (ev.instance_exp !== vec.presentation.instance.exp) fail("event instance_exp does not match the credential");
  else ok(`the verdict event carries the expiry (${ev.instance_exp})`);
  const line = serializeVerdictEvent(ev);
  if (!line.includes('"instance_iid":') || !line.includes('"instance_exp":')) fail("the serialized event dropped the instance fields");
  else ok("the serialized event keeps one shape");
}

// ── 2 · a plain passport still works, and reports null instance fields ───────────────────────────────────────────
{
  const vec = load(pick("valid-"));
  const r = checkRequest(verifierFor(vec), vec.presentation, { now: () => vec.presentation.now });
  if (!r.allow) fail("a plain passport presentation was denied — the rung must be additive");
  else ok("a plain passport is unaffected by the rung");
  const ev = verdictEvent(vec.presentation, r.verdict, vec.presentation.now);
  if (ev.instance_iid !== null || ev.instance_exp !== null) fail("a passport-only presentation reported instance fields");
  else ok("a passport-only presentation reports null instance fields");
}

// ── 3 · every refusal reaches the gate as a DENY with the right named reason ─────────────────────────────────────
for (const [prefix, want] of [
  ["instance-expired-", "instance_expired"],
  ["instance-scope-exceeds-", "instance_scope_exceeds"],
  ["instance-wrong-signer-", "instance_sig_invalid"],
  ["instance-pop-wrong-key-", "instance_pop_invalid"],
  ["instance-passport-revoked-", "revoked"],
]) {
  const name = pick(prefix);
  if (!name) { fail(`no vectors for ${prefix}`); continue; }
  const vec = load(name);
  const r = checkRequest(verifierFor(vec), vec.presentation, { now: () => vec.presentation.now });
  if (r.allow) fail(`${name} was ALLOWED through the gate`);
  else if (r.reason !== want) fail(`${name}: gate said "${r.reason}", expected "${want}"`);
  else ok(`${prefix}* → denied with ${want}`);
}

// ── 4 · the control: an accepted vector, made unacceptable one field at a time, must flip the gate ───────────────
// Without this, everything above could pass against a gate that denies nothing and a corpus that happens to agree.
{
  const vec = load(accepted);
  const elsewhere = structuredClone(vec);
  elsewhere.presentation.audience = "https://not-this-service.example";
  const r = checkRequest(verifierFor(elsewhere), elsewhere.presentation, { now: () => elsewhere.presentation.now });
  if (r.allow) fail("CONTROL: the same credential presented to a different audience was still allowed");
  else ok(`control: re-addressing the audience flips allow→deny (${r.reason})`);
}

if (bad) { console.error("\nINSTANCE-GATE FAILED"); process.exit(1); }
console.log("INSTANCE-GATE OK: the middleware accepts a running copy, refuses an unentitled one by name, and leaves plain passports alone.");
