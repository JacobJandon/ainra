// SPDX-License-Identifier: Apache-2.0 OR MIT
// PLAN-M51 — currency mode (D-021) in the edge engine. Every vectors/v1-currency entry — one gate's life, step by step
// — through the WASM build must give the core's answers; and a gate built with `currency: true` must refuse a genuine
// pre-revocation snapshot once it has seen the revocation, on the request path and the prime path alike.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { initAinra, createAinraEdgeGate, PRESENTATION_HEADER, PRIME_PATH } from "../src/index.mjs";
import { runCurrencyVector } from "../src/conformance.mjs";

const DIR = new URL("../../../vectors/v1-currency/", import.meta.url);
await initAinra(readFileSync(new URL("../wasm/ainra_wasm_bg.wasm", import.meta.url)));

test("every vectors/v1-currency entry: the edge engine agrees with the core, step by step", () => {
  const files = readdirSync(DIR).filter((f) => f.endsWith(".json") && f !== "manifest.json").sort();
  assert.ok(files.length >= 18, `only ${files.length} currency vectors`);
  for (const f of files) {
    const v = JSON.parse(readFileSync(new URL(f, DIR), "utf8"));
    assert.deepEqual(runCurrencyVector(v), v.expect, v.name);
  }
});

test("the replay after the revocation was seen is refused, and only because the gate remembers", () => {
  const v = JSON.parse(readFileSync(new URL("c02-replay-after-the-revocation-was-seen.json", DIR), "utf8"));
  assert.deepEqual(runCurrencyVector(v).map((r) => r.reason ?? r.verdict), ["valid", "revoked", "stale_status"]);
  // The same last step to a gate that never saw the revocation is the honest limit: accepted.
  assert.deepEqual(runCurrencyVector({ ...v, steps: [v.steps[2]] }).map((r) => r.verdict), ["valid"]);
});

// The gate itself, not only the corpus runner: `createAinraEdgeGate({ currency: true })` must keep its memory across
// requests — on the request path and on the send-once prime path. The vector bundles carry no instance credential,
// so a request whose credential passes ends at `presentation_unsigned`; what matters is where it stops.
const vec = (n) => JSON.parse(readFileSync(new URL(`${n}.json`, DIR), "utf8"));
const gateFor = (v, clock) =>
  createAinraEdgeGate({ directory: v.directory, roots: v.roots, audience: "https://shop.example", freshness: v.freshness, currency: true, now: () => clock.t });
const ask = (g, bundle) =>
  g(new Request("https://shop.example/orders", { headers: { [PRESENTATION_HEADER]: Buffer.from(JSON.stringify(bundle)).toString("base64url") } }));
const prime = (g, bundle) =>
  g(new Request(`https://shop.example${PRIME_PATH}`, { method: "POST", body: JSON.stringify(bundle) }));

test("the currency gate remembers: after the revoked passport's newer head, the old snapshot is refused", async () => {
  const v = vec("c02-replay-after-the-revocation-was-seen");
  const clock = { t: v.steps[0].now };
  const g = await gateFor(v, clock);
  const reasons = [];
  for (const s of v.steps) { clock.t = s.now; reasons.push((await ask(g, s.bundle)).reason); }
  assert.deepEqual(reasons, ["presentation_unsigned", "revoked", "stale_status"]);
  // A gate that never saw the newer head stops at the request signature instead: the honest limit.
  const fresh = await gateFor(v, { t: v.steps[2].now });
  assert.equal((await ask(fresh, v.steps[2].bundle)).reason, "presentation_unsigned");
});

test("the prime path is judged as the request is, and what it sees reaches the gate's memory", async () => {
  const v = vec("c02-replay-after-the-revocation-was-seen");
  const clock = { t: v.steps[0].now };
  const g = await gateFor(v, clock);
  const stripped = { ...v.steps[0].bundle };
  delete stripped.fresh_head;
  assert.equal((await prime(g, stripped)).reason, "stale_status");
  // The revoked passport's bundle is refused at prime — and its newer head is remembered...
  assert.equal((await prime(g, v.steps[1].bundle)).reason, "revoked");
  // ...so the older snapshot is refused on the next request, as at a Node or Python gate.
  clock.t = v.steps[2].now;
  assert.equal((await ask(g, v.steps[2].bundle)).reason, "stale_status");
});
