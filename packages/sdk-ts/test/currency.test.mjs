// SPDX-License-Identifier: Apache-2.0 OR MIT
// PLAN-M51 — currency mode (D-021): the TypeScript Verifier answers every vectors/v1-currency step as the core does,
// including the two refusals this milestone added (a head under a revoked delegate, c17) and the binding to the
// presented text rather than a re-encoding (c14, c15).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { runCurrencyVector } from "../dist/conformance.js";

const DIR = new URL("../../../vectors/v1-currency/", import.meta.url);
const v = (n) => JSON.parse(readFileSync(new URL(`${n}.json`, DIR), "utf8"));

test("every vectors/v1-currency entry, step by step", () => {
  const files = readdirSync(DIR).filter((f) => f.endsWith(".json") && f !== "manifest.json").sort();
  assert.ok(files.length >= 18);
  for (const f of files) {
    const vec = JSON.parse(readFileSync(new URL(f, DIR), "utf8"));
    assert.deepEqual(runCurrencyVector(vec), vec.expect, vec.name);
  }
});

test("a head names the list it was handed, byte for byte, and a revoked delegate signs none", () => {
  assert.deepEqual(runCurrencyVector(v("c14-head-names-another-encoding")).map((r) => r.reason), ["stale_status"]);
  assert.deepEqual(runCurrencyVector(v("c15-head-names-this-encoding")).map((r) => r.verdict), ["valid"]);
  assert.deepEqual(runCurrencyVector(v("c17-head-delegate-revoked")).map((r) => r.reason), ["stale_status"]);
});
