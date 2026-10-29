// SPDX-License-Identifier: Apache-2.0 OR MIT
// D-078 / D-079 — the edge engine answers the link and decision-log corpora exactly as the Rust core does: the same
// WebAssembly build the gate runs, held to vectors/v1-link and vectors/v1-decision.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { initAinra, runLinkVector, runDecisionVector, verifyDecisionChain, createAinraLinkCheck } from "../src/index.mjs";

await initAinra(readFileSync(new URL("../wasm/ainra_wasm_bg.wasm", import.meta.url)));
const dir = (d) => new URL(`../../../vectors/${d}/`, import.meta.url);
const vectors = (d) => readdirSync(dir(d)).filter((f) => f.endsWith(".json") && f !== "manifest.json").map((f) => JSON.parse(readFileSync(new URL(f, dir(d)), "utf8")));
const sorted = (o) => JSON.stringify(Object.fromEntries(Object.entries(o).sort()));

test("every vectors/v1-link entry: the edge engine agrees with the core", () => {
  const vs = vectors("v1-link");
  assert.ok(vs.length >= 36);
  for (const v of vs) assert.equal(sorted(runLinkVector(v)), sorted(v.expect), v.name);
});

test("every vectors/v1-decision entry: the edge engine agrees with the core", () => {
  const vs = vectors("v1-decision");
  assert.ok(vs.length >= 21);
  for (const v of vs) assert.equal(sorted(runDecisionVector(v)), sorted(v.expect), v.name);
});

test("the link check, built once from the directory, decides a vector's link the way the corpus says", async () => {
  const v = vectors("v1-link").find((x) => x.name === "l05-link-revoked");
  const check = await createAinraLinkCheck({ directory: v.directory, roots: v.roots, freshness: v.freshness, now: () => v.now });
  assert.deepEqual(check(v.link, v.presented_key), { verdict: "invalid", reason: "revoked" });
  const ok = vectors("v1-link").find((x) => x.name === "l01-valid");
  const check2 = await createAinraLinkCheck({ directory: ok.directory, roots: ok.roots, now: () => ok.now });
  assert.equal(check2(ok.link, ok.presented_key).operator, "acme");
});

test("a chain checked directly reads the same as its vector", () => {
  const v = vectors("v1-decision").find((x) => x.name === "d04-deleted");
  assert.deepEqual(verifyDecisionChain(v.lines, v.gate_key, v.anchor), v.expect);
});

test("D-079: the edge gate records each decision in a signed, chained log the SDK can check", async () => {
  const { createDecisionLog, verifyDecisionChain: sdkChain } = await import("../../sdk-ts/dist/index.js");
  const { createRequire } = await import("node:module");
  const { pathToFileURL } = await import("node:url");
  const sdkRequire = createRequire(new URL("../../sdk-ts/package.json", import.meta.url));
  const { ed25519 } = await import(pathToFileURL(sdkRequire.resolve("@noble/curves/ed25519")).href);
  const { createAinraEdgeGate } = await import("../src/index.mjs");
  const F = new URL("../../middleware/test/fixtures/", import.meta.url);
  const load = (f) => JSON.parse(readFileSync(new URL(f, F), "utf8"));
  const T = load("meta.json").now;
  const secret = ed25519.utils.randomPrivateKey(), pub = ed25519.getPublicKey(secret);
  const lines = [];
  const decisions = createDecisionLog({ gatePublic: pub, sign: (m) => ed25519.sign(m, secret), append: (l) => lines.push(l), freshness: "F2", audience: "https://api.example" });
  const gate = await createAinraEdgeGate({ directory: load("directory.json"), roots: load("roots.json"), audience: "https://api.example", now: () => T, decisions });
  const present = (b) => new Request("https://api.example/orders", { headers: { "x-ainra-passport": Buffer.from(JSON.stringify(b)).toString("base64url") } });
  const unsigned = await gate(present(load("bundle-valid.json")));
  const revoked = await gate(present(load("bundle-revoked.json")));
  assert.equal(unsigned.reason, "presentation_unsigned");
  assert.equal(revoked.reason, "revoked");
  assert.equal(lines.length, 2);
  const recs = lines.map((l) => JSON.parse(l));
  assert.deepEqual(recs.map((r) => r.reason), ["presentation_unsigned", "revoked"]);
  assert.ok(recs.every((r) => r.operator === undefined), "a refusal never names the operator");
  assert.ok(recs[0].status && recs[0].checkpoint, "it records what the decision relied on");
  const keyB64u = Buffer.from(pub).toString("base64url");
  assert.deepEqual(sdkChain(lines, pub), { ok: true, count: 2 }, "the TypeScript checker accepts it");
  assert.deepEqual(verifyDecisionChain(lines, keyB64u), { ok: true, count: 2 }, "and so does the core, in WebAssembly");
});
