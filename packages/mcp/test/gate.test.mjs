// SPDX-License-Identifier: Apache-2.0 OR MIT
// D-074 — what `ainra_verify` DECIDES.
//
// In 0.4.1, the published version, the tool ran the fixture-semantics verifier over whatever it was handed: the bundle's own clock, its
// own freshness class, its own status list. That is what a conformance vector needs and it is not a decision — a
// revoked agent could hand an MCP client a bundle with an all-clear status list of its own and be told "valid".
// The tool now verifies as a gate does, and replaying a vector is a separate mode that must be asked for by name.
//
// WITNESS — could these fail? The gate corpus is the pin: twelve of its vectors read differently when status is not
// authenticated (vectors/v1-gate, D-073), and every one of the "the bundle does not choose" tests below returned
// `valid` from the published 0.4.1 tool.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { TOOL_BY_NAME } from "../src/tools.mjs";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const verify = TOOL_BY_NAME.ainra_verify.handler;
const sample = (f) => JSON.parse(readFileSync(`${ROOT}kits/verifier/sample-artifacts/${f}`, "utf8"));
const directory = sample("directory.json"), roots = sample("roots.json");
const valid = sample("bundle-valid.json"), revoked = sample("bundle-revoked.json");
const T = sample("meta.json").now;
const gate = (presentation, more = {}) => verify({ presentation, directory, roots, now: T, ...more });

test("the gate corpus: ainra_verify decides every vectors/v1-gate entry as ainra-core recorded it", async () => {
  const dir = `${ROOT}vectors/v1-gate`;
  const files = readdirSync(dir).filter((f) => f.endsWith(".json") && f !== "manifest.json");
  assert.ok(files.length >= 27);
  for (const f of files) {
    const v = JSON.parse(readFileSync(`${dir}/${f}`, "utf8"));
    const call = () => verify({ presentation: v.bundle, directory: v.directory, roots: v.roots, audience: v.audience, freshness: v.freshness, now: v.now });
    if (v.expect.verdict === "no_gate") { await assert.rejects(call(), /does not verify against the roots/, v.name); continue; }
    const r = await call();
    assert.equal(r.mode, "gate", v.name);
    assert.equal(r.verdict, v.expect.verdict, `${v.name}: verdict`);
    assert.equal(r.reason ?? undefined, v.expect.reason, `${v.name}: reason`);
    assert.equal(r.decision, v.expect.verdict === "valid" ? "accept" : "refuse", `${v.name}: decision`);
  }
});

test("the honest bundles read as they are, and say whose policy decided", async () => {
  const ok = await gate(valid);
  assert.equal(ok.decision, "accept");
  assert.deepEqual(ok.policy, { now: T, freshness: "F2", audience: null, trust: "the directory and roots you passed" });
  const no = await gate(revoked);
  assert.equal(no.decision, "refuse");
  assert.equal(no.reason, "revoked");
});

test("the bundle does not choose its status: a revoked passport with a list of its own is refused", async () => {
  // Exactly what the published tool accepted: the revoked bundle carrying the earlier, all-clear list.
  const forged = { ...revoked, status_list: valid.status_list, status_issued_at: T };
  const r = await gate(forged);
  assert.equal(r.decision, "refuse");
  assert.equal(r.reason, "stale_status");
  const unsigned = { ...valid };
  delete unsigned.status_sig_ed25519; delete unsigned.status_sig_mldsa65;
  assert.equal((await gate(unsigned)).reason, "stale_status");
});

test("the bundle does not choose the clock: with no `now`, the server's clock decides", async () => {
  // The sample's status was published in April 2026 and the bundle still carries that moment as its own `now`.
  // The published tool read the clock off the bundle, so this sample stayed "valid" forever.
  const r = await verify({ presentation: valid, directory, roots });
  assert.equal(r.decision, "refuse");
  assert.equal(r.reason, "stale_status");
  assert.ok(r.policy.now > T + 86400, "the clock used is the server's, not the bundle's");
});

test("the bundle does not choose the freshness class", async () => {
  const hourLater = { now: T + 3600 };
  assert.equal((await gate({ ...valid, freshness: "F3" }, hourLater)).reason, "stale_status");
  assert.equal((await gate(valid, { ...hourLater, freshness: "F3" })).decision, "accept", "the CALLER may choose F3");
  await assert.rejects(gate(valid, { freshness: "F9" }), /freshness must be F1, F2 or F3/);
});

test("trust is required, whole, and checked", async () => {
  await assert.rejects(verify({ presentation: valid, directory }), /BOTH `directory` and `roots`/);
  await assert.rejects(verify({ presentation: valid, roots }), /BOTH `directory` and `roots`/);
  await assert.rejects(gate(valid, { directory: { ...directory, epoch: directory.epoch + 1 } }), /does not verify against the roots/);
  // No trust passed and no URL target configured (the default target is a local registrar directory).
  await assert.rejects(verify({ presentation: valid }), /needs the trust to verify against/);
});

test("replaying a vector is a mode you ask for by name, and it decides nothing", async () => {
  const vec = JSON.parse(readFileSync(`${ROOT}vectors/v1/valid-0000.json`, "utf8"));
  await assert.rejects(verify({ anchors: vec.anchors, presentation: vec.presentation }), /fixture: true/);
  const r = await verify({ anchors: vec.anchors, presentation: vec.presentation, fixture: true });
  assert.equal(r.mode, "fixture");
  assert.equal(r.verdict, "valid");
  assert.equal(r.decision, null);
  assert.match(r.warning, /does not decide whether to trust a presenter/);
});
