// SPDX-License-Identifier: Apache-2.0 OR MIT
// Wrapper-fidelity differential: the MCP `ainra_verify` tool is a WRAPPER over @ainra/sdk — prove it stays one.
// Over a sampled vector set, the tool's {verdict, reason} must be BYTE-IDENTICAL to runVector() AND to the vector's
// own expected verdict. Plus: safety annotations are correct, and write tools refuse without confirm.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { TOOL_BY_NAME, TOOLS } from "../src/tools.mjs";
import { runVector } from "../../sdk-ts/dist/index.js";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const VDIR = ROOT + "vectors/v1";
const files = readdirSync(VDIR).filter((f) => f.endsWith(".json") && f !== "manifest.json");
// deterministic sample: every 7th vector (~106 of 746), covering every reason class by construction of the corpus.
const sample = files.filter((_, i) => i % 7 === 0);
const norm = (v) => JSON.stringify({ verdict: v.verdict, reason: v.reason ?? null });

test(`ainra_verify ≡ @ainra/sdk over ${sample.length} sampled vectors (byte-identical)`, () => {
  const verify = TOOL_BY_NAME.ainra_verify.handler;
  let checked = 0;
  for (const f of sample) {
    const vec = JSON.parse(readFileSync(`${VDIR}/${f}`, "utf8"));
    const sdk = runVector(vec);                                            // the reference
    const mcp = verify({ anchors: vec.anchors, presentation: vec.presentation }); // the wrapper
    assert.equal(norm(mcp), norm(sdk), `MCP disagrees with SDK on ${f}`);  // wrapper fidelity
    assert.equal(norm(mcp), norm(vec.expect), `MCP disagrees with expected on ${f}`); // and both match the frozen expectation
    checked++;
  }
  assert.ok(checked > 50, "sample too small");
});

test("safety annotations: read-only vs destructive are marked correctly", () => {
  const a = Object.fromEntries(TOOLS.map((t) => [t.name, t.annotations]));
  for (const n of ["ainra_verify", "ainra_lookup", "ainra_status"]) assert.equal(a[n].readOnlyHint, true, `${n} must be read-only`);
  for (const n of ["ainra_issue", "ainra_renew", "ainra_revoke"]) assert.equal(a[n].readOnlyHint, false, `${n} is a write op`);
  assert.equal(a.ainra_revoke.destructiveHint, true, "revoke must be marked destructive");
});

test("write tools fail closed without explicit confirm", async () => {
  for (const n of ["ainra_issue", "ainra_renew", "ainra_revoke"]) {
    await assert.rejects(
      async () => TOOL_BY_NAME[n].handler({ operator: "acme", lineage: "x", version: "1.0.0", sub: "ainra:r:acme:x@1.0.0" }),
      /confirm: true/,
      `${n} must refuse without confirm`,
    );
  }
});
