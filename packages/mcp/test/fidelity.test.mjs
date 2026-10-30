// SPDX-License-Identifier: Apache-2.0 OR MIT
// Wrapper-fidelity differential: the MCP `ainra_verify` tool is a WRAPPER over @ainra/sdk — prove it stays one.
// Over every vectors/v1-gate entry, the tool's {verdict, reason} must be BYTE-IDENTICAL to the SDK's gate
// (runGateVector) AND to the vector's own expected answer. Since 0.6.0 the tool has no fixture mode (D-074): what it
// returns is always a decision. Plus: safety annotations are correct, and write tools refuse without confirm.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { TOOL_BY_NAME, TOOLS } from "../src/tools.mjs";
import { runGateVector } from "../../sdk-ts/dist/conformance.js";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const GDIR = ROOT + "vectors/v1-gate";
const files = readdirSync(GDIR).filter((f) => f.endsWith(".json") && f !== "manifest.json");
const norm = (v) => JSON.stringify({ verdict: v.verdict, reason: v.reason ?? null });

test(`ainra_verify ≡ @ainra/sdk's gate over all ${files.length} gate vectors (byte-identical)`, async () => {
  const verify = TOOL_BY_NAME.ainra_verify.handler;
  let checked = 0;
  for (const f of files) {
    const v = JSON.parse(readFileSync(`${GDIR}/${f}`, "utf8"));
    const sdk = runGateVector(v);
    const call = () => verify({ presentation: v.bundle, directory: v.directory, roots: v.roots, now: v.now, freshness: v.freshness, audience: v.audience });
    if (v.expect.verdict === "no_gate") { await assert.rejects(call(), /does not verify/, f); checked++; continue; }
    const mcp = await call();
    assert.equal(mcp.mode, "gate");
    assert.equal(norm(mcp), norm(sdk), `MCP disagrees with the SDK gate on ${f}`);
    assert.equal(norm(mcp), norm(v.expect), `MCP disagrees with the corpus on ${f}`);
    checked++;
  }
  assert.ok(checked >= 27, "every gate vector");
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
