// SPDX-License-Identifier: Apache-2.0 OR MIT
// D-078 — ainra_verify_link decides as a gate does: every vectors/v1-link entry, through the MCP tool, reads the
// verdict the Rust core recorded, and a valid one names the operator. A key with no link is refused as not_linked.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { TOOLS } from "../src/tools.mjs";

const tool = TOOLS.find((t) => t.name === "ainra_verify_link");
const dir = new URL("../../../vectors/v1-link/", import.meta.url);
const vectors = readdirSync(dir).filter((f) => f.endsWith(".json") && f !== "manifest.json").map((f) => JSON.parse(readFileSync(new URL(f, dir), "utf8")));

test("the tool exists and is read-only", () => {
  assert.ok(tool);
  assert.equal(tool.annotations.readOnlyHint, true);
});

test("every vectors/v1-link entry, through the MCP tool, decides as the core recorded", async () => {
  for (const v of vectors) {
    const call = () => tool.handler({ key: v.presented_key, link: v.link, directory: v.directory, roots: v.roots, freshness: v.freshness, now: v.now, capability: v.capability ?? undefined });
    if (v.expect.verdict === "no_gate") { await assert.rejects(call(), /does not verify/, v.name); continue; }
    const r = await call();
    assert.equal(r.verdict, v.expect.verdict, v.name);
    if (v.expect.verdict === "valid") assert.equal(r.operator, v.expect.operator, v.name);
    else assert.equal(r.reason, v.expect.reason, v.name);
  }
});

test("built from an index: a key the index does not hold is not_linked", async () => {
  const v = vectors.find((x) => x.name === "l01-valid");
  const r = await tool.handler({ key: Buffer.alloc(32, 9).toString("base64url"), index: { links: [] }, status: {}, directory: v.directory, roots: v.roots });
  assert.equal(r.decision, "refuse");
  assert.equal(r.reason, "not_linked");
});
