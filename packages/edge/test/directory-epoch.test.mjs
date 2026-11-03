// SPDX-License-Identifier: Apache-2.0 OR MIT
// PLAN-M50 — the edge engine never goes back to an older directory. Every vectors/v1-directory-epoch entry through the
// same WebAssembly build the gate runs, and a gate rebuilt on a refresh refuses to start on a rollback.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { initAinra, createAinraEdgeGate, createAinraLinkCheck } from "../src/index.mjs";
import * as core from "../wasm/ainra_wasm.js";

await initAinra(readFileSync(new URL("../wasm/ainra_wasm_bg.wasm", import.meta.url)));
const DIR = new URL("../../../vectors/v1-directory-epoch/", import.meta.url);
const vectors = readdirSync(DIR).filter((f) => f.endsWith(".json") && f !== "manifest.json").map((f) => JSON.parse(readFileSync(new URL(f, DIR), "utf8")));
const byName = (n) => vectors.find((v) => v.name === n);

test("every vectors/v1-directory-epoch entry: the edge engine agrees with the core", () => {
  assert.ok(vectors.length >= 9);
  for (const v of vectors) {
    let floor = BigInt(v.min_epoch ?? 0);
    const got = v.directories.map((d) => {
      const r = JSON.parse(core.accredit_at_least(JSON.stringify(d), JSON.stringify({ root_ed25519: v.root_ed25519, root_slh: v.root_slh }), floor));
      if (!r.ok) return { accept: false, refusal: r.refusal };
      floor = BigInt(r.epoch);
      return { accept: true, epoch: r.epoch, registrars: Object.keys(r.trust.anchors).length };
    });
    assert.deepEqual(got, v.expect, v.name);
  }
});

test("a gate rebuilt on a refresh refuses an older, genuinely signed directory", async () => {
  const v = byName("e08-withdrawn-registrar-replayed"); // [epoch 3 without registrar-07, epoch 2 with it]
  const roots = { root_ed25519: v.root_ed25519, root_slh: v.root_slh };
  const [newer, older] = v.directories;
  await createAinraEdgeGate({ directory: newer, roots, audience: "https://shop.example", minEpoch: 3 });
  await assert.rejects(
    createAinraEdgeGate({ directory: older, roots, audience: "https://shop.example", minEpoch: 3 }),
    /epoch 2 is older than 3 — a rollback/,
  );
  await assert.rejects(createAinraLinkCheck({ directory: older, roots, minEpoch: 3 }), /a rollback/);
  // No floor: the old behaviour, unchanged.
  await createAinraEdgeGate({ directory: older, roots, audience: "https://shop.example" });
  await assert.rejects(createAinraEdgeGate({ directory: older, roots, audience: "https://shop.example", minEpoch: -1 }), /non-negative integer/);
});
