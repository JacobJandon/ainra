// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// 0.7.0: the package root decides; only `@ainra/sdk/conformance` replays (D-074). src/index.ts lists the root's
// exports by hand, so this test is what stops the list drifting from engine.ts: every runtime export of the engine is
// in the root except the corpus runners, which are in conformance and nowhere in the root.
import test from "node:test";
import assert from "node:assert/strict";
import * as root from "../dist/index.js";
import * as engine from "../dist/engine.js";
import * as conformance from "../dist/conformance.js";

const RUNNERS = ["runVector", "expectedVerdict", "runDeltaVector", "runDirectoryVector", "runGateVector", "runLinkVector",
  "runDecisionVector", "runDirectoryEpochVector", "runCurrencyVector", "runPresentationVector"];

test("the root exports every engine export except the corpus runners", () => {
  const want = Object.keys(engine).filter((k) => !RUNNERS.includes(k)).sort();
  assert.deepEqual(Object.keys(root).sort(), want);
});

test("no corpus runner is reachable from the root; every one is in conformance", () => {
  for (const r of RUNNERS) {
    assert.equal(r in root, false, `${r} is exported from the package root`);
    assert.equal(typeof conformance[r], "function", `${r} is missing from @ainra/sdk/conformance`);
  }
});
