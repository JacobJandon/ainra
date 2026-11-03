// SPDX-License-Identifier: Apache-2.0 OR MIT
// PLAN-M50 step 5 — `verifyLogCheckpoint`: which accredited registrar's log signed a checkpoint. The genesis board
// counts a witness cosignature only over a checkpoint this accepts, so each refusal below is one a fake would need.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { verifyLogCheckpoint } from "../dist/index.js";

const g = (n) => JSON.parse(readFileSync(new URL(`../../../vectors/v1-gate/${n}.json`, import.meta.url), "utf8"));
const b64u = (s) => Uint8Array.from(Buffer.from(s, "base64url"));
const run = (v, cp = v.bundle.checkpoint, sig = v.bundle.checkpoint_sig, now = v.now, d = v.directory) =>
  verifyLogCheckpoint(d, b64u(v.roots.root_ed25519), b64u(v.roots.root_slh), cp, sig, now);

test("a checkpoint the registrar's log signed names that registrar", () => {
  const v = g("g01-valid");
  assert.equal(run(v), v.bundle.checkpoint.origin.slice("ainra-log/".length));
});

test("a checkpoint the log never signed, another origin, other roots or an unsigned directory: null", () => {
  const v = g("g01-valid");
  const cp = v.bundle.checkpoint;
  assert.equal(run(v, { ...cp, size: cp.size + 1 }), null);
  assert.equal(run(v, { ...cp, origin: "ainra-log/registrar-99" }), null);
  assert.equal(run(v, { ...cp, origin: cp.origin.replace("ainra-log/", "") }), null);
  assert.equal(run(v, { ...cp, root: "AAAA" }), null);
  const other = g("g01-valid");
  other.roots.root_ed25519 = Buffer.alloc(32, 7).toString("base64url");
  assert.equal(run(other), null);
  assert.equal(run(v, cp, v.bundle.checkpoint_sig, v.now, { ...v.directory, epoch: v.directory.epoch + 1 }), null);
});

test("a delegate the directory revokes signs nothing, and a malformed signature is refused, never thrown", () => {
  const r = g("g22-directory-revokes-the-delegate");
  assert.equal(run(r), null);
  const v = g("g01-valid");
  assert.equal(run(v, v.bundle.checkpoint, { mode: "delegate" }), null);
  assert.equal(run(v, v.bundle.checkpoint, null), null);
  assert.equal(run(v, v.bundle.checkpoint, v.bundle.checkpoint_sig, -1), null);
});
