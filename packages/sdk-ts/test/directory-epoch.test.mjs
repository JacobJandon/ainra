// SPDX-License-Identifier: Apache-2.0 OR MIT
// PLAN-M50 — a long-lived verifier keeps the highest directory epoch it accepted and never goes back. Both roots
// signed the older directory too: only the epoch can refuse it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createDirectoryHolder, verifyDirectoryAtLeast, Verifier } from "../dist/index.js";

const v = (n) => JSON.parse(readFileSync(new URL(`../../../vectors/v1-directory-epoch/${n}.json`, import.meta.url), "utf8"));
const b64u = (s) => Uint8Array.from(Buffer.from(s, "base64url"));

test("a holder sees epoch 2, then the older epoch 1: the second is refused, and it never builds a Verifier", () => {
  const vec = v("e03-rollback");
  const [d2, d1] = vec.directories;
  const holder = createDirectoryHolder({ rootEd25519: b64u(vec.root_ed25519), rootSlh: b64u(vec.root_slh) });
  assert.ok(holder.verifier(d2) instanceof Verifier);
  assert.equal(holder.floor(), 2);
  const r = holder.verifier(d1);
  assert.ok(!(r instanceof Verifier));
  assert.deepEqual(r, { ok: false, refusal: "rollback", epoch: 1, floor: 2 });
  // The older directory is genuinely signed: without a floor it would be accepted.
  assert.equal(verifyDirectoryAtLeast(d1, b64u(vec.root_ed25519), b64u(vec.root_slh), 0).ok, true);
});

test("a forgery claiming a high epoch is unauthentic and raises nothing", () => {
  const vec = v("e07-forgery-never-raises-the-floor");
  const [d2, forged, d3] = vec.directories;
  const holder = createDirectoryHolder({ rootEd25519: b64u(vec.root_ed25519), rootSlh: b64u(vec.root_slh) });
  assert.equal(holder.accept(d2).ok, true);
  assert.deepEqual(holder.accept(forged), { ok: false, refusal: "unauthentic" });
  assert.equal(holder.floor(), 2);
  assert.equal(holder.accept(d3).ok, true);
  assert.equal(holder.floor(), 3);
});
