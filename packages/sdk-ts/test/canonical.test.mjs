// SPDX-License-Identifier: Apache-2.0 OR MIT
// D-029: strictB64u is the ONE canonical-only base64url gateway every external decode routes through. It must
// accept exactly the canonical unpadded base64url encoding and reject every non-canonical shape, so the SDK and
// the Rust core (base64ct) reject byte-for-byte identically. A lenient decode here is the fail-open class that
// bit us twice (M9 ceremony dedup, M12 prev_leaf).
import { test } from "node:test";
import assert from "node:assert/strict";
import { strictB64u } from "../dist/index.js";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const enc = (b) => Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

test("accepts canonical, rejects every non-canonical variant", () => {
  const bytes = new Uint8Array(32).fill(0x9a);
  const canonical = enc(bytes); // 43 chars
  assert.notEqual(strictB64u(canonical), null, "canonical must decode");
  assert.deepEqual([...strictB64u(canonical)], [...bytes]);

  // nonzero trailing bits: last char value ≡ 0 mod 4; +1 sets a trailing bit
  const idx = ALPHABET.indexOf(canonical[canonical.length - 1]);
  const trailing = canonical.slice(0, -1) + ALPHABET[idx + 1];
  assert.equal(strictB64u(trailing), null, "nonzero trailing bits rejected");

  assert.equal(strictB64u(canonical + "="), null, "padding rejected");
  assert.equal(strictB64u(canonical.slice(0, 4) + " " + canonical.slice(4)), null, "embedded whitespace rejected");
  assert.equal(strictB64u(" " + canonical), null, "leading whitespace rejected");
  assert.equal(strictB64u(canonical + "\n"), null, "trailing newline rejected");
  // standard-alphabet characters (not unpadded base64url) rejected
  assert.equal(strictB64u(canonical.slice(0, -1) + "+"), null, "'+' rejected");
  assert.equal(strictB64u(canonical.slice(0, -1) + "/"), null, "'/' rejected");
  // and a real urlsafe→standard swap on a value that contains '-'/'_'
  const specials = enc(new Uint8Array([0xff, 0xfb, 0xff, 0xfb, 0xff, 0xfb]));
  assert.ok(/[-_]/.test(specials), "fixture should contain -/_");
  assert.equal(strictB64u(specials.replace(/-/g, "+").replace(/_/g, "/")), null, "-/_ → +// swap rejected");
});

test("exhaustive last-char sweep matches the canonical set (value ≡ 0 mod 4)", () => {
  const prefix = "A".repeat(42);
  const accepted = [...ALPHABET].filter((c) => strictB64u(prefix + c) !== null);
  // exactly the 16 alphabet values whose low 2 bits are zero
  assert.deepEqual(accepted, [...ALPHABET].filter((_, i) => i % 4 === 0));
});
