// SPDX-License-Identifier: Apache-2.0 OR MIT
// Canonical serializer — MUST byte-match ainra-core::canon and the P0 cli-node `cjson` (property P-5).
//
// Scheme: recursively sorted object keys, no whitespace, `JSON.stringify` scalars. Identical rejections to the Rust
// core (DECISIONS D-003/D-010): floats, non-ASCII object keys (JS UTF-16 .sort() vs Rust UTF-8 BTreeMap diverge on
// astral-plane keys), and integers outside ±(2^53−1) (JS cannot represent them exactly).

export class CanonError extends Error {}

const JS_SAFE_INT_MAX = Number.MAX_SAFE_INTEGER; // 2^53 - 1

function isAscii(s: string): boolean {
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) > 0x7f) return false;
  return true;
}

/** Canonicalize a JSON value to the AINRA canonical string. Throws CanonError on a divergent input. */
export function canonicalize(v: unknown): string {
  validate(v);
  return enc(v);
}

function validate(v: unknown): void {
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new CanonError("floating-point numbers are not allowed");
    if (Math.abs(v) > JS_SAFE_INT_MAX) throw new CanonError("integer outside the JS-safe range");
    return;
  }
  if (Array.isArray(v)) {
    for (const it of v) validate(it);
    return;
  }
  if (v !== null && typeof v === "object") {
    for (const k of Object.keys(v as object)) {
      if (!isAscii(k)) throw new CanonError("non-ASCII object keys are not allowed");
      validate((v as Record<string, unknown>)[k]);
    }
  }
}

function enc(v: unknown): string {
  if (v === null) return "null";
  const t = typeof v;
  if (t === "boolean") return v ? "true" : "false";
  if (t === "number") return String(v); // integer, validated
  if (t === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(enc).join(",") + "]";
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + enc(o[k])).join(",") + "}";
}
