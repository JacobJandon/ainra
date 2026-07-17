// SPDX-License-Identifier: Apache-2.0 OR MIT
// Standalone POST-HOC ceremony-transcript verifier — the check any outsider runs on the PUBLISHED artifacts alone,
// with no access to the ceremony dir, no custodian data, and nothing but Node built-ins: recompute SHA-256 of
// transcript.json and confirm it equals the published transcript.sha256 (and the hash the recording shows). This is
// the "trust the recording, verify the bytes" step — a mismatch means the published transcript is not what was
// witnessed. For the fuller dry-run check (commit-reveal opens, distinct custodians), see witness.mjs.
//
//   node verify-transcript.mjs --transcript <transcript.json> --sha256 <transcript.sha256>
//                              [--checklist <ceremony-checklist.json>]   ← optional: also confirm every step ticked

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const A = (n) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : undefined; };
const tPath = A("transcript"), hPath = A("sha256"), cPath = A("checklist");
if (!tPath || !hPath) {
  console.error("usage: verify-transcript.mjs --transcript <transcript.json> --sha256 <transcript.sha256> [--checklist <file>]");
  process.exit(2);
}
let ok = true;
const pass = (m) => console.log("  ✓ " + m);
const fail = (m) => { console.error("  ✗ " + m); ok = false; };

// Hash the transcript EXACTLY as published (raw bytes — the published hash is over the file, not a re-serialization).
const raw = readFileSync(tPath);
const got = createHash("sha256").update(raw).digest("hex");
const published = readFileSync(hPath, "utf8").trim().split(/\s+/)[0].toLowerCase();
console.log(`verifying ${tPath}\n  recomputed SHA-256 = ${got}\n  published  SHA-256 = ${published}\n`);
got === published
  ? pass("recomputed transcript hash == the published hash (this transcript is what was witnessed)")
  : fail("transcript hash MISMATCH — the published transcript is NOT the bytes the published hash commits to");

// The transcript must at least be well-formed JSON naming the roots + registrars (a sanity floor, not the crypto).
try {
  const t = JSON.parse(raw.toString("utf8"));
  const hasRoots = t.roots || t.root_ed25519 || t.root_slh || (t.directory && t.directory.roots);
  hasRoots ? pass("transcript is well-formed and records the ceremony roots") : fail("transcript JSON has no roots field");
} catch { fail("transcript is not valid JSON"); }

// Optional: if a coordinator checklist is provided, every step must be ticked (done:true).
if (cPath) {
  try {
    const cl = JSON.parse(readFileSync(cPath, "utf8"));
    const undone = (cl.steps || []).filter((s) => !s.done).map((s) => s.id);
    undone.length === 0
      ? pass(`ceremony checklist complete — all ${(cl.steps || []).length} steps ticked${cl.test_root ? " (TEST-ROOT)" : ""}`)
      : fail(`ceremony checklist INCOMPLETE — not ticked: ${undone.join(", ")}`);
    if (cl.test_root) console.log("  ⚠ checklist marks test_root:true — this is a REHEARSAL, not the real recorded ceremony.");
  } catch (e) { fail("checklist unreadable: " + e.message); }
}

console.log("");
if (ok) { console.log("TRANSCRIPT VERIFIED — recomputes to the published hash from public bytes alone."); process.exit(0); }
console.error("TRANSCRIPT VERIFY FAILED."); process.exit(1);
