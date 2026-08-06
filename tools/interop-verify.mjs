// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// M26 (d) — cross-implementation interop on FRESHLY-SIGNED material.
//
// The conformance corpus is generated from a fixed seed, so replaying it proves the upgraded `ml-dsa` reproduces
// what the old one produced. That is necessary and it is not sufficient: after the 0.0.4 → 0.1.1 upgrade the
// regenerated corpus came out BYTE-IDENTICAL, which makes "the vectors still pass" an easy test to pass. It says
// nothing about material that has never existed before.
//
// So: the upgraded Rust signs three novel messages under a seed the corpus has never used, and the two
// INDEPENDENT ML-DSA implementations check them —
//
//     TypeScript   @noble/post-quantum      (packages/sdk-ts)
//     Python       OpenSSL via cryptography (packages/sdk-py)
//
// Neither shares a line of code with RustCrypto's ml-dsa, so agreement here is real interoperability evidence and
// not an echo. Each implementation must ALSO refuse a single flipped bit — an implementation that accepts
// everything would otherwise pass the positive half in silence.
//
// This exists as a committed, runnable check rather than something once run in a shell: the claim "both other
// implementations verified it" is worth exactly as much as the command that reproduces it.
//
//     make interop
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, unlinkSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const b64u = (s) => Buffer.from(s, "base64url");
let failures = 0;
const bad = (m) => { console.error(`  ✗ ${m}`); failures++; };

// ── 1. the upgraded Rust signs material that has never existed ────────────────────────────────────────────
const dir = mkdtempSync(join(tmpdir(), "ainra-interop-"));
const out = join(dir, "export.json");
execFileSync("cargo", ["test", "--release", "-q", "-p", "ainra-core", "--test", "interop_export"],
  { cwd: ROOT, env: { ...process.env, AINRA_INTEROP_OUT: out }, stdio: "pipe" });
const x = JSON.parse(readFileSync(out, "utf8"));
console.log(`signed by Rust (ml-dsa 0.1.1): ${x.cases.length} cases under a seed the corpus never uses`);

// A harness that cannot fail proves nothing — and this one already shipped a vacuous check once (it compared the
// success value against a sentinel that never occurs, so every genuine signature read as "rejected" and every
// flipped bit read as "refused"). With NEGATIVE_CONTROL=1 one byte of the ML-DSA signature is corrupted before
// either implementation sees it; the run MUST then fail. If it passes, the checks are not checking.
const NEG = process.env.NEGATIVE_CONTROL === "1";
if (NEG) {
  const s = Buffer.from(x.cases[0].mldsa65, "base64url");
  s[0] ^= 0x01;
  x.cases[0].mldsa65 = s.toString("base64url");
  writeFileSync(out, JSON.stringify(x));
  console.log("negative control: corrupted one byte of case 0's ML-DSA signature — this run MUST fail");
}

// ── 2. TypeScript — @noble/post-quantum ───────────────────────────────────────────────────────────────────
const sdk = await import(pathToFileURL(join(ROOT, "packages/sdk-ts/dist/crypto.js")).href);
const pk = { ed25519: b64u(x.pk_ed25519), mldsa65: b64u(x.pk_mldsa65) };
for (const c of x.cases) {
  const msg = b64u(c.msg);
  const sig = { ed25519: b64u(c.ed25519), mldsa65: b64u(c.mldsa65) };
  // verifyHybrid returns NULL on success (HybridResult = null | "alg_downgrade" | "sig_invalid"). Comparing
  // against a truthy "ok" sentinel reports every genuine signature as rejected AND makes the flipped-bit check
  // below vacuously pass — which is precisely what the first run of this file did.
  const ok = sdk.verifyHybrid(pk, msg, sig);
  if (ok !== null) bad(`TS rejected a genuine signature (case ${c.i}): ${ok}`);
  // negative control: one flipped bit in the ML-DSA half must be refused
  const t = { ed25519: sig.ed25519, mldsa65: Uint8Array.from(sig.mldsa65) };
  t.mldsa65[0] ^= 0x01;
  if (sdk.verifyHybrid(pk, msg, t) === null) bad(`TS ACCEPTED a flipped ML-DSA bit (case ${c.i})`);
}
console.log(`(TS)  @noble/post-quantum        : ${x.cases.length}/${x.cases.length} verified · ${x.cases.length}/${x.cases.length} flipped-bit refused`);

// ── 3. Python — OpenSSL through cryptography.hazmat ───────────────────────────────────────────────────────
const py = `
import base64, json, sys
sys.path.insert(0, ${JSON.stringify(join(ROOT, "packages/sdk-py"))})
from ainra._crypto import mldsa65_verify, ed25519_verify
d = json.load(open(${JSON.stringify(out)}))
u = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
pk_ed, pk_ml = u(d["pk_ed25519"]), u(d["pk_mldsa65"])
ok = flip = 0
for c in d["cases"]:
    m, se, sm = u(c["msg"]), u(c["ed25519"]), u(c["mldsa65"])
    if ed25519_verify(pk_ed, se, m) and mldsa65_verify(pk_ml, sm, m): ok += 1
    t = bytearray(sm); t[0] ^= 1
    if not mldsa65_verify(pk_ml, bytes(t), m): flip += 1
print(json.dumps({"ok": ok, "flip": flip, "n": len(d["cases"])}))
`;
const r = JSON.parse(execFileSync("python3", ["-c", py], { cwd: ROOT, encoding: "utf8" }).trim().split("\n").pop());
if (r.ok !== r.n) bad(`Python verified only ${r.ok}/${r.n} genuine signatures`);
if (r.flip !== r.n) bad(`Python ACCEPTED a flipped ML-DSA bit in ${r.n - r.flip} case(s)`);
console.log(`(PY)  OpenSSL via cryptography   : ${r.ok}/${r.n} verified · ${r.flip}/${r.n} flipped-bit refused`);

unlinkSync(out);
if (NEG && !failures) {
  console.error("\nNEGATIVE CONTROL FAILED: a corrupted signature still passed — the checks are not checking.");
  process.exit(1);
}
if (failures) { console.error(`\nINTEROP FAILED: ${failures} problem(s).`); process.exit(1); }
console.log("\nINTEROP OK: material signed by the upgraded Rust verifies under two independent ML-DSA implementations,");
console.log("and both refuse a single flipped bit.");
