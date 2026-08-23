// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make engine-parity — the two verifiers `site/verify.html` may load must return the SAME verdict.
//
// The page prefers `ainra-core` compiled to WebAssembly and falls back to the JavaScript SDK when WASM does not
// load. Which one a visitor gets is decided by their browser, not by us, so the two must be indistinguishable.
//
// They were not. The WASM path called `verify()`, which defaults the audience to `""`; the JS path called
// `runVector()`, which reads the audience off the presentation. Once the empty audience became fail-closed, the
// same instance bundle was refused by one engine and accepted by the other — and the accepting one let the
// PRESENTER name the verifier, which is the defect the audience parameter exists to prevent. `make wasm-diff`
// could not see it: it drives `run_vector` on both sides, so both sides read the wire audience and agreed.
//
// WITNESS: could this observe a failure? Yes, and it did — restore either half of the old wiring (drop the
// audience argument from the WASM call, or stop writing it onto the presentation for the JS call) and every row
// below flips to DIFFER. That is the check reading the binding and not something incidental.
//
// Usage: node tools/engine-parity.mjs

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const V = join(ROOT, "vectors/v1");

const m = await import(join(ROOT, "site/assets/wasm/ainra_wasm.js"));
await m.default({ module_or_path: readFileSync(join(ROOT, "site/assets/wasm/ainra_wasm_bg.wasm")) });
const sdk = await import(join(ROOT, "packages/sdk-ts/dist/index.js"));

// Exactly the two call shapes site/verify.html uses. Keep them in step with that file.
const wasm = (p, a, n, aud) => {
  const e = JSON.parse(m.verify_aud(JSON.stringify(p), JSON.stringify(a), n, aud));
  return e.status + (e.reason ? "/" + e.reason : "");
};
const js = (p, a, n, aud) => {
  const v = sdk.runVector({ name: "", expect: {}, anchors: a, presentation: { ...p, audience: aud } });
  return v.verdict + (v.reason ? "/" + v.reason : "");
};

// Instance bundles are where the engines diverged, but a plain passport must agree too — otherwise a green
// result here would only mean "we tested the one case we already fixed".
const pick = (prefix) => {
  const f = readdirSync(V).filter((x) => x.startsWith(prefix) && x.endsWith(".json")).sort()[0];
  if (!f) throw new Error(`no vector matching ${prefix}* — the corpus cannot exercise this gate`);
  return JSON.parse(readFileSync(join(V, f), "utf8"));
};

const cases = [];
for (const [kind, prefix] of [["instance", "instance-valid-"], ["plain passport", "valid-"], ["revoked", "instance-passport-revoked-"]]) {
  const vec = pick(prefix);
  const { presentation: p, anchors: a } = vec;
  for (const [label, aud] of [
    ["addressed audience", p.audience || ""],
    ["verifier named nothing", ""],
    ["a different service", "https://other-service.example"],
  ]) {
    cases.push({ kind, label, p, a, now: p.now, aud });
  }
}

let bad = 0;
console.log("engine-parity · site/verify.html · WASM vs the JavaScript fallback");
for (const c of cases) {
  const w = wasm(c.p, c.a, c.now, c.aud);
  const j = js(c.p, c.a, c.now, c.aud);
  const ok = w === j;
  if (!ok) bad = 1;
  console.log(`  ${ok ? "agree " : "DIFFER"}  ${(c.kind + " · " + c.label).padEnd(40)} wasm=${w.padEnd(30)} js=${j}`);
}

if (bad) {
  console.error(`\nENGINE-PARITY FAILED — site/verify.html can return two different verdicts for the same bytes,`);
  console.error(`depending on whether a visitor's browser loaded WebAssembly. Both engines must be given the same`);
  console.error(`audience explicitly: WASM via verify_aud(), the JS mirror by writing it onto the presentation.`);
  process.exit(1);
}
console.log(`ENGINE-PARITY OK: ${cases.length} case(s) — both engines agree on every one.`);
