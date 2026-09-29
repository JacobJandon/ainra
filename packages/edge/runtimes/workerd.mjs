// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The gate inside the workerd runtime itself — not Node pretending: the worker module, the edge package and the
// compiled core are loaded as workerd modules (the .wasm as a CompiledWasm module, the way a deployed worker gets
// it), and requests are dispatched into it. The positive signed path is proven live by `make edge-e2e`.
import { Miniflare } from "miniflare";
import { readFileSync } from "node:fs";
import { presentationRef } from "../../sdk-ts/dist/index.js";

const here = new URL("./", import.meta.url);
const root = new URL("../", here).pathname;
const F = new URL("../../middleware/test/fixtures/", here);
const load = (f) => JSON.parse(readFileSync(new URL(f, F), "utf8"));
const directory = load("directory.json"), roots = load("roots.json"), valid = load("bundle-valid.json");
const T = load("meta.json").now;
const b64u = (s) => Buffer.from(s).toString("base64url");

const mf = (now) => new Miniflare({
  modulesRoot: root,
  modules: [
    { type: "ESModule", path: root + "runtimes/worker.mjs" },
    { type: "ESModule", path: root + "src/index.mjs" },
    { type: "ESModule", path: root + "wasm/ainra_wasm.js" },
    { type: "CompiledWasm", path: root + "wasm/ainra_wasm_bg.wasm" },
  ],
  compatibilityDate: "2026-07-30",
  bindings: { DIRECTORY: directory, ROOTS: roots, NOW: now },
});

let bad = 0;
const check = (ok, msg) => { console.log(`  ${ok ? "ok" : "✗ "}    ${msg}`); if (!ok) bad = 1; };
const at = mf(T);
try {
  const r = await at.dispatchFetch("https://api.example/orders", { headers: { "x-ainra-passport": b64u(JSON.stringify(valid)) } });
  check(r.status === 403 && r.headers.get("x-ainra-reason") === "presentation_unsigned", `a valid credential, unsigned request → ${r.status} ${r.headers.get("x-ainra-reason")}`);
  const p = await at.dispatchFetch("https://api.example/.well-known/ainra-presentation", { method: "POST", body: JSON.stringify(valid) });
  const { ref } = await p.json();
  check(p.status === 201 && ref === presentationRef(valid), `send once → ${p.status}, the same digest the TS SDK computes`);
  const n = await at.dispatchFetch("https://api.example/orders", { headers: { "x-ainra-passport": "sha-256=:" + Buffer.alloc(32).toString("base64") + ":" } });
  check(n.status === 428, `a digest this worker was never sent → ${n.status} ${n.headers.get("x-ainra-reason")}`);
} finally { await at.dispose(); }
const later = mf(T + 3600);
try {
  const s = await later.dispatchFetch("https://api.example/orders", { headers: { "x-ainra-passport": b64u(JSON.stringify(valid)) } });
  check(s.headers.get("x-ainra-reason") === "stale_status", `an hour later, the presenter's F3 does not win → ${s.headers.get("x-ainra-reason")}`);
} finally { await later.dispose(); }
console.log(bad ? "EDGE-WORKERD FAILED" : "EDGE-RUNTIME OK (workerd, via miniflare)");
process.exit(bad);
