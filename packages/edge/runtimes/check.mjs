// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The same checks in whichever runtime executes this file — Deno, Bun or Node — using only what that runtime
// provides natively (fetch-standard Request/Response, WebAssembly, atob). `make edge-runtimes` runs it in each, and
// `workerd.mjs` runs the gate inside Cloudflare's own runtime. A claim that the gate "runs in Deno" is this file
// passing under `deno run`, nothing less.
import { initAinra, createAinraEdgeGate, runPresentationVector } from "../src/index.mjs";

const here = new URL("./", import.meta.url);
const read = async (u) => {
  if (globalThis.Deno) return Deno.readFile(u);
  const { readFile } = await import("node:fs/promises");     // Node and Bun
  return new Uint8Array(await readFile(u));
};
const readText = async (u) => new TextDecoder().decode(await read(u));
const runtime = globalThis.Deno ? `deno ${Deno.version.deno}` : globalThis.Bun ? `bun ${Bun.version}` : `node ${process.versions.node}`;

await initAinra(await read(new URL("../wasm/ainra_wasm_bg.wasm", here)));
let bad = 0;
const check = (ok, msg) => { console.log(`  ${ok ? "ok" : "✗ "}    ${msg}`); if (!ok) bad = 1; };

// 1 · the request-signature corpus, answered by the WASM core in this runtime
const vdir = new URL("../../../vectors/v1-presentation/", here);
const manifest = JSON.parse(await readText(new URL("manifest.json", vdir)));
const names = ["p01-valid-get", "p10-moved-path", "p21-stale", "p24-replayed", "p31-replayed-but-moved", "p33-signature-noncanonical-base64"];
let agree = 0;
for (const n of names) {
  const v = JSON.parse(await readText(new URL(`${n}.json`, vdir)));
  const st = (o) => JSON.stringify(o, Object.keys(o).sort());
  if (st(runPresentationVector(v)) === st(v.expect)) agree++;
}
check(agree === names.length, `request-signature vectors (a cross-section of ${manifest.count}): ${agree}/${names.length} agree with the core`);

// 2 · a gate over the root-signed fixtures, driven with this runtime's own Request objects
const F = new URL("../../middleware/test/fixtures/", here);
const [directory, roots, valid] = await Promise.all(["directory.json", "roots.json", "bundle-valid.json"].map(async (f) => JSON.parse(await readText(new URL(f, F)))));
const T = JSON.parse(await readText(new URL("meta.json", F))).now;
const gate = await createAinraEdgeGate({ directory, roots, audience: "https://api.example", now: () => T });
const b64u = (s) => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const r = await gate(new Request("https://api.example/orders", { headers: { "x-ainra-passport": b64u(JSON.stringify(valid)) } }));
check(r.event?.status === "valid" && r.reason === "presentation_unsigned" && r.response.status === 403,
  `a valid credential on an unsigned request → ${r.response.status} ${r.reason} (credential ${r.event?.status})`);
const later = await createAinraEdgeGate({ directory, roots, audience: "https://api.example", now: () => T + 3600 });
const s = await later(new Request("https://api.example/orders", { headers: { "x-ainra-passport": b64u(JSON.stringify(valid)) } }));
check(s.reason === "stale_status", `the presenter's F3 does not win: an hour later → ${s.reason}`);
let refused = false;
try { await createAinraEdgeGate({ directory: { ...directory, epoch: directory.epoch + 1 }, roots, audience: "x" }); } catch { refused = true; }
check(refused, "a directory that does not verify stops the gate from existing");

console.log(bad ? `EDGE-RUNTIME FAILED (${runtime})` : `EDGE-RUNTIME OK (${runtime})`);
if (bad) { if (globalThis.Deno) Deno.exit(1); else process.exit(1); }
