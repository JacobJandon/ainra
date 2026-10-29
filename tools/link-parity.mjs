#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
// make link-parity (D-078) — three link gates, one battery. Every vectors/v1-link entry is served to the Node link
// gate (@ainra/middleware ainraLinkGate), the edge engine (@ainra/edge createAinraLinkCheck, the Rust core in
// WebAssembly) and the Python link gate (ainra.AinraLinkGate), exactly as a registrar would serve it: a link index
// keyed by thumbprint and a signed status publication. All three must give the same status, the same named reason,
// and on acceptance the same operator. Hermetic: no network.
import { readFileSync, readdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { Verifier } from "../packages/sdk-ts/dist/index.js";
import { ainraLinkGate } from "../packages/middleware/dist/index.js";
import { initAinra, createAinraLinkCheck, linkFromIndex as edgeLinkFromIndex } from "../packages/edge/src/index.mjs";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const DIR = ROOT + "vectors/v1-link/";
const b64 = (s) => Buffer.from(s, "base64url");
const served = (v) => {
  const l = v.link, c = JSON.parse(b64(l.claims).toString("utf8"));
  return {
    index: { checkpoint: l.checkpoint, checkpoint_sig: l.checkpoint_sig, links: [{ thumbprint: c.subject.thumbprint, claims: l.claims, registrar_sig: l.registrar_sig, leaf_index: l.leaf_index, inclusion_proof: l.inclusion_proof }] },
    status: { uri: l.status_uri, status_list_b64: l.status_list, bit_len: l.status_len, issued_at: l.status_issued_at, sig_ed25519: l.status_sig_ed25519, sig_mldsa65: l.status_sig_mldsa65 },
  };
};
await initAinra(readFileSync(ROOT + "packages/edge/wasm/ainra_wasm_bg.wasm"));
const { jwkThumbprintEd25519 } = await import("../packages/sdk-ts/dist/index.js");

async function node(v) {
  const verifier = Verifier.fromDirectoryB64(v.directory, v.roots.root_ed25519, v.roots.root_slh, v.freshness);
  if (!verifier) return { status: "no_gate", reason: null, operator: null };
  const gate = ainraLinkGate(verifier, { verifiedKey: () => b64(v.presented_key), source: () => served(v), now: () => v.now, capability: () => v.capability ?? undefined });
  return new Promise((resolve) => {
    const req = { method: "GET", url: "/", headers: { host: "x.example" } };
    let status = 200;
    const res = { status(c) { status = c; return res; }, json(b) { resolve({ status, reason: b.reason, operator: null }); }, setHeader() {} };
    gate(req, res, () => resolve({ status: 200, reason: null, operator: req.ainraLink.operator }));
  });
}
async function edge(v) {
  let check;
  try { check = await createAinraLinkCheck({ directory: v.directory, roots: v.roots, freshness: v.freshness, now: () => v.now }); }
  catch { return { status: "no_gate", reason: null, operator: null }; }
  const { index, status } = served(v);
  const link = edgeLinkFromIndex(index, status, jwkThumbprintEd25519(b64(v.presented_key)));
  if (!link) return { status: 403, reason: "not_linked", operator: null };
  const r = check(link, v.presented_key, v.capability ?? "");
  return r.verdict === "valid" ? { status: 200, reason: null, operator: r.operator } : { status: 403, reason: r.reason, operator: null };
}
const py = new Map(execFileSync("python3", [ROOT + "tools/link-parity.py", DIR], { encoding: "utf8" })
  .trim().split("\n").map((l) => JSON.parse(l)).map((r) => [r.name, { status: r.status, reason: r.reason, operator: r.operator }]));

let bad = 0, n = 0;
for (const f of readdirSync(DIR).filter((x) => x.endsWith(".json") && x !== "manifest.json").sort()) {
  const v = JSON.parse(readFileSync(DIR + f, "utf8"));
  n++;
  const [a, b, c] = [await node(v), await edge(v), py.get(v.name)];
  const s = (x) => JSON.stringify(x);
  if (s(a) !== s(b) || s(a) !== s(c)) { bad++; console.error(`  ✗ ${v.name}: node ${s(a)} · edge ${s(b)} · python ${s(c)}`); }
}
if (bad) { console.error(`LINK-PARITY FAILED: ${bad}/${n} vectors read differently across the three gates`); process.exit(1); }
console.log(`LINK-PARITY OK: ${n} link vectors, 3 gates (node, edge, python) — the same status, reason and operator on every one.`);
