// SPDX-License-Identifier: Apache-2.0 OR MIT
// The published record, fetched once per page and shared by every living element. Same-origin files in site/net/
// (the copy of the staging network's read contract shipped with the site). Every fetch has a deadline (net.mjs).
// The per-registrar checkpoint files are named by their height, so the page declares which ones it reads in
// <meta name="ainra-checkpoints">, written by tools/record-stamp.mjs from the directory listing at build time.
import { getJSON, sharedJSON } from "./net.mjs";
import { model } from "./record-view.mjs";

let P = null;
const base = () => (document.querySelector('meta[name="ainra-net"]')?.content || "net").replace(/\/$/, "");

export function loadRecord() {
  return (P ||= (async () => {
    const b = base();
    const [published, registry, roots] = await Promise.all([
      sharedJSON(`${b}/published.json`).then((r) => r.json),
      sharedJSON(`${b}/registry.json`).then((r) => r.json),
      sharedJSON(`${b}/roots.json`).then((r) => r.json).catch(() => null),
    ]);
    const checkpoints = {};
    const list = (document.querySelector('meta[name="ainra-checkpoints"]')?.content || "").split(/\s+/).filter(Boolean);
    await Promise.all(list.map(async (p) => {
      try {
        const c = await getJSON(p.replace(/^net/, b));
        const id = (p.match(/registrars\/([^/]+)\//) || [])[1] || c.origin;
        checkpoints[id] = { file: p, size: c.size, root: c.root, origin: c.origin };
      } catch { /* a checkpoint file that does not answer is simply not shown */ }
    }));
    const heads = {};
    await Promise.all((registry.registrars || []).map(async (R) => {
      try { heads[R.registrar] = await getJSON(`${b}/registrars/${R.registrar}/fresh-head.json`, { cache: "no-store" }); } catch { /* optional */ }
    }));
    const net = { published, registry, roots, checkpoints, heads };
    return { net, m: model(net) };
  })());
}

const b64u = (s) => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; const r = atob(s); const u = new Uint8Array(r.length); for (let i = 0; i < r.length; i++) u[i] = r.charCodeAt(i); return u; };
const hex = (s) => { const u = new Uint8Array(s.length / 2); for (let i = 0; i < u.length; i++) u[i] = parseInt(s.substr(i * 2, 2), 16); return u; };

/** The fixed cycle of 32-byte seeds the Life fields grow from, every one a hash printed in the record. */
export function seedCycle(net) {
  const out = [];
  const cp = net.checkpoints || {};
  if (cp["registrar-07"]) out.push({ label: `checkpoint root · registrar-07 · size ${cp["registrar-07"].size}`, value: cp["registrar-07"].root, bytes: b64u(cp["registrar-07"].root) });
  if (cp["registrar-11"]) out.push({ label: `checkpoint root · registrar-11 · size ${cp["registrar-11"].size}`, value: cp["registrar-11"].root, bytes: b64u(cp["registrar-11"].root) });
  const h7 = net.heads?.["registrar-07"];
  if (h7?.status_hash) out.push({ label: `status hash · registrar-07 · seq ${h7.seq}`, value: h7.status_hash, bytes: b64u(h7.status_hash) });
  for (const f of ["index.json", "registry.json", "directory.json", "roots.json"]) {
    const v = net.published?.sha256?.[f];
    if (v) out.push({ label: `sha256(${f})`, value: v, bytes: hex(v) });
  }
  return out;
}
export const hexBytes = hex;
