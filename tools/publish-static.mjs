#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The static half of online verification (D-079): copy each registrar's signed artefacts into content-addressed
// files any mirror can serve. Nothing here is trusted because of where it is hosted — every file carries its own
// signature, so a mirror, a CDN and the registrar are interchangeable, and a verifier downloads whole lists (no
// lookup by key, so a fetch reveals nothing about which agent is being checked).
//
//   node tools/publish-static.mjs --out site-static --registrar http://127.0.0.1:4970 [--registrar …]
//                                 [--directory URL_OR_FILE --roots URL_OR_FILE]
//
// Layout written:
//   <out>/directory.json, roots.json             (when given) the signed directory and its two root keys
//   <out>/<registrar>/status-list.json           the hybrid-signed status publication (authoritative)
//   <out>/<registrar>/status-list.jwt            the same bits as an IETF statuslist+jwt
//   <out>/<registrar>/links.json                 the whole link index, each entry registrar-signed
//   <out>/sha256/<digest>                        every file above, also under its own SHA-256 (immutable)
//   <out>/heads.json                             what is current: registrar → {file → digest, issued_at}
//   <out>/network-status.json                    D-091: every registrar's signed status list and fresh head, in ONE
//                                                unsigned file (each embedded text is exactly what that registrar
//                                                served, so each still verifies under its own key). A verifier that
//                                                fetches status itself reads this, and the host learns only that this
//                                                address verifies AINRA passports — not whose agents it checks.
// Run it on a timer inside the freshness class you serve (F1 30 s, F2 5 min). It never deletes a sha256/ file.
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const args = process.argv.slice(2);
const opt = (k) => { const i = args.indexOf(`--${k}`); return i >= 0 ? args[i + 1] : undefined; };
const all = (k) => args.flatMap((a, i) => (a === `--${k}` ? [args[i + 1]] : []));
const out = opt("out");
const registrars = all("registrar");
if (!out || registrars.length === 0) {
  console.error("usage: node tools/publish-static.mjs --out DIR --registrar URL [--registrar URL …] [--directory U --roots U]");
  process.exit(2);
}
const sha = (b) => createHash("sha256").update(b).digest("base64url");
const get = async (u) => {
  if (!/^https?:/.test(u)) return readFileSync(u);
  const r = await fetch(u, { signal: AbortSignal.timeout(10_000) });
  if (!r.ok) throw new Error(`${u}: HTTP ${r.status}`);
  return Buffer.from(await r.arrayBuffer());
};
mkdirSync(join(out, "sha256"), { recursive: true });
const put = (rel, bytes) => {
  mkdirSync(join(out, rel, ".."), { recursive: true });
  writeFileSync(join(out, rel), bytes);
  const d = sha(bytes);
  const p = join(out, "sha256", d);
  if (!existsSync(p)) writeFileSync(p, bytes);
  return d;
};

const heads = { generated_at: Math.floor(Date.now() / 1000), registrars: {} };
const network = { v: 1, generated_at: heads.generated_at, registrars: {} };
if (opt("directory") && opt("roots")) {
  heads.directory = put("directory.json", await get(opt("directory")));
  heads.roots = put("roots.json", await get(opt("roots")));
}
let failed = 0;
for (const base of registrars) {
  try {
    const acc = JSON.parse((await get(`${base}/accreditation`)).toString("utf8"));
    const id = acc.registrar;
    if (!/^[a-z0-9-]{1,63}$/.test(id)) throw new Error(`refusing an unsafe registrar id: ${JSON.stringify(id)}`);
    const status = await get(`${base}/status-list`);
    const entry = {
      "status-list.json": put(`${id}/status-list.json`, status),
      "status-list.jwt": put(`${id}/status-list.jwt`, await get(`${base}/status-list.jwt`)),
      "links.json": put(`${id}/links.json`, await get(`${base}/links`)),
      issued_at: JSON.parse(status.toString("utf8")).issued_at,
    };
    heads.registrars[id] = entry;
    // The exact texts, not re-encodings: a fresh head binds the list's text (D-086), and every signature covers bytes.
    network.registrars[id] = {
      "status-list.json": status.toString("utf8"),
      "fresh-head.json": (await get(`${base}/fresh-head`)).toString("utf8"),
    };
    console.log(`  ${id}: status issued ${entry.issued_at} · ${Object.keys(entry).length - 1} files`);
  } catch (e) {
    failed++;
    console.error(`  ✗ ${base}: ${e.message}`);
  }
}
heads.network = put("network-status.json", Buffer.from(JSON.stringify(network)));
put("heads.json", Buffer.from(JSON.stringify(heads, null, 2)));
console.log(failed ? `published with ${failed} registrar(s) unreachable` : `published ${Object.keys(heads.registrars).length} registrar(s) to ${out}`);
process.exit(failed ? 1 : 0);
