#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The remote emergency ceremony's transport (PLAN-M53 step 4, D-101): ceremony round files as self-checking text
// frames that can cross an air gap as QR codes or on removable media, through a relay nobody has to trust.
//
// A custodian's signing machine never touches a network. It writes its round file (a FROST commitment, then a
// signature share) into its own postbox; `pack` turns the new files into frames; the frames leave as QR codes shown on
// the screen, or as a text file on a USB stick. The relay — anyone, the steward, a shared folder — collects them,
// `unpack`s them into the coordinator's postbox, and packs back what each custodian needs for the next round.
//
//   node kits/ceremony/remote.mjs pack   <postbox> <session> <out.frames> <relative-path>…
//   node kits/ceremony/remote.mjs unpack <postbox> <session> <in.frames>…
//
// A frame is one line of QR alphanumeric characters (base45, RFC 9285), at most FRAME_CHARS long:
//   AINRA1/<session>/<sha256 of the whole file, 16 hex>/<chunk>/<chunks>/<length of the path field>/<path, base45><payload, base45>
// ('/' is itself a base45 character, so nothing after the last header field is split: the path's length says where it ends)
// The relay can lose, repeat or reorder frames; `unpack` puts them back together and refuses a file whose bytes do not
// hash to the digest every one of its frames names, a frame from another session, and a path that would leave the
// postbox. What crosses is public ceremony material only (commitments, signature shares, the signing package): a
// nonce or a key share never leaves the custodian's home, and nothing here can carry one (`pack` refuses any path
// outside `sign/` and `group/`).
//
// Integrity is not the defence against a relay that substitutes a whole commitment: FROST is. A swapped commitment
// makes the aggregate signature fail to verify, and the coordinator's `aggregate` refuses it. The custodians' own
// defence is unchanged from an in-person ceremony: each re-derives the message from its own copy of the proposal and
// signs only that (PLAN-M52 R6).
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname, normalize } from "node:path";

export const FRAME_CHARS = 1800; // fits a QR code of version ~27 in alphanumeric mode, readable from a phone screen
const A45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
export const b45enc = (bytes) => { let o = "";
  for (let i = 0; i < bytes.length; i += 2) {
    if (i + 1 < bytes.length) { let n = bytes[i] * 256 + bytes[i + 1]; const c = n % 45; n = (n - c) / 45; const d = n % 45; o += A45[c] + A45[d] + A45[(n - d) / 45]; }
    else { const n = bytes[i]; o += A45[n % 45] + A45[Math.floor(n / 45)]; }
  } return o; };
export const b45dec = (s) => { const out = [];
  for (let i = 0; i < s.length; i += 3) {
    const v = [...s.slice(i, i + 3)].map((ch) => { const k = A45.indexOf(ch); if (k < 0) throw new Error("not base45"); return k; });
    if (v.length === 3) { const n = v[0] + v[1] * 45 + v[2] * 2025; if (n > 65535) throw new Error("base45 overflow"); out.push(n >> 8, n & 255); }
    else if (v.length === 2) { const n = v[0] + v[1] * 45; if (n > 255) throw new Error("base45 overflow"); out.push(n); }
    else throw new Error("base45 length");
  } return Buffer.from(out); };
const digest16 = (b) => createHash("sha256").update(b).digest("hex").slice(0, 16).toUpperCase();
const SAFE = /^(sign|group)\/[A-Za-z0-9._-]+$/;

export function pack(box, session, paths) {
  const lines = [];
  for (const rel of paths) {
    if (!SAFE.test(rel)) throw new Error(`refused: ${rel} is not public ceremony material (only sign/… and group/… cross the gap)`);
    const bytes = readFileSync(join(box, rel)), d = digest16(bytes), body = b45enc(bytes), p = b45enc(Buffer.from(rel));
    const head = (i, n) => `AINRA1/${session}/${d}/${i}/${n}/${p.length}/${p}`;
    const room = FRAME_CHARS - head(999, 999).length, n = Math.max(1, Math.ceil(body.length / room));
    for (let i = 0; i < n; i++) lines.push(head(i + 1, n) + body.slice(i * room, (i + 1) * room));
  }
  return lines;
}

export function unpack(box, session, lines) {
  const files = new Map(); // digest → { rel, n, parts }
  for (const raw of lines) {
    const line = raw.trim(); if (!line) continue;
    const m = line.match(/^AINRA1\/([A-Z0-9-]+)\/([0-9A-F]{16})\/(\d+)\/(\d+)\/(\d+)\/(.*)$/);
    if (!m) throw new Error("refused: a line that is not an AINRA ceremony frame");
    const [, s, d, i, n, plen, rest] = m, p = rest.slice(0, +plen), body = rest.slice(+plen);
    if (s !== session) throw new Error(`refused: a frame from session ${s}, not ${session}`);
    const rel = b45dec(p).toString("utf8");
    if (!SAFE.test(rel) || normalize(rel) !== rel) throw new Error(`refused: a frame for ${rel}, outside the ceremony's public files`);
    const f = files.get(d) ?? files.set(d, { rel, n: +n, parts: new Map() }).get(d);
    if (f.rel !== rel || f.n !== +n) throw new Error(`refused: frames for one digest disagree about the file`);
    f.parts.set(+i, body);
  }
  // every file is checked before any is written: a batch with one bad file leaves the postbox as it was
  const ready = [];
  for (const [d, f] of files) {
    if (f.parts.size !== f.n) throw new Error(`refused: ${f.rel} has ${f.parts.size} of ${f.n} frames`);
    const bytes = b45dec([...Array(f.n)].map((_, k) => f.parts.get(k + 1)).join(""));
    if (digest16(bytes) !== d) throw new Error(`refused: ${f.rel} does not hash to the digest its frames name — altered in transit`);
    const out = join(box, f.rel); if (existsSync(out) && !readFileSync(out).equals(bytes)) throw new Error(`refused: ${f.rel} already holds different bytes`);
    if (ready.some((r) => r.rel === f.rel && !r.bytes.equals(bytes))) throw new Error(`refused: ${f.rel} arrived twice with different bytes`);
    ready.push({ rel: f.rel, out, bytes });
  }
  for (const r of ready) { mkdirSync(dirname(r.out), { recursive: true }); writeFileSync(r.out, r.bytes); }
  return ready.map((r) => r.rel);
}

if (process.argv[1]?.endsWith("remote.mjs")) {
  const [cmd, box, session, ...rest] = process.argv.slice(2);
  try {
    if (cmd === "pack") { const [out, ...paths] = rest; const lines = pack(box, session, paths); writeFileSync(out, lines.join("\n") + "\n"); console.log(`${lines.length} frame(s) → ${out}`); }
    else if (cmd === "unpack") { const lines = rest.flatMap((f) => readFileSync(f, "utf8").split("\n")); console.log(`unpacked ${unpack(box, session, lines).join(", ")}`); }
    else { console.error("usage: remote.mjs pack <postbox> <session> <out.frames> <path>… | unpack <postbox> <session> <in.frames>…"); process.exit(2); }
  } catch (e) { console.error(e.message); process.exit(1); }
}
