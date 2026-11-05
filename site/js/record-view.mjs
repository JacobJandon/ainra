// SPDX-License-Identifier: Apache-2.0 OR MIT
// The published record, as the page shows it. PURE functions of the JSON in site/net/ — no DOM, no fetch, no clock —
// so the same code runs in two places and cannot disagree with itself:
//   * at build time, tools/record-stamp.mjs writes these strings into the HTML, so every number reads with JS off;
//   * at run time, the living elements re-read site/net/*.json and redraw from the same functions.
// Nothing here invents a value. Every string is built from a field of the record, and each item names its file.

export const short = (s, a = 8, b = 3) => (typeof s === "string" && s.length > a + b + 1 ? `${s.slice(0, a)}…${s.slice(-b)}` : String(s ?? "—"));
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** net = { published, registry, roots, checkpoints: { [registrar]: { file, size, root, origin } } } */
export function model(net) {
  const reg = net.registry || {};
  const records = [];
  for (const R of reg.registrars || []) for (const e of R.records || []) {
    const r = e.record || {};
    records.push({
      registrar: r.registrar, sub: r.sub, lineage: r.lineage, version: r.version, tier: r.tier, operator: r.operator,
      status_idx: r.status_idx, leaf_index: r.leaf_index, checkpoint_size: r.checkpoint_size, checkpoint_root: r.checkpoint_root,
      proof_len: (r.inclusion_proof || []).length, revoked: !!r.revoked,
      verdict: e.verdict?.verdict === "valid" ? "VALID" : "REFUSED",
      reason: e.verdict?.reason || "",
    });
  }
  let height = 0;
  for (const r of records) if ((r.checkpoint_size || 0) > height) height = r.checkpoint_size;
  const t = reg.totals || {};
  const lists = (reg.registrars || []).map((R) => ({ registrar: R.registrar, seq: R.status_seq, bits: R.status_list?.bit_len, uri: R.status_list?.uri }));
  const pub = net.published || {};
  return {
    records, lists, height,
    totals: { registrars: t.registrars ?? 0, issued: t.issued ?? 0, revoked: t.revoked ?? 0 },
    publishedIso: pub.published_at_iso || "", publishedDate: (pub.published_at_iso || "").slice(0, 10),
    sha: pub.sha256 || {}, root: net.roots?.root_ed25519 || "", checkpoints: net.checkpoints || {},
  };
}

/** The ticker: real record lines only, each linking to the file it came from. */
export function tickerItems(m) {
  const items = [];
  for (const r of m.records) items.push({ href: "net/registry.json", text: `${r.registrar} · ${r.lineage} ${r.version} · ${r.tier} · `, state: r.verdict, cls: r.revoked ? "is-red" : "is-ok" });
  for (const [id, c] of Object.entries(m.checkpoints)) items.push({ href: c.file, text: `LOG ${c.origin} · SIZE ${c.size} · ROOT ${short(c.root)}` });
  for (const l of m.lists) items.push({ href: "net/registry.json", text: `STATUS LIST ${l.registrar} · SEQ ${l.seq} · ${l.bits} BITS` });
  if (m.root) items.push({ href: "net/roots.json", text: `ROOT ed25519 ${short(m.root)}` });
  if (m.sha["registry.json"]) items.push({ href: "net/published.json", text: `sha256 registry.json ${short(m.sha["registry.json"], 8, 4)}` });
  items.push({ href: "foundation.html", text: "WITNESSES 0 · SPLIT-VIEW GUARANTEE NOT IN FORCE", cls: "is-zero" });
  items.push({ href: "foundation.html", text: "PRODUCTION LOGS SEALED 0 · UNTIL GENESIS", cls: "is-zero" });
  return items;
}
export function tickerHTML(m) {
  return tickerItems(m).map((i) =>
    `<li><a href="${esc(i.href)}"${i.cls ? ` class="${i.cls}"` : ""}><span class="glyph" data-glyph="block" aria-hidden="true"></span>${esc(i.text)}${i.state ? `<b>${esc(i.state)}</b>` : ""}</a></li>`).join("");
}

/** The record table under FIG. 02: one static, readable row per published record. */
export function recordRowsHTML(m) {
  return m.records.map((r, i) =>
    `<tr data-row="${i}"><td>${esc(r.registrar)}</td><td>${esc(r.lineage)}</td><td class="hide-sm">${esc(r.version)}</td><td>${esc(r.tier)}</td><td>${r.status_idx}</td><td class="hide-sm">${r.leaf_index} / ${r.checkpoint_size}</td><td class="${r.revoked ? "is-red" : "is-ok"}">${r.revoked ? 'REFUSED<span class="hide-sm"> · revoked</span>' : "VALID"}</td></tr>`).join("");
}

/** One-line seed label for a Life field, naming the file the 32 bytes came from. */
export function seedLabel(kind, m, arg) {
  if (kind === "checkpoint") { const c = m.checkpoints[arg]; return c ? `checkpoint root · ${arg} · size ${c.size} · ${short(c.root, 8, 4)}` : "—"; }
  if (kind === "sha") return `sha256(${arg}) · ${short(m.sha[arg] || "", 8, 4)}`;
  return "—";
}

/** Values the HTML carries for JS-off readers; the runtime overwrites them with the same numbers. */
export function stampValues(m) {
  return {
    "published-iso": m.publishedIso || "—", "published-date": m.publishedDate || "—",
    registrars: String(m.totals.registrars), issued: String(m.totals.issued), revoked: String(m.totals.revoked),
    "checkpoint-height": String(m.height || "—"), records: String(m.records.length),
    "refusals": String(m.records.filter((r) => r.revoked).length),
    "seed-band": seedLabel("checkpoint", m, "registrar-07"),
    "seed-registry": seedLabel("sha", m, "registry.json"), "seed-directory": seedLabel("sha", m, "directory.json"),
    "seed-roots": seedLabel("sha", m, "roots.json"),
    "root-short": short(m.root),
  };
}
export const stampBlocks = { ticker: tickerHTML, "record-rows": recordRowsHTML };

// ── FIG. 02 the chain of trust ─────────────────────────────────────────────────────────────────────────────────
// Two layouts of one drawing (left-to-right at desktop, top-to-bottom on phones). Everything is drawn in its final,
// readable state for record `ri` (default: the first record in file order); motion.mjs only re-labels and highlights.
const LAYOUT = {
  wide: { vb: [1200, 340], root: [16, 64, 178, 88], regs: [[236, 40, 160, 56], [236, 124, 160, 56]], pp: [470, 60, 190, 96],
    ver: [730, 60, 170, 96], vd: [970, 84, 214, 48], log: [350, 236, 214, 42], wit: [350, 294, 214, 34],
    jn: [430, 108], ppc: [565, 108], verc: [815, 108] },
  narrow: { vb: [360, 470], root: [20, 8, 320, 54], regs: [[20, 90, 150, 44], [190, 90, 150, 44]], pp: [20, 188, 200, 76],
    ver: [20, 300, 200, 76], vd: [20, 410, 320, 48], log: [232, 188, 108, 40], wit: [232, 240, 108, 34],
    jn: [131, 164], ppc: [131, 226], verc: [131, 338] },
};
const rect = (b, cls, extra = "") => `<rect x="${b[0]}" y="${b[1]}" width="${b[2]}" height="${b[3]}" class="${cls}" ${extra}/>`;
const txt = (x, y, s, cls = "", extra = "") => `<text x="${x}" y="${y}" class="${cls}" ${extra}>${esc(s)}</text>`;
export function chainState(m, ri = 0) {
  const r = m.records[ri] || {};
  return { r, l1: `${r.lineage} ${r.version}`, l2: `${r.tier} · status idx ${r.status_idx}`, log: `LOGGED · leaf ${r.leaf_index} of ${r.checkpoint_size}`,
    vd: r.revoked ? "REFUSED · revoked" : "VALID", cap: `${r.registrar} · ${r.lineage} ${r.version} · ${r.tier} · status idx ${r.status_idx} · ${r.revoked ? "REFUSED" : "VALID"}` };
}
export function chainSVG(m, kind = "wide", ri = 0) {
  const L = LAYOUT[kind], s = chainState(m, ri), wide = kind === "wide";
  const regIds = m.lists.map((l) => l.registrar);
  const [rx, ry, rw, rh] = L.root;
  let o = `<svg class="chain chain--${kind}" viewBox="0 0 ${L.vb[0]} ${L.vb[1]}" aria-hidden="true" data-jn="${L.jn}" data-ppc="${L.ppc}" data-verc="${L.verc}">`;
  // connectors (grey, always complete) + ink overlay (draws on once, M14)
  const regOut = L.regs.map((b) => (wide ? [b[0] + b[2], b[1] + b[3] / 2] : [b[0] + b[2] / 2, b[1] + b[3]]));
  const rootOut = wide ? [rx + rw, ry + rh / 2] : [rx + rw / 2, ry + rh];
  const wires = [];
  L.regs.forEach((b, i) => {
    const inn = wide ? [b[0], b[1] + b[3] / 2] : [b[0] + b[2] / 2, b[1]];
    wires.push(wide ? `M${rootOut} H${rootOut[0] + 25} V${inn[1]} H${inn[0]}` : `M${rootOut} V${rootOut[1] + 14} H${inn[0]} V${inn[1]}`);
    wires.push(wide ? `M${regOut[i]} H${L.jn[0]} V${L.jn[1]}` : `M${regOut[i]} V${L.jn[1]} H${L.jn[0]}`);
  });
  const ppIn = wide ? [L.pp[0], L.jn[1]] : [L.jn[0], L.pp[1]];
  wires.push(`M${L.jn} ${wide ? "H" + ppIn[0] : "V" + ppIn[1]}`);
  const ppOut = wide ? [L.pp[0] + L.pp[2], L.ppc[1]] : [L.ppc[0], L.pp[1] + L.pp[3]];
  const verIn = wide ? [L.ver[0], L.verc[1]] : [L.verc[0], L.ver[1]];
  const verOut = wide ? [L.ver[0] + L.ver[2], L.verc[1]] : [L.verc[0], L.ver[1] + L.ver[3]];
  const vdIn = wide ? [L.vd[0], L.verc[1]] : [L.verc[0], L.vd[1]];
  wires.push(`M${ppOut} L${verIn}`, `M${verOut} L${vdIn}`);
  const logTop = wide ? [L.jn[0], L.log[1]] : [L.log[0] + L.log[2] / 2, L.log[1]];
  const logWire = wide ? `M${L.jn} V${logTop[1]}` : `M${L.jn} H${logTop[0]} V${logTop[1]}`;
  const witWire = `M${L.log[0] + L.log[2] / 2},${L.log[1] + L.log[3]} V${L.wit[1]}`;
  o += `<g class="chain__wires">${wires.map((d) => `<path d="${d}"/>`).join("")}<path d="${logWire}"/></g>`;
  o += `<g class="chain__ink">${wires.map((d) => `<path d="${d}" data-draw/>`).join("")}</g>`;
  o += `<path class="chain__logwire" d="${logWire}" data-k="logwire"/>`;
  o += `<path class="chain__wit" d="${witWire}"/>`;
  // arrowheads at node inputs
  const arrow = ([x, y], dir) => (dir === "r" ? `<path class="chain__arrow" d="M${x - 6},${y - 4} L${x},${y} L${x - 6},${y + 4}"/>` : `<path class="chain__arrow" d="M${x - 4},${y - 6} L${x},${y} L${x + 4},${y - 6}"/>`);
  o += [ppIn, verIn, vdIn].map((p) => arrow(p, wide ? "r" : "d")).join("");
  // nodes
  o += `<g class="chain__node">${rect(L.root, "chain__box")}${txt(rx + 12, ry + 20, "ROOT", "chain__h")}${txt(rx + 12, ry + 38, "ed25519 " + short(m.root), "chain__t")}${wide ? txt(rx + 12, ry + 54, "+ SLH-DSA", "chain__t") + txt(rx + 12, ry + 72, "PRE-CEREMONY", "chain__t chain__t--amber") : txt(rx + 12, ry + 54, "+ SLH-DSA · PRE-CEREMONY · TEST-ROOT", "chain__t")}</g>`;
  L.regs.forEach((b, i) => {
    const id = regIds[i] || `registrar-${i}`, l = m.lists[i] || {}, n = m.records.filter((r) => r.registrar === id).length;
    const on = s.r.registrar === id;
    o += `<g class="chain__node">${rect(b, "chain__box" + (on ? " is-on" : ""), `data-k="reg-${esc(id)}"`)}${txt(b[0] + 10, b[1] + 19, id, "chain__h")}${txt(b[0] + 10, b[1] + 35, `${n} records · seq ${l.seq}`, "chain__t")}</g>`;
  });
  const [px, py, pw, ph] = L.pp;
  o += `<g class="chain__node">${rect(L.pp, "chain__box chain__box--doc")}${txt(px + 12, py + 18, "PASSPORT", "chain__h")}`;
  o += `<g class="chain__portrait" transform="translate(${px + 12},${py + 28})">${[0, 1, 2, 3, 4].map((y) => [0, 1, 2, 3, 4].map((x) => ((x * 7 + y * 3) % 5 < 2 ? `<rect x="${x * 5}" y="${y * 5}" width="4" height="4"/>` : "")).join("")).join("")}</g>`;
  o += `${txt(px + 44, py + 40, s.l1, "chain__t chain__t--ink", 'data-k="pp-l1"')}${txt(px + 44, py + 56, s.l2, "chain__t", 'data-k="pp-l2"')}${txt(px + 12, py + ph - 12, "ED25519 + ML-DSA-65", "chain__t")}</g>`;
  const [vx, vy, vw, vh] = L.ver;
  o += `<g class="chain__node">${rect(L.ver, "chain__box")}${txt(vx + 12, vy + 18, "VERIFIER", "chain__h")}${txt(vx + 12, vy + 34, "offline, own machine", "chain__t")}`;
  o += `<g class="chain__strip" data-k="strip" transform="translate(${vx + 12},${vy + 46})">${Array.from({ length: 16 }, (_, i) => `<rect x="${i * 9}" y="0" width="8" height="8" data-i="${i}"${i === s.r.status_idx ? ` class="${s.r.revoked ? "is-red" : "is-ok"}"` : ""}/>`).join("")}</g>`;
  o += `${txt(vx + 12, vy + vh - 12, "status list · bit " + s.r.status_idx, "chain__t", 'data-k="ver-bit"')}</g>`;
  o += `<g class="chain__verdict ${s.r.revoked ? "is-red" : "is-ok"}" data-k="vd">${rect(L.vd, "chain__vdbox")}${txt(L.vd[0] + L.vd[2] / 2, L.vd[1] + L.vd[3] / 2 + 5, s.vd, "chain__vd", 'text-anchor="middle" data-k="vd-t"')}</g>`;
  o += `<g class="chain__node">${rect(L.log, "chain__box")}${txt(L.log[0] + 10, L.log[1] + 17, wide ? "LOG · RFC 6962" : "LOG", "chain__h")}${txt(L.log[0] + 10, L.log[1] + 32, wide ? s.log : `leaf ${s.r.leaf_index}/${s.r.checkpoint_size}`, "chain__t", `data-k="${wide ? "log" : "log-n"}"`)}</g>`;
  o += `<g class="chain__node">${rect(L.wit, "chain__box chain__box--dash")}${txt(L.wit[0] + 10, L.wit[1] + 22, wide ? "WITNESSES · 0 · RECRUITING" : "WITNESSES 0", "chain__t chain__t--amber")}</g>`;
  if (wide) o += `<g class="chain__key">${txt(730, 250, "KEY", "chain__h")}${'<rect x="730" y="262" width="12" height="9" class="chain__k-mint"/>'}${txt(750, 271, "the registrar that issued this record", "chain__t")}${'<path d="M730 290 h12" class="chain__logwire"/>'}${txt(750, 294, "logged before it is valid", "chain__t")}${'<path d="M730 312 h12" class="chain__wit"/>'}${txt(750, 316, "dashed: does not exist yet", "chain__t")}</g>`;
  // the travelling passport token (hidden in the still frame)
  o += `<g class="chain__token" data-k="token" transform="translate(${L.ppc[0] - 14},${L.ppc[1] - 9})"><rect width="28" height="18" rx="2"/><rect x="4" y="4" width="8" height="10" class="chain__token-p"/><path d="M15 6h9M15 10h7M15 14h8"/></g>`;
  return o + "</svg>";
}

// ── FIG. 03 the log tree: an RFC 6962 tree of `size` leaves and the inclusion path for `leaf` ─────────────────────
export function treeLayout(size, leaf) {
  const nodes = [], edges = [];
  const build = (lo, hi, depth) => {
    const id = nodes.length; nodes.push({ lo, hi, depth, x: 0, y: 0 });
    if (hi - lo === 1) { nodes[id].leaf = lo; return id; }
    let k = 1; while (k * 2 < hi - lo) k *= 2;
    const a = build(lo, lo + k, depth + 1), b = build(lo + k, hi, depth + 1);
    nodes[id].kids = [a, b]; edges.push([id, a], [id, b]);
    return id;
  };
  if (size > 0) build(0, size, 0);
  const maxD = Math.max(0, ...nodes.map((n) => n.depth));
  const W = 300, pad = 18, H = 26 + maxD * 46 + 34;
  const leaves = nodes.filter((n) => n.leaf !== undefined).sort((a, b) => a.leaf - b.leaf);
  leaves.forEach((n, i) => { n.x = leaves.length === 1 ? W / 2 : pad + (i * (W - pad * 2)) / (leaves.length - 1); n.y = 26 + maxD * 46; });
  const place = (id) => { const n = nodes[id]; if (n.kids) { n.kids.forEach(place); n.x = (nodes[n.kids[0]].x + nodes[n.kids[1]].x) / 2; n.y = 26 + n.depth * 46; } };
  if (nodes.length) place(0);
  // the path leaf → root, and the sibling of each node on it (the audit path the proof carries)
  const path = [], sibs = [];
  let cur = 0;
  while (nodes[cur] && nodes[cur].kids) {
    const [a, b] = nodes[cur].kids, goA = leaf < nodes[b].lo;
    path.push(cur); sibs.push(goA ? b : a); cur = goA ? a : b;
  }
  path.push(cur);
  return { nodes, edges, path: path.reverse(), sibs: sibs.reverse(), W, H };
}
export function treeSVG(m, ri = 0) {
  const r = m.records[ri]; if (!r) return "";
  const t = treeLayout(r.checkpoint_size, r.leaf_index);
  const ok = t.sibs.length === r.proof_len;
  const lv = new Map(t.path.map((id, i) => [id, i])), sv = new Map(t.sibs.map((id, i) => [id, i]));
  let o = `<svg class="tree" viewBox="0 0 ${t.W} ${t.H}" aria-hidden="true" data-ok="${ok}">`;
  for (const [a, b] of t.edges) { const A = t.nodes[a], B = t.nodes[b]; o += `<path d="M${A.x},${A.y} L${B.x},${B.y}" class="tree__e${lv.has(a) && lv.has(b) && ok ? " is-path" : ""}" data-lv="${lv.get(b) ?? ""}"/>`; }
  t.nodes.forEach((n, id) => {
    const cls = ok && lv.has(id) ? "is-path" : ok && sv.has(id) ? "is-sib" : "";
    o += `<rect x="${n.x - 4}" y="${n.y - 4}" width="8" height="8" class="tree__n ${cls}" data-lv="${lv.get(id) ?? sv.get(id) ?? ""}"/>`;
    if (n.leaf !== undefined) o += `<text x="${n.x}" y="${n.y + 20}" text-anchor="middle" class="tree__t${n.leaf === r.leaf_index ? " is-ink" : ""}">${n.leaf}</text>`;
  });
  const root = t.nodes[0];
  o += `<text x="${root.x}" y="${root.y - 10}" text-anchor="middle" class="tree__t is-ink">root ${esc(short(r.checkpoint_root))}</text>`;
  return o + "</svg>";
}
export function treeCaption(m, ri = 0) {
  const r = m.records[ri]; if (!r) return "";
  const t = treeLayout(r.checkpoint_size, r.leaf_index);
  return t.sibs.length === r.proof_len
    ? `FIG. 03 — LOG · ${r.registrar} · SIZE ${r.checkpoint_size} · INCLUSION PATH FOR LEAF ${r.leaf_index} · ${r.proof_len} SIBLING HASH${r.proof_len === 1 ? "" : "ES"}`
    : `FIG. 03 — LOG · ${r.registrar} · PATH NOT DRAWN · PROOF LENGTH ${r.proof_len} DOES NOT FIT SIZE ${r.checkpoint_size}`;
}

/** The JS-off line under FIG. 04, from the records (the bit-level proof is tools/status-grid-check.mjs). */
export function statusSummary(m, registrar) {
  const l = m.lists.find((x) => x.registrar === registrar); if (!l) return "";
  const rev = m.records.filter((r) => r.registrar === registrar && r.revoked);
  return `${registrar} · seq ${l.seq} · ${l.bits} bits · ${rev.length} set: ${rev.map((r) => `bit ${r.status_idx} (${r.lineage} ${r.version}, revoked)`).join(", ") || "none"}`;
}
Object.assign(stampBlocks, {
  "chain-wide": (m) => chainSVG(m, "wide", 0), "chain-narrow": (m) => chainSVG(m, "narrow", 0),
  "chain-cap": (m) => esc(chainState(m, 0).cap), tree: (m) => treeSVG(m, 0), "tree-cap": (m) => esc(treeCaption(m, 0)),
  "status-07": (m) => esc(statusSummary(m, "registrar-07")), "status-11": (m) => esc(statusSummary(m, "registrar-11")),
});
