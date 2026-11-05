// SPDX-License-Identifier: Apache-2.0 OR MIT
// Life state glyphs (MOTION.md M04): a 5×5 torus running real B3/S23, chosen by state. Decorative (aria-hidden):
// the state is always also written in words beside the glyph.
//   glider  — live, in force (travels and wraps, period 4)
//   blinker — gap, recruiting, proposed (oscillates, period 2: not yet settled)
//   block   — sealed, done, signed (a still life: will not change)
//   zero    — nothing there, honestly (an empty grid)
//   revoked — a block in red: a fixed, final fact
// One generation per 400 ms (discrete steps, no tween), through the page's one scheduler; glyphs off-screen do not
// step. With motion off each glyph shows generation 0, which still reads as its pattern.
import { register } from "./motion.mjs";

const N = 5;
const START = {
  glider: [[0, 1], [1, 2], [2, 0], [2, 1], [2, 2]],
  blinker: [[2, 1], [2, 2], [2, 3]],
  block: [[1, 1], [1, 2], [2, 1], [2, 2]],
  revoked: [[1, 1], [1, 2], [2, 1], [2, 2]],
  zero: [],
};
const NS = "http://www.w3.org/2000/svg";
const step = (c) => {
  const n = new Uint8Array(25);
  for (let y = 0; y < N; y++) for (let x = 0; x < N; x++) {
    let s = 0;
    for (let dy = -1; dy <= 1; dy++) for (let dx = -1; dx <= 1; dx++) if (dx || dy) s += c[((y + dy + N) % N) * N + ((x + dx + N) % N)];
    const i = y * N + x; n[i] = c[i] ? (s === 2 || s === 3 ? 1 : 0) : s === 3 ? 1 : 0;
  }
  return n;
};

const glyphs = [];
function build(el) {
  if (el.__glyph) return;
  const kind = START[el.dataset.glyph] ? el.dataset.glyph : "zero";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("aria-hidden", "true"); svg.setAttribute("focusable", "false");
  svg.classList.add("glyph__svg", "glyph--" + kind);
  const rects = [];
  for (let i = 0; i < 25; i++) {
    const r = document.createElementNS(NS, "rect");
    r.setAttribute("x", (i % N) * 5); r.setAttribute("y", ((i / N) | 0) * 5); r.setAttribute("width", 4); r.setAttribute("height", 4);
    svg.appendChild(r); rects.push(r);
  }
  el.textContent = ""; el.appendChild(svg); el.setAttribute("aria-hidden", "true");
  const g = { el, kind, rects, c0: new Uint8Array(25), c: null, still: kind === "block" || kind === "revoked" || kind === "zero" };
  for (const [y, x] of START[kind]) g.c0[y * N + x] = 1;
  g.c = g.c0;
  paint(g, null);
  el.__glyph = g; glyphs.push(g);
  return g;
}
function paint(g, prev) {
  for (let i = 0; i < 25; i++) if (!prev || prev[i] !== g.c[i]) g.rects[i].classList.toggle("on", !!g.c[i]);
}
export function scanGlyphs(root = document) {
  root.querySelectorAll("[data-glyph]").forEach((el) => {
    const g = build(el);
    if (g && !g.still) register({
      el, name: "glyphs", hz: 2.5,
      step() { const p = g.c; g.c = step(p); paint(g, p); },
      draw(still) { if (still) { const p = g.c; g.c = g.c0; paint(g, p); } },
    });
  });
}
scanGlyphs();
