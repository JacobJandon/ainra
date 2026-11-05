// SPDX-License-Identifier: Apache-2.0 OR MIT
// Conway's Game of Life — the AINRA doctrine made visible: simple rules build complex systems. B3/S23, exactly
// Conway, on a toroidal grid, and everything that happens in a field emerges from three rules and one seed.
//
// The seed is the published record (MOTION.md M07/M19/M20). 32 bytes of a real hash — a checkpoint root, a status
// hash, the sha256 of a published file — laid out as a 16×16 tile of bits (MSB first). The field is tiled with it;
// tile k is XORed with the bits of the 32-bit word k·2654435761, so tiles differ deterministically. The same record
// always grows the same field: anyone can reproduce generation n from the file named in the readout.
//
// Solid colour only: a cell's age is one of three opaque tints (newborn, young, settled), never alpha. Only changed
// cells are redrawn. Stepping is done by the page's one scheduler (motion.mjs): paused off-screen, in a hidden tab,
// and with motion off, when the field shows one still frame (generation 64 for the band, 32 for ribbons and 404).
//
// Markup: <div class="life" data-life data-seed="cycle|sha:<file>|checkpoint:<registrar>|path" data-hz="5">, with
// optional [data-life-gen], [data-life-pop], [data-life-seed], [data-life-glider] inside it.
import { register, motionOn } from "./motion.mjs";

const css = (n, d) => getComputedStyle(document.documentElement).getPropertyValue(n).trim() || d;

export class Field {
  constructor(canvas, o = {}) {
    this.cv = canvas; this.ctx = canvas.getContext("2d", { alpha: false });
    this.pitch = o.pitch || 8; this.size = o.size || 7;
    this.col = [css("--band", "#ECEEE9"), css("--life-new", "#9CC7B0"), css("--life-mid", "#BFD1C5"), css("--life-cell", "#D3D6D1")];
    this.cols = 0; this.rows = 0; this.gen = 0; this.pop = 0; this.hist = [];
  }
  resize(w, h) {
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const cols = Math.max(4, Math.floor(w / this.pitch)), rows = Math.max(3, Math.floor(h / this.pitch));
    this.cv.width = Math.round(w * dpr); this.cv.height = Math.round(h * dpr);
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.w = w; this.h = h;
    this.ox = Math.floor((w - cols * this.pitch) / 2); this.oy = Math.floor((h - rows * this.pitch) / 2) + 1;
    if (cols !== this.cols || rows !== this.rows) {
      const n = cols * rows, old = this.cur, oc = this.cols, or = this.rows;
      this.cols = cols; this.rows = rows; this.n = n;
      this.cur = new Uint8Array(n); this.nxt = new Uint8Array(n); this.age = new Uint8Array(n); this.ci = new Uint8Array(n);
      this.dirty = new Int32Array(n); this.nd = 0;
      this.L = new Int32Array(cols); this.R = new Int32Array(cols);
      for (let x = 0; x < cols; x++) { this.L[x] = (x - 1 + cols) % cols; this.R[x] = (x + 1) % cols; }
      if (old) for (let y = 0; y < Math.min(or, rows); y++) for (let x = 0; x < Math.min(oc, cols); x++) this.cur[y * cols + x] = old[y * oc + x];
    }
  }
  seed(bytes) {
    const { cols, rows } = this, tx = Math.ceil(cols / 16);
    for (let y = 0; y < rows; y++) for (let x = 0; x < cols; x++) {
      const b = (y & 15) * 16 + (x & 15), k = (y >> 4) * tx + (x >> 4), w = Math.imul(k, 2654435761) >>> 0;
      const bit = ((bytes[b >> 3] >> (7 - (b & 7))) & 1) ^ ((w >>> (b & 31)) & 1);
      const i = y * cols + x; this.cur[i] = bit; this.age[i] = bit; this.ci[i] = bit ? 1 : 0;
    }
    this.gen = 0; this.hist = []; this.pop = this.count(); this.full = true;
  }
  count() { let p = 0; for (let i = 0; i < this.n; i++) p += this.cur[i]; return p; }
  step() {
    const { cols, rows, cur, nxt, age, ci, L, R, dirty } = this;
    let nd = 0, pop = 0;
    for (let y = 0; y < rows; y++) {
      const up = ((y - 1 + rows) % rows) * cols, mid = y * cols, dn = ((y + 1) % rows) * cols;
      for (let x = 0; x < cols; x++) {
        const l = L[x], r = R[x];
        const n = cur[up + l] + cur[up + x] + cur[up + r] + cur[mid + l] + cur[mid + r] + cur[dn + l] + cur[dn + x] + cur[dn + r];
        const i = mid + x, alive = cur[i] ? (n === 2 || n === 3) : n === 3;
        nxt[i] = alive ? 1 : 0;
        let a = alive ? (cur[i] ? Math.min(255, age[i] + 1) : 1) : 0;
        age[i] = a; pop += alive ? 1 : 0;
        const c = a === 0 ? 0 : a === 1 ? 1 : a < 8 ? 2 : 3;
        if (c !== ci[i]) { ci[i] = c; dirty[nd++] = i; }
      }
    }
    this.cur = nxt; this.nxt = cur; this.nd = nd; this.pop = pop; this.gen++;
    this.hist.push(pop); if (this.hist.length > 65) this.hist.shift();
  }
  stagnant() {
    if (this.pop === 0) return true;
    if (this.hist.length < 65) return false;
    return Math.abs(this.hist[64] - this.hist[0]) < Math.max(1, this.hist[64] * 0.01);
  }
  draw() {
    const { ctx, pitch: p, size: s, ox, oy, cols, ci, col } = this;
    if (this.full) {
      ctx.fillStyle = col[0]; ctx.fillRect(0, 0, this.w, this.h);
      for (let c = 1; c < 4; c++) { ctx.fillStyle = col[c]; for (let i = 0; i < this.n; i++) if (ci[i] === c) ctx.fillRect(ox + (i % cols) * p, oy + ((i / cols) | 0) * p, s, s); }
      this.full = false; this.nd = 0; return;
    }
    const { dirty, nd } = this;
    for (let c = 0; c < 4; c++) {
      ctx.fillStyle = col[c];
      for (let k = 0; k < nd; k++) { const i = dirty[k]; if (ci[i] === c) ctx.fillRect(ox + (i % cols) * p, oy + ((i / cols) | 0) * p, s, s); }
    }
    this.nd = 0;
  }
  /** A glider at (x, y), travelling down and to the right. */
  glider(x, y) {
    const { cols, rows } = this;
    for (const [dy, dx] of [[0, 1], [1, 2], [2, 0], [2, 1], [2, 2]]) {
      const i = ((y + dy + rows) % rows) * cols + ((x + dx + cols) % cols);
      this.cur[i] = 1; this.age[i] = 1; if (this.ci[i] !== 1) { this.ci[i] = 1; this.dirty[this.nd++] = i; }
    }
    this.pop = this.count();
  }
}

const pad4 = (n) => String(n).padStart(4, "0");

async function seedsFor(el) {
  const spec = el.dataset.seed || "cycle";
  if (spec === "path") {
    const p = location.pathname;
    let bytes;
    try { bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(p))); }
    catch { bytes = new Uint8Array(32); for (let i = 0; i < p.length; i++) bytes[i % 32] = (bytes[i % 32] * 31 + p.charCodeAt(i)) & 255; }
    return [{ label: `sha256("${p}")`, value: [...bytes].map((b) => b.toString(16).padStart(2, "0")).join(""), bytes }];
  }
  const { loadRecord, seedCycle } = await import("./record.mjs");
  const { net } = await loadRecord();
  const all = seedCycle(net);
  if (spec === "cycle") return all;
  const [kind, arg] = spec.split(":");
  const pick = all.filter((s) => (kind === "sha" ? s.label === `sha256(${arg})` : s.label.includes(arg)));
  return pick.length ? pick.concat(all.filter((s) => !pick.includes(s))) : all;
}

async function boot(el) {
  const host = el.querySelector(".life__field") || el;
  const canvas = document.createElement("canvas");
  canvas.setAttribute("aria-hidden", "true");
  host.prepend(canvas);
  const f = new Field(canvas, { pitch: +el.dataset.pitch || 8, size: (+el.dataset.pitch || 8) - 1 });
  const scope = el.closest("figure") || el;   // a readout may sit beside the field, inside the same figure
  const out = { gen: scope.querySelector("[data-life-gen]"), pop: scope.querySelector("[data-life-pop]"), seed: scope.querySelector("[data-life-seed]"), state: scope.querySelector("[data-life-state]") };
  const still = +el.dataset.still || 64;
  let seeds;
  try { seeds = await seedsFor(el); } catch { seeds = []; }
  if (!seeds.length) { el.classList.add("is-unseeded"); return; }   // no record, no field: never a random one
  let si = 0, lastText = 0, mine = 0;
  const size = () => { const r = host.getBoundingClientRect(); f.resize(Math.max(8, Math.round(r.width)), Math.max(8, Math.round(r.height))); };
  const reseed = (i) => {
    si = i % seeds.length; f.seed(seeds[si].bytes);
    if (out.seed) out.seed.textContent = seeds[si].label + " · " + short(seeds[si].value || "");
  };
  const text = (paused) => {
    if (out.gen) out.gen.textContent = pad4(f.gen);
    if (out.pop) out.pop.textContent = pad4(f.pop);
    if (out.state) out.state.textContent = paused ? "PAUSED" : mine ? `+${mine} GLIDER${mine > 1 ? "S" : ""} (YOURS)` : "RUNNING";
  };
  size(); reseed(0);
  const stillFrame = () => { reseed(si); for (let g = 0; g < still; g++) f.step(); f.full = true; f.draw(); text(true); };
  register({
    el, name: "life:" + (el.dataset.name || el.dataset.seed || "field"), hz: +el.dataset.hz || 5,
    step(now) {
      f.step();
      if (f.gen >= 1024 || f.stagnant()) { reseed(si + 1); mine = 0; }
      if (now - lastText > 190) { lastText = now; text(false); }
    },
    draw(isStill) { if (isStill) stillFrame(); else f.draw(); },
  });
  if (motionOn()) { f.full = true; f.draw(); text(false); }
  // OD-M3: add a glider — by pointer on the field, or by the visible button (keyboard)
  const add = (x, y) => { f.glider(x, y); mine++; if (!motionOn()) { f.draw(); } text(!motionOn()); };
  canvas.addEventListener("click", (e) => { const r = canvas.getBoundingClientRect(); add(Math.floor((e.clientX - r.left - f.ox) / f.pitch), Math.floor((e.clientY - r.top - f.oy) / f.pitch)); });
  el.querySelector("[data-life-glider]")?.addEventListener("click", () => add(Math.floor(f.cols * 0.2 + Math.random() * f.cols * 0.6) | 0, 2));
  let rz; new ResizeObserver(() => { clearTimeout(rz); rz = setTimeout(() => { size(); f.full = true; f.draw(); }, 150); }).observe(host);
}
const short = (s) => (s.length > 14 ? `${s.slice(0, 8)}…${s.slice(-4)}` : s);  // same form as record-view short(s, 8, 4)

document.querySelectorAll("[data-life]").forEach((el) => { boot(el).catch(() => el.classList.add("is-unseeded")); });
