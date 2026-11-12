// SPDX-License-Identifier: Apache-2.0 OR MIT
// The AINRA mark, alive: the site's own drawn mark (an orbit arrow around a seal ring around a globe) on a canvas,
// moving to say what the verifier is doing. Every line here is the mark's own geometry (viewBox 0 0 112 112, as in
// the page-switch band and the header); nothing is borrowed from another site's animation.
//
//   import { mark } from "./mark.mjs";
//   const m = mark(canvas, { state: "checking" });   // "idle" · "checking" · "valid" · "revoked"
//   m.set("valid"); m.stop();
//
//   idle      the mark at rest; only the globe turns.
//   checking  the orbit arrow travels once round; the seal ring is cut into nine parts, one per check, and each
//             turns blue as the arrow passes it. Loops: it is also the screen between pages.
//   valid     the ring is whole again and the globe's green arc is drawn all the way round, then rests where the
//             mark has always had it.
//   revoked   the arrow comes to a stop and is gone; the seal ring breaks into nine red parts; the equator is red.
//
// Colour carries meaning, as on the site: ink at rest, signal blue for work in progress, green only for a valid
// verdict, red only for a revocation. Reduced motion draws one still frame. Off screen, nothing is drawn.

const INK = [11, 18, 32], SIGNAL = [47, 91, 255], GREEN = [26, 107, 78], RED = [168, 58, 44];
const rgba = (c, a = 1) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;
const clamp = (x) => (x <= 0 ? 0 : x >= 1 ? 1 : x);
const smooth = (x) => { x = clamp(x); return x * x * (3 - 2 * x); };
const out = (x) => 1 - (1 - clamp(x)) ** 3;
const RAD = Math.PI / 180;
const C = 56, R_ORBIT = 48, R_RING = 36, R_GLOBE = 26;
const REST_HEAD = 298, REST_TAIL = 326;                 // where the mark's arrow rests, and how long its arc is
const LAP = 1.9;                                        // seconds for the arrow to go once round while checking

// For each state, at t seconds since it began: what to draw.
const STATES = {
  idle: { still: 0, at: () => ({ head: REST_HEAD, tail: REST_TAIL, arc: INK, ring: "whole" }) },
  checking: { still: LAP * 0.62, at: (t) => {
    const p = (t % LAP) / LAP;
    return { head: REST_HEAD + 360 * p, tail: REST_TAIL - 190 * Math.sin(Math.PI * p), arc: SIGNAL, ring: "nine",
      done: p * 9, fade: 1 - smooth((p - 0.94) / 0.06) };
  } },
  valid: { still: 2, at: (t) => ({ head: REST_HEAD, tail: REST_TAIL, arc: INK, ring: "whole",
    green: t < 0.65 ? 360 * out(t / 0.65) : 360 - 270 * smooth((t - 0.75) / 0.55) }) },
  revoked: { still: 2, at: (t) => {
    const k = smooth(t / 0.8);
    return { head: REST_HEAD + 40 * out(t / 0.8), tail: REST_TAIL * (1 - k), arc: INK, arcAlpha: 1 - k, ring: "broken",
      gap: 4 + 12 * k, red: smooth(t / 0.5), dim: 1 - 0.5 * k };
  } },
};

export function mark(canvas, opts = {}) {
  const ctx = canvas.getContext("2d");
  let state = STATES[opts.state] ? opts.state : "idle";
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches && !opts.motion;
  const born = performance.now();
  let raf = 0, on = true, t0 = born - (opts.at ?? 0) * 1000, W = 0, H = 0, css = 0, dpr = 1;

  const size = () => {
    const r = canvas.getBoundingClientRect();
    dpr = Math.min(3, devicePixelRatio || 1);
    W = Math.max(1, Math.round(r.width * dpr)); H = Math.max(1, Math.round(r.height * dpr));
    canvas.width = W; canvas.height = H; css = Math.min(r.width, r.height) || 1;
  };

  const draw = (t, turn) => {
    const s = STATES[state].at(t), k = Math.min(W, H) / 112, small = css < 44;
    const lw = (u) => Math.max(u, ((small ? 1.3 : 1) * dpr) / k);     // never thinner than about a pixel
    const P = (r, deg) => [C + r * Math.cos(deg * RAD), C + r * Math.sin(deg * RAD)];
    const arc = (r, a, b, w, colour) => { if (b - a <= 0.01) return; ctx.beginPath(); ctx.arc(C, C, r, a * RAD, b * RAD); ctx.lineWidth = lw(w); ctx.strokeStyle = colour; ctx.stroke(); };
    ctx.setTransform(1, 0, 0, 1, 0, 0); ctx.clearRect(0, 0, W, H);
    ctx.setTransform(k, 0, 0, k, (W - 112 * k) / 2, (H - 112 * k) / 2);
    ctx.lineCap = "round";
    const dim = s.dim ?? 1;

    // the globe: its outline, an equator, two parallels, and meridians that turn
    arc(R_GLOBE, 0, 360, 1.6, rgba(INK, dim));
    for (let j = 0; j < (small ? 2 : 3); j++) {
      const rx = R_GLOBE * Math.abs(Math.sin(turn + (j * Math.PI) / (small ? 2 : 3)));
      if (rx < 0.6) continue;
      ctx.beginPath(); ctx.ellipse(C, C, rx, R_GLOBE, 0, 0, Math.PI * 2); ctx.lineWidth = lw(1); ctx.strokeStyle = rgba(INK, 0.8 * dim); ctx.stroke();
    }
    if (!small) { ctx.beginPath(); ctx.moveTo(33.5, 43); ctx.lineTo(78.5, 43); ctx.moveTo(33.5, 69); ctx.lineTo(78.5, 69); ctx.lineWidth = lw(0.8); ctx.strokeStyle = rgba(INK, 0.6 * dim); ctx.stroke(); }
    ctx.beginPath(); ctx.moveTo(30, 56); ctx.lineTo(82, 56); ctx.lineWidth = lw(s.red ? 1.1 + 0.9 * s.red : 1.1);
    ctx.strokeStyle = s.red ? rgba(INK.map((v, i) => Math.round(v + (RED[i] - v) * s.red))) : rgba(INK); ctx.stroke();

    // the seal ring: whole, or in nine parts (one per check), or broken
    if (s.ring === "whole") arc(R_RING, 0, 360, 1.3, rgba(INK));
    else for (let i = 0; i < 9; i++) {
      const g = s.ring === "broken" ? s.gap : 5, a = REST_HEAD + 40 * i + g / 2, b = a + 40 - g;
      if (s.ring === "broken") { arc(R_RING, a, b, 1.3 + 1.1 * s.red, rgba(INK.map((v, n) => Math.round(v + (RED[n] - v) * s.red)))); continue; }
      arc(R_RING, a, b, 1.3, rgba(INK, 0.24));
      const part = clamp(s.done - i);                                 // how much of this check the arrow has passed
      if (part > 0) arc(R_RING, a, a + (b - a) * part, 2.6, rgba(SIGNAL, s.fade));
    }

    // the green arc on the globe: only ever for a valid verdict
    if (s.green) arc(R_GLOBE, -90, -90 + s.green, 3, rgba(GREEN));

    // the orbit arrow: its arc, its head, and the three small marks in the gap ahead of it
    const aa = s.arcAlpha ?? 1;
    if (aa > 0.02 && s.tail > 1) {
      arc(R_ORBIT, s.head - s.tail, s.head, 3, rgba(s.arc, aa));
      const [bx, by] = P(R_ORBIT, s.head), [tx, ty] = P(R_ORBIT, s.head + 8.5), [ix, iy] = P(R_ORBIT - 4, s.head - 1), [ox, oy] = P(R_ORBIT + 4, s.head - 1);
      ctx.beginPath(); ctx.moveTo(tx, ty); ctx.lineTo(ix, iy); ctx.lineTo(bx, by); ctx.lineTo(ox, oy); ctx.closePath(); ctx.fillStyle = rgba(s.arc, aa); ctx.fill();
      if (!small) { ctx.beginPath(); for (const d of [15, 21.5, 28]) { const [x1, y1] = P(46.6, s.head + d), [x2, y2] = P(50.1, s.head + d); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); }
        ctx.lineWidth = lw(1); ctx.strokeStyle = rgba(INK, 0.5 * aa); ctx.stroke(); }
    }
  };

  const still = () => draw(STATES[state].still, 0.9);
  const frame = (now) => { raf = 0; if (!on) return; draw((now - t0) / 1000, ((now - born) / 1000) * 0.45 + 0.9); raf = requestAnimationFrame(frame); };
  const start = () => { if (!raf && on && !reduce) raf = requestAnimationFrame(frame); };

  size();
  if (reduce) still(); else draw((opts.at ?? 0), 0.9);                 // a first frame at once, even off screen
  start();
  new ResizeObserver(() => { size(); if (reduce) still(); }).observe(canvas);
  if ("IntersectionObserver" in window) new IntersectionObserver((es) => { on = es[0].isIntersecting; if (on) start(); }).observe(canvas);
  canvas.setAttribute("role", "img");
  if (!canvas.getAttribute("aria-label")) canvas.setAttribute("aria-label", opts.label || state);

  return {
    set(s, at = 0) { if (STATES[s]) { state = s; t0 = performance.now() - at * 1000; if (reduce) still(); } },
    stop() { on = false; if (raf) cancelAnimationFrame(raf); raf = 0; },
  };
}

export const MARK_STATES = Object.keys(STATES);
