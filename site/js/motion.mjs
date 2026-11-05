// SPDX-License-Identifier: Apache-2.0 OR MIT
// One scheduler for every living element on a page (MOTION.md B2). One requestAnimationFrame loop; each element
// registers { el, hz, step(now, dt), draw(still) } and is stepped only while it is near the viewport (one shared
// IntersectionObserver, rootMargin 100px) and the tab is visible. Motion is OFF under prefers-reduced-motion unless
// the visitor turns it on, and the visitor's own choice (the Motion switch) is remembered per browser. With motion
// off the loop stops and every element draws ONE still frame: the page is complete either way.
//
// The loop measures itself: performance.now() around every step+draw, per element and per frame, so the CPU budget
// (≤ 1.5 ms average, ≤ 4 ms p95 per frame for all elements together) is a number anyone can read:
// window.ainraMotion.stats(). ?motion-debug=1 on a local host also prints it in a corner.

const html = document.documentElement;
const RM = matchMedia("(prefers-reduced-motion: reduce)");
const KEY = "ainra-motion";
const lowPower = (navigator.hardwareConcurrency || 8) <= 4 || !!navigator.connection?.saveData;

let pref = null;
try { pref = localStorage.getItem(KEY); } catch { pref = null; }
const decide = () => (pref === "on" || pref === "off" ? pref : RM.matches ? "off" : "on");
html.dataset.motion = decide();
export const motionOn = () => html.dataset.motion !== "off";

const items = new Set();
const io = "IntersectionObserver" in window
  ? new IntersectionObserver((es) => { for (const e of es) { const o = e.target.__motion; if (o) for (const it of o) it.visible = e.isIntersecting; } kick(); }, { rootMargin: "100px" })
  : null;

// stats: a ring of per-frame script time, and per-element totals
const RING = 1800;
const frameMs = new Float32Array(RING);
let fi = 0, frames = 0;
const per = new Map();

let raf = 0;
function kick() { if (!raf && motionOn() && !document.hidden) { raf = requestAnimationFrame(loop); } }
function loop(now) {
  raf = 0;
  if (!motionOn() || document.hidden) return;
  let total = 0, any = false;
  for (const o of items) {
    if (!o.visible || o.paused) continue;
    any = true;
    const period = (1000 / o.hz) * (lowPower ? 2 : 1);
    if (now - o.last < period - 1) continue;
    const dt = o.last ? Math.min(now - o.last, 250) : period;
    o.last = now;
    const t0 = performance.now();
    if (o.step) o.step(now, dt);
    if (o.draw) o.draw(false);
    const ms = performance.now() - t0;
    total += ms;
    const s = per.get(o.name) || { n: 0, ms: 0, max: 0 };
    s.n++; s.ms += ms; if (ms > s.max) s.max = ms; per.set(o.name, s);
  }
  frameMs[fi] = total; fi = (fi + 1) % RING; frames++;
  if (dbg) dbgDraw();
  if (any || items.size) raf = requestAnimationFrame(loop);
}

/** Register a living element. Returns a handle with .paused (settable) and .remove(). */
export function register(o) {
  o.visible = !io; o.last = 0; o.paused = !!o.paused; o.name = o.name || "element";
  items.add(o);
  if (io && o.el) { (o.el.__motion ||= new Set()).add(o); io.observe(o.el); }
  if (!motionOn() && o.draw) o.draw(true);
  kick();
  o.remove = () => { items.delete(o); o.el?.__motion?.delete(o); };
  return o;
}

function setMotion(v, remember) {
  html.dataset.motion = v;
  if (remember) { pref = v; try { localStorage.setItem(KEY, v); } catch { /* per-viewer convenience only */ } }
  document.querySelectorAll("[data-motion-toggle]").forEach((b) => {
    b.setAttribute("aria-pressed", v === "on" ? "true" : "false");
    const l = b.querySelector("[data-motion-label]"); if (l) l.textContent = v === "on" ? "Motion: on" : "Motion: off";
  });
  if (v === "off") { if (raf) cancelAnimationFrame(raf); raf = 0; for (const o of items) o.draw?.(true); }
  else { for (const o of items) o.last = 0; kick(); }
  window.dispatchEvent(new CustomEvent("ainra:motion", { detail: v }));
}
document.addEventListener("visibilitychange", kick);
RM.addEventListener?.("change", () => { if (pref !== "on" && pref !== "off") setMotion(decide(), false); });

function wireToggles() {
  document.querySelectorAll("[data-motion-toggle]").forEach((b) => {
    if (b.__wired) return; b.__wired = true;
    b.hidden = false;
    b.addEventListener("click", () => setMotion(motionOn() ? "off" : "on", true));
  });
  setMotion(html.dataset.motion, false);
}
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", wireToggles); else wireToggles();

/** Average and p95 of per-frame script time over the recorded frames, and per-element means. */
function stats() {
  const n = Math.min(frames, RING), a = Array.from(frameMs.slice(0, n)).sort((x, y) => x - y);
  const avg = a.reduce((s, v) => s + v, 0) / (n || 1);
  const p95 = a[Math.floor(n * 0.95)] || 0;
  const el = {}; for (const [k, s] of per) el[k] = { steps: s.n, mean_ms: +(s.ms / s.n).toFixed(3), max_ms: +s.max.toFixed(3) };
  return { frames: n, avg_ms: +avg.toFixed(3), p95_ms: +p95.toFixed(3), max_ms: +(a[n - 1] || 0).toFixed(3), lowPower, elements: el, motion: html.dataset.motion };
}
function reset() { frameMs.fill(0); fi = 0; frames = 0; per.clear(); }
window.ainraMotion = { stats, reset, set: (v) => setMotion(v, false), items: () => [...items].map((o) => ({ name: o.name, visible: o.visible })) };

// local-only debug readout (never in production markup: it is created here, on a local host, on request)
const dbg = /[?&]motion-debug=1/.test(location.search) && /^(localhost|127\.|\[::1\])/.test(location.hostname) ? document.createElement("pre") : null;
let dbgAt = 0;
function dbgDraw() {
  const t = performance.now(); if (t - dbgAt < 500) return; dbgAt = t;
  const s = stats();
  dbg.textContent = `frames ${s.frames}  avg ${s.avg_ms} ms  p95 ${s.p95_ms} ms\n` + Object.entries(s.elements).map(([k, v]) => `${k.padEnd(14)} ${v.mean_ms} ms × ${v.steps}`).join("\n");
}
if (dbg) { dbg.className = "motion-debug"; document.addEventListener("DOMContentLoaded", () => document.body.appendChild(dbg)); }
