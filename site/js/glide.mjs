// SPDX-License-Identifier: Apache-2.0 OR MIT
// The page glides. A notch of a mouse wheel moves the page toward where it is going over about a third of a second
// instead of jumping there, so reveals and the hero's drift are seen moving, not arriving. Loaded by g.mjs.
//
// What it leaves alone, on purpose:
//   · a touch screen, a touchpad or a mouse that already scrolls in small steps (the system glides those itself);
//   · the keyboard, the scrollbar, a link to a place in the page, the browser's find: they scroll as always, and
//     take over at once if they are used while the page is gliding;
//   · anything on the page with its own scrollbar, and the page while a panel has locked it (menu, search);
//   · Ctrl+wheel (zoom), a sideways wheel, reduced motion, and Motion: off.
// It only ever calls scrollTo: the position is the browser's own, so nothing else on the page needs to know.
const html = document.documentElement;
const fine = matchMedia("(hover:hover) and (pointer:fine)"), reduce = matchMedia("(prefers-reduced-motion: reduce)");
const TAU = 95;                  // ms: the glide covers 95% of the way in about three of these
const NOTCH = 50;                // px: a wheel step at least this large is a notch, not a touchpad's stream

let target = 0, pos = 0, raf = 0, last = 0, set = -1;
const on = () => fine.matches && !reduce.matches && html.dataset.motion !== "off";
const limit = () => Math.max(0, html.scrollHeight - innerHeight);
const locked = () => getComputedStyle(html).overflowY === "hidden" || getComputedStyle(document.body).overflowY === "hidden";
// between the pointer and the page, is there something that scrolls this way by itself?
const scrollsItself = (el, dy) => {
  for (; el && el !== document.body && el !== html; el = el.parentElement) {
    if (el.scrollHeight <= el.clientHeight + 1) continue;
    if (!/(auto|scroll)/.test(getComputedStyle(el).overflowY)) continue;
    if (dy < 0 ? el.scrollTop > 0 : el.scrollTop + el.clientHeight < el.scrollHeight - 1) return true;
  }
  return false;
};
const stop = () => { if (raf) cancelAnimationFrame(raf); raf = 0; set = -1; };
const step = (now) => {
  const dt = Math.min(48, now - last); last = now;
  pos += (target - pos) * (1 - Math.exp(-dt / TAU));
  if (Math.abs(target - pos) < 0.5) pos = target;
  set = pos; scrollTo({ top: pos, left: scrollX, behavior: "instant" });
  raf = pos === target ? 0 : requestAnimationFrame(step);
  if (!raf) set = -1;
};

addEventListener("wheel", (e) => {
  if (!on() || e.defaultPrevented || e.ctrlKey || e.metaKey || e.shiftKey) return;
  if (Math.abs(e.deltaX) > Math.abs(e.deltaY)) return;
  const dy = e.deltaMode === 1 ? e.deltaY * 40 : e.deltaMode === 2 ? e.deltaY * innerHeight : e.deltaY;
  if (e.deltaMode === 0 && Math.abs(dy) < NOTCH) { stop(); return; }           // a touchpad: the system's own glide
  if (locked() || scrollsItself(e.target, dy)) { stop(); return; }
  e.preventDefault();
  if (!raf) { pos = target = scrollY; last = performance.now(); }
  target = Math.max(0, Math.min(limit(), target + dy));
  if (!raf && target !== pos) raf = requestAnimationFrame(step);
}, { passive: false });

// anything else that moves the page takes over at once
addEventListener("scroll", () => { if (raf && set >= 0 && Math.abs(scrollY - set) > 2) stop(); }, { passive: true });
for (const ev of ["keydown", "pointerdown", "touchstart", "hashchange", "resize"]) addEventListener(ev, stop, { passive: true });
new MutationObserver(() => { if (!on()) stop(); }).observe(html, { attributes: true, attributeFilter: ["data-motion", "class"] });
