// SPDX-License-Identifier: Apache-2.0 OR MIT
// Small state transitions every page shares (MOTION.md M13, M17). State, not decoration: each one follows something
// the visitor did or where they are, and under reduced motion (or Motion off) it jumps instead of sliding.
//   M17  the code-panel tab underline slides to the chosen tab; COPY → COPIED shows a still block glyph
//   M13  the chapter rail's current-item marker (a 2px ink bar) slides between items (docs, foundation)
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

for (const list of $$('.code-panel__tabs[role="tablist"]')) {
  const ink = document.createElement("span"); ink.className = "code-panel__ink"; ink.setAttribute("aria-hidden", "true");
  list.appendChild(ink); list.classList.add("has-ink");
  const place = () => { const t = list.querySelector('[aria-selected="true"]'); if (!t) return; ink.style.width = `${t.offsetWidth}px`; ink.style.transform = `translateX(${t.offsetLeft - list.scrollLeft}px)`; };
  new MutationObserver(place).observe(list, { attributes: true, subtree: true, attributeFilter: ["aria-selected"] });
  list.addEventListener("scroll", place, { passive: true }); addEventListener("resize", place); place();
}

// COPY → COPIED: every copy button on every page writes its label; mark the confirmed state for the glyph
const copyBtns = $$(".code-panel__copy, #askCopy, [data-copy]");
for (const b of copyBtns) new MutationObserver(() => b.classList.toggle("is-copied", /^COPIED/.test(b.textContent.trim()))).observe(b, { childList: true, characterData: true, subtree: true });

for (const rail of $$(".chapter-rail")) {
  const box = rail.querySelector("ol, ul"); if (!box) continue;
  const ink = document.createElement("span"); ink.className = "rail-ink"; ink.setAttribute("aria-hidden", "true");
  rail.appendChild(ink); rail.classList.add("has-ink");   // the rail is sticky (positioned) on desktop, static below 1024px
  const place = () => {
    const cur = rail.querySelector('a[aria-current="true"], a.is-current, a[aria-current="location"]');
    if (!cur || getComputedStyle(rail).position === "static") { ink.style.display = "none"; return; }
    ink.style.display = "block"; ink.style.height = `${cur.offsetHeight}px`; ink.style.transform = `translateY(${cur.offsetTop}px)`;
  };
  new MutationObserver(place).observe(rail, { attributes: true, subtree: true, attributeFilter: ["aria-current", "class"] });
  addEventListener("resize", place); place();
}

// M14 figure draw-on: the grey drawing is complete underneath; an ink overlay of its connectors draws on once, when
// the figure is a quarter in view. Decoration only — no text moves or hides. With motion off it is simply drawn.
for (const root of $$("[data-drawon]")) {
  const paths = $$("[data-draw]", root); if (!paths.length) continue;
  if (document.documentElement.dataset.motion === "off" || !("IntersectionObserver" in window)) { root.classList.add("is-drawn"); continue; }
  for (const p of paths) { const l = p.getTotalLength?.() || 0; p.style.strokeDasharray = `${l}`; p.style.strokeDashoffset = `${l}`; }
  const io = new IntersectionObserver((es) => { if (es.some((e) => e.isIntersecting)) { io.disconnect(); requestAnimationFrame(() => paths.forEach((p) => (p.style.strokeDashoffset = "0"))); } }, { threshold: 0.25 });
  io.observe(root);
}
