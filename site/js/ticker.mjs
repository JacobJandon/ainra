// SPDX-License-Identifier: Apache-2.0 OR MIT
// Published-record ticker (MOTION.md M05): real record lines only, re-read from site/net/*.json, each linking to its
// file. The drift is one CSS animation on one composited layer (24 px/s, 18 on phones), right to left so the text
// enters reading left to right; it pauses on hover, on keyboard focus, with its own button, and off-screen. With
// motion off it does not drift: the line becomes a strip you scroll yourself. It never flashes "new": a published
// record is a snapshot.
import { loadRecord } from "./record.mjs";
import { tickerHTML } from "./record-view.mjs";
import { scanGlyphs } from "./glyphs.mjs";
const $ = (s, r = document) => r.querySelector(s);

/* ── M05 published-record ticker: real lines, drifting right-to-left, pausable ────────────────────────────────── */
function ticker(t, m) {
  const list = $(".ticker__list", t);
  const html = tickerHTML(m);
  if (list && list.innerHTML !== html) { list.innerHTML = html; scanGlyphs(list); }
  const move = $(".ticker__move", t);
  if (move && list && !$(".ticker__clone", t)) {
    const c = list.cloneNode(true); c.classList.add("ticker__clone"); c.setAttribute("aria-hidden", "true");
    c.querySelectorAll("a").forEach((a) => a.setAttribute("tabindex", "-1"));
    move.appendChild(c);
  }
  const speed = innerWidth < 600 ? 18 : 24;
  const set = () => { if (list) t.style.setProperty("--ticker-dur", `${Math.max(20, list.scrollWidth / speed).toFixed(1)}s`); };
  set(); new ResizeObserver(set).observe(list);
  const btn = $("[data-ticker-pause]", t);
  btn?.addEventListener("click", () => { const p = btn.getAttribute("aria-pressed") !== "true"; btn.setAttribute("aria-pressed", String(p)); t.classList.toggle("is-paused", p); });
  if ("IntersectionObserver" in window) new IntersectionObserver((es) => t.classList.toggle("is-off", !es[0].isIntersecting)).observe(t);
}


for (const t of document.querySelectorAll("[data-ticker]")) loadRecord().then(({ m }) => ticker(t, m)).catch(() => t.classList.add("no-drift"));
