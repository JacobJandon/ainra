// SPDX-License-Identifier: Apache-2.0 OR MIT
// The AINRA mark, alive (mark.mjs), in the two places the site uses it. Loaded by g.mjs on every page.
//   1. between pages: the site covers the switch with its band (g.mjs, #gIntro) and draws the mark on it. Here the
//      mark on that band moves: the orbit arrow goes round and the nine parts of the seal ring fill, until the next
//      page is ready. With motion off there is no band, as before. If this module never loads, the still drawing in
//      the page stays;
//   2. beside the verdict on Verify (and the home page's demos), following the page's own verdict text. A refusal
//      that is not a revocation stays in ink (DESIGN.md: red is for REVOKED only).
import { mark } from "./mark.mjs";

const css = document.createElement("style");
css.textContent = `
.g-intro__live{width:128px;height:128px;transform:skewX(12deg);display:block}
.g-intro__panel:has(.g-intro__live) .g-intro__mark{display:none}
.live-mark{display:inline-block;flex:none;vertical-align:middle}
.verdict-top{display:grid;grid-template-columns:auto 1fr;column-gap:16px;align-items:center}
.verdict-top .live-mark{grid-row:1 / span 2;width:64px;height:64px}
.g-verdict-row{display:flex;align-items:center;gap:10px}
.g-verdict-row .live-mark{width:36px;height:36px}`;
document.head.append(css);

// ── 1. on the band between pages ──
const intro = document.getElementById("gIntro"), panel = intro?.querySelector(".g-intro__panel");
if (panel) {
  const c = document.createElement("canvas"); c.className = "g-intro__live"; c.setAttribute("aria-hidden", "true");
  panel.append(c);                                                     // the still drawing hides once this one is in
  const m = mark(c, { state: "checking", motion: true, at: 0.5 });     // a first frame is drawn at once
  // each covering starts the arrow from where the mark rests
  let leaving = false;
  new MutationObserver(() => { const l = intro.classList.contains("is-leaving"); if (l && !leaving) m.set("checking"); leaving = l; })
    .observe(intro, { attributes: true, attributeFilter: ["class"] });
}

// ── 2. beside a verdict ──
const slot = () => { const c = document.createElement("canvas"); c.className = "live-mark"; c.setAttribute("aria-hidden", "true"); return c; };
const MIN_CHECK = 1400;
function follow(canvas, verdictEl, reasonEl) {
  const o = mark(canvas, { state: "idle" });
  let shown = "idle", since = 0, pending = 0;
  const pick = () => {
    const t = verdictEl.textContent.trim(), cls = verdictEl.className;
    if (/\bpend\b/.test(cls)) return t === "…" ? "checking" : "idle";
    if (/\bok\b/.test(cls) || /^VALID/.test(t)) return "valid";
    if (/revoked/i.test(t) || (reasonEl && /revoked/i.test(reasonEl.textContent))) return "revoked";
    return "idle";
  };
  const show = (s) => { if (s === shown) return; shown = s; o.set(s); if (s === "checking") since = performance.now(); };
  const sync = () => {
    const s = pick(); clearTimeout(pending);
    if (shown === "checking" && s !== "checking") { const w = MIN_CHECK - (performance.now() - since); if (w > 0) { pending = setTimeout(() => show(pick()), w); return; } }
    show(s);
  };
  const mo = new MutationObserver(sync);
  mo.observe(verdictEl, { attributes: true, childList: true, characterData: true, subtree: true });
  if (reasonEl) mo.observe(reasonEl, { childList: true, characterData: true, subtree: true });
  sync();
}
const vt = document.querySelector(".verdict-top"), big = document.getElementById("big");
if (vt && big) { const c = slot(); vt.prepend(c); follow(c, big, document.getElementById("reason")); }
document.querySelectorAll(".g-verdict-row").forEach((row) => { const v = row.querySelector(".g-verdict"); if (!v) return; const c = slot(); row.prepend(c); follow(c, v, null); });
