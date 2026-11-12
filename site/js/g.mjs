// SPDX-License-Identifier: Apache-2.0 OR MIT
// Headline preview for the owner: ?h=1 (recommended) … ?h=4 sets the hero headline before anything animates it.
{ const H = ["A passport for every AI agent.", "Know which agent you're dealing with.", "Proof of who an agent is.", "Every AI agent, accountable."];
  const n = +new URLSearchParams(location.search).get("h"); const h = document.querySelector(".g-hero h1, #g-h1");
  if (h && n >= 1 && n <= H.length) h.textContent = H[n - 1]; }
// Concept G: the full-screen menu (a dialog: Esc and the button close it, focus is kept inside and returned) and the
// parts list's preview (hovering or focusing a row shows that part's frame from the film).
const html = document.documentElement;
const menu = document.getElementById("gMenu"), btn = document.querySelector("[data-g-menu]");
if (menu && btn) {
  let last = null;
  const focusables = () => [...menu.querySelectorAll("a, button")].filter((e) => !e.hidden);
  // while the menu is open everything behind it is inert: focus, clicks and screen readers stay in the menu and header
  const behind = (on) => { for (const el of document.body.children) if (el !== menu && !el.contains(btn) && el.tagName !== "SCRIPT") el.inert = on; };
  const open = () => { last = document.activeElement; menu.hidden = false; behind(true); html.classList.add("g-menu-open");
    // the header now stays above the open sheet, so the sheet's first line starts below the header's lower edge
    const nb = document.querySelector("nav:not([class]) .nav-in")?.getBoundingClientRect().bottom || 0; menu.style.paddingTop = `${Math.max(96, Math.round(nb + 24))}px`; btn.setAttribute("aria-expanded", "true"); btn.querySelector("span").textContent = "Close"; focusables()[0]?.focus(); };
  const close = () => { menu.hidden = true; behind(false); html.classList.remove("g-menu-open"); btn.setAttribute("aria-expanded", "false"); btn.querySelector("span").textContent = "Menu"; (last || btn).focus(); };
  btn.addEventListener("click", () => (menu.hidden ? open() : close()));
  menu.addEventListener("click", (e) => { if (e.target.closest("a") || e.target === menu || e.target.parentElement === menu) close(); });   // a link, or the sheet's empty space
  addEventListener("keydown", (e) => {
    if (menu.hidden) return;
    if (e.key === "Escape") { e.preventDefault(); close(); return; }
    if (e.key === "Tab") { const f = [...focusables(), btn], i = f.indexOf(document.activeElement);
      if (e.shiftKey && i <= 0) { e.preventDefault(); f[f.length - 1].focus(); } else if (!e.shiftKey && i === f.length - 1) { e.preventDefault(); f[0].focus(); } }
  });
}

const fig = document.querySelector(".g-preview"), img = fig?.querySelector("img");
if (fig && img) {
  for (const row of document.querySelectorAll(".g-row[data-preview]")) {
    const show = () => { if (img.getAttribute("src") !== row.dataset.preview) img.src = row.dataset.preview; const r = row.getBoundingClientRect(), p = fig.parentElement.getBoundingClientRect();
      const h = fig.offsetHeight || 300, above = r.top - p.top - h - 12;
      fig.style.top = `${above >= 0 ? above : r.bottom - p.top + 12}px`; fig.classList.add("is-on");
      const v = fig.querySelector("video"); if (v && row.dataset.previewVideo && html.dataset.motion !== "off") {
        if (v.getAttribute("src") !== row.dataset.previewVideo) { fig.classList.remove("is-playing"); v.src = row.dataset.previewVideo; }
        v.onplaying = () => fig.classList.add("is-playing"); v.currentTime = 0; v.play().catch(() => {}); } };
    const hide = () => { fig.classList.remove("is-on", "is-playing"); fig.querySelector("video")?.pause(); };
    row.addEventListener("mouseenter", show); row.addEventListener("focus", show);
    row.addEventListener("mouseleave", hide); row.addEventListener("blur", hide);
  }
}

// the hero plate rolls in on load (the reveal script handles concept F's hero; this is G's)
const hero = document.querySelector(".g-hero");
if (hero && !document.getElementById("gIntro")) requestAnimationFrame(() => requestAnimationFrame(() => hero.classList.add("is-in")));

// the headline leaves and returns with the film: data-chapters lists the seconds at which each world shot opens
// (film/cut2.py prints them). Over the last 0.8 s of a chapter the words lift away; as the next opens they rise again.
// Only while the film is actually playing and motion is on — paused, stalled or still, the headline stands.
const chapVid = hero?.querySelector("[data-film][data-chapters]"), plate = hero?.querySelector(".g-hero__plate");
if (chapVid && plate && html.classList.contains("rv")) {
  const marks = chapVid.dataset.chapters.split(",").map(Number).filter((n) => n > 0), LEAD = 0.8;
  let out = false, raf = 0;
  const back = () => { if (!out) return; out = false; plate.classList.add("is-reset"); plate.classList.remove("is-out"); void plate.offsetWidth; plate.classList.remove("is-reset"); };
  const tick = () => {
    const t = chapVid.currentTime, ends = Number.isFinite(chapVid.duration) ? [...marks, chapVid.duration] : marks;
    const leaving = ends.some((m) => t >= m - LEAD && t < m);
    if (leaving && !out) { out = true; plate.classList.add("is-out"); } else if (!leaving) back();
    raf = requestAnimationFrame(tick);
  };
  chapVid.addEventListener("playing", () => { cancelAnimationFrame(raf); raf = requestAnimationFrame(tick); });
  for (const ev of ["pause", "waiting", "ended", "emptied"]) chapVid.addEventListener(ev, () => { cancelAnimationFrame(raf); back(); });
}

// the announcement strip: dismissing it is remembered in this browser (a convenience; it may not persist)
const ann = document.querySelector("[data-announce]");
if (ann) {
  const KEY = "ainra-g-announce", ID = "tradeoffs-2026-11-05";
  try { if (localStorage.getItem(KEY) === ID) ann.hidden = true; } catch { /* storage unavailable */ }
  ann.querySelector("[data-announce-x]")?.addEventListener("click", () => { ann.hidden = true; try { localStorage.setItem(KEY, ID); } catch { /* not kept */ } });
}

// the feature carousel, as the reference moves it: a strip of cards that slides by one card; the selected chip fills
// grey over the card's own clip and then the strip slides on; each card has its own previous / next arrows that rise in on hover or
// focus; three copies of the strip let it loop without a jump. Only the card in view plays its scene. Pointing at
// it pauses the advance; choosing a chip or an arrow stops it; with motion off nothing moves by itself.
const tabs = document.querySelector("[data-tabs]");
if (tabs) {
  const chips = [...tabs.querySelectorAll("[role=tab]")], data = [...tabs.querySelectorAll("[data-tab-data] li")].map((li) => ({ ...li.dataset }));
  const track = tabs.querySelector("[data-car-track]"), N = data.length, DWELL = 10000, GAP = 20;
  // on a phone the card's caption is hidden, so each clip has a phone framing where the drawing fills the frame
  // (data-src-m); those clips carry no blueprint, so nothing steps aside for one
  const phone = matchMedia("(max-width:800px)").matches;
  const arrow = (dir) => `<button type="button" class="g-car__arr g-car__arr--${dir}" data-car-step="${dir === "prev" ? -1 : 1}" aria-label="${dir === "prev" ? "Previous" : "Next"}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="${dir === "prev" ? "M19 12H5m6-6-6 6 6 6" : "M5 12h14m-6-6 6 6-6 6"}" fill="none" stroke="currentColor" stroke-width="1.5"/></svg></button>`;
  for (let copy = 0; copy < 3; copy++) for (let i = 0; i < N; i++) {
    const d = data[i], el = document.createElement("div");
    el.className = "g-car__card"; el.dataset.i = i; if (copy !== 1) el.setAttribute("aria-hidden", "true");
    el.innerHTML = `<video muted playsinline loop preload="none" data-src="${(phone && d.srcM) || d.src}" data-poster="${(phone && d.posterM) || d.poster || ""}"></video><a class="g-tabs__label" href="${d.href}"${copy !== 1 ? ' tabindex="-1"' : ""}><span class="g-tabs__k">${d.k}</span><b>${d.t} ↗</b></a>${arrow("prev")}${arrow("next")}<button type="button" class="g-car__play" aria-pressed="false" aria-label="Play this clip"><svg viewBox="0 0 20 20" aria-hidden="true"><path class="i-play" d="M6 4l10 6-10 6z"/><path class="i-pause" d="M6 4h3v12H6zM11 4h3v12h-3z"/></svg><span>Play</span></button>`;
    if (copy !== 1) el.querySelectorAll("button").forEach((x) => (x.tabIndex = -1));
    // each clip ends on a blueprint with its own title in the top-left corner: from data-bp seconds on, the caption
    // steps aside (the chip still names the clip) and comes back when the clip starts again
    if (d.bp && !(phone && d.srcM)) { const v = el.querySelector("video"); v.addEventListener("timeupdate", () => el.classList.toggle("is-bp", v.currentTime >= +d.bp)); }
    track.append(el);
  }
  const cards = [...track.children];
  let pos = N, timer = 0, chosen = false, hold = false, onScreen = false;
  const motion = () => html.dataset.motion !== "off";
  const width = () => track.parentElement.getBoundingClientRect().width;
  const place = (animate) => { track.style.transition = animate && motion() ? "transform .5s cubic-bezier(.65,0,.35,1)" : "none"; track.style.transform = `translateX(${-pos * (width() + GAP)}px)`; };
  // the current card (and its two neighbours, which slide past) carries its still as the clip's poster, so a card is
  // never an empty panel — not while the clip loads, and not with motion off, where the clip waits for its own Play
  const playOnly = () => cards.forEach((c, k) => { const v = c.querySelector("video");
    if ((k === pos || (onScreen && Math.abs(k - pos) <= 1)) && v.dataset.poster && !v.getAttribute("poster")) v.poster = v.dataset.poster;   // the current card has its picture from the start
    c.inert = k !== pos;   // only the card on screen can be focused or clicked (the copies and off-screen cards were tab stops)
    c.classList.toggle("is-still", k === pos && !motion());
    if (k === pos && onScreen) { if (!v.getAttribute("src")) v.src = v.dataset.src;
      if (motion()) { if (v.paused && !v.dataset.keep) v.currentTime = 0; v.play().catch(() => {}); } else if (!c.dataset.asked) v.pause(); } else { v.pause(); delete c.dataset.asked; } });
  // motion off: the card's own Play plays (or pauses) that one clip, by the reader's choice
  track.addEventListener("click", (e) => { const b = e.target.closest(".g-car__play"); if (!b) return; const c = b.closest(".g-car__card"), v = c.querySelector("video");
    if (v.paused) { c.dataset.asked = "1"; if (!v.getAttribute("src")) v.src = v.dataset.src; v.play().catch(() => {}); } else { delete c.dataset.asked; v.pause(); } });
  track.addEventListener("play", (e) => { const b = e.target.closest(".g-car__card")?.querySelector(".g-car__play"); if (b) { b.setAttribute("aria-pressed", "true"); b.lastChild.textContent = "Pause"; b.setAttribute("aria-label", "Pause this clip"); } }, true);
  track.addEventListener("pause", (e) => { const b = e.target.closest(".g-car__card")?.querySelector(".g-car__play"); if (b) { b.setAttribute("aria-pressed", "false"); b.lastChild.textContent = "Play"; b.setAttribute("aria-label", "Play this clip"); } }, true);
  track.parentElement.addEventListener("scroll", () => { track.parentElement.scrollLeft = 0; });   // focus must never scroll the clipped strip itself
  // on a phone the chips are one swipeable row: keep the current one in view (horizontally only — never moves the page)
  const reveal = (c) => { const bar = c.parentElement; if (bar.scrollWidth <= bar.clientWidth + 2) return;
    const left = c.getBoundingClientRect().left - bar.getBoundingClientRect().left + bar.scrollLeft, want = Math.max(0, left - (bar.clientWidth - c.offsetWidth) / 2);
    try { bar.scrollTo({ left: want, behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" }); } catch { bar.scrollLeft = want; } };
  const sync = () => { const i = ((pos % N) + N) % N; chips.forEach((c, j) => { c.setAttribute("aria-selected", String(j === i)); c.tabIndex = j === i ? 0 : -1; }); reveal(chips[i]); playOnly(); run(); };
  const go = (to, animate = true) => { pos = to; place(animate); sync(); };
  // after a slide ends in a copy, jump back to the same card in the middle copy, without a transition
  track.addEventListener("transitionend", () => { if (pos < N || pos >= 2 * N) {
    const was = cards[pos].querySelector("video"), t = was.currentTime;   // the same card in the middle copy carries on from here
    pos = ((pos % N) + N) % N + N; place(false); const now = cards[pos].querySelector("video");
    if (!now.getAttribute("src")) now.src = now.dataset.src; now.currentTime = t; now.dataset.keep = "1"; playOnly(); delete now.dataset.keep; } });
  const run = () => {
    clearTimeout(timer); tabs.classList.remove("is-running");
    if (chosen || hold || !onScreen || !motion()) return;
    // each card stays for its own clip (scene, then its blueprint drawing in); the chip fills over the same time
    const v = cards[pos]?.querySelector("video");
    if (v && !(v.duration > 1) && !v.dataset.waiting) { v.dataset.waiting = "1"; v.addEventListener("loadedmetadata", () => { delete v.dataset.waiting; run(); }, { once: true }); }
    const ms = v && v.duration > 1 && isFinite(v.duration) ? Math.round(v.duration * 1000) : DWELL;
    void tabs.offsetWidth; tabs.style.setProperty("--dwell", `${ms}ms`); tabs.classList.add("is-running");
    timer = setTimeout(() => go(pos + 1), ms);
  };
  chips.forEach((c, i) => c.addEventListener("click", () => { chosen = true; const cur = ((pos % N) + N) % N; go(pos + ((i - cur + N) % N)); }));
  track.addEventListener("click", (e) => { const b = e.target.closest("[data-car-step]"); if (b) { chosen = true; go(pos + Number(b.dataset.carStep)); } });
  tabs.querySelector("[role=tablist]").addEventListener("keydown", (e) => {
    const d = { ArrowRight: 1, ArrowLeft: -1 }[e.key]; if (!d) return; e.preventDefault(); chosen = true; go(pos + d);
    chips[((pos % N) + N) % N].focus();
  });
  for (const [ev, v] of [["mouseenter", true], ["mouseleave", false], ["focusin", true], ["focusout", false]]) tabs.addEventListener(ev, () => { hold = v; run(); });
  new IntersectionObserver((es) => { onScreen = es[0].isIntersecting; playOnly(); run(); }, { rootMargin: "100px 0px" }).observe(tabs);
  new MutationObserver(() => { playOnly(); run(); }).observe(html, { attributes: true, attributeFilter: ["data-motion"] });
  addEventListener("resize", () => place(false));
  go(N, false);
}

// the cards row: previous / next move it by one card (the row never moves by itself)
const track = document.querySelector(".g-asks__track");
for (const b of document.querySelectorAll("[data-asks]")) b.addEventListener("click", () => {
  const card = track?.querySelector(".g-ask"); if (!card) return;
  const step = card.getBoundingClientRect().width + 10;
  track.scrollBy({ left: step * Number(b.dataset.asks), behavior: html.dataset.motion === "off" ? "auto" : "smooth" });
});

// ── intro and page switch ──────────────────────────────────────────────────────────────────────────────────────
// On load: a panel holds the screen while the sigil's snake draws (0.7 s), then wipes off sideways and the headline
// rises word by word. Leaving for another page of this site: the panel sweeps back across, then the browser
// navigates. Only with motion on (html.rv); a fail-safe clears it if anything stalls.
const intro = document.getElementById("gIntro");
// the mark moves on the band and beside a verdict (mark-hooks.mjs). Loaded apart from this module, so a failed
// download costs only the motion: the band still lifts and the still mark stays.
import("./mark-hooks.mjs").catch(() => {});
// a mouse wheel glides the page (glide.mjs); apart from this module for the same reason
import("./glide.mjs").catch(() => {});
// the next page starts to arrive when a link is pointed at or focused, so the band between pages has less to wait for
{ const seen = new Set();
  const warm = (e) => { const a = e.target.closest?.("a[href]"); if (!a || (a.target && a.target !== "_self") || a.hasAttribute("download")) return;
    let u; try { u = new URL(a.href, location.href); } catch { return; }
    if (u.origin !== location.origin || u.pathname === location.pathname || !/(\.html|\/)$/.test(u.pathname) || seen.has(u.pathname)) return;
    if (navigator.connection?.saveData) return;
    seen.add(u.pathname); const l = document.createElement("link"); l.rel = "prefetch"; l.href = u.pathname; l.as = "document"; document.head.append(l); };
  document.addEventListener("pointerover", warm, { passive: true }); document.addEventListener("focusin", warm); document.addEventListener("touchstart", warm, { passive: true }); }
const h1 = document.querySelector(".g-hero h1");
if (h1 && html.classList.contains("rv")) {
  let i = 0; const walk = (node) => { for (const n of [...node.childNodes]) { if (n.nodeType === 1) { walk(n); continue; }
    if (n.nodeType !== 3 || !n.nodeValue.trim()) continue; const frag = document.createDocumentFragment();
    for (const part of n.nodeValue.split(/(\s+)/)) { if (!part) continue; if (/^\s+$/.test(part)) { frag.append(part); continue; }
      const w = document.createElement("span"); w.className = "gw"; const s = document.createElement("span"); s.textContent = part; s.style.setProperty("--i", i++); w.append(s); frag.append(w); }
    n.replaceWith(frag); } };
  walk(h1);
}
const heroEl = document.querySelector(".g-hero");
if (intro && html.classList.contains("rv")) {
  heroEl?.classList.remove("is-in");
  html.classList.add("g-intro-hold");
  const done = () => { intro.classList.add("is-done"); html.classList.remove("g-intro-hold"); setTimeout(() => heroEl?.classList.add("is-in"), 250); };
  // the full intro plays once, on the first page of a visit; after that the switch between pages is brief (a review
  // measured about two seconds from a click to a readable page with no network time at all)
  let seen = false; try { seen = sessionStorage.getItem("ainra-intro") === "1"; sessionStorage.setItem("ainra-intro", "1"); } catch { /* storage may be blocked: play it in full */ }
  if (seen) html.classList.add("g-intro-brief");
  // brief: 380 ms, long enough to see the mark move on the band (mark-hooks.mjs), no longer
  setTimeout(done, seen ? 380 : 750); setTimeout(() => { if (!intro.classList.contains("is-done")) done(); }, 2000);
  document.addEventListener("click", (e) => {
    const a = e.target.closest("a[href]"); if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    if (a.target && a.target !== "_self") return; if (a.hasAttribute("download")) return;
    const url = new URL(a.href, location.href); if (url.origin !== location.origin || (url.pathname === location.pathname && url.hash)) return;
    if (html.dataset.motion === "off" || !html.classList.contains("rv")) return;
    e.preventDefault(); intro.classList.remove("is-done"); intro.classList.add("is-leaving");
    requestAnimationFrame(() => requestAnimationFrame(() => intro.classList.add("is-cover")));
    setTimeout(() => { location.href = url.href; }, 280);
  });
  // coming back through the browser's history restores this page as it was: clear the cover
  addEventListener("pageshow", (e) => { if (e.persisted) { intro.classList.remove("is-leaving", "is-cover"); intro.classList.add("is-done"); } });
}

// ── the details panel: in after the intro; away while the page's hero is off screen; back when it returns, unless
// the reader closed it — then the edge tab offers it again ──────────────────────────────────────────────────────
const side = document.querySelector("[data-side]"), sideTab = document.querySelector("[data-side-open]");
if (side && sideTab) {
  const heroBox = document.querySelector(".g-hero, .gi-hero");
  let closedByReader = false, heroOn = true, ready = false;
  const set = (open) => { side.classList.toggle("is-open", open); sideTab.classList.toggle("is-shown", !open && heroOn); sideTab.setAttribute("aria-expanded", String(open)); };
  side.querySelector("[data-side-close]").addEventListener("click", () => { closedByReader = true; set(false); sideTab.focus(); });
  sideTab.addEventListener("click", () => { closedByReader = false; set(true); side.querySelector("[data-side-close]").focus(); });
  side.addEventListener("keydown", (e) => { if (e.key === "Escape") { closedByReader = true; set(false); sideTab.focus(); } });
  // the film's drawings play on a stage in its upper right (data-stage-bottom: where that stage ends, as a fraction of
  // the 1920×1080 frame). On a short window the panel would cover the stage's lower right, and on a tall one
  // (the film a strip at the top) the page's text; there it starts closed and the edge tab offers it — the same
  // state as when the reader closes it.
  const overStage = () => {
    const v = document.querySelector(".g-hero [data-film][data-stage-bottom]"); if (!v) return false;
    const r = v.getBoundingClientRect(), k = Math.max(r.width / 1920, r.height / 1080), py = parseFloat(getComputedStyle(v).objectPosition.split(" ")[1]) / 100;
    if (r.height < innerHeight * 0.6) return true;   // a tall window: the film is a strip at the top and the page's own text is where the panel would sit
    return r.top + scrollY + (r.height - 1080 * k) * py + +v.dataset.stageBottom * 1080 * k > side.getBoundingClientRect().top - 4;
  };
  const introMs = document.getElementById("gIntro") && html.classList.contains("rv") ? 1150 : 300;
  setTimeout(() => { ready = true; if (overStage()) closedByReader = true; if (heroOn) set(!closedByReader); }, introMs);
  // a panel fixed to the window (the home page's) may sit only over the hero: once the hero's lower edge has risen
  // past the panel's, the page's own text and buttons would be under it (a review found "Read the standard" fully
  // covered through the first scroll), so it steps away at once and returns at the top
  const fixedPanel = getComputedStyle(side).position === "fixed";
  const clear = () => !fixedPanel || !heroBox || heroBox.getBoundingClientRect().bottom >= side.getBoundingClientRect().bottom - 4;
  let ratioOn = true;
  const apply = () => { const on = ratioOn && clear(); if (on === heroOn) return; heroOn = on;
    if (!heroOn) { side.classList.remove("is-open"); sideTab.classList.remove("is-shown"); sideTab.setAttribute("aria-expanded", "false"); }
    else if (ready) set(!closedByReader); };
  if (heroBox && "IntersectionObserver" in window) new IntersectionObserver((es) => { ratioOn = es[0].intersectionRatio > 0.35; apply(); }, { threshold: [0, 0.35, 0.6] }).observe(heroBox);
  if (fixedPanel) { addEventListener("scroll", apply, { passive: true }); addEventListener("resize", apply); }
}

// the cards drift slowly (about 27 px a second); pointing, focus, a touch or the arrows stop them for a while; off
// screen they rest; with motion off they do not move. A hidden second set lets the row loop without a jump.
const drift = document.querySelector(".g-asks__track");
if (drift) {
  let last = 0, rest = 0, on = false, hover = false, acc = 0; const SPEED = 26.7 / 1000;
  const half = () => drift.scrollWidth / 2;
  const tick = (now) => { const dt = last ? Math.min(64, now - last) : 0; last = now;
    const moving = on && !hover && now > rest && html.dataset.motion !== "off";
    drift.classList.toggle("is-drifting", moving);   // snapping would pull each small step back to a card
    if (moving) { acc += SPEED * dt; const step = Math.floor(acc); if (step) { acc -= step; drift.scrollLeft += step; if (drift.scrollLeft >= half()) drift.scrollLeft -= half(); } }
    requestAnimationFrame(tick); };
  const pause = (ms = 6000) => { rest = performance.now() + ms; };
  for (const [ev, v] of [["mouseenter", true], ["mouseleave", false], ["focusin", true], ["focusout", false]]) drift.addEventListener(ev, () => { hover = v; });
  for (const ev of ["wheel", "touchstart", "pointerdown", "keydown"]) drift.addEventListener(ev, () => pause(), { passive: true });
  document.querySelectorAll("[data-asks]").forEach((b) => b.addEventListener("click", () => pause()));
  new IntersectionObserver((es) => { on = es[0].isIntersecting; }).observe(drift);
  requestAnimationFrame(tick);
}

// inner pages: the title settles once the intro has wiped away (or at once without it)
const gi = document.querySelector(".gi-hero");
if (gi) setTimeout(() => gi.classList.add("is-in"), document.getElementById("gIntro") && html.classList.contains("rv") ? 950 : 0);

// the header's call to action stays quiet (an outline) while the hero film is under it, and turns solid once the hero
// has scrolled out from under the header. The film no longer opens on a dark title shot — the headline is the page's
// own <h1> again — so the header never needs to read light-on-dark over it.
const heroBoxEl = document.querySelector(".g-hero [data-film]")?.closest(".g-hero");
if (heroBoxEl) {
  const navEl = document.querySelector("nav:not([class])");
  const setHero = () => { const r = heroBoxEl.getBoundingClientRect(), nb = navEl ? navEl.getBoundingClientRect().bottom : 90; html.classList.toggle("nav-on-hero", r.top < nb && r.bottom > nb); };
  addEventListener("scroll", setHero, { passive: true }); addEventListener("resize", setHero); setHero();
}
// phones: the floating bottom bar steps aside while the page's own two main buttons are under it
const leadCta = document.querySelector(".g-lead__cta"), barMq = matchMedia("(max-width:700px)");
if (leadCta) {
  const yieldBar = () => { const r = leadCta.getBoundingClientRect(); html.classList.toggle("nav-bar-yield", barMq.matches && !html.classList.contains("g-menu-open") && r.bottom > innerHeight - 92 && r.top < innerHeight - 8); };
  addEventListener("scroll", yieldBar, { passive: true }); addEventListener("resize", yieldBar); yieldBar();
}

// the wider argument (Docs): the talk loads from its host only when the reader presses play — nothing is requested before
for (const box of document.querySelectorAll("[data-yt]")) box.querySelector("[data-yt-load]")?.addEventListener("click", () => {
  const t = box.querySelector("template"); if (!t) return; box.replaceChildren(t.content.cloneNode(true)); box.querySelector("iframe")?.focus();
});

// ── search, the way the reference does it: the header's search button opens a full-screen panel; the field waits
// mid-screen with popular searches under it; typing lifts it under the header and lists matching parts of the site,
// read from one static index (search-index.json) — nothing typed ever leaves the browser. Esc or the button closes it.
const sBtn = document.querySelector("nav .g-sq");
if (sBtn) {
  const POPULAR = [["Verify an agent", "verify"], ["Revocation", "revocation"], ["Freshness class", "freshness"], ["Get a passport", "passport"], ["Charter", "charter"]];
  const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const icon = sBtn.innerHTML, closeIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>';
  let ov, input, list, clear, idx = null, t = 0;
  const load = () => idx ? Promise.resolve(idx) : fetch("/search-index.json").then((r) => r.json()).then((d) => (idx = d)).catch(() => (idx = []));
  const mark = (s, toks) => toks.reduce((h, k) => h.replace(new RegExp(`(${k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`, "gi"), "<mark>$1</mark>"), esc(s));
  const render = async () => {
    const q = input.value.trim().toLowerCase(); ov.classList.toggle("has-q", !!q); clear.hidden = !q;
    if (!q) { list.innerHTML = ""; return; }
    const toks = q.split(/\s+/).filter(Boolean), d = await load();
    const hits = d.map((e) => { const tl = e.t.toLowerCase(), hay = `${tl} ${e.x.toLowerCase()} ${e.p.toLowerCase()} ${e.k || ""}`;
      if (!toks.every((k) => hay.includes(k))) return null;
      // a word in the title or the page's name counts most, in the excerpt less, only in the part's body least
      const pl = e.p.toLowerCase(), xl = e.x.toLowerCase();
      return { e, s: toks.reduce((n, k) => n + (tl.includes(k) || pl.includes(k) ? 3 : xl.includes(k) ? 1 : 0.4), 0) + (tl.startsWith(q) ? 5 : 0) }; })
      .filter(Boolean).sort((a, b) => b.s - a.s).slice(0, 12);
    list.innerHTML = hits.length ? hits.map(({ e }) => `<li><a href="/${esc(e.u)}"><span class="g-search__p">${esc(e.p)}</span><span class="g-search__t">${mark(e.t, toks)}</span><span class="g-search__x">${mark(e.x, toks)}</span></a></li>`).join("")
      : `<li class="g-search__none">No results found</li>`;
  };
  const build = () => {
    ov = document.createElement("div"); ov.className = "g-search"; ov.id = "gSearch"; ov.hidden = true;
    ov.setAttribute("role", "dialog"); ov.setAttribute("aria-modal", "true"); ov.setAttribute("aria-label", "Search this site");
    ov.innerHTML = `<div class="g-search__in"><form class="g-search__form" role="search"><label class="vh" for="gSearchQ">Search this site</label><input id="gSearchQ" class="g-search__q" type="search" autocomplete="off" spellcheck="false" placeholder="Start typing to search"><button class="g-search__clear" type="button" hidden>× Clear</button></form>`
      + `<div class="g-search__pop"><span class="g-search__k">Popular searches</span>${POPULAR.map(([l, q]) => `<button type="button" data-q="${q}">${l}</button>`).join("")}</div>`
      + `<ol class="g-search__res" aria-live="polite"></ol></div>`;
    document.body.append(ov);
    input = ov.querySelector("input"); list = ov.querySelector(".g-search__res"); clear = ov.querySelector(".g-search__clear");
    input.addEventListener("input", () => { clearTimeout(t); t = setTimeout(render, 70); });
    clear.addEventListener("click", () => { input.value = ""; render(); input.focus(); });
    ov.querySelector(".g-search__pop").addEventListener("click", (e) => { const b = e.target.closest("[data-q]"); if (!b) return; input.value = b.dataset.q; render(); input.focus(); });
    ov.querySelector("form").addEventListener("submit", (e) => { e.preventDefault(); const a = list.querySelector("a"); if (a) location.href = a.href; });
    ov.addEventListener("keydown", (e) => {
      if (e.key === "Escape") { e.preventDefault(); close(); return; }
      if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
      const links = [...list.querySelectorAll("a")]; if (!links.length) return; e.preventDefault();
      const i = links.indexOf(document.activeElement), n = e.key === "ArrowDown" ? (i + 1) % links.length : i <= 0 ? -1 : i - 1;
      (n < 0 ? input : links[n]).focus();
    });
  };
  const open = () => { if (!ov) build(); ov.hidden = false; void ov.offsetWidth; html.classList.add("g-search-open");
    sBtn.setAttribute("aria-expanded", "true"); sBtn.setAttribute("aria-label", "Close search"); sBtn.innerHTML = closeIcon; load(); setTimeout(() => input.focus(), 30); };
  const close = () => { html.classList.remove("g-search-open"); sBtn.setAttribute("aria-expanded", "false"); sBtn.setAttribute("aria-label", "Search"); sBtn.innerHTML = icon;
    setTimeout(() => { if (!html.classList.contains("g-search-open")) ov.hidden = true; }, 300); sBtn.focus(); };
  sBtn.setAttribute("aria-label", "Search"); sBtn.setAttribute("aria-controls", "gSearch"); sBtn.setAttribute("aria-expanded", "false");
  sBtn.addEventListener("click", (e) => { e.preventDefault(); html.classList.contains("g-search-open") ? close() : open(); });
  document.querySelector("nav .g-menubtn")?.addEventListener("click", () => { if (html.classList.contains("g-search-open")) close(); }, true);
  addEventListener("keydown", (e) => { if (e.key === "/" && !/input|textarea|select/i.test(document.activeElement?.tagName || "") && !html.classList.contains("g-search-open")) { e.preventDefault(); open(); } });
}
