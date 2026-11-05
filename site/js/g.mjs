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
  const open = () => { last = document.activeElement; menu.hidden = false; html.classList.add("g-menu-open"); btn.setAttribute("aria-expanded", "true"); btn.querySelector("span").textContent = "Close"; focusables()[0]?.focus(); };
  const close = () => { menu.hidden = true; html.classList.remove("g-menu-open"); btn.setAttribute("aria-expanded", "false"); btn.querySelector("span").textContent = "Menu"; (last || btn).focus(); };
  btn.addEventListener("click", () => (menu.hidden ? open() : close()));
  menu.addEventListener("click", (e) => { if (e.target.closest("a")) close(); });
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
  const arrow = (dir) => `<button type="button" class="g-car__arr g-car__arr--${dir}" data-car-step="${dir === "prev" ? -1 : 1}" aria-label="${dir === "prev" ? "Previous" : "Next"}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="${dir === "prev" ? "M19 12H5m6-6-6 6 6 6" : "M5 12h14m-6-6 6 6-6 6"}" fill="none" stroke="currentColor" stroke-width="1.5"/></svg></button>`;
  for (let copy = 0; copy < 3; copy++) for (let i = 0; i < N; i++) {
    const d = data[i], el = document.createElement("div");
    el.className = "g-car__card"; el.dataset.i = i; if (copy !== 1) el.setAttribute("aria-hidden", "true");
    el.innerHTML = `<video muted playsinline loop preload="none" data-src="${d.src}"></video><a class="g-tabs__label" href="${d.href}"${copy !== 1 ? ' tabindex="-1"' : ""}><span class="g-tabs__k">${d.k}</span><b>${d.t} ↗</b></a>${arrow("prev")}${arrow("next")}`;
    if (copy !== 1) el.querySelectorAll("button").forEach((x) => (x.tabIndex = -1));
    track.append(el);
  }
  const cards = [...track.children];
  let pos = N, timer = 0, chosen = false, hold = false, onScreen = false;
  const motion = () => html.dataset.motion !== "off";
  const width = () => track.parentElement.getBoundingClientRect().width;
  const place = (animate) => { track.style.transition = animate && motion() ? "transform .5s cubic-bezier(.65,0,.35,1)" : "none"; track.style.transform = `translateX(${-pos * (width() + GAP)}px)`; };
  const playOnly = () => cards.forEach((c, k) => { const v = c.querySelector("video");
    if (k === pos && onScreen) { if (!v.getAttribute("src")) v.src = v.dataset.src; if (v.paused && !v.dataset.keep) v.currentTime = 0; if (motion()) v.play().catch(() => {}); } else v.pause(); });
  const sync = () => { const i = ((pos % N) + N) % N; chips.forEach((c, j) => { c.setAttribute("aria-selected", String(j === i)); c.tabIndex = j === i ? 0 : -1; }); playOnly(); run(); };
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
  setTimeout(done, 750); setTimeout(() => { if (!intro.classList.contains("is-done")) done(); }, 2000);
  document.addEventListener("click", (e) => {
    const a = e.target.closest("a[href]"); if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    if (a.target && a.target !== "_self") return; if (a.hasAttribute("download")) return;
    const url = new URL(a.href, location.href); if (url.origin !== location.origin || (url.pathname === location.pathname && url.hash)) return;
    if (html.dataset.motion === "off" || !html.classList.contains("rv")) return;
    e.preventDefault(); intro.classList.remove("is-done"); intro.classList.add("is-leaving");
    requestAnimationFrame(() => requestAnimationFrame(() => intro.classList.add("is-cover")));
    setTimeout(() => { location.href = url.href; }, 470);
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
  const introMs = document.getElementById("gIntro") && html.classList.contains("rv") ? 1150 : 300;
  setTimeout(() => { ready = true; if (heroOn && !closedByReader) set(true); }, introMs);
  if (heroBox && "IntersectionObserver" in window) new IntersectionObserver((es) => {
    heroOn = es[0].intersectionRatio > 0.35;
    if (!heroOn) { side.classList.remove("is-open"); sideTab.classList.remove("is-shown"); sideTab.setAttribute("aria-expanded", "false"); }
    else if (ready) set(!closedByReader);
  }, { threshold: [0, 0.35, 0.6] }).observe(heroBox);
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

// the header reads light-on-dark while the film's dark opening (its first 5 s, or the poster before it plays) is
// behind it, and ink again once the film reaches its light footage or the hero scrolls out from under it
const heroVid = document.querySelector(".g-hero [data-film]"), heroBoxEl = document.querySelector(".g-hero");
if (heroVid && heroBoxEl) {
  const OPENING = 5.0;
  const setDark = () => {
    const r = heroBoxEl.getBoundingClientRect(), underNav = r.top < 90 && r.bottom > 90;
    html.classList.toggle("nav-on-dark", underNav && heroVid.currentTime < OPENING);
  };
  heroVid.addEventListener("timeupdate", setDark); heroVid.addEventListener("seeked", setDark);
  addEventListener("scroll", setDark, { passive: true }); setDark();
}

// the wider argument: the talk loads from its host only when the reader presses play (nothing is requested before)
for (const box of document.querySelectorAll("[data-yt]")) box.querySelector("[data-yt-load]")?.addEventListener("click", () => {
  const t = box.querySelector("template"); if (!t) return; box.replaceChildren(t.content.cloneNode(true)); box.querySelector("iframe")?.focus();
});

// blueprint clips beside "who runs it": load and play only while on screen, and only with motion on
const bpv = document.querySelectorAll("video[data-bp-video]");
if (bpv.length && "IntersectionObserver" in window) {
  const io = new IntersectionObserver((es) => es.forEach(({ target: v, isIntersecting: on }) => {
    if (on && html.dataset.motion !== "off") { if (!v.getAttribute("src")) v.src = v.dataset.src; v.play().catch(() => {}); } else v.pause();
  }), { threshold: 0.35 });
  bpv.forEach((v) => io.observe(v));
}
