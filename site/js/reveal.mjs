// SPDX-License-Identifier: Apache-2.0 OR MIT
// Reveal (concept F). Motion patterns measured on a large defense-software home page (research/MOTION.md P1–P7),
// rebuilt here in our own code, faster, and without the parts AINRA refuses (glass, marquees, text below 4.5:1).
// The one film that plays by itself is the home page's hero (the owner's rule, 2026-11-12), with its Pause button:
//   * headings roll in line by line out of a clip, 0.55 s, quint ease-out — the page reads as already loaded;
//   * blocks lift 10px and fade in 0.4 s, and start before they reach the viewport;
//   * one statement sharpens into place as you scroll (soft and low → ink and set), never below muted contrast;
//   * the header lifts into a floating, solid bar once the page scrolls;
//   * list rows: a full-width band fades in, the name slides 16px, the index turns to ink (CSS);
//   * the rings open, the chips arrive ring by ring, and the sigil's snake draws itself around the root.
// Every hidden state lives under html.rv, set in <head> only when motion is on (the Motion switch, else
// prefers-reduced-motion). Motion off, reduced motion, no JavaScript, or this file failing: the page is complete.
const html = document.documentElement;
html.dataset.rvReady = "1";
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

// arrows in buttons and links step forward on hover (with motion on or off)
for (const el of $$(".btn, .c-btn, .sec-head__row a, .c-head__a, .next-link a")) {
  for (const n of [...el.childNodes]) {
    if (n.nodeType !== 3 || !n.nodeValue.includes("→")) continue;
    const [a, b] = n.nodeValue.split("→");
    const arr = document.createElement("span"); arr.className = "arr"; arr.textContent = "→";
    n.replaceWith(document.createTextNode(a), arr, document.createTextNode(b));
  }
}

// the header lifts into a floating bar once the page has scrolled (a class; the look is CSS, solid, no blur)
const nav = document.querySelector("nav");
const floatNav = () => html.classList.toggle("nav-float", scrollY > 24);
addEventListener("scroll", floatNav, { passive: true }); floatNav();

new MutationObserver(() => { if (html.dataset.motion === "off") html.classList.remove("rv"); })
  .observe(html, { attributes: true, attributeFilter: ["data-motion"] });

// reading time for the hero's metadata line, counted from the page itself
const rt = document.querySelector("[data-read-time]");
if (rt) { const words = (document.querySelector("main")?.innerText || "").split(/\s+/).filter(Boolean).length; rt.textContent = `${Math.max(1, Math.round(words / 230))} min`; }

if (html.classList.contains("rv") && "IntersectionObserver" in window) {
  // lines: split a heading into its rendered lines, each inside a mask; restored to the original markup once shown,
  // so a later resize re-wraps it like any text
  const lines = (el, d = 0) => {
    const orig = el.innerHTML;
    const words = [];
    const walk = (node) => {
      for (const n of [...node.childNodes]) {
        if (n.nodeType === 1) { walk(n); continue; }
        if (n.nodeType !== 3 || !n.nodeValue.trim()) continue;
        const frag = document.createDocumentFragment();
        for (const part of n.nodeValue.split(/(\s+)/)) {
          if (!part) continue;
          if (/^\s+$/.test(part)) { frag.append(part); continue; }
          const s = document.createElement("span"); s.className = "lw"; s.textContent = part; frag.append(s); words.push(s);
        }
        n.replaceWith(frag);
      }
    };
    walk(el);
    let row = -1, top = null;
    for (const w of words) { const t = Math.round(w.offsetTop); if (t !== top) { row++; top = t; } w.style.setProperty("--l", row); }
    el.style.setProperty("--d", `${d}ms`);
    el.classList.add("rv-lines");
    const done = () => { el.innerHTML = orig; el.classList.remove("rv-lines"); };
    el.__rvDone = () => setTimeout(done, d + 550 + (row + 1) * 70 + 80);
    return row + 1;
  };
  const mark = (el, d = 0, kind) => { if (!el || el.hasAttribute("data-rv")) return; el.setAttribute("data-rv", kind || ""); if (d) el.style.setProperty("--d", `${d}ms`); };
  const show = (el) => { el.classList.add("is-in"); for (const h of $$(".rv-lines", el)) h.__rvDone?.(); if (el.__rvDone) el.__rvDone(); };

  const start = () => {
    // the hero: on load, under half a second end to end
    const hero = document.querySelector(".c-hero");
    if (hero) {
      const h1 = hero.querySelector("h1"); if (h1) lines(h1, 0);
      mark(hero.querySelector(".hero__kick"), 0, "fade");
      mark(hero.querySelector(".c-hero__lead"), 140);
      $$(".hero__proof li", hero).forEach((li, k) => mark(li, 200 + k * 40));
      mark(hero.querySelector(".cta-row"), 300);
      mark(hero.querySelector(".hero-meta"), 360, "fade");
      requestAnimationFrame(() => requestAnimationFrame(() => { show(hero); $$("[data-rv]", hero).forEach(show); }));
    }

    const io = new IntersectionObserver((es) => {
      for (const e of es) if (e.isIntersecting) { show(e.target); io.unobserve(e.target); }
    }, { rootMargin: "0px 0px 12% 0px", threshold: 0 });

    const film = document.querySelector(".film"); if (film) io.observe(film);
    for (const sec of $$("main section")) {
      if (sec.classList.contains("film")) continue;
      const head = sec.querySelector(".sec-head");
      if (head) {
        const h2 = head.querySelector("h2"); if (h2) lines(h2, 60);
        mark(head.querySelector(".sec-head__row"), 0, "fade");
        $$(".split__r > *", head).forEach((p, k) => mark(p, 140 + k * 60));
        $$("[data-rv]", head).forEach((el) => io.observe(el));
        io.observe(head);
      }
      const wrap = sec.querySelector(".wrap") || sec;
      let k = 0;
      for (const block of [...wrap.children]) {
        if (block === head || block.matches(".sec-head")) continue;
        const items = block.matches(".compare, .index, .steps-rail, ol, ul") ? [...block.children]
          : block.matches(".split") ? $$(":scope > div > *", block) : [block];
        for (const it of items) {
          const list = it.matches("ol, ul") ? [...it.children] : [it];
          for (const x of list) { mark(x, Math.min(k++, 8) * 40); io.observe(x); }
        }
      }
      if (sec.id === "root" && sec.querySelector(".orbit svg")) {   // the G home draws its own rings figure
        const svg = sec.querySelector(".orbit svg");
        $$(".oring", svg).forEach((c, i) => c.style.setProperty("--d", `${i * 80}ms`));
        $$(".ochip, .otxt, .otag", svg).forEach((c) => { const y = +(c.getAttribute("y") || 320), x = +(c.getAttribute("x") || 320); c.style.setProperty("--d", `${150 + Math.hypot(x - 320, y - 320) * 1.2}ms`); });
        const f = sec.querySelector(".orbit .fig__body"); if (f) io.observe(f);
      }
      $$(".web4__verbs", sec).forEach((v, era) => { $$("b", v).forEach((b, i) => b.style.setProperty("--d", `${era * 110 + i * 45 + (b.classList.contains("new") ? 120 : 0)}ms`)); io.observe(v.parentElement); });
    }

    // the statement: sharpens into place over the scroll that brings it to the middle of the screen
    const st = document.querySelector("[data-scrub]");
    const bar = document.querySelector(".rv-progress"), globe = document.querySelector(".c-globe");
    let ticking = false;
    const frame = () => {
      ticking = false;
      if (!html.classList.contains("rv")) { if (st) st.style.cssText = ""; if (globe) globe.style.translate = ""; return; }
      const max = document.documentElement.scrollHeight - innerHeight;
      if (bar) bar.style.transform = `scaleX(${max > 0 ? Math.min(1, scrollY / max) : 0})`;
      if (globe && scrollY < innerHeight * 1.2) globe.style.translate = `0 ${Math.round(scrollY * 0.12)}px`;
      if (st) {
        const r = st.getBoundingClientRect();
        const p = Math.min(1, Math.max(0, (innerHeight * 0.95 - r.top) / (innerHeight * 0.5)));   // 0 entering → 1 set
        st.style.setProperty("--p", p.toFixed(3));
      }
    };
    const onScroll = () => { if (!ticking) { ticking = true; requestAnimationFrame(frame); } };
    addEventListener("scroll", onScroll, { passive: true }); addEventListener("resize", onScroll); frame();
  };
  // line breaks depend on the web font; split once it is in (or at once if it already is)
  (document.fonts?.ready || Promise.resolve()).then(start, start);
}

// the video: Quiet Paper's poster; pressing it plays the video in place (nothing loads from the host before that)
for (const v of $$("[data-vid]")) {
  const b = v.querySelector(".poster"); if (!b) continue;
  b.addEventListener("click", () => {
    const f = document.createElement("iframe");
    f.src = "https://www.youtube-nocookie.com/embed/ZlHlpMpu8ug?rel=0&playsinline=1&autoplay=1";
    f.title = "A national security emergency — Wyatt Tessari L’Allié, AI Governance and Safety Canada";
    f.allow = "autoplay; encrypted-media; picture-in-picture; fullscreen";
    f.referrerPolicy = "strict-origin-when-cross-origin"; f.allowFullscreen = true;
    v.append(f); v.classList.add("is-on"); f.focus();
  });
}

// the film: sources load only when it comes near; it plays muted and loops only while on screen; the Pause button is
// always there and its choice sticks for the visit. Other films play only with motion on. The home hero ALWAYS starts by
// itself (owner, 2026-11-12): reduced motion, a remembered "Motion: off" and a data-saving connection no longer hold it
// on its poster. Switching Motion off during the visit still pauses it, and switching it back on plays it again.
for (const v of $$("[data-film]")) {
  const btn = (v.closest(".film, .g-hero") || v.parentElement).querySelector("[data-film-toggle]"), lbl = btn?.querySelector(".film__lbl");
  // a connection that asks to save data, or a slow one, starts on the poster: the film is several megabytes
  const thrifty = (() => { const c = navigator.connection; return !!c && (c.saveData || /(^|-)(2g|3g)$/.test(c.effectiveType || "")); })();
  const hero = !!v.closest(".g-hero");
  let loaded = false, userPaused = hero ? false : (html.dataset.motion === "off" || thrifty), onScreen = false, lastMotion = html.dataset.motion;
  // the film waits for the page: its poster shows at once; the film itself starts downloading 1.2 s after load
  const afterLoad = new Promise((r) => (document.readyState === "complete" ? setTimeout(r, 1200) : addEventListener("load", () => setTimeout(r, 1200), { once: true })));
  // a phone (or a window taller than wide) gets the film's phone cut, where each drawing fills the frame
  const small = matchMedia("(max-width:700px),(max-aspect-ratio:5/4)").matches;
  if (small && v.dataset.posterM) v.poster = v.dataset.posterM;
  // the hero's poster is the film at one second, after it has faded up from paper. Its first play starts there too,
  // so the still picture begins to move; started from zero it went back to paper first, which read as a flash.
  if (hero) v.addEventListener("loadedmetadata", () => { try { if (v.currentTime < 0.1) v.currentTime = 1; } catch { /* not seekable yet: it starts from zero */ } }, { once: true });
  const load = () => { if (loaded) return; loaded = true; afterLoad.then(() => { for (const s of v.querySelectorAll("source[data-src]")) s.src = (small && s.dataset.srcM) || s.dataset.src; v.load(); decide(); }); };
  const sync = () => { if (btn) { btn.setAttribute("aria-pressed", String(userPaused)); btn.setAttribute("aria-label", userPaused ? "Play the film" : "Pause the film"); if (lbl) lbl.textContent = userPaused ? "Play" : "Pause"; } };
  const decide = () => { if (!userPaused && onScreen && (hero || html.dataset.motion !== "off")) { load(); v.play().catch(() => {}); } else v.pause(); };
  btn?.addEventListener("click", () => { userPaused = !userPaused; if (!userPaused) load(); sync(); decide(); });
  new MutationObserver(() => {
    const m = html.dataset.motion;
    // the hero follows only a real change the visitor makes now (the switch re-announces the same value at start-up)
    if (hero) { if (m !== lastMotion) userPaused = m === "off"; } else if (m === "off") userPaused = true;
    lastMotion = m; sync(); decide();
  }).observe(html, { attributes: true, attributeFilter: ["data-motion"] });
  // the film is fetched only when it is about to play (decide → load), never just because it is on screen
  if ("IntersectionObserver" in window) new IntersectionObserver((es) => { onScreen = es[0].isIntersecting; decide(); }, { rootMargin: "200px 0px" }).observe(v);
  else { onScreen = true; decide(); }
  sync();
}
