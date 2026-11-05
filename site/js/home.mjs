// SPDX-License-Identifier: Apache-2.0 OR MIT
// The home page's living figures (MOTION.md Part C). Everything here decorates content that is already complete in
// the HTML (stamped from site/net/ at build time): with JS off, or motion off, every word and number still reads.
// Every moving datum is re-read from site/net/*.json at run time; nothing simulates activity that is not there.
import { register, motionOn } from "./motion.mjs";
import { loadRecord } from "./record.mjs";
import { chainState, treeSVG, treeCaption } from "./record-view.mjs";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const easeOut = (t) => 1 - Math.pow(1 - t, 3);
const inOut = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);

/* ── M02 hero counters: count to the real number once, first viewport only, zeroes never count ───────────────── */
function counters() {
  if (!motionOn()) return;
  for (const el of $$("[data-count]")) {
    const real = el.querySelector("[data-live]") || el.firstElementChild; if (!real) continue;
    const v = parseInt(real.textContent, 10);
    if (!(v > 0) || el.getBoundingClientRect().top > innerHeight) continue;
    const anim = document.createElement("span");
    anim.className = "count__anim"; anim.setAttribute("aria-hidden", "true"); anim.textContent = "0";
    el.appendChild(anim);
    let t0 = 0;
    const h = register({ el, name: "counters", hz: 60, step(now) {
      t0 ||= now; const p = Math.min(1, (now - t0) / 400);
      anim.textContent = String(Math.round(easeOut(p) * v));
      if (p >= 1) { anim.remove(); h.remove(); }
    }, draw(still) { if (still) { anim.remove(); h.remove(); } } });
  }
}

/* ── M06 globe: two registrar squares from the record, illustrative verifier dots, one refusal per revoked record ─ */
function globe(m) {
  const cv = $("#globe"); if (!cv?.getContext) return;
  const x = cv.getContext("2d", { alpha: false });
  const dpr = Math.min(2, devicePixelRatio || 1);
  let W = 0, R = 0, cx = 0, cy = 0;
  const size = () => { const w = Math.round(cv.getBoundingClientRect().width) || 600; cv.width = cv.height = Math.round(w * dpr); W = cv.width; R = W * 0.335; cx = W / 2; cy = W / 2; };
  size();
  const SH = 10, shade = [...Array(SH)].map((_, i) => { const t = 0.12 + 0.34 * i / (SH - 1), c = (v) => Math.round(255 + (v - 255) * t); return `rgb(${c(11)},${c(18)},${c(32)})`; });
  const pts = []; for (let lat = -80; lat <= 80; lat += 7.5) { const n = Math.max(6, Math.round(46 * Math.cos(lat * Math.PI / 180))); for (let i = 0; i < n; i++) pts.push([lat * Math.PI / 180, i / n * Math.PI * 2]); }
  let seed = 7; const rnd = (a, b) => { seed = (seed * 16807) % 2147483647; return a + (seed / 2147483647) * (b - a); };
  const hashLon = (s) => { let h = 0; for (const ch of s) h = (h * 31 + ch.charCodeAt(0)) >>> 0; return (h % 628) / 100; };
  const regs = m.lists.map((l, i) => ({ id: l.registrar, p: [i ? -0.35 : 0.42, hashLon(l.registrar)] }));
  const vers = [...Array(44)].map(() => ({ p: [rnd(-1.1, 1.1), rnd(0, 6.28)], red: 0 }));
  const refusals = m.records.filter((r) => r.revoked).map((r, k, a) => ({ reg: regs.findIndex((g) => g.id === r.registrar), at: k / a.length, done: -1 }));
  const TURN = Math.PI * 2 / 90000;
  let rot = 0, ping = null;
  const proj = ([lat, lon]) => { const c = Math.cos(lat), X = c * Math.sin(lon + rot), Y = -Math.sin(lat), Z = c * Math.cos(lon + rot), t = 0.32; return [cx + X * R, cy + (Y * Math.cos(t) - Z * Math.sin(t)) * R, Y * Math.sin(t) + Z * Math.cos(t)]; };
  const k = W / 1040;
  const draw = () => {
    x.fillStyle = "#FFFFFF"; x.fillRect(0, 0, W, W);
    x.lineWidth = 2.4 * k; x.strokeStyle = "#C6C8CB"; x.beginPath(); x.ellipse(cx, cy, R * 1.36, R * 0.4, -0.18, Math.PI, 2 * Math.PI); x.stroke();
    x.strokeStyle = "#3A404C"; x.lineWidth = 2 * k; x.beginPath(); x.arc(cx, cy, R, 0, 7); x.stroke();
    const s = 4 * k, buckets = shade.map(() => []);
    for (const p of pts) { const [sx, sy, z] = proj(p); if (z >= 0) buckets[Math.min(SH - 1, Math.round(z * (SH - 1)))].push(sx, sy); }
    buckets.forEach((b, i) => { x.fillStyle = shade[i]; for (let j = 0; j < b.length; j += 2) x.fillRect(b[j] - s / 2, b[j + 1] - s / 2, s, s); });
    x.strokeStyle = "#1A6B4E"; x.lineWidth = 7 * k; x.lineCap = "round"; x.beginPath(); x.arc(cx, cy, R, -Math.PI / 2, 0); x.stroke();
    for (const v of vers) { const [sx, sy, z] = proj(v.p); if (z < 0) continue; x.fillStyle = v.red > 0 ? "#A83A2C" : "#1A6B4E"; x.beginPath(); x.arc(sx, sy, 4.6 * k, 0, 7); x.fill(); }
    for (const g of regs) { const [sx, sy, z] = proj(g.p); if (z < 0) continue; x.fillStyle = "#0B1220"; x.fillRect(sx - 7 * k, sy - 7 * k, 14 * k, 14 * k); }
    if (ping) { x.fillStyle = "#A83A2C"; x.beginPath(); x.arc(ping.x, ping.y, (2 + 2 * ping.step) * 2 * k, 0, 7); x.fill(); }
    x.strokeStyle = "#5A606B"; x.lineWidth = 2.4 * k; x.beginPath(); x.ellipse(cx, cy, R * 1.36, R * 0.4, -0.18, 0, Math.PI); x.stroke();
  };
  register({ el: cv, name: "globe", hz: 30, step(now, dt) {
    rot += dt * TURN;
    const turn = (rot / (Math.PI * 2)) % 1, lap = Math.floor(rot / (Math.PI * 2));
    for (const v of vers) if (v.red > 0) v.red -= dt;
    for (const r of refusals) if (turn >= r.at && r.done !== lap && regs[r.reg]) {
      r.done = lap;
      const [ex, ey] = proj(regs[r.reg].p); let best = null, bd = 1e9;
      for (const v of vers) { const [sx, sy, z] = proj(v.p); const d = Math.hypot(sx - ex, sy - ey); if (z > 0.2 && d < bd) { bd = d; best = v; } }
      if (best) { const [sx, sy] = proj(best.p); ping = { x: sx, y: sy, t: now, step: 0, v: best }; }
    }
    if (ping) { const e = now - ping.t; ping.step = Math.min(2, Math.floor(e / 200)); const [sx, sy] = proj(ping.v.p); ping.x = sx; ping.y = sy; if (e > 600) { ping.v.red = 3000; ping = null; } }
  }, draw });
  draw();
  let rz; new ResizeObserver(() => { clearTimeout(rz); rz = setTimeout(() => { size(); draw(); }, 150); }).observe(cv);
}

/* ── M08 + M09 + table: one real record at a time travels the chain; the refusals are refused ─────────────────── */
function chain(m) {
  const fig = $("[data-chain]"); if (!fig || !m.records.length) return;
  const rows = $$("[data-row]", fig.parentElement.parentElement);
  const cap = $("[data-chain-cap]"), dwell = $("[data-chain-dwell]");
  const treeBox = $("[data-tree]"), treeCap = $("[data-tree-cap]");
  const playB = $("[data-chain-play]", fig), stepB = $("[data-chain-step]", fig);
  const mqNarrow = matchMedia("(max-width:760px)");
  let svg, K = {}, pts = {}, wires = [];
  const bind = () => {
    svg = $(mqNarrow.matches ? ".chain--narrow" : ".chain--wide", fig); if (!svg) return;
    K = {}; svg.querySelectorAll("[data-k]").forEach((e) => (K[e.dataset.k] = e));
    const p = (a) => (svg.dataset[a] || "0,0").split(",").map(Number);
    pts = { jn: p("jn"), ppc: p("ppc"), verc: p("verc") };
    wires = $$("[data-draw]", svg);
  };
  bind(); mqNarrow.addEventListener?.("change", () => { bind(); show(ri, T_END); });
  const L = { 0: 0, a: 200, b: 840, c: 1940, d: 2240, e: 2560, f: 4160, end: 4360 };
  const T_END = L.end;
  let ri = 0, t = 0, playing = true, treeLevels = 0, lastRi = -1;
  const regBox = (r) => K["reg-" + r.registrar];
  const regOut = (r) => { const b = regBox(r); if (!b) return pts.jn; const x = +b.getAttribute("x"), y = +b.getAttribute("y"), w = +b.getAttribute("width"), h = +b.getAttribute("height"); return mqNarrow.matches ? [x + w / 2, y + h] : [x + w, y + h / 2]; };
  const lerp = (a, b, f) => [a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f];
  const logLen = () => K.logwire?.getTotalLength?.() || 100;
  function show(i, time) {
    const r = m.records[i], s = chainState(m, i);
    if (i !== lastRi) {
      lastRi = i;
      for (const id of ["registrar-07", "registrar-11"]) K["reg-" + id]?.classList.remove("is-on");
      if (K["pp-l1"]) K["pp-l1"].textContent = s.l1;
      if (K["pp-l2"]) K["pp-l2"].textContent = s.l2;
      if (K.log) K.log.textContent = s.log;
      if (K["log-n"]) K["log-n"].textContent = `leaf ${r.leaf_index}/${r.checkpoint_size}`;
      if (K["ver-bit"]) K["ver-bit"].textContent = "status list · bit " + r.status_idx;
      if (K["vd-t"]) K["vd-t"].textContent = s.vd;
      K.vd?.classList.remove("is-wait");
      K.vd?.classList.toggle("is-red", r.revoked); K.vd?.classList.toggle("is-ok", !r.revoked);
      if (cap) cap.textContent = s.cap;
      rows.forEach((row) => row.classList.toggle("is-current", +row.dataset.row === i));
      if (treeBox) { treeBox.innerHTML = treeSVG(m, i); if (treeCap) treeCap.textContent = treeCaption(m, i); }
      treeLevels = -1;
    }
    // 1 registrar lights · 2 stroke registrar → log · 3 token travels · 4 status strip steps · 5 verdict · 6 hold · 7 clear
    regBox(r)?.classList.toggle("is-on", time >= 0 && time < L.f);
    if (K.logwire) { const len = logLen(); K.logwire.style.strokeDasharray = `${len}`; K.logwire.style.strokeDashoffset = `${time < L.a ? len : time < L.b ? len * (1 - inOut((time - L.a) / (L.b - L.a))) : time < L.f ? 0 : len}`; }
    const tok = K.token;
    if (tok) {
      let p = null; const seg = L.c - L.b, hold = 120, mv = (seg - hold * 2) / 2;
      if (time >= L.b && time < L.f) {
        const e = time - L.b, a = regOut(r);
        if (e < mv) p = lerp(lerp(a, pts.jn, Math.min(1, inOut(e / mv) * 2)), pts.ppc, Math.max(0, inOut(e / mv) * 2 - 1));
        else if (e < mv + hold) p = pts.ppc;
        else if (e < mv * 2 + hold) p = lerp(pts.ppc, pts.verc, inOut((e - mv - hold) / mv));
        else p = pts.verc;
      }
      tok.style.display = p ? "" : "none";
      if (p) tok.setAttribute("transform", `translate(${(p[0] - 14).toFixed(1)},${(p[1] - 9).toFixed(1)})`);
    }
    const strip = K.strip;
    if (strip) {
      const upto = time < L.c ? -1 : time < L.d ? Math.floor((time - L.c) / ((L.d - L.c) / (r.status_idx + 1))) : r.status_idx;
      strip.querySelectorAll("rect").forEach((c) => { const n = +c.dataset.i; c.classList.toggle("is-scan", n === upto && upto < r.status_idx && time < L.d); c.classList.toggle("is-red", time >= L.d - 1 && time < L.f && n === r.status_idx && r.revoked); c.classList.toggle("is-ok", time >= L.d - 1 && time < L.f && n === r.status_idx && !r.revoked); });
    }
    const shown = time >= L.d && time < L.f, wait = !shown;
    if (K.vd && K.vd.classList.contains("is-wait") !== wait) {
      K.vd.classList.toggle("is-wait", wait);
      if (K["vd-t"]) K["vd-t"].textContent = wait ? "VERDICT" : chainState(m, i).vd;
    }
    // FIG. 03: the inclusion path lights one level per 120 ms from step 2
    if (treeBox) {
      const lv = time < L.a ? -1 : Math.floor((time - L.a) / 120);
      if (lv !== treeLevels) { treeLevels = lv; treeBox.querySelectorAll("[data-lv]").forEach((n) => n.classList.toggle("is-lit", n.dataset.lv !== "" && +n.dataset.lv <= lv && time < L.f)); }
    }
    if (dwell) dwell.style.transform = `scaleX(${Math.min(1, time / T_END).toFixed(4)})`;
  }
  const still = () => { ri = 0; lastRi = -1; show(0, L.e + 1); if (K.token) K.token.style.display = "none"; if (dwell) dwell.style.transform = "scaleX(1)"; treeBox?.querySelectorAll("[data-lv]").forEach((n) => n.classList.toggle("is-lit", n.dataset.lv !== "")); };
  const h = register({ el: fig, name: "chain", hz: 60, step(now, dt) {
    if (!playing) return;
    t += dt; if (t >= T_END) { t = 0; ri = (ri + 1) % m.records.length; }
  }, draw(isStill) { if (isStill) still(); else show(ri, t); } });
  const sync = () => { if (playB) { playB.setAttribute("aria-pressed", String(!playing)); playB.querySelector("span").textContent = playing ? "Pause" : "Play"; } };
  playB?.addEventListener("click", () => { playing = !playing; h.paused = !playing; sync(); if (!playing) show(ri, t); });
  stepB?.addEventListener("click", () => { playing = false; h.paused = true; sync(); ri = (ri + 1) % m.records.length; t = L.e + 1; show(ri, t); });
  if (!motionOn()) still();
  window.addEventListener("ainra:motion", (e) => { if (e.detail === "off") still(); });
  sync();
  // M14: the ink overlay of the connectors draws on once, when the figure is a quarter in view
  drawOn(fig);
}

/* ── M14 figure draw-on (decoration only: the grey drawing is complete underneath) ─────────────────────────────── */
function drawOn(root) {
  const paths = $$("[data-draw]", root); if (!paths.length) return;
  if (!motionOn()) { root.classList.add("is-drawn"); return; }
  for (const p of paths) { const l = p.getTotalLength?.() || 0; p.style.strokeDasharray = `${l}`; p.style.strokeDashoffset = `${l}`; }
  const io = new IntersectionObserver((es) => { if (es.some((e) => e.isIntersecting)) { io.disconnect(); requestAnimationFrame(() => { root.classList.add("is-drawn"); paths.forEach((p) => (p.style.strokeDashoffset = "0")); }); } }, { threshold: 0.25 });
  io.observe(root);
}

/* ── M10 status list grids: drawn ONLY after each decode is checked against the records with the real SDK ──────── */
function statusGrid(m, net) {
  const fig = $("[data-status-grid]"); if (!fig) return;
  const tip = $("[data-sg-tip]", fig);
  const P = innerWidth < 600 ? 4 : 6, C = P - 1, N = 64, dpr = Math.min(2, devicePixelRatio || 1);
  const COL = { line: "#E2E5DF", red: "#A83A2C", ink: "#0B1220", card: "#FFFFFF" };
  let sdkP = null;
  const lists = $$("[data-sg]", fig).map((box) => {
    const cv = $("canvas", box), ctx = cv.getContext("2d", { alpha: false });
    cv.width = cv.height = N * P * dpr; cv.style.width = cv.style.height = `${N * P}px`; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { id: box.dataset.sg, box, cv, ctx, msg: $("[data-sg-msg]", box), bits: null, R: null, scan: 0, row: 0 };
  });
  const cell = (L, i, c) => { L.ctx.fillStyle = c; L.ctx.fillRect((i % N) * P, ((i / N) | 0) * P, C, C); };
  const full = (L) => { L.ctx.fillStyle = COL.card; L.ctx.fillRect(0, 0, N * P, N * P); for (let i = 0; i < N * N; i++) cell(L, i, L.bits[i] ? COL.red : COL.line); };
  async function check(L) {
    const Rr = net.registry.registrars.find((x) => x.registrar === L.id); if (!Rr) return false;
    const sdk = await (sdkP ||= import("../vendor/ainra-sdk.js"));
    const b64 = Rr.status_list.status_list_b64.replace(/-/g, "+").replace(/_/g, "/");
    const raw = Uint8Array.from(atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, "=")), (c) => c.charCodeAt(0));
    const packed = new Uint8Array(await new Response(new Blob([raw]).stream().pipeThrough(new DecompressionStream("deflate"))).arrayBuffer());
    const bits = new Uint8Array(Rr.status_list.bit_len); for (let i = 0; i < bits.length; i++) bits[i] = (packed[i >> 3] >> (i & 7)) & 1;   // LSB-first, the SDK's statusBit
    const enc = (s) => btoa(String.fromCharCode(...new TextEncoder().encode(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const NOW = net.registry.generated_window?.verified_at ?? 0;
    let ok = true; const rev = [];
    for (const e of Rr.records) {
      const r = e.record;
      const v = (sdk.conformance?.runVector ?? sdk.runVector)({ name: r.sub, expect: {}, anchors: { [Rr.registrar]: { issuer_key: Rr.accreditation.issuer_key, log_root_key: Rr.accreditation.log_root_key } },
        presentation: { claims: enc(r.claims), issuer_sig: { ed25519: r.issuer_sig_ed25519, mldsa65: r.issuer_sig_mldsa65 }, now: NOW, chain_keys: r.chain_keys, hop_proofs: r.hop_proofs,
          status_list: Rr.status_list.status_list_b64, status_len: Rr.status_list.bit_len, status_issued_at: Rr.status_list.issued_at, freshness: "F3",
          checkpoint: { origin: r.log_origin, size: r.checkpoint_size, root: r.checkpoint_root }, checkpoint_sig: r.checkpoint_sig, leaf_index: r.leaf_index,
          inclusion_proof: r.inclusion_proof, mandate_revocations: [], revoked_delegates: [] } });
      if ((v.verdict === "valid") === !!r.revoked) ok = false;      // the SDK must refuse exactly the revoked records
      if (bits[r.status_idx] !== (r.revoked ? 1 : 0)) ok = false;    // and each record's bit must say the same
      if (r.revoked) rev.push(r.status_idx);
    }
    const set = []; for (let i = 0; i < bits.length; i++) if (bits[i]) set.push(i);
    if (set.join() !== rev.sort((a, c) => a - c).join()) ok = false;  // no set bit without a revoked record
    L.set = set;
    if (ok) { L.bits = bits; L.R = Rr; }
    return ok;
  }
  async function run(L) {
    L.msg.textContent = "CHECKING…";
    let ok = false; try { ok = await check(L); } catch { ok = false; }
    if (!ok) { L.cv.hidden = true; L.msg.textContent = "STATUS LIST · NOT DRAWN · DECODE CHECK FAILED"; return; }
    const seq = $("[data-sg-seq]", L.box); if (seq) seq.textContent = `seq ${L.R.status_seq}`;
    full(L); L.msg.textContent = `CHECKED IN THIS TAB · SET: BIT ${L.set.join(", ") || "none"} = THE REVOKED RECORD${L.set.length === 1 ? "" : "S"} THE SDK REFUSES`;
  }
  for (const L of lists) {
    L.cv.addEventListener("mousemove", (e) => {
      if (!L.bits) return; const r = L.cv.getBoundingClientRect(), i = Math.floor((e.clientY - r.top) / P) * N + Math.floor((e.clientX - r.left) / P);
      if (i < 0 || i >= N * N) return; tip.hidden = false;
      tip.textContent = `BIT ${i} · ${L.bits[i] ? "SET" : "UNSET"} · ${L.id} · SEQ ${L.R.status_seq}`;
    });
    L.cv.addEventListener("mouseleave", () => (tip.hidden = true));
  }
  const io = new IntersectionObserver((es) => { if (es[0].isIntersecting) { io.disconnect(); lists.reduce((p, L) => p.then(() => run(L)), Promise.resolve()); } }, { rootMargin: "300px" });
  io.observe(fig);
  // the scan line: one cell per 94 ms along a row, one row per 6 s, on each list
  register({ el: fig, name: "status-grid", hz: 1000 / 94, step() {
    for (const L of lists) {
      if (!L.bits) continue; const prev = L.row * N + L.scan; cell(L, prev, L.bits[prev] ? COL.red : COL.line);
      L.scan++; if (L.scan >= N) { L.scan = 0; L.row = (L.row + 1) % N; }
      cell(L, L.row * N + L.scan, COL.ink);
    }
  }, draw(still) { if (still) for (const L of lists) if (L.bits) full(L); } });
}

/* ── M11 passport callouts A–D, two-way ─────────────────────────────────────────────────────────────────────────── */
function callouts() {
  const on = (k, v) => $$(`[data-callout="${k}"]`).forEach((e) => e.classList.toggle("is-on", v));
  for (const e of $$("[data-callout]")) {
    const k = e.dataset.callout;
    for (const [ev, v] of [["mouseenter", true], ["mouseleave", false], ["focusin", true], ["focusout", false]]) e.addEventListener(ev, () => on(k, v));
  }
  const card = $("#passportCard");
  if (card && "IntersectionObserver" in window) new IntersectionObserver((es) => card.classList.toggle("is-visible", es[0].isIntersecting)).observe(card);
}

/* ── M04 rings: hovering a duty row lights the ring it governs ──────────────────────────────────────────────────── */
function rings() {
  const fig = $(".orbit"); if (!fig) return;
  for (const a of $$("[data-ring]")) for (const [ev, v] of [["mouseenter", 1], ["mouseleave", 0], ["focus", 1], ["blur", 0]]) a.addEventListener(ev, () => { fig.dataset.lit = v ? a.dataset.ring : ""; });
  drawOn(fig);
}

/* ── M13 section index readout ──────────────────────────────────────────────────────────────────────────────────── */
function sectionIndex() {
  const box = $("[data-sec-index]"); if (!box) return;
  const out = $("[data-sec-now]", box), secs = $$("[data-sec]");
  const io = new IntersectionObserver((es) => {
    for (const e of es) if (e.isIntersecting) { const s = e.target; out.textContent = s.dataset.sec; box.querySelectorAll("a").forEach((a) => a.toggleAttribute("aria-current", a.getAttribute("href") === "#" + s.id)); }
  }, { rootMargin: "-45% 0px -50% 0px" });
  secs.forEach((s) => io.observe(s));
  box.querySelectorAll("a").forEach((a) => a.addEventListener("click", () => box.removeAttribute("open")));
}

/* ── M15 statement settle: line-height and offset follow the scroll; colour and opacity never change ───────────── */
function settle() {
  const el = $("[data-settle]"); if (!el) return;
  let vis = false, pend = false;
  const apply = () => {
    pend = false;
    if (!motionOn()) { el.style.transform = ""; el.style.lineHeight = ""; return; }
    const r = el.getBoundingClientRect(), y = (r.top + r.height / 2) / innerHeight;
    const p = Math.max(0, Math.min(1, (0.9 - y) / 0.5));
    el.style.transform = `translateY(${(24 * (1 - p)).toFixed(1)}px)`; el.style.lineHeight = (1.12 - 0.12 * p).toFixed(3);
  };
  new IntersectionObserver((es) => { vis = es[0].isIntersecting; if (vis) apply(); }).observe(el);
  addEventListener("scroll", () => { if (vis && !pend) { pend = true; requestAnimationFrame(apply); } }, { passive: true });
  addEventListener("ainra:motion", apply);
}

callouts(); rings(); sectionIndex(); settle(); counters();
loadRecord().then(({ net, m }) => { globe(m); chain(m); statusGrid(m, net); }).catch(() => {
  // no record reachable: the stamped HTML stands as it is, and the figures stay still — never a made-up frame
  document.documentElement.classList.add("record-unreachable");
});
