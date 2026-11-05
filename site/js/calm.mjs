// SPDX-License-Identifier: Apache-2.0 OR MIT
// The calm home variants (home-a, home-b, home-c). Every figure is complete in the HTML first — stamped from
// site/net/ at build time, or drawn as a still SVG of the same frame — so the page reads with JavaScript off and at
// first paint. This file only adds the one slow motion each variant allows, through the page's one scheduler
// (motion.mjs): paused off-screen and in hidden tabs, and still under prefers-reduced-motion or with Motion off.
//   [data-calm-globe]            A · the globe turns once every 120 s; nothing else on it moves
//   [data-calm-life]             B · one Game-of-Life field, B3/S23, seeded from a checkpoint root in the record
//   [data-chain="loop|step|once"] the chain of trust: loop (with Pause), step (the visitor runs each check), or
//                                once (plays a valid record and then a revoked one, when reached, then stops)
//   [data-status-grid]           B · the two status lists, drawn only after this tab's SDK run matches the record
import { register, motionOn } from "./motion.mjs";
import { loadRecord, seedCycle } from "./record.mjs";
import { chainState } from "./record-view.mjs";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const inOut = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);

/* ── page basics: menu, copy buttons, the installer tabs, the specimen portrait, passport callouts ───────────── */
function basics() {
  const burger = $("#burger"), links = $("#navLinks");
  if (burger && links) {
    const close = () => { links.classList.remove("open"); burger.setAttribute("aria-expanded", "false"); };
    burger.addEventListener("click", () => { const o = links.classList.toggle("open"); burger.setAttribute("aria-expanded", o ? "true" : "false"); });
    links.querySelectorAll("a").forEach((a) => a.addEventListener("click", close));
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && links.classList.contains("open")) { close(); burger.focus(); } });
  }
  const copy = (btn, get, sel) => {
    const reset = () => setTimeout(() => { btn.textContent = "COPY"; }, 1600);
    btn.addEventListener("click", () => {
      const ok = () => { btn.textContent = "COPIED"; reset(); };
      const fail = () => { btn.textContent = "COPY FAILED"; if (sel) { const r = document.createRange(); r.selectNodeContents(sel); const g = getSelection(); g.removeAllRanges(); g.addRange(r); } reset(); };
      if (navigator.clipboard?.writeText) navigator.clipboard.writeText(get()).then(ok, fail); else fail();
    });
  };
  const M = {
    skill: { cap: "terminal", desc: "One command. Your coding assistant gains AINRA's skills — verify, issue, present, renew, revoke.", code: "npx skills add https://ainra.org/.well-known/skills/index.json" },
    mcp: { cap: ".mcp.json", desc: "Add the AINRA MCP server (it ships in the repo). Your agent gets verify · lookup · status · issue · renew · revoke; point AINRA_TARGET at a network you run.", code: '{\n  "mcpServers": {\n    "ainra": {\n      "command": "node",\n      "args": ["packages/mcp/src/server.mjs"],\n      "env": { "AINRA_TARGET": "http://127.0.0.1:8091" }\n    }\n  }\n}' },
    prompt: { cap: "paste to any agent", desc: "Paste this to any agent. It reads the machine-readable map and verifies an AINRA passport on its own.", code: "Read https://ainra.org/skills.md and verify an AINRA passport." },
    http: { cap: "terminal", desc: "No runtime, no SDK — fetch the signed facts over plain HTTP and check them yourself.", code: "curl https://ainra.org/llms.txt" },
  };
  const desc = $("#i-desc"), cap = $("#i-cap"), code = $("#i-code"), cp = $("#i-copy"), panel = $("#i-panel");
  if (desc && code) {
    const tabs = $$(".itab");
    const set = (m, focus) => { const d = M[m]; if (!d) return; desc.textContent = d.desc; cap.textContent = d.cap; code.textContent = d.code;
      tabs.forEach((t) => { const on = t.dataset.m === m; t.setAttribute("aria-selected", on ? "true" : "false"); t.tabIndex = on ? 0 : -1; if (on) { panel?.setAttribute("aria-labelledby", t.id); if (focus) t.focus(); } }); };
    tabs.forEach((t, i) => {
      t.addEventListener("click", () => set(t.dataset.m));
      t.addEventListener("keydown", (e) => { let j = -1;
        if (e.key === "ArrowRight") j = (i + 1) % tabs.length; else if (e.key === "ArrowLeft") j = (i - 1 + tabs.length) % tabs.length;
        else if (e.key === "Home") j = 0; else if (e.key === "End") j = tabs.length - 1;
        if (j >= 0) { e.preventDefault(); set(tabs[j].dataset.m, true); } });
    });
    if (cp) copy(cp, () => code.textContent, code);
  }
  const g = $("#portrait");
  if (g && !g.children.length) {
    let h = 0; const seed = "8F2EC41AINRA";
    for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
    for (let r = 0; r < 7; r++) { const row = []; for (let c = 0; c < 4; c++) { h = (h * 1103515245 + 12345) >>> 0; row.push(h % 100); }
      for (let c = 0; c < 7; c++) { const v = row[c < 4 ? c : 6 - c], el = document.createElement("i"); if (v < 42) el.className = "on"; else if (v < 52) el.className = "gn"; g.appendChild(el); } }
  }
  const on = (k, v) => $$(`[data-callout="${k}"]`).forEach((e) => e.classList.toggle("is-on", v));
  for (const e of $$("[data-callout]")) for (const [ev, v] of [["mouseenter", true], ["mouseleave", false], ["focusin", true], ["focusout", false]]) e.addEventListener(ev, () => on(e.dataset.callout, v));
}

/* ── A · the globe on paper. Same projection as the still SVG under it, so the first canvas frame is that SVG ── */
function globe(box, m) {
  const cv = $("canvas", box); if (!cv?.getContext) return;
  const x = cv.getContext("2d", { alpha: false });
  const dpr = Math.min(2, devicePixelRatio || 1);
  let W = 0, R = 0, cx = 0, cy = 0, k = 1;
  const size = () => { const w = Math.round(box.getBoundingClientRect().width) || 600; cv.width = cv.height = Math.round(w * dpr); W = cv.width; R = W * 0.335; cx = cy = W / 2; k = W / 1040; };
  size();
  const SH = 10, shade = [...Array(SH)].map((_, i) => { const t = 0.12 + 0.34 * i / (SH - 1), c = (v) => Math.round(255 + (v - 255) * t); return `rgb(${c(11)},${c(18)},${c(32)})`; });
  const pts = []; for (let lat = -80; lat <= 80; lat += 7.5) { const n = Math.max(6, Math.round(46 * Math.cos(lat * Math.PI / 180))); for (let i = 0; i < n; i++) pts.push([lat * Math.PI / 180, i / n * Math.PI * 2]); }
  let seed = 7; const rnd = (a, b) => { seed = (seed * 16807) % 2147483647; return a + (seed / 2147483647) * (b - a); };
  const hashLon = (s) => { let h = 0; for (const ch of s) h = (h * 31 + ch.charCodeAt(0)) >>> 0; return (h % 628) / 100; };
  const regs = m.lists.map((l, i) => ({ p: [i ? -0.35 : 0.42, hashLon(l.registrar)] }));     // the registrars in the record
  const vers = [...Array(44)].map(() => ({ p: [rnd(-1.1, 1.1), rnd(0, 6.28)] }));              // illustrative verifiers
  const TURN = Math.PI * 2 / 120000;
  let rot = 0;
  const proj = ([lat, lon]) => { const c = Math.cos(lat), X = c * Math.sin(lon + rot), Y = -Math.sin(lat), Z = c * Math.cos(lon + rot), t = 0.32; return [cx + X * R, cy + (Y * Math.cos(t) - Z * Math.sin(t)) * R, Y * Math.sin(t) + Z * Math.cos(t)]; };
  const draw = () => {
    x.fillStyle = "#F5F6F3"; x.fillRect(0, 0, W, W);
    x.lineWidth = 2.4 * k; x.strokeStyle = "#C6C8CB"; x.beginPath(); x.ellipse(cx, cy, R * 1.36, R * 0.4, -0.18, Math.PI, 2 * Math.PI); x.stroke();
    x.strokeStyle = "#3A404C"; x.lineWidth = 2 * k; x.beginPath(); x.arc(cx, cy, R, 0, 7); x.stroke();
    const s = 4 * k, b = shade.map(() => []);
    for (const p of pts) { const [sx, sy, z] = proj(p); if (z >= 0) b[Math.min(SH - 1, Math.round(z * (SH - 1)))].push(sx, sy); }
    b.forEach((q, i) => { x.fillStyle = shade[i]; for (let j = 0; j < q.length; j += 2) x.fillRect(q[j] - s / 2, q[j + 1] - s / 2, s, s); });
    x.strokeStyle = "#1A6B4E"; x.lineWidth = 7 * k; x.lineCap = "round"; x.beginPath(); x.arc(cx, cy, R, -Math.PI / 2, 0); x.stroke();
    x.fillStyle = "#1A6B4E"; for (const v of vers) { const [sx, sy, z] = proj(v.p); if (z < 0) continue; x.beginPath(); x.arc(sx, sy, 4.6 * k, 0, 7); x.fill(); }
    x.fillStyle = "#0B1220"; for (const g of regs) { const [sx, sy, z] = proj(g.p); if (z < 0) continue; x.fillRect(sx - 7 * k, sy - 7 * k, 14 * k, 14 * k); }
    x.strokeStyle = "#5A606B"; x.lineWidth = 2.4 * k; x.beginPath(); x.ellipse(cx, cy, R * 1.36, R * 0.4, -0.18, 0, Math.PI); x.stroke();
  };
  register({ el: box, name: "globe", hz: 20, step(now, dt) { rot += dt * TURN; }, draw });
  draw(); box.classList.add("is-live");
  let rz; new ResizeObserver(() => { clearTimeout(rz); rz = setTimeout(() => { size(); draw(); }, 150); }).observe(box);
}

/* ── B · one Life field. A fixed 68 × 62 grid scaled to cover its panel, exactly as the still SVG is ──────────── */
async function life(box, net) {
  const { Field } = await import("./life.mjs");
  const seeds = seedCycle(net); if (!seeds.length) return;
  const first = seeds.findIndex((s) => s.label.includes(box.dataset.seedFrom || "registrar-07"));
  const cv = document.createElement("canvas"); cv.setAttribute("aria-hidden", "true"); box.appendChild(cv);
  const GW = 680, GH = 620, AHEAD = 64;
  const f = new Field(cv, { pitch: 10, size: 9 }); f.resize(GW, GH);
  f.col = [f.col[0], f.col[2], f.col[3], f.col[3]];   // calmer: newborn cells soft mint, every other live cell grey
  const fit = () => { const r = box.getBoundingClientRect(), s = Math.max(r.width / GW, r.height / GH);
    Object.assign(cv.style, { width: `${GW * s}px`, height: `${GH * s}px`, left: `${(r.width - GW * s) / 2}px`, top: `${(r.height - GH * s) / 2}px`, inset: "auto" }); };
  let si = Math.max(0, first);
  const reseed = (i) => { si = i % seeds.length; f.seed(seeds[si].bytes); for (let g = 0; g < AHEAD; g++) f.step(); f.full = true; };
  fit(); reseed(si); f.draw(); box.classList.add("is-live");
  register({ el: box, name: "life:hero", hz: +box.dataset.hz || 3,
    step() { f.step(); if (f.gen >= 1024 || f.stagnant()) reseed(si + 1); },
    draw(still) { if (still) { reseed(Math.max(0, first)); } f.draw(); } });
  new ResizeObserver(fit).observe(box);
}

/* ── the chain of trust: one real record at a time travels root → registrar → passport → verifier → verdict ──── */
function chain(fig, m) {
  if (!m.records.length) return;
  const mode = fig.dataset.chain || "once";
  const cap = $("[data-chain-cap]", fig.parentElement), playB = $("[data-chain-play]", fig.parentElement), nextB = $("[data-chain-next]", fig.parentElement);
  const mq = matchMedia("(max-width:760px)");
  let svg, K = {}, pts = {};
  const bind = () => {
    svg = $(mq.matches ? ".chain--narrow" : ".chain--wide", fig); if (!svg) return;
    K = {}; svg.querySelectorAll("[data-k]").forEach((e) => (K[e.dataset.k] = e));
    const p = (a) => (svg.dataset[a] || "0,0").split(",").map(Number);
    pts = { jn: p("jn"), ppc: p("ppc"), verc: p("verc") };
  };
  const L = { a: 240, b: 1000, c: 2300, d: 2700, e: 3100, f: 5200, end: 5500 };
  const HOLD = L.e + 1;     // the finished frame: verdict shown, registrar lit
  let ri = 0, t = HOLD, active = false, last = -1, queue = [];
  const regBox = (r) => K["reg-" + r.registrar];
  const regOut = (r) => { const b = regBox(r); if (!b) return pts.jn; const x = +b.getAttribute("x"), y = +b.getAttribute("y"), w = +b.getAttribute("width"), h = +b.getAttribute("height"); return mq.matches ? [x + w / 2, y + h] : [x + w, y + h / 2]; };
  const lerp = (a, b, q) => [a[0] + (b[0] - a[0]) * q, a[1] + (b[1] - a[1]) * q];
  function show(i, time) {
    const r = m.records[i], s = chainState(m, i);
    if (i !== last) {
      last = i;
      for (const l of m.lists) K["reg-" + l.registrar]?.classList.remove("is-on");
      if (K["pp-l1"]) K["pp-l1"].textContent = s.l1;
      if (K["pp-l2"]) K["pp-l2"].textContent = s.l2;
      if (K.log) K.log.textContent = s.log;
      if (K["log-n"]) K["log-n"].textContent = `leaf ${r.leaf_index}/${r.checkpoint_size}`;
      if (K["ver-bit"]) K["ver-bit"].textContent = "status list · bit " + r.status_idx;
      K.vd?.classList.toggle("is-red", r.revoked); K.vd?.classList.toggle("is-ok", !r.revoked);
      if (cap) cap.innerHTML = `${s.cap.replace(/ · (REFUSED|VALID)$/, "")} · <b class="${r.revoked ? "is-red" : "is-ok"}">${r.revoked ? "REFUSED" : "VALID"}</b>`;
    }
    regBox(r)?.classList.toggle("is-on", time < L.f);
    if (K.logwire) { const len = K.logwire.getTotalLength?.() || 100; K.logwire.style.strokeDasharray = `${len}`; K.logwire.style.strokeDashoffset = `${time < L.a ? len : time < L.b ? len * (1 - inOut((time - L.a) / (L.b - L.a))) : time < L.f ? 0 : len}`; }
    const tok = K.token;
    if (tok) {
      let p = null; const seg = L.c - L.b, hold = 140, mv = (seg - hold * 2) / 2;
      if (time >= L.b && time < L.f && time !== HOLD) {
        const e = time - L.b, a = regOut(r);
        if (e < mv) p = lerp(lerp(a, pts.jn, Math.min(1, inOut(e / mv) * 2)), pts.ppc, Math.max(0, inOut(e / mv) * 2 - 1));
        else if (e < mv + hold) p = pts.ppc;
        else if (e < mv * 2 + hold) p = lerp(pts.ppc, pts.verc, inOut((e - mv - hold) / mv));
        else p = pts.verc;
      }
      tok.style.display = p ? "inline" : "none";
      if (p) tok.setAttribute("transform", `translate(${(p[0] - 14).toFixed(1)},${(p[1] - 9).toFixed(1)})`);
    }
    if (K.strip) {
      const upto = time < L.c ? -1 : time < L.d ? Math.floor((time - L.c) / ((L.d - L.c) / (r.status_idx + 1))) : r.status_idx;
      K.strip.querySelectorAll("rect").forEach((c) => { const n = +c.dataset.i;
        c.classList.toggle("is-scan", n === upto && upto < r.status_idx && time < L.d);
        c.classList.toggle("is-red", time >= L.d - 1 && time < L.f && n === r.status_idx && r.revoked);
        c.classList.toggle("is-ok", time >= L.d - 1 && time < L.f && n === r.status_idx && !r.revoked); });
    }
    const wait = !(time >= L.d && time < L.f);
    K.vd?.classList.toggle("is-wait", wait);
    if (K["vd-t"]) K["vd-t"].textContent = wait ? "VERDICT" : s.vd;
  }
  const finish = () => { active = false; t = HOLD; show(ri, HOLD); };
  const play = (list) => { queue = list.slice(); ri = queue.shift(); t = 0; active = true; last = -1; };
  bind(); mq.addEventListener?.("change", () => { bind(); last = -1; show(ri, t); });
  show(0, HOLD);
  register({ el: fig, name: "chain", hz: 60,
    step(now, dt) {
      if (!active) return;
      t += dt;
      if (mode === "loop") { if (t >= L.end) { t = 0; ri = (ri + 1) % m.records.length; } return; }
      if (queue.length ? t >= L.end : t >= HOLD) { if (queue.length) { ri = queue.shift(); t = 0; } else { finish(); done(); } }
    },
    draw(still) { if (still) { active = false; queue = []; show(ri, HOLD); } else if (active) show(ri, t); } });
  const done = () => { if (mode === "once" && playB) { playB.hidden = false; } if (mode === "step" && nextB) nextB.textContent = "Next record →"; };
  if (mode === "loop") {
    const sync = () => { if (playB) { playB.setAttribute("aria-pressed", String(!active)); playB.textContent = active ? "Pause" : "Play"; } };
    const io = new IntersectionObserver((es) => { if (es[0].isIntersecting && motionOn() && !fig.__started) { fig.__started = true; play([0]); sync(); } }, { threshold: 0.3 });
    io.observe(fig);
    if (playB && motionOn()) playB.hidden = false;
    playB?.addEventListener("click", () => { if (active) { active = false; } else { active = true; if (t === HOLD) t = 0; } sync(); });
    addEventListener("ainra:motion", (e) => { if (playB) playB.hidden = e.detail !== "on"; if (e.detail === "on" && fig.__started) { active = true; } sync(); });
    sync();
  } else if (mode === "once") {
    const valid = m.records.findIndex((r) => !r.revoked), revoked = m.records.findIndex((r) => r.revoked);
    const seq = [valid, revoked].filter((i) => i >= 0);
    const io = new IntersectionObserver((es) => { if (es[0].isIntersecting) { io.disconnect(); if (motionOn()) play(seq); } }, { threshold: 0.4 });
    io.observe(fig);
    playB?.addEventListener("click", () => { playB.hidden = true; if (motionOn()) play(seq); else { ri = seq[seq.length - 1]; finish(); } });
  } else {
    if (nextB) nextB.hidden = false;
    nextB?.addEventListener("click", () => {
      const n = nextB.textContent.startsWith("Next") ? (ri + 1) % m.records.length : ri;
      if (motionOn()) play([n]); else { ri = n; last = -1; finish(); }
      nextB.textContent = "Next record →";
    });
  }
}

/* ── B · status lists, drawn only after each decode is checked against the records with the real SDK ─────────── */
function statusGrid(fig, net) {
  const P = innerWidth < 600 ? 4 : 5, C = P - 1, N = 64, dpr = Math.min(2, devicePixelRatio || 1);
  let sdkP = null;
  const lists = $$("[data-sg]", fig).map((box) => {
    const cv = $("canvas", box), ctx = cv.getContext("2d", { alpha: false });
    cv.width = cv.height = N * P * dpr; cv.style.width = cv.style.height = `${N * P}px`; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.fillStyle = "#FFFFFF"; ctx.fillRect(0, 0, N * P, N * P);
    return { id: box.dataset.sg, box, cv, ctx, msg: $("[data-sg-msg]", box) };
  });
  async function check(L) {
    const Rr = net.registry.registrars.find((x) => x.registrar === L.id); if (!Rr) return false;
    const sdk = await (sdkP ||= import("../vendor/ainra-sdk.js"));
    const b64 = Rr.status_list.status_list_b64.replace(/-/g, "+").replace(/_/g, "/");
    const raw = Uint8Array.from(atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, "=")), (c) => c.charCodeAt(0));
    const packed = new Uint8Array(await new Response(new Blob([raw]).stream().pipeThrough(new DecompressionStream("deflate"))).arrayBuffer());
    const bits = new Uint8Array(Rr.status_list.bit_len); for (let i = 0; i < bits.length; i++) bits[i] = (packed[i >> 3] >> (i & 7)) & 1;
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
      if ((v.verdict === "valid") === !!r.revoked) ok = false;
      if (bits[r.status_idx] !== (r.revoked ? 1 : 0)) ok = false;
      if (r.revoked) rev.push(r.status_idx);
    }
    const set = []; for (let i = 0; i < bits.length; i++) if (bits[i]) set.push(i);
    if (set.join() !== rev.sort((a, c) => a - c).join()) ok = false;
    if (!ok) return false;
    L.ctx.fillStyle = "#FFFFFF"; L.ctx.fillRect(0, 0, N * P, N * P);
    for (let i = 0; i < N * N; i++) { L.ctx.fillStyle = bits[i] ? "#A83A2C" : "#E2E5DF"; L.ctx.fillRect((i % N) * P, ((i / N) | 0) * P, C, C); }
    L.msg.textContent = "Checked in this tab · " + L.msg.textContent;
    return true;
  }
  const io = new IntersectionObserver((es) => { if (es[0].isIntersecting) { io.disconnect();
    lists.reduce((p, L) => p.then(async () => { let ok = false; try { ok = await check(L); } catch { ok = false; } if (!ok) { L.cv.hidden = true; L.msg.textContent = "Not drawn: the decode check did not pass in this tab."; } }), Promise.resolve()); } }, { rootMargin: "300px" });
  io.observe(fig);
}

basics();
loadRecord().then(({ net, m }) => {
  const g = $("[data-calm-globe]"); if (g) globe(g, m);
  const l = $("[data-calm-life]"); if (l) life(l, net).catch(() => {});
  for (const f of $$("[data-chain]")) chain(f, m);
  const s = $("[data-status-grid]"); if (s) statusGrid(s, net);
}).catch(() => { document.documentElement.classList.add("record-unreachable"); });
