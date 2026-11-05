// SPDX-License-Identifier: Apache-2.0 OR MIT
// Verify page, living layer (MOTION.md M08 mini-chain, M10 strip, M16). It never runs or alters a check: it WATCHES
// the verify engine's own output (#steps, #big — written by the unchanged engine script, G15) and lights the part of
// the chain the real check actually reached. The status strip shows the first 16 bits of the selected passport's
// registrar list from net/registry.json, with that passport's own bit marked. Nothing here moves on its own.
import { loadRecord } from "./record.mjs";

const $ = (s, r = document) => r.querySelector(s);
const fig = $("[data-vchain]");
if (fig) {
  // engine step index → chain node (0 schema, 1 issuer, 2 window, 3 sig, 4 chain → CHAIN · 5 status → STATUS · 6 log → LOG)
  const NODE = [1, 1, 1, 1, 1, 2, 3];
  const nodes = [...fig.querySelectorAll("[data-vn]")];
  const setNode = (n, state, text) => { const el = nodes[n]; if (!el) return; el.dataset.state = state; const t = el.querySelector("[data-vt]"); if (t) t.textContent = text; };
  const reset = () => nodes.forEach((_, i) => setNode(i, "wait", "WAITING"));
  const read = () => {
    const steps = [...document.querySelectorAll("#steps .dstep .i")];
    if (!steps.length) { reset(); return; }
    const per = [[], [], [], []];
    steps.forEach((s, i) => per[NODE[i] ?? 3].push(s.classList.contains("ok") ? "ok" : s.classList.contains("no") ? "no" : "pend"));
    setNode(0, "ok", "PRESENTED");
    for (let n = 1; n <= 3; n++) {
      const a = per[n]; const st = a.includes("no") ? "no" : a.every((x) => x === "ok") ? "ok" : "skip";
      setNode(n, st, st === "ok" ? "CHECKED" : st === "no" ? "REFUSED HERE" : "NOT REACHED");
    }
    const big = ($("#big")?.textContent || "").trim();
    setNode(4, big === "VALID" ? "ok" : "no", big || "—");
  };
  new MutationObserver(read).observe($("#steps") || document.body, { childList: true, subtree: true });
  reset();

  const strip = $("[data-vstrip]"), lab = $("[data-vstrip-lab]");
  loadRecord().then(({ net }) => {
    const all = []; for (const R of net.registry.registrars || []) for (const e of R.records || []) all.push({ r: e.record, R });
    const show = () => {
      const sub = $("#pick")?.value; const hit = all.find((x) => x.r.sub === sub); if (!hit || !strip) return;
      const set = new Set(hit.R.records.filter((e) => e.record.revoked).map((e) => e.record.status_idx));
      strip.querySelectorAll("rect").forEach((c) => { const i = +c.dataset.i; c.setAttribute("class", (set.has(i) ? "is-red" : "") + (i === hit.r.status_idx ? " is-me" : "")); });
      if (lab) lab.textContent = `${hit.R.registrar} · seq ${hit.R.status_seq} · bits 0–15 · this passport is bit ${hit.r.status_idx}: ${set.has(hit.r.status_idx) ? "SET — revoked" : "unset"}`;
    };
    $("#pick")?.addEventListener("change", show);
    new MutationObserver(show).observe($("#pick"), { childList: true });
    show();
  }).catch(() => { if (lab) lab.textContent = "record not reachable — no bits shown"; });
}
