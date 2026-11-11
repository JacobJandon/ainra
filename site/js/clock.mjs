// SPDX-License-Identifier: Apache-2.0 OR MIT
// Record clock (MOTION.md M01): how old the published record is, counted once a second from published.json's own
// stamp, with the staleness word from js/staleness.mjs (never green: a copy of a record is not "live"). The date
// itself is in the HTML from the build (tools/record-stamp.mjs); this only adds the age and the state. With motion
// off the age is whole days and does not tick. One text update per second, aligned to the second; no animation frame.
import { staleness } from "./staleness.mjs";
import { sharedJSON } from "./net.mjs";

const els = [...document.querySelectorAll("[data-record-clock]")];
const base = (document.querySelector('meta[name="ainra-net"]')?.content || "net").replace(/\/$/, "");
const two = (n) => String(n).padStart(2, "0");

if (els.length) sharedJSON(`${base}/published.json`).then((r) => r.json).then((p) => {
  const t = Date.parse(p?.published_at_iso);
  if (!Number.isFinite(t)) return;
  const { state } = staleness(p.published_at_iso);
  for (const el of els) {
    el.dataset.state = state;
    el.querySelectorAll("[data-rc-state]").forEach((s) => (s.textContent = state.toUpperCase()));
    el.querySelectorAll("[data-rc-more]").forEach((s) => (s.hidden = false));
  }
  let timer = 0;
  const tick = () => {
    clearTimeout(timer);
    const off = document.documentElement.dataset.motion === "off";
    const s = Math.max(0, Math.floor((Date.now() - t) / 1000)), d = Math.floor(s / 86400);
    const long = off ? `${d} d` : `${d} d ${two(Math.floor(s / 3600) % 24)}:${two(Math.floor(s / 60) % 60)}:${two(s % 60)}`;
    for (const el of els) {
      el.querySelectorAll("[data-rc-age]").forEach((a) => (a.textContent = long));
      el.querySelectorAll("[data-rc-days]").forEach((a) => (a.textContent = `${d} d`));
    }
    timer = setTimeout(tick, !off && !document.hidden ? 1000 - (Date.now() % 1000) + 5 : 60000);
  };
  tick();
  window.addEventListener("ainra:motion", tick);
  document.addEventListener("visibilitychange", tick);
}).catch(() => { /* no stamp reachable: the build-time date stays, and no age is claimed */ });
