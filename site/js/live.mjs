// SPDX-License-Identifier: Apache-2.0 OR MIT
// Live-data adapter. Where the public artifact contract is reachable, the numbers that CAN be live become live;
// otherwise the honest committed values stand. Never a fabricated value, never a perpetual spinner.
//
//   * Contract endpoint: ?net=<url>  →  <meta name="ainra-contract">  →  http://127.0.0.1:8091 (only on localhost).
//     The site ships the staging network's PUBLISHED artifact contract at /net (same directory of JSON the
//     artifact server hands out), so these pages work on any static host — not only next to a running network.
//     A same-origin path is a published record, a remote origin is a live network, and the panel says which:
//     "published record" vs "live". Never claim liveness we do not have.
//     On a public host with none of these, the adapter does nothing and the static page stands (honest).
//   * Root-key detection: the response's X-AINRA-Root header. A TEST-ROOT means no production log exists yet, so
//     "production logs sealed = 0" is DERIVED here, not asserted in copy. Staging figures are labeled STAGING·TEST-ROOT.
//   * Everything runs client-side against the same public read contract AINRAscan/mirrors use (CORS from M14). Zero telemetry.

const qs = new URLSearchParams(location.search);
const metaC = document.querySelector('meta[name="ainra-contract"]')?.content?.trim();
const onLocalhost = /^(localhost|127\.|0\.0\.0\.0|\[::1\])/.test(location.hostname);
const CONTRACT = (qs.get("net") || metaC || (onLocalhost ? "http://127.0.0.1:8091" : "")).replace(/\/$/, "");

if (CONTRACT) connect(CONTRACT);

async function connect(base) {
  let res, reg;
  try {
    res = await fetch(base + "/registry.json", { cache: "no-store" });
    if (!res.ok) return;                       // no live contract — the static page stands
    reg = await res.json();
  } catch { return; }                          // unreachable — honest constants remain, no fake state

  const root = (res.headers.get("X-AINRA-Root") || "test-root").trim();
  const net = (res.headers.get("X-AINRA-Network") || "staging").trim();
  const isTestRoot = root === "test-root";

  const t = reg.totals || {};
  let height = 0;
  for (const R of reg.registrars || []) for (const e of R.records || []) {
    const h = e.record?.checkpoint_size || 0;
    if (h > height) height = h;
  }

  const set = (k, v) =>
    document.querySelectorAll(`[data-live="${k}"]`).forEach((el) => {
      el.textContent = v;
      el.classList.add("is-live");
    });

  set("net", net.toUpperCase());
  set("root", root.toUpperCase());
  // A same-origin path is the record we published with the site; anything else is a network answering right now.
  set("mode", /^https?:/i.test(base) ? "live" : "published record");
  set("registrars", t.registrars ?? "—");
  set("issued", t.issued ?? "—");
  set("revoked", t.revoked ?? "—");
  set("checkpoint-height", height || "—");
  // Derived, not asserted: a TEST-ROOT ⇒ no production log exists ⇒ 0 sealed. (A real root would report its own count.)
  set("logs-sealed", isTestRoot ? "0" : String(t.sealed ?? 0));

  // Reveal blocks that must appear only when a live contract is actually connected (so the public static page,
  // with no reachable contract, never shows an empty or misleading "live" panel).
  document.querySelectorAll("[data-live-panel]").forEach((el) => (el.hidden = false));
}
