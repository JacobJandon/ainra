#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The stranger journeys, replayed against PRODUCTION on a schedule.
//
// M27 found eleven things a visitor hit that no board could see, because every check the project had ran against
// local files. Local files are always fresh, always complete, and always agree with each other. The deployed site is
// none of those things — pushing is not deploying, an export can lag a commit, and a claim that was true when it was
// written goes on being served long after it stops being true. The only way to know what a stranger meets is to be
// one, on the real URL, on a schedule.
//
//   node tools/stranger-journeys.mjs                     walk https://ainra.vercel.app
//   node tools/stranger-journeys.mjs --base <url>        walk somewhere else
//   node tools/stranger-journeys.mjs --json              machine-readable
//
// THREE VERDICTS, kept separate on purpose. "Is the site up?" and "is the record it publishes any good?" are
// different questions with different owners and different fixes, and collapsing them into one green tick is how a
// site with a broken record goes on looking healthy:
//
//   SITE BROKEN   a page, a link, or an asset a stranger is sent to does not work
//   NETWORK DOWN  the site is fine, but the record it publishes is missing, unreadable, or empty
//   ALL UP        both halves check out
//
// It reports what it CHECKED, never what it assumed: a journey that could not run is reported as not run, and a run
// with any unreachable step never returns ALL UP. Plain HTTP, no browser — CI must not be able to fail this for
// running out of memory, which is exactly what defeated the browser walk on the dev machine.

import { writeFileSync, mkdirSync } from "node:fs";

const arg = (n, d) => { const i = process.argv.indexOf("--" + n); return i > 0 ? process.argv[i + 1] : d; };
const BASE = (arg("base", process.env.AINRA_SITE || "https://ainra.vercel.app")).replace(/\/$/, "");
const JSON_OUT = process.argv.includes("--json");
const TIMEOUT = Number(arg("timeout", 20000));

const site = [];   // failures that mean SITE BROKEN
const record = []; // failures that mean NETWORK DOWN
const notes = [];
// Classify by WHAT is missing, not by who linked to it. The record lives under /net, and several pages link
// straight into it — so a missing registry.json also shows up as a dead link on the home page and in llms.txt. If
// those were counted as site failures, a perfectly-served site with no record behind it would report SITE BROKEN and
// the NETWORK DOWN verdict could never be reached at all. The pages are fine; the data is gone. Say that.
const RECORD_PATH = /(^|\/)net\//;
const siteFail = (j, m) => (RECORD_PATH.test(m) ? record : site).push({ journey: j, problem: m });
const recFail = (j, m) => record.push({ journey: j, problem: m });

async function get(path, { json = false } = {}) {
  const url = path.startsWith("http") ? path : `${BASE}/${path.replace(/^\//, "")}`;
  const res = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT), redirect: "follow" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return json ? res.json() : res.text();
}

// ── J1 · land and navigate ───────────────────────────────────────────────────────────────────────────────────
const PAGES = ["", "verify.html", "get.html", "foundation.html", "docs.html", "standard.html", "status.html", "404.html"];
let homeHtml = "";
async function j1() {
  const seen = new Set();
  for (const p of PAGES) {
    let html;
    try { html = await get(p); } catch (e) { siteFail("land-and-navigate", `GET /${p || "(home)"} → ${e.message}`); continue; }
    if (p === "") homeHtml = html;
    // Every internal link a stranger can click must resolve. A link that 404s is the site sending someone nowhere.
    for (const m of html.matchAll(/<a[^>]+href="([^"]+)"/g)) {
      const href = m[1];
      if (!href || href.startsWith("#") || /^(mailto:|tel:|javascript:|https?:)/.test(href)) continue;
      const target = href.split("#")[0].replace(/^\.?\//, "");
      if (!target || seen.has(target)) continue;
      seen.add(target);
      try { await get(target); } catch (e) { siteFail("land-and-navigate", `/${p || "(home)"} links to /${target} → ${e.message}`); }
    }
  }
  notes.push(`${PAGES.length} pages walked, ${seen.size} distinct internal links followed`);
}

// ── J2 · the 404's own escape routes ─────────────────────────────────────────────────────────────────────────
// The finding that started this: relative escape links resolved INTO the nested directory and were themselves 404,
// so the one page a lost visitor lands on had no working way out.
async function j2() {
  let html;
  try { html = await get("404.html"); } catch (e) { return siteFail("lost-and-found", `the 404 page itself → ${e.message}`); }
  const links = [...html.matchAll(/<a[^>]+href="([^"]+)"/g)].map((m) => m[1]).filter((h) => !/^(https?:|mailto:|#)/.test(h));
  if (!links.length) return siteFail("lost-and-found", "the 404 page offers no way back at all");
  for (const href of links) {
    if (!href.startsWith("/")) siteFail("lost-and-found", `404 escape link "${href}" is relative — it dies at any nested path`);
    else try { await get(href); } catch (e) { siteFail("lost-and-found", `404 escape link ${href} → ${e.message}`); }
  }
  notes.push(`${links.length} escape links on the 404 page, all root-absolute and resolving`);
}

// ── J3 · the record the site publishes ───────────────────────────────────────────────────────────────────────
// This half is NETWORK DOWN, not SITE BROKEN: the pages can be perfect while the data behind them is gone.
let reg = null;
async function j3() {
  try { reg = await get("net/registry.json", { json: true }); }
  catch (e) { return recFail("browse-the-record", `net/registry.json → ${e.message}`); }
  const t = reg?.totals || {};
  if (!(t.registrars > 0)) recFail("browse-the-record", `the record publishes ${t.registrars ?? "no"} registrars`);
  if (!(t.issued > 0)) recFail("browse-the-record", `the record publishes ${t.issued ?? "no"} passports`);
  if (!Array.isArray(reg?.registrars) || !reg.registrars.length) recFail("browse-the-record", "the record carries no registrar entries");

  // The publication stamp. Its ABSENCE is not a failure — an unstamped copy honestly claims no date — but a stamp
  // that cannot be parsed is worse than none, because the panels render it.
  try {
    const pub = await get("net/published.json", { json: true });
    if (!pub?.published_at_iso || Number.isNaN(Date.parse(pub.published_at_iso)))
      recFail("browse-the-record", "published.json exists but carries no parseable publication time");
    else {
      const days = Math.round((Date.now() - Date.parse(pub.published_at_iso)) / 86400000);
      notes.push(`published record stamped ${pub.published_at_iso.slice(0, 10)} (${days} day${days === 1 ? "" : "s"} ago)`);
    }
  } catch { notes.push("no publication stamp on the record (it claims no date, which is honest)"); }

  // Every page that reads a contract must read the SAME one. Two surfaces publishing two different networks, each
  // denying the other's passports, was finding #2 and is the kind of thing only a cross-page check sees.
  const contracts = new Set();
  for (const p of ["get.html", "foundation.html", "verify.html"]) {
    try {
      const html = await get(p);
      const m = html.match(/<meta name="ainra-contract" content="([^"]+)"/);
      if (m) contracts.add(m[1]);
      for (const d of html.matchAll(/["'`]([^"'`]*\/registry\.json)["'`]/g)) contracts.add(d[1]);
    } catch { /* J1 already recorded the page failure */ }
  }
  // Compare the DIRECTORY each surface reads, not how it happens to spell it: "/net" from a meta tag and
  // "net/registry.json" from a script are the same record. What must never differ is which record.
  const norm = (c) => "/" + c.replace(/\/registry\.json$/, "").replace(/^\.?\/*/, "").replace(/\/+$/, "");
  const roots = new Set([...contracts].map(norm));
  if (roots.size > 1) siteFail("browse-the-record", `pages read ${roots.size} different records: ${[...roots].join(" vs ")}`);
  else if (roots.size === 1) notes.push(`every page reads one record — ${[...roots][0]}`);
}

// ── J4 · read the docs, then install ─────────────────────────────────────────────────────────────────────────
// Finding #4: the install step pointed at a download that does not contain what the sentence promised.
async function j4() {
  let html;
  try { html = await get("docs.html"); } catch (e) { return siteFail("read-and-install", `docs.html → ${e.message}`); }
  const dl = [...html.matchAll(/href="([^"]*\.(?:zip|tar\.gz|tgz))"/g)].map((m) => m[1]);
  if (!dl.length) siteFail("read-and-install", "the docs offer no downloadable CLI at all");
  for (const d of new Set(dl)) {
    try { await get(d); notes.push(`download ${d} serves`); }
    catch (e) { siteFail("read-and-install", `the docs offer ${d} but it → ${e.message}`); }
  }
}

// ── J5 · arriving as an AI agent ─────────────────────────────────────────────────────────────────────────────
// llms.txt calls itself the map. Finding #3: it named the wrong current release, and nothing checked it.
async function j5() {
  let txt;
  try { txt = await get("llms.txt"); } catch (e) { return siteFail("agent-arrival", `llms.txt → ${e.message}`); }
  for (const m of txt.matchAll(/\]\(([^)]+)\)/g)) {
    const u = m[1];
    if (/^(https?:|mailto:)/.test(u)) continue;
    try { await get(u.split("#")[0]); } catch (e) { siteFail("agent-arrival", `llms.txt maps agents to /${u} → ${e.message}`); }
  }
  const cur = txt.match(/current:\s*(v[0-9][0-9.]*)/i);
  if (!cur) siteFail("agent-arrival", "llms.txt names no current release — the map does not say what it describes");
  else {
    // Against the real published tags, not against our own repo state: this runs where a stranger stands.
    try {
      const rel = await get("https://api.github.com/repos/JacobJandon/ainra/releases", { json: true });
      const newest = rel.filter((r) => !r.draft).map((r) => r.tag_name)[0];
      if (newest && newest !== cur[1]) siteFail("agent-arrival", `llms.txt says current: ${cur[1]}, newest public release is ${newest}`);
      else if (newest) notes.push(`llms.txt names the newest public release — ${newest}`);
    } catch { notes.push(`could not read public releases to cross-check llms.txt (says ${cur[1]})`); }
  }
}

// ── run ──────────────────────────────────────────────────────────────────────────────────────────────────────
const JOURNEYS = [["land-and-navigate", j1], ["lost-and-found", j2], ["browse-the-record", j3], ["read-and-install", j4], ["agent-arrival", j5]];
let ran = 0;
for (const [name, fn] of JOURNEYS) {
  try { await fn(); ran++; }
  catch (e) { siteFail(name, `the journey could not complete: ${e.message}`); }
}

// A run that did not complete every journey is never ALL UP — "we didn't look" is not "nothing was there".
const incomplete = ran < JOURNEYS.length;
const verdict = site.length ? "SITE BROKEN" : record.length ? "NETWORK DOWN" : incomplete ? "INCOMPLETE" : "ALL UP";
const result = {
  base: BASE,
  checked_at: new Date().toISOString(),
  verdict,
  journeys_run: ran,
  journeys_total: JOURNEYS.length,
  site_failures: site,
  record_failures: record,
  notes,
};

try { mkdirSync("build", { recursive: true }); writeFileSync("build/stranger-last.json", JSON.stringify(result, null, 2)); } catch { /* read-only cwd is fine */ }

if (JSON_OUT) { console.log(JSON.stringify(result, null, 2)); }
else {
  console.log(`\nSTRANGER JOURNEYS · ${BASE}`);
  console.log("─".repeat(78));
  for (const n of notes) console.log(`  · ${n}`);
  if (site.length) { console.log("\n  SITE:"); for (const f of site) console.log(`    ✗ [${f.journey}] ${f.problem}`); }
  if (record.length) { console.log("\n  RECORD:"); for (const f of record) console.log(`    ✗ [${f.journey}] ${f.problem}`); }
  console.log(`\n  ${ran}/${JOURNEYS.length} journeys completed`);
  console.log(`  VERDICT: ${verdict}\n`);
}
process.exit(verdict === "ALL UP" ? 0 : 1);
