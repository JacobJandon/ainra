// SPDX-License-Identifier: Apache-2.0 OR MIT
// make site-check — static link/anchor checker for site/. Fails (exit 1) on any dead internal href, missing #anchor,
// duplicate element id, or external (non-self-contained) resource request. CI-safe: no network, no browser.
// Metadata URLs that only DECLARE the canonical host (canonical / og:url / og:image → ainra.org) or a namespace
// (schema.org in JSON-LD) are not cross-origin fetches and are exempt.
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const SITE = join(dirname(fileURLToPath(import.meta.url)), "..", "site");
const pages = readdirSync(SITE).filter((f) => f.endsWith(".html"));
const html = Object.fromEntries(pages.map((p) => [p, readFileSync(join(SITE, p), "utf8")]));
const ids = Object.fromEntries(pages.map((p) => [p, new Set([...html[p].matchAll(/id="([^"]+)"/g)].map((m) => m[1]))]));
let fail = 0;
const bad = (m) => { console.log("  ✗ " + m); fail++; };

for (const p of pages) {
  const s = html[p];
  // 1. external resource requests — the site must stay self-contained. Two deliberate exceptions, both
  //    user-initiated (the zero-external-requests privacy guarantee is about resources loaded at render time,
  //    not about what a visitor chooses to click):
  //      a. a plain <a href> to the canonical source repository;
  //      b. ONE embed URL for the §watch video, pinned to its exact ID. It appears only inside a click handler —
  //         this scanner cannot tell a JS string from an attribute, so it fires on `f.src="…"` — and the page
  //         itself never requests it: the poster is a LOCAL jpeg, the iframe exists only after the visitor
  //         is a direct embed. Its two preconnect hints are matched as BARE ORIGINS only
  //         (href="https://www.youtube.com" exactly) — a deeper link to the video host still fails the gate. Any other external URL, including any other
  //         video, still fails this gate.
  for (const m of s.matchAll(/(?:src|href)="(https?:)?\/\/[^"]+"/g))
    if (!/(localhost|127\.|ainra\.org|ainra\.vercel\.app|schema\.org|github\.com\/JacobJandon\/ainra|youtube(?:-nocookie)?\.com\/embed\/ZlHlpMpu8ug|href="https:\/\/(www\.youtube|i\.ytimg)\.com")/.test(m[0])) bad(`${p}: external request ${m[0].slice(0, 80)}`);
  // 2. internal links resolve; anchors exist in the target file
  for (const m of s.matchAll(/href="([^"#][^"]*?)(?:#([^"]+))?"/g)) {
    const [, file, anchor] = m;
    if (/^(https?:|mailto:|data:|tel:)/.test(file)) continue;
    const rel = file.replace(/^\.\//, "");
    if (!existsSync(join(SITE, rel))) { bad(`${p}: broken link → ${file}`); continue; }
    if (anchor && rel.endsWith(".html") && !ids[rel]?.has(anchor)) bad(`${p}: missing anchor ${rel}#${anchor}`);
  }
  // 3. same-page anchors
  for (const m of s.matchAll(/href="#([^"]+)"/g))
    if (!ids[p].has(m[1])) bad(`${p}: missing same-page anchor #${m[1]}`);
  // 4. duplicate ids
  const all = [...s.matchAll(/id="([^"]+)"/g)].map((m) => m[1]);
  const dupes = [...new Set(all.filter((v, i) => all.indexOf(v) !== i))];
  if (dupes.length) bad(`${p}: duplicate id(s): ${dupes.join(", ")}`);
  // 5. rough structural tag balance
  for (const t of ["main", "header", "footer", "article", "section", "nav", "script", "style"]) {
    const open = (s.match(new RegExp(`<${t}[\\s>]`, "g")) || []).length;
    const close = (s.match(new RegExp(`</${t}>`, "g")) || []).length;
    if (open !== close) bad(`${p}: <${t}> open/close mismatch ${open}/${close}`);
  }
}
// M17 — the agent surface: llms.txt markdown links resolve, and the skills index points at files that exist.
// (These reference DERIVED files — mirrors/openapi — so run after `make site`; CI does `make site site-check`.)
const llms = join(SITE, "llms.txt");
if (existsSync(llms)) {
  for (const m of readFileSync(llms, "utf8").matchAll(/\]\(([^)]+)\)/g)) {
    const [, url] = m;
    if (/^(https?:|mailto:)/.test(url)) continue;
    const [file] = url.split("#");
    if (!existsSync(join(SITE, file.replace(/^\.?\//, "")))) bad(`llms.txt: broken link → ${url}`);
  }
}
const idx = join(SITE, ".well-known", "skills", "index.json");
if (existsSync(idx)) {
  try {
    const j = JSON.parse(readFileSync(idx, "utf8"));
    for (const sk of j.skills || []) for (const u of [sk.entry, sk.reference, ...(sk.openapi || [])])
      if (u && !/^https?:/.test(u) && !existsSync(join(SITE, u.replace(/^\//, "")))) bad(`skills/index.json: broken link → ${u}`);
  } catch (e) { bad(`skills/index.json: invalid JSON (${e.message})`); }
}

console.log(fail === 0
  ? `✓ site link-check clean: ${pages.length} pages + agent surface (llms.txt, skills index) — all links resolve, no dupes, no external requests`
  : `\n${fail} link/structure problem(s) — build fails`);
process.exit(fail ? 1 : 0);
