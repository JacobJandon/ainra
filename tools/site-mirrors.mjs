// SPDX-License-Identifier: Apache-2.0 OR MIT
// M17 Task 3 — generate a plaintext-markdown TWIN of every content page from its HTML <main>, so an agent (or any
// text client) can read the page without parsing HTML. Deterministic and generated from source — never hand-copied,
// so the .md cannot drift from the page. `standard.md` is the canonical Standard verbatim (its true source is
// docs/AINRA_I_The_Standard.md); the rest are extracted from each page's <main>. Run by `make site`; listed in sitemap.
import { readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SITE = join(ROOT, "site");

const ENT = { "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#x27;": "'", "&#39;": "'", "&nbsp;": " ", "&mdash;": "—", "&ndash;": "–" };
const decode = (s) => s.replace(/&[a-z#0-9]+;/gi, (m) => ENT[m] ?? m);

// Deterministic HTML <main> → markdown. Block tags become newlines/prefixes; inline tags are stripped to their text.
// Entities are decoded ONCE, after the last tag strip: decoding inside a heading first turned "&lt;60s" into "<60s",
// which the page-wide strip then read as the start of a tag and deleted up to the next ">" (site/status.md lost a
// heading that way until PLAN-M50 step 6; tools/release-state-check.mjs holds every heading's text to the mirror now).
export function toMarkdown(html) {
  const main = html.match(/<main[^>]*>([\s\S]*?)<\/main>/i)?.[1] ?? html;
  let s = main
    .replace(/<(script|style|svg|noscript)[\s\S]*?<\/\1>/gi, "")
    .replace(/<h1[^>]*>([\s\S]*?)<\/h1>/gi, (_, t) => `\n\n# ${strip(t)}\n`)
    .replace(/<h2[^>]*>([\s\S]*?)<\/h2>/gi, (_, t) => `\n\n## ${strip(t)}\n`)
    .replace(/<h3[^>]*>([\s\S]*?)<\/h3>/gi, (_, t) => `\n\n### ${strip(t)}\n`)
    .replace(/<h4[^>]*>([\s\S]*?)<\/h4>/gi, (_, t) => `\n\n#### ${strip(t)}\n`)
    .replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, (_, t) => `\n- ${strip(t)}`)
    .replace(/<(p|tr)[^>]*>/gi, "\n\n")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|section|ul|ol|table|tbody|thead|header)>/gi, "\n");
  s = decode(strip(s));
  return s.replace(/\n{3,}/g, "\n\n").split("\n").map((l) => l.replace(/[ \t]+$/g, "")).join("\n").trim() + "\n";
}
// strip remaining tags → text, collapse inline whitespace (but keep newlines from block replacements). No decoding here.
function strip(t) {
  return t.replace(/<[^>]+>/g, "").replace(/[ \t]+/g, " ").replace(/ ?\n ?/g, "\n");
}
export const headingTexts = (html) =>
  [...(html.match(/<main[^>]*>([\s\S]*?)<\/main>/i)?.[1] ?? html).replace(/<(script|style|svg|noscript)[\s\S]*?<\/\1>/gi, "")
    .matchAll(/<h[1-4][^>]*>([\s\S]*?)<\/h[1-4]>/gi)].map((m) => decode(strip(m[1])).trim()).filter(Boolean);

const banner = (title, page) =>
  `<!-- Generated markdown mirror of ${page} — do not edit; regenerate with \`make site\` (tools/site-mirrors.mjs). -->\n# ${title}\n\n`;

export const PAGES = [
  { html: "verify.html", md: "verify.md", title: "AINRA — Verify" },
  { html: "foundations.html", md: "foundations.md", title: "AINRA — Foundations" },
  { html: "foundation.html", md: "status.md", title: "AINRA — Foundation & status" },
];

if (import.meta.url === `file://${process.argv[1]}`) {
  // standard.md = the canonical Standard, verbatim (its real source), not an HTML re-extraction.
  copyFileSync(join(ROOT, "docs", "AINRA_I_The_Standard.md"), join(SITE, "standard.md"));
  let n = 1;
  for (const p of PAGES) {
    const body = toMarkdown(readFileSync(join(SITE, p.html), "utf8"));
    writeFileSync(join(SITE, p.md), banner(p.title, p.html) + body);
    n++;
  }
  console.log(`generated ${n} markdown mirrors (standard.md + ${PAGES.map((p) => p.md).join(", ")})`);
}
