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
function toMarkdown(html) {
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
  s = strip(s);
  return s.replace(/\n{3,}/g, "\n\n").split("\n").map((l) => l.replace(/[ \t]+$/g, "")).join("\n").trim() + "\n";
}
// strip remaining tags → text, decode entities, collapse inline whitespace (but keep newlines from block replacements)
function strip(t) {
  return decode(t.replace(/<[^>]+>/g, "")).replace(/[ \t]+/g, " ").replace(/ ?\n ?/g, "\n");
}

const banner = (title, page) =>
  `<!-- Generated markdown mirror of ${page} — do not edit; regenerate with \`make site\` (tools/site-mirrors.mjs). -->\n# ${title}\n\n`;

const PAGES = [
  { html: "verify.html", md: "verify.md", title: "AINRA — Verify" },
  { html: "foundations.html", md: "foundations.md", title: "AINRA — Foundations" },
  { html: "status.html", md: "status.md", title: "AINRA — Status" },
];

// standard.md = the canonical Standard, verbatim (its real source), not an HTML re-extraction.
copyFileSync(join(ROOT, "docs", "AINRA_I_The_Standard.md"), join(SITE, "standard.md"));
let n = 1;
for (const p of PAGES) {
  const body = toMarkdown(readFileSync(join(SITE, p.html), "utf8"));
  writeFileSync(join(SITE, p.md), banner(p.title, p.html) + body);
  n++;
}
console.log(`generated ${n} markdown mirrors (standard.md + ${PAGES.map((p) => p.md).join(", ")})`);
