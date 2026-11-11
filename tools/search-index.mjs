// SPDX-License-Identifier: Apache-2.0 OR MIT
// The site's search index: every titled part of every public page (its heading, a short excerpt, and the link to
// it), written to site/search-index.json. The search box reads this one static file in the browser; nothing a
// visitor types ever leaves their machine.   node tools/search-index.mjs   (run by tools/site.sh)
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const SITE = new URL("../site/", import.meta.url).pathname;
const PAGES = [["index.html", "Home"], ["verify.html", "Verify"], ["get.html", "Network"], ["landscape.html", "Landscape"],
  ["foundation.html", "Foundation"], ["docs.html", "Docs"], ["standard.html", "Standard"], ["request-demo.html", "Demo"], ["control.html", "Control room"]];
// the words of a part, for matching only (never shown): a search for "install", "npm", "python" or "contact" found
// nothing while the index held just each heading and its first 220 characters
// Sorted, so it is a bag of words and never a sentence: a phrase copied here would be a second, unregistered place
// where the site states a tracked claim (tools/claims.mjs found exactly that).
const words = (t) => [...new Set(t.toLowerCase().match(/[a-z0-9@][a-z0-9@._/+-]{2,}/g) || [])].sort().join(" ").slice(0, 900);
const ent = { amp: "&", lt: "<", gt: ">", quot: '"', "#39": "'", nbsp: " ", mdash: "—", ndash: "–", rsquo: "’", lsquo: "‘", ldquo: "“", rdquo: "”", hellip: "…", middot: "·", rarr: "→", eacute: "é" };
const text = (h) => h.replace(/<[^>]+>/g, " ").replace(/&(#?\w+);/g, (m, e) => ent[e] ?? (e[0] === "#" ? String.fromCodePoint(e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : +e.slice(1)) : m)).replace(/\s+/g, " ").trim();

const out = [];
for (const [file, label] of PAGES) {
  let h = readFileSync(join(SITE, file), "utf8");
  h = h.replace(/<(script|style|svg|template|nav|footer|aside)\b[\s\S]*?<\/\1>/gi, " ")
       .replace(/<div class="g-menu"[\s\S]*?<\/ul>\s*<\/div>\s*<\/div>\s*<\/div>/, " ")
       // the Standard's Part IV is the first registrar's required disclosure: it is read in place, in full, and kept
       // out of the index, so its names never surface in a result list (doctrine-check holds where they may appear)
       .replace(/<h2[^>]*>\s*PART IV\b[\s\S]*?(?=<h2[^>]*>\s*PART V\b)/, " ");
  const title = text((h.match(/<title>([\s\S]*?)<\/title>/) || [, label])[1]);
  out.push({ p: label, t: title.replace(/\s*[—·|]\s*AINRA$/, ""), u: file, x: text((h.match(/<meta name="description" content="([^"]*)"/) || [, ""])[1]).slice(0, 220), k: words(`${label} ${title}`) });
  // every heading, linked to the nearest id at or before it
  const re = /<(h[1-3])\b([^>]*)>([\s\S]*?)<\/\1>/g; let m;
  while ((m = re.exec(h))) {
    if (/\bgi-title\b/.test(m[2])) continue;   // the page's one-word title, set letter by letter: the page entry above already names it
    const head = text(m[3]); if (head.length < 3) continue;
    const before = h.slice(0, m.index + m[0].length);
    const own = (m[2].match(/\bid="([^"]+)"/) || [])[1];
    const near = own || [...before.matchAll(/\bid="([^"]+)"/g)].pop()?.[1];
    const rest = h.slice(m.index + m[0].length), next = rest.search(/<h[1-3]\b/);
    const after = text(rest.slice(0, 1600)).slice(0, 220);
    out.push({ p: label, t: head, u: near ? `${file}#${near}` : file, x: after, k: words(text(rest.slice(0, next < 0 ? 6000 : Math.min(next, 6000)))) });
  }
}
// two things people look for that are not headings anywhere
out.push({ p: "Contact", t: "Write to AINRA", u: "request-demo.html", x: "info@ainra.org — a demo, a question, a founding seat.", k: "contact email mail address reach write info@ainra.org support help" });
out.push({ p: "Docs", t: "Install: the reference, the SDKs, the CLI", u: "docs.html#install", x: "git clone and make verify · npm i @ainra/sdk · pip install ainra", k: "install setup npm pip python typescript node rust cargo sdk cli package download get started quickstart" });
const seen = new Set(), uniq = out.filter((e) => { const k = e.u + "|" + e.t; if (seen.has(k)) return false; seen.add(k); return true; });
writeFileSync(join(SITE, "search-index.json"), JSON.stringify(uniq));
console.log(`search-index.json: ${uniq.length} entries from ${PAGES.length} pages`);
