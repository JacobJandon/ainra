// SPDX-License-Identifier: Apache-2.0 OR MIT
// Keep short hyphenated words whole across a line break (2026-11-12; owner: at some window sizes "some letters go
// down"). A browser may break a line after any hyphen, so "ML-DSA-65", "SD-JWT", "5-of-9", "end-to-end" or
// "fail-closed" could end a line with "ML-" and start the next with "DSA-65". CSS has no switch for breaks at a hyphen,
// so this wraps such words in <span class="nw"> (white-space:nowrap, site/css/ainra.css) in the built pages.
//
//   node tools/nobreak.mjs            rewrite site/*.html and site/_includes/*.html in place (idempotent)
//   node tools/nobreak.mjs --check    exit 1 if any page still holds an unwrapped short hyphenated word
//
// Only text between tags is touched, and only inside <body> (or the whole file for an include). Never a tag, an
// attribute, an entity, or anything inside <script>, <style>, <pre>, <textarea>, <svg>, <template>, <title> or
// <option>. Words longer than MAX characters stay breakable, so a long identifier can never run off a phone screen.
// Inline code (<code>, <kbd>, <samp>) is never changed inside: a short one that holds a hyphen is wrapped whole from
// outside instead, so a command such as `make soak-smoke` keeps its exact text for every gate that reads it.
// Second pass, headings: in an h2, h3, h4 or a lead paragraph of three or more words, the space before a short last
// word becomes a no-break space, so a heading never ends with one short word alone on its last line ("…source, not" /
// "us."). Only when the joined pair is at most PAIR characters, so a large heading is never forced wider than its column.
// Run after tools/site-includes.mjs, so the shared header and footer and the pages that carry them stay identical.
import { readFileSync, writeFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SITE = join(ROOT, "site");
const MAX = 20;
const LAST = 6, PAIR = 10;          // the last word's letters, and the joined pair's length, for the heading pass
const SKIP = new Set(["script", "style", "pre", "textarea", "svg", "template", "title", "option"]);
const OPEN = '<span class="nw">';
const CODE = new Set(["code", "kbd", "samp"]);
// a word: letters/digits with . : / @ inside, joined by at least one hyphen or en dash
const WORD = /[A-Za-z0-9][A-Za-z0-9.:/@]*(?:[-–][A-Za-z0-9.:/@]+)+/g;
const BEFORE = /[A-Za-z0-9.:/@\-–&#;]/;
const AFTER = /[A-Za-z0-9.:/@\-–]/;

function wrapText(text) {
  let n = 0;
  const out = text.replace(WORD, (w, at, all) => {
    const prev = at > 0 ? all[at - 1] : "", next = all[at + w.length] ?? "";
    if ((prev && BEFORE.test(prev)) || (next && AFTER.test(next))) return w;
    const bare = w.replace(/[.:]+$/, "");               // a sentence's own full stop or colon is not part of the word
    if (bare.length < 4 || bare.length > MAX || !/[-–]/.test(bare)) return w;
    n++;
    return OPEN + bare + "</span>" + w.slice(bare.length);
  });
  return { out, n };
}

/** Rewrite one HTML string; returns { html, wrapped, missed } (missed = words --check would report). */
export function nobreak(html, { fragment = false } = {}) {
  let i = 0, out = "", wrapped = 0, inBody = fragment;
  const stack = [];                                       // open skip elements
  let lastTag = "";
  while (i < html.length) {
    const lt = html.indexOf("<", i);
    const end = lt === -1 ? html.length : lt;
    if (end > i) {                                        // a run of text
      const text = html.slice(i, end);
      if (inBody && !stack.length && lastTag !== OPEN) { const r = wrapText(text); out += r.out; wrapped += r.n; }
      else out += text;
      i = end;
      continue;
    }
    // a tag, comment or declaration: copy it whole
    if (html.startsWith("<!--", lt)) { const c = html.indexOf("-->", lt); const e = c === -1 ? html.length : c + 3; out += html.slice(lt, e); i = e; continue; }
    const gt = html.indexOf(">", lt);
    const e = gt === -1 ? html.length : gt + 1;
    const tag = html.slice(lt, e);
    const lastBefore = lastTag;
    out += tag; i = e; lastTag = tag;
    const m = /^<\s*(\/)?\s*([a-zA-Z][\w-]*)/.exec(tag);
    if (!m) continue;
    const name = m[2].toLowerCase(), closing = !!m[1];
    if (name === "body") inBody = !closing;
    if (!closing && CODE.has(name) && inBody && !stack.length) {
      const close = html.toLowerCase().indexOf(`</${name}`, i);
      if (close !== -1) {
        const closeEnd = html.indexOf(">", close) + 1;
        const inner = html.slice(i, close).replace(/<span class="nw">([^<]*)<\/span>/g, "$1");   // undo an older pass
        const text = inner.replace(/<[^>]*>/g, "");
        const wrapIt = /[-\u2013]/.test(text) && text.length <= MAX && text.length >= 4 && lastBefore !== OPEN;
        out = out.slice(0, out.length - tag.length) + (wrapIt ? OPEN : "") + tag + inner + html.slice(close, closeEnd) + (wrapIt ? "</span>" : "");
        if (wrapIt) wrapped++;
        i = closeEnd; lastTag = wrapIt ? "</span>" : html.slice(close, closeEnd);
        continue;
      }
    }
    if (SKIP.has(name)) {
      if (closing) { const k = stack.lastIndexOf(name); if (k !== -1) stack.splice(k); }
      else if (!/\/\s*>$/.test(tag)) {
        stack.push(name);
        // raw-text elements: jump straight to their end tag, so a "<" inside a script cannot be read as a tag
        if (name === "script" || name === "style" || name === "textarea" || name === "title") {
          const close = html.toLowerCase().indexOf(`</${name}`, i);
          const stop = close === -1 ? html.length : close;
          out += html.slice(i, stop); i = stop;
        }
      }
    }
  }
  const w2 = widont(out, fragment);
  return { html: w2.html, wrapped: wrapped + w2.n };
}

// headings and lead paragraphs: join a short last word to the word before it with a no-break space
function widont(html, fragment) {
  let n = 0;
  const bodyAt = fragment ? 0 : Math.max(0, html.search(/<body\b/i));
  const head = html.slice(0, bodyAt), body = html.slice(bodyAt);
  const out = body.replace(/(<(h[2-4])\b[^>]*>|<p\b[^>]*\bclass="[^"]*\blede\b[^"]*"[^>]*>)([\s\S]*?)(<\/(?:h[2-4]|p)>)/gi, (all, open, hx, inner, close) => {
    if (/<(h[2-4]|p)\b/i.test(inner)) return all;                       // nested block: leave it
    const text = inner.replace(/<[^>]*>/g, " ").replace(/&nbsp;|\u00a0/g, " ");
    if (text.trim().split(/\s+/).length < 3) return all;               // two words may stack; joining them could overflow
    // the last text run that holds a visible word
    const runs = [...inner.matchAll(/(^|>)([^<]*)/g)].filter((m) => /\S/.test(m[2]));
    if (!runs.length) return all;
    const r = runs[runs.length - 1], runText = r[2], runAt = r.index + r[1].length;
    const m = /(\S+) (\S+)(\s*)$/.exec(runText);
    if (!m) return all;
    const last = m[2].replace(/[^\p{L}\p{N}]/gu, ""), pair = m[1].length + 1 + m[2].length;
    // the word before must be a word (not a dash or a bullet: "0 OPERATORS — GAP" is an exact phrase a gate reads)
    if (!last || last.length > LAST || pair > PAIR || /&|;/.test(m[1] + m[2]) || !/[\p{L}\p{N}]/u.test(m[1])) return all;
    const fixed = runText.slice(0, m.index) + m[1] + "&nbsp;" + m[2] + m[3];
    n++;
    return open + inner.slice(0, runAt) + fixed + inner.slice(runAt + runText.length) + close;
  });
  return { html: head + out, n };
}

// The command line runs only when this file is executed, so the function can be imported and tested.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const files = [
    ...readdirSync(SITE).filter((f) => f.endsWith(".html")).map((f) => ({ path: join(SITE, f), fragment: false })),
    ...(existsSync(join(SITE, "_includes")) ? readdirSync(join(SITE, "_includes")).filter((f) => f.endsWith(".html")).map((f) => ({ path: join(SITE, "_includes", f), fragment: true })) : []),
  ];
  const check = process.argv.includes("--check");
  let total = 0, pending = 0;
  for (const f of files) {
    const src = readFileSync(f.path, "utf8");
    const { html, wrapped } = nobreak(src, { fragment: f.fragment });
    if (check) { if (html !== src) { pending++; console.error(`  ✗ ${f.path.slice(ROOT.length + 1)}: ${wrapped} short hyphenated word(s) or code names can still break`); } continue; }
    if (html !== src) { writeFileSync(f.path, html); total += wrapped; }
  }
  if (check) { console.log(pending ? `nobreak: ${pending} file(s) not kept whole — run node tools/nobreak.mjs` : "nobreak OK: every short hyphenated word in the built pages stays whole"); process.exit(pending ? 1 : 0); }
  console.log(`nobreak: ${total} short hyphenated word(s) kept whole across ${files.length} file(s)`);
}
