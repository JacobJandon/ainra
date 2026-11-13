// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make site (and make site-check) — the news page and its feed, drawn from one hand-written file.
//
// site/news.json is the only place an entry is written: a date, a kind (release · rules · security · network), a
// title, a few plain paragraphs and the links that prove it. Entries are few on purpose. This tool
//   · draws them into site/news.html, between the two `news:` markers, newest first, the major ones first of all;
//   · writes site/news.xml, an Atom feed of the same entries (a feed is how a reader follows without an account);
//   · holds the file to the record, so choosing what to tell cannot become leaving something out:
//       – every release in CHANGELOG.md dated on or after `since` has an entry that covers it;
//       – every HIGH or MEDIUM incident in site/incidents.json opened on or after `since` has an entry that covers it
//         (a LOW one may have an entry, and need not);
//       – nothing is covered that does not exist; ids are unique; dates run newest first; every link on this site
//         points at a file that is there.
//
//   node tools/news.mjs            → write news.html's block and news.xml
//   node tools/news.mjs --check    → the page and the feed are what the file says, and the file agrees with the record
//   node tools/news.mjs --drill    → the witness
//
// WITNESS: --drill plants, one at a time, a release with no entry, a MEDIUM incident with no entry, an entry covering
// a release that does not exist, two entries with one id, dates out of order and a link to a missing file — each
// must be refused by name — and shows the real file passes.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SITE = join(ROOT, "site");
const ORIGIN = "https://ainra.org/";
const read = (p) => readFileSync(join(ROOT, p), "utf8");
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
const day = (d) => { const [y, m, dd] = d.split("-").map(Number); return `${dd} ${MONTHS[m - 1]} ${y}`; };
const month = (d) => { const [y, m] = d.split("-").map(Number); return `${MONTHS[m - 1]} ${y}`; };

export function check({ news, changelog, incidents, exists }) {
  const errors = [], E = news.entries || [];
  const seen = new Set();
  for (const [i, e] of E.entries()) {
    const who = e.id || `entry ${i + 1}`;
    if (!e.id || !/^[a-z0-9][a-z0-9.-]*$/.test(e.id)) errors.push(`${who}: an id is lower-case letters, digits, dots and hyphens`);
    if (seen.has(e.id)) errors.push(`${who}: two entries share this id`); seen.add(e.id);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(e.date || "")) errors.push(`${who}: the date is YYYY-MM-DD`);
    if (!news.kinds?.[e.kind]) errors.push(`${who}: kind "${e.kind}" is not one of ${Object.keys(news.kinds || {}).join(", ")}`);
    if (!e.title || !Array.isArray(e.body) || !e.body.length) errors.push(`${who}: a title and at least one paragraph`);
    if (!Array.isArray(e.proof) || !e.proof.length) errors.push(`${who}: an entry links to its proof`);
    if (i && E[i - 1].date < e.date) errors.push(`${who}: dates run newest first (${E[i - 1].date} is above ${e.date})`);
    for (const l of e.proof || []) if (!/^https:\/\//.test(l.href) && !exists(l.href.split("#")[0])) errors.push(`${who}: the link "${l.label}" points at ${l.href}, which is not on the site`);
  }
  const releases = [...changelog.matchAll(/^## \[v?(\d+\.\d+\.\d+)\] — (\d{4}-\d{2}-\d{2})/gm)].map((m) => ({ v: m[1], date: m[2] }));
  const covered = { releases: new Set(E.flatMap((e) => e.covers?.releases || [])), incidents: new Set(E.flatMap((e) => e.covers?.incidents || [])) };
  for (const r of releases) if (r.date >= news.since && !covered.releases.has(r.v)) errors.push(`release ${r.v} (${r.date}) has no entry`);
  for (const v of covered.releases) if (!releases.some((r) => r.v === v)) errors.push(`an entry covers release ${v}, which CHANGELOG.md does not have`);
  const inc = incidents.entries || [];
  for (const x of inc) if (x.opened >= news.since && /^(HIGH|MEDIUM)$/.test(x.class) && !covered.incidents.has(x.id)) errors.push(`incident ${x.id} (${x.class}) has no entry`);
  for (const id of covered.incidents) if (!inc.some((x) => x.id === id)) errors.push(`an entry covers incident ${id}, which the incident log does not have`);
  return errors;
}

const item = (e, kinds, big) => `    <article class="nw-item${big ? " nw-item--major" : ""}" id="n-${esc(e.id)}" data-kind="${esc(e.kind)}"${e.major ? " data-major" : ""}>
      <p class="nw-when"><time datetime="${esc(e.date)}">${esc(day(e.date))}</time><span class="nw-kind nw-kind--${esc(e.kind)}">${esc(kinds[e.kind])}</span>${e.major ? '<span class="nw-flag">Major</span>' : ""}</p>
      <h3 class="nw-title"><a href="#n-${esc(e.id)}">${esc(e.title)}</a></h3>
${e.body.map((p) => `      <p>${esc(p)}</p>`).join("\n")}
      <p class="nw-proof">${e.proof.map((l) => `<a href="${esc(l.href)}">${esc(l.label)}</a>`).join("")}</p>
    </article>`;

export function render(news) {
  const E = news.entries, out = [];
  let m = "";
  for (const e of E) {
    if (month(e.date) !== m) { if (m) out.push("  </section>"); m = month(e.date); out.push(`  <section class="nw-month" aria-label="${esc(m)}">\n    <h2 class="nw-month__h">${esc(m)}</h2>`); }
    out.push(item(e, news.kinds, e.major));
  }
  if (m) out.push("  </section>");
  return out.join("\n");
}

export function feed(news) {
  const E = news.entries, updated = `${E[0].date}T12:00:00Z`;
  return `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>AINRA news</title>
  <subtitle>Releases, rules, security and the network. Few entries, each linked to its proof.</subtitle>
  <link href="${ORIGIN}news.xml" rel="self"/>
  <link href="${ORIGIN}news.html"/>
  <id>${ORIGIN}news.html</id>
  <updated>${updated}</updated>
  <author><name>AINRA</name></author>
${E.map((e) => `  <entry>
    <title>${esc(e.title)}</title>
    <link href="${ORIGIN}news.html#n-${esc(e.id)}"/>
    <id>${ORIGIN}news.html#n-${esc(e.id)}</id>
    <updated>${esc(e.date)}T12:00:00Z</updated>
    <category term="${esc(e.kind)}"/>${e.major ? '\n    <category term="major"/>' : ""}
    <content type="html">${esc(e.body.map((p) => `<p>${esc(p)}</p>`).join("") + `<p>${e.proof.map((l) => `<a href="${esc(/^https:/.test(l.href) ? l.href : ORIGIN + l.href)}">${esc(l.label)}</a>`).join(" · ")}</p>`)}</content>
  </entry>`).join("\n")}
</feed>
`;
}

const START = "<!--news:start-->", END = "<!--news:end-->";
const inputs = () => ({ news: JSON.parse(read("site/news.json")), changelog: read("CHANGELOG.md"), incidents: JSON.parse(read("site/incidents.json")), exists: (p) => existsSync(join(SITE, p)) });

function main() {
  const mode = process.argv[2] || "";
  if (mode === "--drill") return drill();
  const inp = inputs(), errors = check(inp);
  if (errors.length) { for (const e of errors) console.error(`  ✗ ${e}`); console.error(`NEWS CHECK FAILED (${errors.length})`); process.exit(1); }
  const page = join(SITE, "news.html"), html = readFileSync(page, "utf8"), a = html.indexOf(START), b = html.indexOf(END);
  if (a < 0 || b < a) { console.error("  ✗ site/news.html has no news:start / news:end markers"); process.exit(1); }
  const xml = feed(inp.news);
  if (mode === "--check") {
    // the page's words are kept whole across line breaks by a later step, so the block is compared by its entries
    const ids = [...html.slice(a, b).matchAll(/<article class="nw-item[^"]*" id="n-([^"]+)"/g)].map((m) => m[1]);
    const want = inp.news.entries.map((e) => e.id);
    const bad = [];
    if (ids.join("|") !== want.join("|")) bad.push("site/news.html does not show the entries of site/news.json, in order — run `make site`");
    for (const e of inp.news.entries) if (!html.includes(esc(e.title).replace(/&#39;/g, "'")) && !html.replace(/<span class="nw">|<\/span>|&nbsp;/g, (x) => (x === "&nbsp;" ? " " : "")).includes(esc(e.title))) bad.push(`site/news.html does not carry the title of "${e.id}"`);
    if (!existsSync(join(SITE, "news.xml")) || readFileSync(join(SITE, "news.xml"), "utf8") !== xml) bad.push("site/news.xml is not what site/news.json says — run `make site`");
    if (bad.length) { for (const e of bad) console.error(`  ✗ ${e}`); console.error(`NEWS CHECK FAILED (${bad.length})`); process.exit(1); }
    console.log(`news: ${want.length} entries (${inp.news.entries.filter((e) => e.major).length} major), the page and the feed agree with site/news.json, and it covers every release and every HIGH or MEDIUM incident since ${inp.news.since}`);
    return;
  }
  writeFileSync(page, html.slice(0, a + START.length) + "\n" + render(inp.news) + "\n  " + html.slice(b));
  writeFileSync(join(SITE, "news.xml"), xml);
  console.log(`news.html + news.xml: ${inp.news.entries.length} entries`);
}

function drill() {
  const base = inputs(); let bad = 0;
  const clean = check(base);
  if (clean.length) { console.error(`  ✗ the real file does not pass: ${clean[0]}`); bad++; } else console.log("  ok    the real file passes");
  const refused = (name, mutate, needle) => {
    const i = structuredClone({ news: base.news, changelog: base.changelog, incidents: base.incidents }); i.exists = base.exists; mutate(i);
    const errs = check(i);
    if (errs.some((e) => e.includes(needle))) console.log(`  ok    ${name} — refused: ${errs.find((e) => e.includes(needle))}`);
    else { console.error(`  ✗ ${name} was NOT refused`); bad++; }
  };
  refused("a release with no entry", (i) => { i.changelog = `## [9.9.9] — 2099-01-01\n` + i.changelog; }, "release 9.9.9");
  refused("a MEDIUM incident with no entry", (i) => { i.incidents.entries.push({ id: "INC-DRILL", class: "MEDIUM", opened: "2099-01-01" }); }, "incident INC-DRILL");
  refused("an entry covering a release that does not exist", (i) => { i.news.entries[0].covers = { releases: ["7.7.7"] }; }, "covers release 7.7.7");
  refused("two entries with one id", (i) => { i.news.entries[1].id = i.news.entries[0].id; }, "share this id");
  refused("dates out of order", (i) => { i.news.entries[1].date = "2099-12-31"; }, "newest first");
  refused("a link to a missing file", (i) => { i.news.entries[0].proof.push({ label: "nowhere", href: "no-such-page.html" }); }, "not on the site");
  if (bad) { console.error(`NEWS DRILL FAILED (${bad})`); process.exit(1); }
  console.log("NEWS DRILL OK — an untold release, an untold incident, a phantom release, a doubled id, a wrong order and a dead link are each refused");
}

if (import.meta.url === `file://${process.argv[1]}`) main();
