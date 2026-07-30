// SPDX-License-Identifier: Apache-2.0 OR MIT
// Shared header/footer include. The four peer content pages (standard/verify/foundations/status) draw their <nav>
// and <footer> from site/_includes/{header,footer}.html — ONE source of truth, so they cannot drift. The only
// per-page differences are applied deterministically here: the active nav link (green) and self-anchors made relative.
//   node tools/site-includes.mjs          → sync: rewrite each page's <nav>/<footer> from the include (idempotent).
//   node tools/site-includes.mjs --check  → CI: exit 1 if any page's region differs from what the include produces.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const SITE = join(dirname(fileURLToPath(import.meta.url)), "..", "site");
const INC = join(SITE, "_includes");
const PAGES = ["standard", "verify", "foundations", "status"];
// nav-only peers: pages that must carry the identical menu but keep their own compact footer (app pages)
const NAV_ONLY = ["get"];
const headerN = readFileSync(join(INC, "header.html"), "utf8").trimEnd(); // page-neutral (no active state)
const footerN = readFileSync(join(INC, "footer.html"), "utf8").trimEnd(); // page-neutral (all self-anchors absolute)

// active nav link (green) on this page's short-label link only (dropdown links contain <span>, so [^<]+ won't match them)
const headerFor = (p) => headerN.replace(new RegExp(`(<a href="${p}\\.html")>([^<]+)</a>`, "g"), `$1 style="color:var(--green)">$2</a>`);
// this page's own anchors become relative; cross-page anchors stay absolute
const footerFor = (p) => footerN.replace(new RegExp(`href="${p}\\.html#`, "g"), `href="#`);

const navRe = /<nav>[\s\S]*?<\/nav>/;
const footRe = /<footer[\s\S]*?<\/footer>/;
const check = process.argv.includes("--check");
let drift = 0, synced = 0;

for (const p of PAGES) {
  const file = join(SITE, p + ".html");
  let s = readFileSync(file, "utf8");
  const wantNav = headerFor(p), wantFoot = footerFor(p);
  const curNav = s.match(navRe)?.[0], curFoot = s.match(footRe)?.[0];
  const navOk = curNav === wantNav, footOk = curFoot === wantFoot;
  if (check) {
    if (!navOk) { console.log(`  ✗ ${p}.html: <nav> drifted from _includes/header.html`); drift++; }
    if (!footOk) { console.log(`  ✗ ${p}.html: <footer> drifted from _includes/footer.html`); drift++; }
  } else if (!navOk || !footOk) {
    s = s.replace(navRe, wantNav).replace(footRe, wantFoot);
    writeFileSync(file, s); synced++;
    console.log(`  ↻ ${p}.html: header/footer synced from _includes/`);
  }
}

for (const p of NAV_ONLY) {
  const file = join(SITE, p + ".html");
  let s = readFileSync(file, "utf8");
  const wantNav = headerFor(p);
  const navOk = s.match(navRe)?.[0] === wantNav;
  if (check) {
    if (!navOk) { console.log(`  ✗ ${p}.html: <nav> drifted from _includes/header.html`); drift++; }
  } else if (!navOk) {
    s = s.replace(navRe, wantNav);
    writeFileSync(file, s); synced++;
    console.log(`  ↻ ${p}.html: header synced from _includes/ (nav-only page)`);
  }
}

if (check) {
  console.log(drift ? `\n${drift} drift(s) — run \`make site\` to resync from _includes/` : "✓ shared header/footer in sync across the 4 content pages + the nav-only live page");
  process.exit(drift ? 1 : 0);
}
console.log(synced ? `synced ${synced} page(s) from _includes/header.html + footer.html` : "✓ header/footer already in sync with _includes/");
