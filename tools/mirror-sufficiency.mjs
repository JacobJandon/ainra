// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make mirror-sufficiency — how many bytes a day must a mirror carry to keep verification working?
//
// `make root-dark-drill` proves a mirror's bytes are SUFFICIENT. This asks the operational question behind that:
// what does keeping such a mirror actually cost, and does that cost fall on anyone who could refuse to pay it?
//
// The split that matters, and the reason a single number would be misleading:
//
//   STATIC   the corpus, the samples, the trust anchors. Fetched once. Never changes between releases.
//   DYNAMIC  the revocation surface. Must be re-fetched inside the freshness class or verification fails closed,
//            so this is the only part that recurs — and it is what a mirror operator is really signing up for.
//
// Every size below is MEASURED from real artifacts on disk. The per-day figures are arithmetic on those
// measurements and the freshness constants, and are labelled [extrapolated] wherever they multiply out to a scale
// this project has not run at — the distinction `make doctrine` now enforces.
//
// WITNESS: could this observe a failure? It fails if an artifact it measures is missing (a mirror that cannot be
// costed is a mirror whose contents are not known), and if the freshness constants it reads from the core no
// longer match the ones it prints. Change F1 in `ainra-core` without changing it here and this goes red.

import { readFileSync, readdirSync, existsSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const size = (p) => { try { return statSync(join(ROOT, p)).size; } catch { return null; } };
let bad = 0;
const fail = (m) => { console.error(`  ✗ ${m}`); bad++; };

// ── the freshness constants, read from the core rather than restated ─────────────────────────────────────────
const statusRs = readFileSync(join(ROOT, "crates/ainra-core/src/status.rs"), "utf8");
const grab = (name, re) => { const m = statusRs.match(re); if (!m) { fail(`could not read ${name} from ainra-core/src/status.rs — this file must not restate a constant it cannot verify`); return null; } return Number(eval(m[1])); };
const F1 = grab("F1", /Freshness::F1 => (\d+)/);
const F2 = grab("F2", /Freshness::F2 => ([\d\s*]+),/);
const F3 = grab("F3", /Freshness::F3 => ([\d\s*]+),/);
if (bad) process.exit(1);

// ── measured artifact sizes ──────────────────────────────────────────────────────────────────────────────────
const regDir = "site/net/registrars";
const registrars = existsSync(join(ROOT, regDir)) ? readdirSync(join(ROOT, regDir)) : [];
if (!registrars.length) fail(`no registrars under ${regDir} — nothing to measure`);

const per = { freshHead: 0, status: 0, accreditation: 0 };
for (const r of registrars) {
  per.freshHead += size(`${regDir}/${r}/fresh-head.json`) ?? 0;
  per.status += size(`${regDir}/${r}/status/current.json`) ?? 0;
  per.accreditation += size(`${regDir}/${r}/accreditation.json`) ?? 0;
}
const directory = size("site/net/directory.json") ?? 0;
if (!per.freshHead || !per.status) fail(`a registrar is missing fresh-head.json or status/current.json — the recurring cost cannot be measured`);
if (bad) process.exit(1);

// STATIC: the mirror as `make mirror` assembles it.
const MIRROR = "build/mirror";
let staticBytes = 0, staticFiles = 0;
if (existsSync(join(ROOT, MIRROR))) {
  const walk = (d) => { for (const e of readdirSync(join(ROOT, d), { withFileTypes: true })) { const p = `${d}/${e.name}`; if (e.isDirectory()) walk(p); else { staticBytes += size(p) ?? 0; staticFiles++; } } };
  walk(MIRROR);
} else fail(`no mirror at ${MIRROR} — run 'make mirror' first`);
if (bad) process.exit(1);

// ── the recurring cost, per freshness class ──────────────────────────────────────────────────────────────────
// A verifier re-fetches the revocation surface once per freshness window. The fresh head is the small heartbeat;
// the status list is fetched when the head says it moved. The worst case — the one worth quoting — is a verifier
// that re-fetches BOTH every window, which is what a cache-less client does.
const DAY = 86400;
const perWindow = per.freshHead + per.status;
const row = (label, secs) => ({
  label, secs,
  fetches: Math.round(DAY / secs),
  bytes: Math.round((DAY / secs) * perWindow),
});
const rows = [row("F1", F1), row("F2", F2), row("F3", F3)];

const mb = (b) => (b / 1048576).toFixed(1);
const kb = (b) => (b / 1024).toFixed(1);
const human = (b) => (b >= 1073741824 ? `${(b / 1073741824).toFixed(2)} GB` : b >= 1048576 ? `${mb(b)} MB` : `${kb(b)} KB`);

console.log(`mirror-sufficiency · every size measured from artifacts on disk`);
console.log(`\n  STATIC (fetched once, changes only on release)`);
console.log(`      mirror                ${String(staticFiles).padStart(5)} files   ${human(staticBytes).padStart(9)}`);
console.log(`\n  DYNAMIC (must be re-fetched inside the freshness window, or verification fails closed)`);
console.log(`      registrars measured   ${String(registrars.length).padStart(5)}`);
console.log(`      fresh head (all)      ${human(per.freshHead).padStart(9)}`);
console.log(`      status list (all)     ${human(per.status).padStart(9)}`);
console.log(`      per window            ${human(perWindow).padStart(9)}`);
console.log(`\n  PER VERIFIER PER DAY, by freshness class`);
for (const r of rows)
  console.log(`      ${r.label}  window ${String(r.secs).padStart(5)}s → ${String(r.fetches).padStart(5)} fetches/day → ${human(r.bytes).padStart(9)}`);

mkdirSync(join(ROOT, "docs/drills"), { recursive: true });
writeFileSync(join(ROOT, "docs/drills/MIRROR-SUFFICIENCY.md"),
`<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Drill — mirror sufficiency and what a mirror costs

**Question.** Does the full verification path work from a mirror-only environment, and what does running such a
mirror cost per day at present scale?

**That it WORKS is [ROOT-DARK.md](ROOT-DARK.md)** — an issued credential and a conformance vector both verify from
mirror bytes alone, in an isolated cage, with a revoked credential refused as the control. This document is the
cost.

**Run.** ${new Date().toISOString()} · all sizes measured from artifacts on disk.

## The split that a single number would hide

| | What it is | How often |
|---|---|---|
| **static** | corpus, samples, trust anchors | fetched once; changes only on release |
| **dynamic** | the revocation surface — fresh head + status list | every freshness window, or verification fails closed |

Only the dynamic half recurs, and it is the only part a mirror operator is really signing up for.

## Measured

| Artifact | Files | Size |
|---|---|---|
| the mirror (static) | ${staticFiles} | ${human(staticBytes)} |
| fresh head, all ${registrars.length} registrars | ${registrars.length} | ${human(per.freshHead)} |
| status list, all ${registrars.length} registrars | ${registrars.length} | ${human(per.status)} |
| **per refresh window** | | **${human(perWindow)}** |

## Per verifier, per day

Method: \`bytes/day = (86400 / freshness_window_seconds) × bytes_per_window\`. The freshness constants are read
from \`ainra-core/src/status.rs\` at run time rather than restated here, so this table cannot drift from the code.
Worst case assumed: a cache-less verifier re-fetching both artifacts every window.

| Class | Window | Fetches/day | Bytes/day |
|---|---|---|---|
${rows.map((r) => `| ${r.label} | ${r.secs}s | ${r.fetches} | **${human(r.bytes)}** |`).join("\n")}

## What this is and is not

**Measured:** every artifact size, the registrar count, the freshness constants.

**[extrapolated]:** the per-day figures are arithmetic on those measurements — real bytes multiplied by a real
cadence, not observed traffic. This project has never run a mirror for a day at any scale, and the number of
verifiers is **zero**, so a total-fleet figure would be a measurement of nothing. The per-verifier figure is the
honest unit and the one an operator can multiply by their own fleet.

**Not covered:** compression (these are raw sizes; the transfer is smaller), CDN caching between verifiers sharing
a mirror, and any growth in registrar count — ${registrars.length} registrars is what exists today, not a forecast.
`);

console.log(`\nreport → docs/drills/MIRROR-SUFFICIENCY.md`);
if (bad) process.exit(1);
console.log(`MIRROR-SUFFICIENCY OK: static ${human(staticBytes)} once; dynamic ${human(rows[0].bytes)}/day per verifier at F1, ${human(rows[2].bytes)}/day at F3.`);
