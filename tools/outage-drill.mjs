// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make outage-drill — what happens to an agent when the network around it goes dark?
//
// A common reading of a fail-closed design is "one outage and every agent stops". This measures what actually
// happens, with the real SDK verifier and the repo's own fixture passport (packages/middleware/test/fixtures), by
// verifying the same carried bundle at later and later clock times, as if nothing new had been published since:
//   * the root dark: nothing changes — verification never contacts the root (and make root-dark-drill proves a
//     credential verifies from mirror bytes alone);
//   * the registrar's status signer dark: the agent keeps verifying until its last signed status list is older than
//     the VERIFIER's own freshness class — F1 30 s, F2 300 s (the SDK default), F3 86 400 s (MTS ADR-007) — and is
//     then refused as `stale_status`. Never accepted on stale data, and never earlier than the class allows;
//   * a revoked passport stays refused through the whole outage: a status host that goes dark (or is knocked
//     offline) cannot turn a revocation back into a pass — first `revoked`, then `stale_status`.
// The verifier, not the network, chooses the window; one class per action is the operator's dial between
// availability and how quickly a revocation must bite.
//
//   node tools/outage-drill.mjs            measure and compare with the spec table (exit 1 on any difference)
//   node tools/outage-drill.mjs --write    also regenerate docs/drills/REGISTRAR-DARK.md
//   node tools/outage-drill.mjs --negative plant each failure and require the comparison to catch it
//
// WITNESS: `--negative` plants (1) a verifier that never goes stale, (2) a class window one second too long, (3) a
// revoked passport that passes once its registrar is dark, and (4) a verifier that refuses before its window ends —
// each must make the measured table differ from the spec table. Honest limit: this is the verifier's behaviour on a
// carried bundle; how long a real registrar stays dark, and how fast it fails over, are operations, not this drill.
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const FX = join(ROOT, "packages/middleware/test/fixtures");
const DOC = join(ROOT, "docs/drills/REGISTRAR-DARK.md");
const sdk = await import(join(ROOT, "packages/sdk-ts/dist/index.js"));
const load = (f) => JSON.parse(readFileSync(join(FX, f), "utf8"));
const directory = load("directory.json"), roots = load("roots.json");
const valid = load("bundle-valid.json"), revoked = load("bundle-revoked.json");

// The spec (MTS ADR-007): each class's window, in seconds. Every measured row must match these.
const WINDOW = { F1: 30, F2: 300, F3: 86400 };
// the probes: the AGE of the carried status list (seconds since the registrar signed it) — just inside, exactly at and
// just past each window, and the extremes. Verified at issued_at + age.
const AGES = [0, 29, 30, 31, 299, 300, 301, 3600, 86399, 86400, 86401, 7 * 86400];
const ISSUED = valid.status_issued_at;
if (!Number.isInteger(ISSUED) || ISSUED !== revoked.status_issued_at) throw new Error("the fixtures must carry one status_issued_at");

const verdict = (r) => (r.verdict === "valid" ? "valid" : r.reason);
function measure(plant = {}) {
  const rows = {};
  for (const cls of ["F1", "F2", "F3"]) {
    const v = sdk.Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, cls);
    if (!v) throw new Error("the fixture directory does not verify against its roots");
    rows[cls] = AGES.map((age) => {
      let a = verdict(v.verify(valid, ISSUED + age)), b = verdict(v.verify(revoked, ISSUED + age));
      if (plant.neverStale && a === "stale_status") a = "valid";
      if (plant.longWindow && cls === "F2" && age === WINDOW.F2 + 1) a = "valid";
      if (plant.revokedPassesDark && age > WINDOW[cls]) b = "valid";
      if (plant.earlyRefusal && cls === "F3" && age === 3600) a = "stale_status";
      return { age, valid: a, revoked: b };
    });
  }
  return rows;
}

// What the spec says must be measured: valid while age ≤ window, stale_status after; revoked never passes.
function expected() {
  const rows = {};
  for (const cls of ["F1", "F2", "F3"]) rows[cls] = AGES.map((age) => {
    return { age, valid: age <= WINDOW[cls] ? "valid" : "stale_status", revoked: age <= WINDOW[cls] ? "revoked" : "stale_status" }; });
  return rows;
}

const stable = (o) => JSON.stringify(o);
const diff = (a, b) => { const out = [];
  for (const cls of Object.keys(b)) b[cls].forEach((e, i) => { const m = a[cls][i];
    if (m.valid !== e.valid || m.revoked !== e.revoked) out.push(`${cls} at status age ${e.age}s: measured valid=${m.valid} revoked=${m.revoked}, spec valid=${e.valid} revoked=${e.revoked}`); });
  return out; };

const spec = expected(), got = measure();

if (process.argv.includes("--negative")) {
  const plants = [
    ["a verifier that never goes stale", { neverStale: true }],
    ["an F2 window one second too long", { longWindow: true }],
    ["a revoked passport that passes once its registrar is dark", { revokedPassesDark: true }],
    ["an F3 verifier that refuses an hour in, inside its window", { earlyRefusal: true }],
  ];
  let missed = 0;
  for (const [what, p] of plants) { const caught = diff(measure(p), spec).length > 0; console.log(`  ${caught ? "ok  caught " : "✗   MISSED "} ${what}`); if (!caught) missed++; }
  if (diff(got, spec).length) { console.error("  ✗   the unplanted measurement itself differs from the spec"); missed++; }
  if (missed) { console.error(`OUTAGE-DRILL NEGATIVE FAILED — ${missed} plant(s) not caught`); process.exit(1); }
  console.log(`OUTAGE-DRILL NEGATIVE OK — all ${plants.length} planted failures change the table, and the clean run matches the spec`);
  process.exit(0);
}

const bad = diff(got, spec);
if (bad.length) { console.error("OUTAGE-DRILL FAILED — the verifier does not behave as the freshness classes say:"); for (const b of bad) console.error("  " + b); process.exit(1); }

if (process.argv.includes("--write")) {
  const fmt = (s) => (s % 86400 === 0 && s ? `${s / 86400} d` : s % 3600 === 0 && s ? `${s / 3600} h` : `${s.toLocaleString("en-US").replace(/,/g, " ")} s`);
  const row = (cls) => `| ${cls} (${fmt(WINDOW[cls])}) | ` + got[cls].map((m) => (m.valid === "valid" ? "valid" : "**stale**")).join(" | ") + " |";
  writeFileSync(DOC, `<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Drill — when the registrar goes dark

Generated by \`node tools/outage-drill.mjs --write\`; held to the spec by \`make outage-drill\` (and
\`--negative\`). Measured with the real SDK verifier on the fixture passport in \`packages/middleware/test/fixtures\`,
verified at later and later clock times as if its registrar had published nothing since its last signed status list.
Each column is the **age** of that list — seconds since the registrar signed it. A verifier accepts while the age is
at most its class's window, and refuses from one second past it.

**Question.** Does one outage stop every agent?

**Answer.** No. An outage of the **root** changes nothing: verification never contacts it
([ROOT-DARK.md](ROOT-DARK.md)). An outage of a **registrar's status signer** stops only that registrar's agents, and
only once their last signed status is older than the window each **verifier** chose. Until then they verify; after
it they are refused as \`stale_status\` — never accepted on stale data.

| Verifier's class ↓ · status age → | ${AGES.map(fmt).join(" | ")} |
|---|${AGES.map(() => "---").join("|")}|
${row("F1")}
${row("F2")}
${row("F3")}

A **revoked** passport is refused at every one of those moments, in every class: first \`revoked\`, then
\`stale_status\`. Knocking a status host offline cannot turn a revocation back into a pass — that is what fail-closed
buys, and it is why the outage cost exists at all.

**What a deployment controls.**
- *The verifier* picks the class per action: F1 where a revocation must bite within 30 s (payments-grade), F2 by
  default, F3 for offline or low-stakes checks that can ride out a day.
- *The registrar* keeps its status signer available; signed lists can be served by any mirror or CDN, since a mirror
  cannot forge them — but a mirror extends reach, not freshness: only the registrar's delegate can sign a newer list.
- *Other registrars* are unaffected: each signs its own status (MTS ADR-009).

**What this drill does not cover.** How long a real registrar stays dark, and how quickly it fails over to a
standby signer, are operations. The specification's target for that is in MTS §20 (status freshness RTO ≤ delegate
failover); it is not built or measured here.
`);
  console.log(`wrote ${DOC}`);
}
console.log(`OUTAGE-DRILL OK — registrar dark: valid until each class's window (F1 30 s, F2 300 s, F3 86400 s), then stale_status; a revoked passport never passes (root dark: make root-dark-drill)`);
