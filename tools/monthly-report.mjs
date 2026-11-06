// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make monthly-report — the operator's monthly report (PLAN-M52 step 13), built only from published artifacts.
//
// Every figure names the file it comes from, the field it reads, and that file's SHA-256, so anyone can re-derive the
// report from the same record. A figure that does not come from an artifact is refused, not printed: the report is
// the record read aloud, never a place to type a number. Its age is stated by the same rule the site uses (D-058),
// so a report nobody refreshes says so by itself. Open requests are listed with their dates and judged against the
// published target: at most 90 days from a request passing R2 to its publication (D-094 item 3).
//
//   node tools/monthly-report.mjs            → reports/monthly/<YYYY-MM>.md for the published record's month
//   node tools/monthly-report.mjs --check    → re-derive and compare with the committed file (drift fails)
//   node tools/monthly-report.mjs --drill    → the witness: a hand-typed figure is refused; an old report is labelled
//
// WITNESS: --drill plants a figure with a value and no artifact and requires the build to refuse it by name; then
// fast-forwards the clock past the horizon and requires the header to read stale. Remove the refusal or the
// staleness call and the drill fails.
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { staleness, HORIZON_DAYS } from "../site/js/staleness.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(ROOT, p));
const json = (p) => JSON.parse(read(p).toString("utf8"));
const sha = (p) => createHash("sha256").update(read(p)).digest("hex").slice(0, 16);

// ── the figures: each one is a source file, the field it reads, and a pure function of that file ─────────────────
const FIGURES = [
  { label: "Record taken from the network", source: "site/net/published.json", field: "published_at_iso", get: (f) => f.published_at_iso },
  { label: "Network · root", source: "site/net/published.json", field: "network · root", get: (f) => `${f.network} · ${f.root}` },
  { label: "Accredited registrars", source: "site/net/registry.json", field: "totals.registrars", get: (f) => f.totals.registrars },
  { label: "Passports issued (all time)", source: "site/net/registry.json", field: "totals.issued", get: (f) => f.totals.issued },
  { label: "Passports revoked (all time)", source: "site/net/registry.json", field: "totals.revoked", get: (f) => f.totals.revoked },
  { label: "Witness entries in the record", source: "site/net/registry.json", field: "witnesses.length", get: (f) => f.witnesses.length },
  { label: "Independent witnesses", source: "site/net/registry.json", field: "witnesses[self_declared=false].length", get: (f) => f.witnesses.filter((w) => w.self_declared === false).length },
  { label: "Directory epochs published", source: "site/net/epochs.json", field: "epochs.length", get: (f) => f.epochs.length },
  { label: "Latest directory epoch", source: "site/net/epochs.json", field: "max(epochs[].epoch) · issued_at", get: (f) => { const e = f.epochs.reduce((a, b) => (b.epoch > a.epoch ? b : a)); return `${e.epoch} · ${new Date(e.issued_at * 1000).toISOString().slice(0, 10)}`; } },
  ...readdirSync(join(ROOT, "site/net/registrars")).sort().map((id) => (
    { label: `${id} · status sequence`, source: `site/net/registrars/${id}/fresh-head.json`, field: "seq", get: (f) => f.seq })),
  { label: "Conformance vectors (passport corpus)", source: "vectors/v1", field: "count of *.json except manifest.json", dir: true, get: (names) => names.filter((n) => n.endsWith(".json") && n !== "manifest.json").length },
  { label: "Current release", source: "packages/sdk-ts/package.json", field: "version", get: (f) => `v${f.version}` },
  { label: "Incidents on the public log", source: "site/incidents.json", field: "entries.length", get: (f) => f.entries.length },
  { label: "Incidents with no fix yet", source: "site/incidents.json", field: "entries[fixed=null].length", get: (f) => f.entries.filter((e) => e.fixed === null).length },
];

// open requests: decision records still PROPOSED, with the date their status line gives (if any)
const TARGET_DAYS = 90; // D-094 item 3: the longest time from a request passing R2 to its publication
const openDecisions = () => {
  const src = "docs/DECISIONS.md", text = read(src).toString("utf8"), out = [];
  let head = "";
  for (const line of text.split("\n")) {
    if (line.startsWith("## D-")) head = line.slice(3);
    else if (/^\*Status:\* PROPOSED/.test(line)) out.push({ id: head.split(" — ")[0], title: head.split(" — ").slice(1).join(" — ").replace(/\s*\((PROPOSED|M\d+)\)\s*$/, ""), since: (line.match(/PROPOSED (\d{4}-\d{2}-\d{2})/) || [])[1] || null });
  }
  return { src, list: out };
};

export function build(figures = FIGURES, nowMs = null) {
  const rows = [];
  for (const fig of figures) {
    if (!fig.source || typeof fig.get !== "function") throw new Error(`refused: "${fig.label}" does not come from an artifact (no source file or reader)`);
    const path = join(ROOT, fig.source);
    if (!existsSync(path)) throw new Error(`refused: "${fig.label}" — its source ${fig.source} does not exist`);
    const value = fig.dir ? fig.get(readdirSync(path)) : fig.get(json(fig.source));
    if (value === undefined || value === null || Number.isNaN(value)) throw new Error(`refused: "${fig.label}" — ${fig.source} has no ${fig.field}`);
    rows.push({ ...fig, value, digest: fig.dir ? "directory" : sha(fig.source) });
  }
  const pub = json("site/net/published.json"), stamp = pub.published_at_iso, month = stamp.slice(0, 7);
  const age = staleness(stamp, nowMs ?? Date.parse(stamp));
  const open = openDecisions();
  // the report says "no registrar request is on record" only while none can be: once /net/proposals/ is published,
  // that sentence would be a typed-in figure, so the build stops until the report reads the requests themselves
  if (existsSync(join(ROOT, "site/net/proposals"))) throw new Error("refused: site/net/proposals/ is published — the report must read and age those requests before it can say none is overdue");
  const md = [
    `# AINRA operator report — ${month}`,
    "",
    `Built by \`tools/monthly-report.mjs\` from the published record of ${stamp}. Every figure below is read from the file named`,
    "beside it; re-run the tool on the same record and you get this file byte for byte (`make monthly-report-check`).",
    "",
    `**Age of the record (D-058):** ${age.state} — ${age.text}`,
    "",
    "| Figure | Value | Source | Field | SHA-256 (first 16) |",
    "|---|---|---|---|---|",
    ...rows.map((r) => `| ${r.label} | ${r.value} | \`${r.source}\` | \`${r.field}\` | \`${r.digest}\` |`),
    "",
    "## Open requests",
    "",
    `Decision records still PROPOSED in \`${open.src}\`:`,
    "",
    ...(open.list.length ? open.list.map((d) => `- **${d.id}** — ${d.title}${d.since ? ` · proposed ${d.since}` : " · proposal date not stated in the record"}`) : ["- none"]),
    "",
    "Change requests from registrars: none on record (`/net/proposals/` is not published yet — PLAN-M52 step 6).",
    "",
    `**Overdue:** a registrar request is overdue ${TARGET_DAYS} days after it passes R2 without being published (D-094 item 3).`,
    "No registrar request is on record, so none is overdue.",
    "",
  ].join("\n");
  return { month, md, age };
}

const args = process.argv.slice(2);
if (args.includes("--drill")) {
  let bad = 0;
  try { build([...FIGURES, { label: "Agents registered (typed in)", value: 1000000 }]); console.error("  ✗ a hand-typed figure was printed"); bad++; }
  catch (e) { console.log(`  ok    hand-typed figure refused — ${e.message}`); }
  try { build([...FIGURES, { label: "From a file that is not there", source: "site/net/nope.json", field: "x", get: (f) => f.x }]); console.error("  ✗ a figure from a missing file was printed"); bad++; }
  catch (e) { console.log(`  ok    missing source refused — ${e.message}`); }
  const stamp = json("site/net/published.json").published_at_iso;
  const later = build(FIGURES, Date.parse(stamp) + (HORIZON_DAYS + 5) * 86400000);
  if (later.age.state === "current") { console.error("  ✗ a report read past the horizon still says current"); bad++; }
  else console.log(`  ok    read ${HORIZON_DAYS + 5} days later, the report says: ${later.age.state}`);
  if (bad) { console.error("MONTHLY-REPORT DRILL FAILED"); process.exit(1); }
  console.log("MONTHLY-REPORT DRILL OK — a figure without an artifact is refused, a missing source is refused, an old report labels itself");
  process.exit(0);
}
const { month, md } = build();
const file = join(ROOT, "reports", "monthly", `${month}.md`);
if (args.includes("--check")) {
  if (!existsSync(file)) { console.error(`monthly-report: ${file} is missing — run \`make monthly-report\``); process.exit(1); }
  if (readFileSync(file, "utf8") !== md) { console.error(`monthly-report: reports/monthly/${month}.md no longer matches the record — re-run \`make monthly-report\``); process.exit(1); }
  console.log(`MONTHLY-REPORT OK: reports/monthly/${month}.md re-derives byte for byte from the published record`);
} else {
  mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, md);
  console.log(`reports/monthly/${month}.md written (${md.split("\n").length} lines)`);
}
