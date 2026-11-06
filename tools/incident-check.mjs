// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make incident-check — the public incident log is complete, in order and on time (PLAN-M52 step 13, D-094 item 16).
//
// Reads three things and holds them to each other:
//   · deploy/runbooks/root-incident.md — the classes and their deadlines, parsed from its table (the doc is the
//     code's list: change a number there and the gate follows; there is no second copy here);
//   · site/incidents.json — the public log, served at /incidents.json;
//   · SECURITY.md and SECURITY-ADVISORIES.md — every advisory and post-mortem heading must be a log entry or listed
//     as not an incident, with a reason. A post-mortem with no entry is a quiet incident, and is refused.
// Entries opened on or after the runbook's effective date are held to their class's deadlines (a late one must say
// why); older entries are measured and printed, never judged. An open incident past a deadline turns this red on
// the day it becomes late, so the gate cannot be satisfied by not looking. The tabletops in deploy/runbooks/tabletop/
// may name only `make` targets and tests that exist.
//
//   node tools/incident-check.mjs            → check, print each entry's measured days
//   node tools/incident-check.mjs --drill    → the witness
//
// WITNESS: --drill plants, one at a time, a post-mortem with no entry, a late entry with no reason, an open HIGH
// past its fix deadline, dates out of order, a release not in CHANGELOG.md, and a tabletop naming a make target
// that does not exist — each must be refused by name — and shows a late entry WITH a reason is accepted.
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { execFileSync } from "node:child_process";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const txt = (p) => readFileSync(join(ROOT, p), "utf8");
const DAY = 86400000;
const day = (s) => Date.parse(`${s}T00:00:00Z`);
const days = (a, b) => Math.round((day(b) - day(a)) / DAY);
const ISO = /^\d{4}-\d{2}-\d{2}$/;

// the classes, from the runbook's table: | **HIGH** | what | within **3 days** … | within **14 days** | within **30 days** |
export function parsePolicy(md) {
  const classes = {};
  for (const line of md.split("\n")) {
    const m = line.match(/^\|\s*\*\*(HIGH|MEDIUM|LOW)\*\*\s*\|/);
    if (!m) continue;
    const cells = line.split("|").slice(1, -1).map((c) => c.trim());
    const n = (c) => { const k = c.match(/\*\*(\d+) days\*\*/); return k ? Number(k[1]) : null; };
    classes[m[1]] = { entry: n(cells[2]), fix: n(cells[3]), postmortem: n(cells[4]) };
  }
  for (const c of ["HIGH", "MEDIUM", "LOW"]) {
    if (!classes[c]) throw new Error(`runbook: no row for class ${c}`);
    if (classes[c].entry === null || classes[c].fix === null) throw new Error(`runbook: class ${c} has no entry or fix deadline`);
  }
  for (const rule of ["No one overrides a witness refusal", "A root is never announced by message"])
    if (!md.includes(rule)) throw new Error(`runbook: the rule "${rule}" is missing`);
  if (!/^\|\s*Deputy\s*\|/m.test(md)) throw new Error("runbook: the Deputy row is missing (named or stated as not named)");
  return classes;
}

const headings = (md, re) => md.split("\n").filter((l) => re.test(l)).map((l) => l.replace(/^##\s+/, "").trim());
const covers = (rec, file, h) => rec && rec.file === file && h.startsWith(rec.heading);

export function check({ log, policyMd, docs, changelog, makefile, tabletops, testSource, now }) {
  const errors = [], notes = [];
  const policy = parsePolicy(policyMd);
  if (log.format !== "ainra-incident-log/1") errors.push(`log: unknown format ${log.format}`);
  if (!ISO.test(log.effective || "")) errors.push("log: no effective date");
  const ids = new Set();
  for (const e of log.entries || []) {
    const who = e.id || "(no id)";
    if (ids.has(e.id)) errors.push(`${who}: duplicate id`); ids.add(e.id);
    const cls = policy[e.class];
    if (!cls) { errors.push(`${who}: class "${e.class}" is not one the runbook defines`); continue; }
    for (const f of ["opened", "disclosed"]) if (!ISO.test(e[f] || "")) errors.push(`${who}: ${f} is not a date`);
    if (e.fixed !== null && !ISO.test(e.fixed || "")) errors.push(`${who}: fixed is neither a date nor null`);
    if (errors.length && errors[errors.length - 1].startsWith(who)) continue;
    if (e.disclosed < e.opened) errors.push(`${who}: disclosed ${e.disclosed} is before opened ${e.opened}`);
    if (e.fixed && e.fixed < e.opened) errors.push(`${who}: fixed ${e.fixed} is before opened ${e.opened}`);
    if (e.released) {
      if (!e.fixed) errors.push(`${who}: a release carries a fix that never landed`);
      else if (!ISO.test(e.released.date || "") || e.released.date < e.fixed) errors.push(`${who}: released ${e.released.date} is not on or after fixed ${e.fixed}`);
      const v = String(e.released.version).replace(/^v/, "");
      if (!new RegExp(`^## \\[v?${v.replace(/\./g, "\\.")}\\]`, "m").test(changelog)) errors.push(`${who}: release ${v} is not in CHANGELOG.md`);
    }
    if (e.record) {
      const doc = docs[e.record.file];
      if (doc === undefined) errors.push(`${who}: record file ${e.record.file} is not one the gate reads`);
      else if (!headings(doc, /^##\s/).some((h) => h.startsWith(e.record.heading))) errors.push(`${who}: ${e.record.file} has no heading "${e.record.heading}"`);
    }
    // measured: days to entry, to the fix users can get (a release if there is one, else main), to the record
    const fixAt = e.released ? e.released.date : e.fixed;
    const m = { entry: days(e.opened, e.disclosed), fix: fixAt ? days(e.opened, fixAt) : null, open: fixAt ? null : days(e.opened, now) };
    const judged = e.opened >= log.effective;
    const late = [];
    if (m.entry > cls.entry) late.push(`public entry after ${m.entry} days (${e.class} allows ${cls.entry})`);
    if (m.fix !== null && m.fix > cls.fix) late.push(`fix published after ${m.fix} days (${e.class} allows ${cls.fix})`);
    if (m.open !== null && m.open > cls.fix) late.push(`still unfixed after ${m.open} days (${e.class} allows ${cls.fix})`);
    if (!e.record && cls.postmortem !== null && days(e.opened, now) > cls.postmortem) late.push(`no post-mortem after ${days(e.opened, now)} days (${e.class} allows ${cls.postmortem})`);
    if (cls.postmortem !== null && !e.record && (e.class === "HIGH" || e.class === "MEDIUM") && fixAt) late.push("fixed, but no post-mortem is named");
    const line = `${who} ${e.class.padEnd(6)} entry ${m.entry}d · fix ${m.fix ?? `open ${m.open}d`}${m.fix !== null ? "d" : ""}`;
    if (!judged) notes.push(`${line} — before the runbook (${log.effective}): measured, not judged${late.length ? `; today's rule would say: ${late.join("; ")}` : ""}`);
    else if (late.length && !(e.late && e.late.reason)) errors.push(`${who}: late with no stated reason — ${late.join("; ")}`);
    else notes.push(`${line}${late.length ? ` — late, reason published: ${e.late.reason}` : " — on time"}`);
  }
  // completeness: every advisory and post-mortem heading is logged or said not to be an incident
  const wanted = [
    ...headings(docs["SECURITY.md"], /^## (Advisory|Post-mortem):/).map((h) => ["SECURITY.md", h]),
    ...headings(docs["SECURITY-ADVISORIES.md"], /^## RUSTSEC-/).map((h) => ["SECURITY-ADVISORIES.md", h]),
  ];
  for (const [file, h] of wanted) {
    const logged = (log.entries || []).some((e) => covers(e.record, file, h));
    const excused = (log.not_incidents || []).some((n) => covers(n.record, file, h) && n.reason && n.reason.length > 10);
    if (!logged && !excused) errors.push(`${file} "${h.slice(0, 70)}" has no log entry and no stated reason it is not an incident`);
  }
  // tabletops: name only what exists
  const targets = new Set([...makefile.matchAll(/^([a-z0-9][a-z0-9-]*):/gm)].map((m) => m[1]));
  for (const [name, md] of Object.entries(tabletops)) {
    if (!md.includes("root-incident.md")) errors.push(`tabletop ${name}: does not cite the runbook`);
    for (const m of md.matchAll(/`make ([a-z0-9-]+)`/g)) if (!targets.has(m[1])) errors.push(`tabletop ${name}: names \`make ${m[1]}\`, which does not exist`);
    for (const m of md.matchAll(/test `([a-z0-9_]+)`/g)) if (!new RegExp(`fn ${m[1]}\\s*\\(`).test(testSource)) errors.push(`tabletop ${name}: names test \`${m[1]}\`, which does not exist`);
  }
  if (Object.keys(tabletops).length < 2) errors.push("tabletops: fewer than two (PLAN-M52 step 13 names steward compromise and a custodian no-show)");
  return { errors, notes, policy };
}

function inputs() {
  const tdir = "deploy/runbooks/tabletop";
  const tabletops = Object.fromEntries(readdirSync(join(ROOT, tdir)).filter((f) => f.endsWith(".md")).map((f) => [f, txt(`${tdir}/${f}`)]));
  const rs = execFileSync("grep", ["-rhE", "--include=*.rs", "fn [a-z0-9_]+\\s*\\(", "crates", "services"], { cwd: ROOT, maxBuffer: 64 << 20 }).toString();
  return {
    log: JSON.parse(txt("site/incidents.json")), policyMd: txt("deploy/runbooks/root-incident.md"),
    docs: { "SECURITY.md": txt("SECURITY.md"), "SECURITY-ADVISORIES.md": txt("SECURITY-ADVISORIES.md") },
    changelog: txt("CHANGELOG.md"), makefile: txt("Makefile"), tabletops, testSource: rs,
    now: new Date().toISOString().slice(0, 10),
  };
}

const args = process.argv.slice(2);
if (args.includes("--drill")) {
  const base = inputs(); let bad = 0;
  const clone = (x) => JSON.parse(JSON.stringify(x));
  const effective = base.log.effective;
  const plus = (s, n) => new Date(day(s) + n * DAY).toISOString().slice(0, 10);
  const refused = (what, mutate, needle) => {
    const inp = { ...base, log: clone(base.log), docs: { ...base.docs }, tabletops: { ...base.tabletops } };
    mutate(inp);
    let errors;
    try { ({ errors } = check(inp)); } catch (e) { errors = [e.message]; }
    const hit = errors.find((e) => e.includes(needle));
    if (hit) console.log(`  ok    ${what} — refused: ${hit.slice(0, 120)}`); else { console.error(`  ✗ ${what} was not refused (${errors.length} other errors)`); bad++; }
  };
  const fresh = (o) => ({ id: "INC-DRILL", class: "HIGH", surface: "drill", title: "drill", opened: effective, disclosed: effective, fixed: null, released: null, record: null, ...o });
  if (check(base).errors.length) { console.error("  ✗ the committed log does not pass, so the drill proves nothing"); process.exit(1); }
  refused("a post-mortem with no log entry", (i) => { i.docs["SECURITY.md"] += "\n## Post-mortem: a planted quiet incident\n"; }, "a planted quiet incident");
  refused("a HIGH entry opened 5 days before it was disclosed, no reason", (i) => { i.log.entries.push(fresh({ disclosed: plus(effective, 5), fixed: plus(effective, 5), record: i.log.entries[0].record })); }, "public entry after 5 days");
  refused("an open HIGH, 20 days old, unfixed", (i) => { i.log.entries.push(fresh({ record: i.log.entries[0].record })); i.now = plus(effective, 20); }, "still unfixed after 20 days");
  refused("a fix dated before the incident was opened", (i) => { i.log.entries.push(fresh({ fixed: plus(effective, -2) })); }, "is before opened");
  refused("a release CHANGELOG.md does not have", (i) => { i.log.entries.push(fresh({ fixed: effective, released: { version: "9.9.9", date: effective }, record: i.log.entries[0].record })); }, "9.9.9 is not in CHANGELOG.md");
  refused("a tabletop naming a make target that does not exist", (i) => { i.tabletops["planted.md"] = "root-incident.md · Witness: `make no-such-drill`"; }, "no-such-drill");
  refused("a runbook without the witness rule", (i) => { i.policyMd = i.policyMd.replace("No one overrides a witness refusal", "witness refusals are reviewed"); }, "witness refusal");
  {
    const inp = { ...base, log: clone(base.log) };
    inp.log.entries.push(fresh({ disclosed: plus(effective, 5), fixed: plus(effective, 5), record: base.log.entries[0].record, late: { reason: "drill: the lead was unreachable" } }));
    const { errors, notes } = check(inp);
    if (errors.length) { console.error(`  ✗ a late entry WITH a stated reason was refused: ${errors[0]}`); bad++; }
    else console.log(`  ok    a late entry with a published reason passes, and says so: ${notes.find((n) => n.startsWith("INC-DRILL")).slice(0, 110)}`);
  }
  if (bad) { console.error("INCIDENT DRILL FAILED"); process.exit(1); }
  console.log("INCIDENT DRILL OK — a quiet incident, a late entry, an overdue fix, bad dates, an unknown release and a phantom tabletop step are each refused");
  process.exit(0);
}

let result;
try { result = check(inputs()); } catch (e) { console.error(`incident-check: ${e.message}`); process.exit(1); }
for (const n of result.notes) console.log(`  ${n}`);
if (result.errors.length) { for (const e of result.errors) console.error(`  ✗ ${e}`); console.error(`INCIDENT CHECK FAILED (${result.errors.length})`); process.exit(1); }
const p = result.policy;
console.log(`INCIDENT CHECK OK: log complete against SECURITY.md + SECURITY-ADVISORIES.md; deadlines from the runbook (HIGH ${p.HIGH.entry}/${p.HIGH.fix}/${p.HIGH.postmortem} d, MEDIUM ${p.MEDIUM.entry}/${p.MEDIUM.fix}/${p.MEDIUM.postmortem} d, LOW ${p.LOW.entry}/${p.LOW.fix} d); tabletops name only what exists`);
