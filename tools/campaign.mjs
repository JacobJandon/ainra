// SPDX-License-Identifier: Apache-2.0 OR MIT
// AINRA CAMPAIGN DRIVER — the operating surface for the fourteen days that move the three real-world rows.
//
// Three rows in docs/DOD.md can only be moved by people who are not us: independent verifiers, a recorded custodian
// ceremony, and a 14-day soak. Every one of them starts with a human sending a message. This tool is the schedule,
// the tracker, and the honest scoreboard for that work — nothing more. It has the same posture as the rest of the
// repository: local, zero network, zero telemetry, and it NEVER flips a Definition-of-Done row.
//
//   node tools/campaign.mjs [status]                 today's primary action + every count, each from its source
//   node tools/campaign.mjs init                     create the LOCAL tracker (gitignored — it holds people)
//   node tools/campaign.mjs add <kind> <id> [opts]   mark a candidate   (kind: verifier|interview|custodian|witness)
//   node tools/campaign.mjs send <id> [--on DATE]    record a send      (arms the 3-day nudge)
//   node tools/campaign.mjs nudge <id> [--on DATE]   record the one nudge this person gets
//   node tools/campaign.mjs reply <id> <yes|no|later>
//   node tools/campaign.mjs interview <id> [--on DATE]   record a COMPLETED interview
//   node tools/campaign.mjs drop <id> --reason "..."     stop tracking someone (also the delete-my-data path)
//   node tools/campaign.mjs gates                    the gate register, with days remaining
//   node tools/campaign.mjs redate <K1|K4> <DATE> --reason "..."   re-date a gate IN THE OPEN (appends history)
//   node tools/campaign.mjs render [--check]         regenerate the generated blocks of campaign/{PLAN,GATES}.md
//   node tools/campaign.mjs check                    CI gate: published counts == registry reality (no tracker needed)
//
// WHERE EACH NUMBER COMES FROM (nothing here is asserted):
//   verifier attestations  submitted → evidence/verifier/*.json      confirmed → tools/genesis-board/board.mjs
//   witness candidacies    witnesses/candidates.json
//   ceremony / soak        the genesis board (absent evidence = honestly "not held" / "not started")
//   outreach + interviews  the LOCAL tracker only — people never enter this repository (D-036)
//
// PRIVACY (D-036, load-bearing): names, addresses, employers, and interview notes live in campaign/tracker.local.json
// and campaign/notes/, both gitignored. What is publishable is a COUNT. `check` enforces that the counts we publish
// match the registries; there is no command that writes a person into a tracked file.

import { readFileSync, writeFileSync, existsSync, readdirSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const TRACKER = ROOT + "campaign/tracker.local.json";
const GATES = ROOT + "campaign/gates.json";
const NOTES = ROOT + "campaign/notes";

// ── the calendar: ONE source of truth, rendered into campaign/PLAN.md and read by `status` ────────────────────────
// Anchored to real weekdays (D1 = Mon 03 Aug 2026). The nudge rhythm is deliberately NOT a calendar day: it is
// mechanical (3 days after a send, exactly one), so `status` surfaces it every day instead of on one scheduled day.
const ANCHOR = "2026-08-03";
const CALENDAR = [
  { d: 1,  title: "Unblock the pastes",        do: "Publish the packages, then mark candidates — names only, no messages yet.",
    cmds: ["make publish-preflight", "node tools/campaign.mjs add verifier <id> --name '…' --why '…'"],
    target: "20 verifier + 30 interview candidates marked" },
  { d: 2,  title: "First five verifier asks",  do: "5 verifier asks (personalize two sentences each) + 10 interview asks.",
    cmds: ["node tools/campaign.mjs send <id>"], target: "5/20 verifier asks · 10/30 interview asks" },
  { d: 3,  title: "Custodian conversations open", do: "Custodian packet to 5 candidates, asking for 20 minutes. + 5 interview asks.",
    cmds: ["node tools/campaign.mjs send <id>"], target: "5 custodian asks · 15/30 interview asks" },
  { d: 4,  title: "Jurisdiction decision day", do: "Read the memo, DECIDE, write the decision into the memo, start the registration the same day.",
    cmds: ["$EDITOR campaign/JURISDICTION.md"], target: "legal shell chosen and filed for" },
  { d: 5,  title: "Verifier wave two",         do: "5 more verifier asks + 5 interview asks.",
    cmds: ["node tools/campaign.mjs send <id>"], target: "10/20 verifier asks · 20/30 interview asks" },
  { d: 6,  title: "Interviews begin",          do: "Run every interview that landed. Listen 80%; log verbatim quotes the same day.",
    cmds: ["node tools/campaign.mjs interview <id>"], target: "2 interviews done" },
  { d: 7,  title: "Interviews continue",       do: "Second sitting of the weekend. This is the K1 gate's whole substance.",
    cmds: ["node tools/campaign.mjs interview <id>"], target: "3 interviews done (cumulative)" },
  { d: 8,  title: "The regulator letter",      do: "One page to the digital-identity regulator of the jurisdiction you chose: what AINRA is, the analogy paragraph, ask for a conversation.",
    cmds: ["$EDITOR campaign/TEMPLATES.md   # §5"], target: "letter sent · wave-three list ready" },
  { d: 9,  title: "Honesty checkpoint",        do: "Count. If interviews-done < 4, RE-DATE K1 in the open — never fudge it. Then the last 10 verifier asks.",
    cmds: ["node tools/campaign.mjs status", "node tools/campaign.mjs redate K1 <DATE> --reason '…'"],
    target: "20/20 verifier asks in flight" },
  { d: 10, title: "Interview sprint",          do: "1–2 interviews. Custodian calls happen. Any verifier who replied gets white-glove support the same day.",
    cmds: ["node tools/campaign.mjs interview <id>"], target: "1–2 interviews" },
  { d: 11, title: "Interview sprint",          do: "1–2 interviews. Watch each verifier's attestation PR self-verify in CI.",
    cmds: ["node tools/campaign.mjs interview <id>"], target: "1–2 interviews" },
  { d: 12, title: "Interview sprint",          do: "1–2 interviews. Chase whatever is still confirmable for the weekend.",
    cmds: ["node tools/campaign.mjs interview <id>"], target: "1–2 interviews" },
  { d: 13, title: "Pre-K1 close",              do: "Last confirmable interviews. Send the witness quickstart to anyone technically warm who declined verifying — ten minutes on their own infrastructure is an easier yes.",
    cmds: ["node tools/campaign.mjs send <id>"], target: "witness asks out" },
  { d: 14, title: "K1 gate reading",           do: "Count honestly, record the result either way, publish the number.",
    cmds: ["node tools/campaign.mjs gates", "node tools/campaign.mjs render"], target: "K1 read and recorded" },
];

// ── small helpers ────────────────────────────────────────────────────────────────────────────────────────────────
const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : d; };
const has = (n) => process.argv.includes(`--${n}`);
const DAY = 86400000;
const iso = (dt) => dt.toISOString().slice(0, 10);
const today = () => arg("on", iso(new Date()));
const parse = (s) => { const d = new Date(s + "T00:00:00Z"); if (Number.isNaN(d.getTime())) die(`not a date: ${s} (use YYYY-MM-DD)`); return d; };
const daysBetween = (a, b) => Math.round((parse(b) - parse(a)) / DAY);
const pretty = (s) => parse(s).toUTCString().slice(0, 11).trim();               // "Mon, 03 Aug"
const die = (m) => { console.error(`campaign: ${m}`); process.exit(1); };
const readJSON = (p, fallback) => { try { return JSON.parse(readFileSync(p, "utf8")); } catch { return fallback; } };
const writeJSON = (p, v) => writeFileSync(p, JSON.stringify(v, null, 2) + "\n");
const bar = "─".repeat(78);

// ── registry readers — the only sources of a published number ────────────────────────────────────────────────────
// Public intake: submissions that CI shape-checked. A submitted attestation is NOT a counted one (evidence/README.md).
function intakeSubmitted() {
  const dir = ROOT + "evidence/verifier";
  return existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith(".json")).length : 0;
}
// Confirmed: the genesis board re-verifies each durable attestation and reports the distinct valid count. We parse the
// board rather than re-implement its crypto — one implementation of "counted", not two. --html /dev/null keeps this
// read-only. If the board cannot run we return null and print "unknown", never 0 (fail closed, never flatter).
function boardCounts() {
  try {
    const out = execFileSync("node", [ROOT + "tools/genesis-board/board.mjs", "--html", "/dev/null"], { encoding: "utf8", cwd: ROOT });
    const v = out.match(/≥3 external verifiers\s+(\d+)\/3/);
    const cer = /Recorded in-person ceremony\s+no transcript yet/.test(out) ? "not held" : "transcript present";
    const soakM = out.match(/soak (\d+) region-run/);
    return { verifiers: v ? Number(v[1]) : null, ceremony: cer, soakRegions: soakM ? Number(soakM[1]) : null };
  } catch (e) { return { verifiers: null, ceremony: "unknown", soakRegions: null, error: e.message }; }
}
function witnessCandidacies() {
  const j = readJSON(ROOT + "witnesses/candidates.json", null);
  return j && Array.isArray(j.candidates) ? j.candidates.length : null;
}
// What ROADMAP.md publishes to the world, so `check` can prove the two agree.
function roadmapClaims() {
  const t = readFileSync(ROOT + "ROADMAP.md", "utf8");
  const v = t.match(/\*\*Independent verifiers\*\*.*?\*\*(\d+)\s*\/\s*3\*\*/s);
  const w = t.match(/Witness candidacies[^:]*:\s*\*\*(\d+)\*\*/);
  return { verifiers: v ? Number(v[1]) : null, witnesses: w ? Number(w[1]) : null };
}

// ── the local tracker (people; never committed) ──────────────────────────────────────────────────────────────────
const KINDS = ["verifier", "interview", "custodian", "witness"];
const loadTracker = () => (existsSync(TRACKER) ? readJSON(TRACKER, null) : null);
function requireTracker() {
  const t = loadTracker();
  if (!t) die("no local tracker — run `make campaign-init` first (it is gitignored; people never enter this repo)");
  return t;
}
const findPerson = (t, id) => t.people.find((p) => p.id === id) || die(`no candidate with id "${id}" (see \`node tools/campaign.mjs status\`)`);

function cmdInit() {
  if (existsSync(TRACKER)) die(`tracker already exists at campaign/tracker.local.json — not overwriting`);
  writeJSON(TRACKER, {
    _warning: "LOCAL ONLY. Holds personal data (names, contacts). Gitignored by design — see D-036. Never commit, never paste into an issue. `node tools/campaign.mjs drop <id>` deletes a person.",
    created: today(), anchor: ANCHOR, people: [],
  });
  mkdirSync(NOTES, { recursive: true });
  writeFileSync(NOTES + "/.keep", "");
  console.log("created campaign/tracker.local.json + campaign/notes/  (both gitignored)");
  console.log("next: node tools/campaign.mjs add verifier <id> --name '…' --org '…' --contact '…' --why '…'");
}

function cmdAdd() {
  const [, , , kind, id] = process.argv;
  if (!KINDS.includes(kind)) die(`kind must be one of: ${KINDS.join(" | ")}`);
  if (!id || !/^[a-z0-9][a-z0-9-]*$/.test(id)) die("id must be kebab-case, e.g. `a-lastname` or `uni-crypto-group`");
  const t = requireTracker();
  if (t.people.some((p) => p.id === id)) die(`id "${id}" is already tracked`);
  t.people.push({ id, kind, name: arg("name", ""), org: arg("org", ""), contact: arg("contact", ""), why: arg("why", ""),
    marked: today(), sent: null, nudged: null, reply: null, replied: null, interview_done: null, dropped: null });
  writeJSON(TRACKER, t);
  console.log(`marked ${kind}: ${id}${arg("why", "") ? `  — "${arg("why", "")}"` : ""}`);
  if (!arg("why", "")) console.log("  note: --why is the personalization sentence. A cold ask without it converts badly.");
}

function stamp(field, extra = {}) {
  const t = requireTracker(), id = process.argv[3];
  if (!id) die("which candidate? pass the id");
  const p = findPerson(t, id);
  p[field] = today();
  Object.assign(p, extra);
  writeJSON(TRACKER, t);
  return p;
}

function cmdSend() {
  const p = stamp("sent");
  console.log(`sent → ${p.id} (${p.kind}) on ${p.sent}`);
  console.log(`  nudge due ${iso(new Date(parse(p.sent).getTime() + 3 * DAY))} — one nudge, one sentence, then stop.`);
}
function cmdNudge() {
  const p = stamp("nudged");
  if (!p.sent) console.log("  warning: nudging someone with no recorded send.");
  console.log(`nudged → ${p.id} on ${p.nudged}. That was the only one they get.`);
}
function cmdReply() {
  const v = process.argv[4];
  if (!["yes", "no", "later"].includes(v)) die("reply must be: yes | no | later");
  const p = stamp("replied", { reply: v });
  console.log(`reply → ${p.id}: ${v}`);
  if (v === "yes" && p.kind === "verifier") console.log("  white-glove them TODAY: send the challenge folder, offer to be on a call while they run it.");
  if (v === "no" && p.kind === "verifier") console.log("  if they were technically warm, the witness ask is the easier second yes (campaign/TEMPLATES.md §4).");
}
function cmdInterview() {
  const p = stamp("interview_done");
  const note = `${NOTES}/${p.id}.md`;
  if (!existsSync(note)) {
    mkdirSync(NOTES, { recursive: true });
    writeFileSync(note, `# ${p.id} — ${p.interview_done}\n\n<!-- LOCAL ONLY. Verbatim quotes. Never committed. -->\n\n` +
      INTERVIEW_Q.map((q, i) => `## ${i + 1}. ${q}\n\n`).join(""));
  }
  console.log(`interview done → ${p.id} on ${p.interview_done}`);
  console.log(`  notes: campaign/notes/${p.id}.md (created with the script; fill it in TODAY, verbatim)`);
}
function cmdDrop() {
  const p = stamp("dropped", { reply: null, name: "", org: "", contact: "", why: "" });
  console.log(`dropped → ${p.id} (personal fields cleared${arg("reason", "") ? `; reason: ${arg("reason", "")}` : ""}). Delete campaign/notes/${p.id}.md by hand if it exists.`);
}

const INTERVIEW_Q = [
  "What do your agents actually do today, end to end?",
  "Walk me through the last time an agent's identity or permissions mattered.",
  "When another party's agent contacts your system, what do you check now?",
  "What's the worst thing an impostor agent could do to you?",
  "Have you ever needed to kill an agent's access everywhere at once — what happened?",
  "Who in your organization would own \"agent identity\" if it existed?",
  "What would a passport need to assert for you to act on it?",
  "What would make you refuse to rely on a third-party root — what breaks trust?",
  "Would you rather run verification yourself or call an API — why?",
  "Who else should I talk to?",
];

// ── gates ────────────────────────────────────────────────────────────────────────────────────────────────────────
function loadGates() { const g = readJSON(GATES, null); if (!g) die("campaign/gates.json is missing or malformed"); return g; }

// A gate's live count is read from its declared source — never stored, so it cannot go stale or be edited upward.
function gateCount(g, t, board) {
  if (g.metric === "verifiers_confirmed") return board.verifiers;
  if (g.metric === "interviews_done") return t ? t.people.filter((p) => p.kind === "interview" && p.interview_done && !p.dropped).length : null;
  return null;
}
function gateRows() {
  const g = loadGates(), t = loadTracker(), board = boardCounts(), now = today();
  return g.gates.map((x) => {
    const n = gateCount(x, t, board);
    const left = daysBetween(now, x.date);
    const met = n !== null && n >= x.threshold;
    const state = x.status === "closed" ? x.result || "closed"
      : met ? "MET"
      : n === null ? "UNTRACKED"
      : left < 0 ? "MISSED — re-date it in the open or close it"
      : left <= 3 && n < x.threshold / 2 ? "AT RISK"
      : "open";
    return { ...x, n, left, state };
  });
}
function cmdGates() {
  console.log(`\nGATE REGISTER   (dates are public commitments; a missed gate gets re-dated in the open, never fudged)\n${bar}`);
  for (const r of gateRows()) {
    const count = r.n === null ? "—" : `${r.n}/${r.threshold}`;
    console.log(`  ${r.id}  ${r.name}`);
    console.log(`      ${count.padEnd(7)} due ${pretty(r.date)} ${r.date.slice(0, 4)} ` +
      `(${r.left >= 0 ? `${r.left} day${r.left === 1 ? "" : "s"} left` : `${-r.left} day${r.left === -1 ? "" : "s"} overdue`})   ${r.state}`);
    console.log(`      source: ${r.source}`);
    if (r.history?.length) for (const h of r.history) console.log(`      re-dated ${h.on}: ${h.from} → ${h.to} — ${h.reason}`);
  }
  console.log(bar + "\n");
}
function cmdRedate() {
  const id = (process.argv[3] || "").toUpperCase(), to = process.argv[4], reason = arg("reason", "");
  const g = loadGates(), gate = g.gates.find((x) => x.id === id);
  if (!gate) die(`no gate "${id}" (have: ${g.gates.map((x) => x.id).join(", ")})`);
  if (!to) die("give the new date: node tools/campaign.mjs redate K1 2026-08-30 --reason '…'");
  parse(to);
  if (!reason) die("--reason is required. A gate moves in the OPEN or not at all — the written reason is the whole point.");
  gate.history = gate.history || [];
  gate.history.push({ on: today(), from: gate.date, to, reason });
  gate.date = to;
  writeJSON(GATES, g);
  renderDocs(false);
  console.log(`${id} re-dated ${gate.history.at(-1).from} → ${to}`);
  console.log(`  reason recorded: "${reason}"`);
  console.log(`  campaign/GATES.md regenerated — commit it, so the move is public.`);
}

// ── generated document blocks (lockstep: `render --check` fails CI if a doc drifts from the data) ─────────────────
function calendarTable() {
  const rows = CALENDAR.map((c) => {
    const date = iso(new Date(parse(ANCHOR).getTime() + (c.d - 1) * DAY));
    return `| **D${c.d}** | ${pretty(date)} | **${c.title}** | ${c.do} | ${c.target} |`;
  });
  return ["| Day | Date | Primary action | What it is | Done looks like |", "|---|---|---|---|---|", ...rows].join("\n");
}
function gatesTable() {
  const g = loadGates();
  const rows = g.gates.map((x) => `| **${x.id}** | ${x.name} | ${x.threshold} — ${x.target} | ${x.date} | ${x.source} |`);
  const hist = g.gates.flatMap((x) => (x.history || []).map((h) => `| ${h.on} | ${x.id} | ${h.from} → ${h.to} | ${h.reason} |`));
  return ["| Gate | What it tests | Bar | Date | Where the count comes from |", "|---|---|---|---|---|", ...rows].join("\n") +
    "\n\n### Re-datings\n\n" + (hist.length
      ? ["| Recorded | Gate | Moved | Reason |", "|---|---|---|---|", ...hist].join("\n")
      : "_None. If this table stays empty it means every date was met or the campaign has not yet reached one — not that a slip went unrecorded._");
}
const MARK = (name, body) => ({ begin: `<!-- ${name}:BEGIN — generated by tools/campaign.mjs render; do not edit by hand -->`, end: `<!-- ${name}:END -->`, body });
function spliceBlock(path, name, body) {
  const m = MARK(name, body), text = readFileSync(path, "utf8");
  const i = text.indexOf(m.begin), j = text.indexOf(m.end);
  if (i < 0 || j < 0) die(`${path} is missing its ${name} markers`);
  return text.slice(0, i) + m.begin + "\n\n" + body + "\n\n" + text.slice(j);
}
function renderDocs(check) {
  const targets = [[ROOT + "campaign/PLAN.md", "CALENDAR", calendarTable()], [ROOT + "campaign/GATES.md", "GATES", gatesTable()]];
  let drift = 0;
  for (const [path, name, body] of targets) {
    const next = spliceBlock(path, name, body);
    if (readFileSync(path, "utf8") === next) { console.log(`  ✓ ${path.replace(ROOT, "")} in lockstep with the data`); continue; }
    if (check) { console.error(`  ✗ ${path.replace(ROOT, "")} is stale — run \`node tools/campaign.mjs render\``); drift++; continue; }
    writeFileSync(path, next);
    console.log(`  ↻ ${path.replace(ROOT, "")} regenerated`);
  }
  if (drift) { console.error("\nCAMPAIGN RENDER FAILED: a generated block drifted from campaign/gates.json / the calendar."); process.exit(1); }
}

// ── check: the counts we PUBLISH must equal the counts the registries HOLD (CI-safe; needs no tracker) ───────────
function cmdCheck() {
  let ok = true;
  const fail = (m) => { console.error("  ✗ " + m); ok = false; };
  const pass = (m) => console.log("  ✓ " + m);
  const board = boardCounts(), claims = roadmapClaims(), w = witnessCandidacies(), sub = intakeSubmitted();

  if (board.verifiers === null) fail(`could not read the verifier count from the genesis board${board.error ? ` (${board.error})` : ""}`);
  else if (claims.verifiers === null) fail("ROADMAP.md no longer states an `N / 3` independent-verifier count in a form this check can read");
  else if (claims.verifiers !== board.verifiers) fail(`ROADMAP.md publishes ${claims.verifiers}/3 confirmed verifiers, the board counts ${board.verifiers} — update ROADMAP.md`);
  else pass(`ROADMAP verifier count matches the genesis board (${board.verifiers}/3 confirmed; ${sub} submitted to evidence/verifier/)`);

  if (w === null) fail("witnesses/candidates.json is missing or has no `candidates` array");
  else if (claims.witnesses === null) fail("ROADMAP.md no longer states a witness-candidacy count this check can read");
  else if (claims.witnesses !== w) fail(`ROADMAP.md publishes ${claims.witnesses} witness candidacies, witnesses/candidates.json holds ${w}`);
  else pass(`ROADMAP witness-candidacy count matches the registry (${w})`);

  renderDocs(true);

  if (!ok) { console.error("\nCAMPAIGN CHECK FAILED: a published count does not match its registry."); process.exit(1); }
  console.log("CAMPAIGN OK: every published count is backed by the registry it claims to read.");
}

// ── status: the daily driver ─────────────────────────────────────────────────────────────────────────────────────
function cmdStatus() {
  const now = today(), t = loadTracker(), board = boardCounts(), w = witnessCandidacies();
  const dayNo = daysBetween(ANCHOR, now) + 1;
  const day = CALENDAR.find((c) => c.d === dayNo);
  const people = (f) => (t ? t.people.filter((p) => !p.dropped).filter(f) : []);
  const n = (f) => (t ? people(f).length : null);
  const show = (v) => (v === null ? "—" : String(v));

  console.log(`\nAINRA CAMPAIGN   ${pretty(now)} ${now.slice(0, 4)}   ` +
    (dayNo < 1 ? `starts in ${1 - dayNo} day(s)` : dayNo > CALENDAR.length ? `day ${dayNo} — the fourteen days are over; the K4 track continues` : `day ${dayNo} of ${CALENDAR.length}`));
  console.log(bar);

  if (day) {
    console.log(`  TODAY (D${day.d})  ${day.title}`);
    console.log(`            ${day.do}`);
    for (const c of day.cmds) console.log(`            → ${c}`);
    console.log(`            done looks like: ${day.target}`);
  } else if (dayNo > CALENDAR.length) {
    console.log(`  TODAY     The calendar is spent. What remains is the K4 rhythm: nudge every 3 days, custodian`);
    console.log(`            conversations to ≥5 confirmed, and the soak clock — which starts on genesis day, not before.`);
  } else {
    console.log(`  The campaign begins ${pretty(ANCHOR)}. Until then: campaign/PLAN.md.`);
  }

  console.log(`\n  THE THREE ROWS   read-only — no command in this tool can move one of them`);
  console.log(`    external verifiers    ${show(board.verifiers)} / 3 confirmed   (${sub_str()})`);
  console.log(`    recorded ceremony     ${board.ceremony}${t ? `   · custodians confirmed ${people((p) => p.kind === "custodian" && p.reply === "yes").length} / 9` : ""}`);
  console.log(`    14-day / 3-region soak  ${board.soakRegions ? `${board.soakRegions} region-run(s) collected` : "not started"} — the clock starts on genesis day`);
  console.log(`    witness candidacies   ${show(w)}   witnesses/candidates.json`);

  console.log(`\n  GATES`);
  for (const r of gateRows())
    console.log(`    ${r.id}  ${(r.n === null ? "—" : `${r.n}/${r.threshold}`).padEnd(6)} due ${pretty(r.date)}  ` +
      `${r.left >= 0 ? `${r.left}d left` : `${-r.left}d OVERDUE`}   ${r.state}`);

  console.log(`\n  OUTREACH`);
  if (!t) {
    console.log(`    no local tracker — nothing recorded. \`make campaign-init\` creates it (gitignored).`);
  } else {
    for (const k of KINDS) {
      const marked = n((p) => p.kind === k), sent = n((p) => p.kind === k && p.sent);
      const yes = n((p) => p.kind === k && p.reply === "yes"), no = n((p) => p.kind === k && p.reply === "no");
      const extra = k === "interview" ? ` · done ${n((p) => p.kind === k && p.interview_done)}` : "";
      console.log(`    ${k.padEnd(10)} marked ${String(marked).padStart(3)} · sent ${String(sent).padStart(3)} · yes ${yes} · no ${no}${extra}`);
    }
    const due = people((p) => p.sent && !p.nudged && !p.replied && daysBetween(p.sent, now) >= 3);
    console.log(`\n  DUE TODAY   the 3-day rule: one nudge, one sentence, then stop`);
    if (!due.length) console.log(`    nothing due.`);
    for (const p of due) console.log(`    nudge ${p.id.padEnd(24)} sent ${p.sent} (${daysBetween(p.sent, now)} days ago)   → node tools/campaign.mjs nudge ${p.id}`);
    const warm = people((p) => p.reply === "yes" && p.kind === "verifier" && !p.interview_done);
    for (const p of warm) console.log(`    white-glove ${p.id.padEnd(18)} said yes — send the challenge folder and stay on the line`);
  }

  const blocking = [];
  // Fail closed: a missing memo is not "decided", it is a missing memo — say so rather than silently dropping the row.
  const jurPath = ROOT + "campaign/JURISDICTION.md";
  if (!existsSync(jurPath)) blocking.push("campaign/JURISDICTION.md is missing — the legal-entity decision has nowhere to live");
  else if (/^- \*\*Decision:\*\* _undecided_/m.test(readFileSync(jurPath, "utf8")))
    blocking.push("legal entity undecided — campaign/JURISDICTION.md (D4, and every grant + letter + custodian paper blocks on it)");
  if (t) {
    const iv = people((p) => p.kind === "interview");
    if (dayNo >= 3 && iv.filter((p) => p.sent).length < 25) blocking.push(`interview asks out: ${iv.filter((p) => p.sent).length}/30 — K1 needs ~25–30 in flight by D5 to land 8 done`);
    const vf = people((p) => p.kind === "verifier" && p.sent).length;
    if (dayNo >= 9 && vf < 20) blocking.push(`verifier asks out: ${vf}/20 — K4 wants all 20 in flight by D9`);
  }
  if (blocking.length) { console.log(`\n  BLOCKING`); for (const b of blocking) console.log(`    ✗ ${b}`); }

  console.log(`\n${bar}`);
  console.log(`  the counts above come from: the genesis board, evidence/verifier/, witnesses/candidates.json,`);
  console.log(`  and your local tracker. Nothing on this line was asserted by hand.\n`);

  function sub_str() {
    const s = intakeSubmitted();
    return s ? `${s} submitted to evidence/verifier/, awaiting the private answer-key check` : "no attestations submitted yet";
  }
}

// ── dispatch ─────────────────────────────────────────────────────────────────────────────────────────────────────
const cmd = process.argv[2] || "status";
({
  status: cmdStatus, init: cmdInit, add: cmdAdd, send: cmdSend, nudge: cmdNudge, reply: cmdReply,
  interview: cmdInterview, drop: cmdDrop, gates: cmdGates, redate: cmdRedate, check: cmdCheck,
  render: () => renderDocs(has("check")),
}[cmd] || (() => die(`unknown command "${cmd}". Try: status | init | add | send | nudge | reply | interview | drop | gates | redate | render | check`)))();
