// SPDX-License-Identifier: Apache-2.0 OR MIT
// AINRA CAMPAIGN DRIVER — the fourteen steps that move the three real-world rows.
//
// Three rows in docs/DOD.md can only be moved by people who are not us: independent verifiers, a recorded custodian
// ceremony, and a 14-day soak. Every one of them starts with a human sending a message. This tool is the sequence,
// the tracker, and the honest scoreboard for that work — nothing more. It has the same posture as the rest of the
// repository: local, zero network, zero telemetry, and it NEVER flips a Definition-of-Done row.
//
// NO DATES, BY DESIGN. This is a SEQUENCE, not a schedule: fourteen ordered steps you advance when the previous one
// is actually done, and gates that are bars rather than deadlines. A published date is a promise about a calendar,
// and a promise about a calendar is the one kind of claim this repository cannot verify. So there are none — no due
// dates, no countdowns, no elapsed-time triggers. What replaces the deadline is the bar plus a recorded reading.
//
//   node tools/campaign.mjs [status]                 this step, every count, who is waiting, what is blocking
//   node tools/campaign.mjs init                     create the LOCAL tracker (gitignored — it holds people)
//   node tools/campaign.mjs step [n]                 show / set which step you are on
//   node tools/campaign.mjs add <kind> <id> [opts]   mark a candidate   (kind: verifier|interview|custodian|witness)
//   node tools/campaign.mjs send <id>                record that the ask went out
//   node tools/campaign.mjs nudge <id>               record the one follow-up this person gets
//   node tools/campaign.mjs reply <id> <yes|no|later>
//   node tools/campaign.mjs interview <id>           record a COMPLETED interview (opens its notes file)
//   node tools/campaign.mjs drop <id> [--reason ..]  stop tracking someone (also the delete-my-data path)
//   node tools/campaign.mjs gates                    the gate register, read live from each gate's source
//   node tools/campaign.mjs record <K1|K4> <continuing|met|missed> --reason "..."   a reading, in the open
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

// ── the sequence: ONE source of truth, rendered into campaign/PLAN.md and read by `status` ───────────────────────
// Ordered, not scheduled. Do a step when the one before it is done; the arithmetic in PLAN.md is about ORDER
// (asks must be out before replies can arrive), which is true regardless of how fast you move.
const STEPS = [
  { n: 1,  title: "Unblock the pastes",        do: "Publish the packages, then mark candidates — names only, no messages yet.",
    cmds: ["make publish-preflight", "node tools/campaign.mjs add verifier <id> --name '…' --why '…'"],
    target: "20 verifier + 30 interview candidates marked" },
  { n: 2,  title: "First five verifier asks",  do: "5 verifier asks (personalize two sentences each) + 10 interview asks.",
    cmds: ["node tools/campaign.mjs send <id>"], target: "5/20 verifier asks · 10/30 interview asks" },
  { n: 3,  title: "Custodian conversations open", do: "Custodian packet to 5 candidates, asking for twenty minutes. + 5 interview asks.",
    cmds: ["node tools/campaign.mjs send <id>"], target: "5 custodian asks · 15/30 interview asks" },
  { n: 4,  title: "Jurisdiction decision",     do: "Read the memo, DECIDE, write the decision into it, start the registration the same sitting.",
    cmds: ["$EDITOR campaign/JURISDICTION.md"], target: "legal shell chosen and filed for" },
  { n: 5,  title: "Verifier wave two",         do: "5 more verifier asks + 5 interview asks.",
    cmds: ["node tools/campaign.mjs send <id>"], target: "10/20 verifier asks · 20/30 interview asks" },
  { n: 6,  title: "Interviews begin",          do: "Run every interview that landed. Listen 80%; log verbatim quotes while they are fresh.",
    cmds: ["node tools/campaign.mjs interview <id>"], target: "2 interviews done" },
  { n: 7,  title: "Interviews continue",       do: "The second sitting. This is the K1 gate's whole substance.",
    cmds: ["node tools/campaign.mjs interview <id>"], target: "3 interviews done (cumulative)" },
  { n: 8,  title: "The regulator letter",      do: "One page to the digital-identity regulator of the jurisdiction you chose: what AINRA is, the analogy paragraph, ask for a conversation.",
    cmds: ["$EDITOR campaign/TEMPLATES.md   # §5"], target: "letter sent · wave-three list ready" },
  { n: 9,  title: "Honesty checkpoint",        do: "Count. If the interviews are not landing, record that reading in the open before pressing on. Then the last 10 verifier asks.",
    cmds: ["node tools/campaign.mjs status", "node tools/campaign.mjs record K1 continuing --reason '…'"],
    target: "20/20 verifier asks in flight" },
  { n: 10, title: "Interview sprint",          do: "Interviews. Custodian calls happen. Any verifier who replied gets white-glove support immediately.",
    cmds: ["node tools/campaign.mjs interview <id>"], target: "interviews advancing" },
  { n: 11, title: "Interview sprint",          do: "Interviews. Watch each verifier's attestation PR self-verify in CI.",
    cmds: ["node tools/campaign.mjs interview <id>"], target: "interviews advancing" },
  { n: 12, title: "Interview sprint",          do: "Interviews. Chase whatever is still confirmable.",
    cmds: ["node tools/campaign.mjs interview <id>"], target: "interviews advancing" },
  { n: 13, title: "Pre-K1 close",              do: "Last confirmable interviews. Send the witness quickstart to anyone technically warm who declined verifying — ten minutes on their own infrastructure is an easier yes.",
    cmds: ["node tools/campaign.mjs send <id>"], target: "witness asks out" },
  { n: 14, title: "K1 reading",                do: "Count honestly, record the reading either way, publish the number.",
    cmds: ["node tools/campaign.mjs record K1 <met|missed|continuing> --reason '…'", "node tools/campaign.mjs render"],
    target: "K1 read and recorded" },
];

// ── small helpers ────────────────────────────────────────────────────────────────────────────────────────────────
const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : d; };
const has = (n) => process.argv.includes(`--${n}`);
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
    step: 1, people: [],
  });
  mkdirSync(NOTES, { recursive: true });
  writeFileSync(NOTES + "/.keep", "");
  console.log("created campaign/tracker.local.json + campaign/notes/  (both gitignored)");
  console.log("next: node tools/campaign.mjs add verifier <id> --name '…' --org '…' --contact '…' --why '…'");
}

function cmdStep() {
  const t = requireTracker(), n = process.argv[3];
  if (n === undefined) { console.log(`step ${t.step} of ${STEPS.length} — ${STEPS.find((s) => s.n === t.step)?.title ?? "(past the sequence)"}`); return; }
  const v = Number(n);
  if (!Number.isInteger(v) || v < 1 || v > STEPS.length + 1) die(`step must be 1..${STEPS.length + 1} (${STEPS.length + 1} = the sequence is spent)`);
  t.step = v; writeJSON(TRACKER, t);
  const s = STEPS.find((x) => x.n === v);
  console.log(s ? `now on step ${v} — ${s.title}` : "the fourteen steps are spent; what remains is the K4 rhythm");
}

function cmdAdd() {
  const [, , , kind, id] = process.argv;
  if (!KINDS.includes(kind)) die(`kind must be one of: ${KINDS.join(" | ")}`);
  if (!id || !/^[a-z0-9][a-z0-9-]*$/.test(id)) die("id must be kebab-case, e.g. `a-lastname` or `uni-crypto-group`");
  const t = requireTracker();
  const why = arg("why", "");
  // A cold ask with no reason-for-them is the ask that fails, and `draft` refuses to write one without it. So
  // this refuses to record one without it either, rather than storing a candidate that can never be drafted.
  if (!why) die(`--why is required: one sentence on why THIS person, in your words.\n` +
                `  e.g. node tools/campaign.mjs add ${kind} ${id} --name '…' --why 'runs the X conformance suite'`);
  // L5: EVERY claim about a person cites a public page that actually names them. Research about people is where
  // a confident fabrication does the most damage — the jurisdiction pass invented verbatim quotes from primary
  // sources, and that was only about fees. So the citation is not a convention here, it is a required field: a
  // candidate cannot be recorded at all without the URL a human can open to check the claim.
  const evidence = arg("evidence", "");
  if (!evidence) die(`--evidence is required: the public URL that NAMES this person and shows the claim.\n` +
                     `  anything you cannot cite is dropped, not softened.`);
  if (!/^https?:\/\//.test(evidence)) die(`--evidence must be a fetchable http(s) URL, got: ${evidence}`);
  // IDEMPOTENT BY ID: pasting a batch twice must update, not duplicate and not abort half way through.
  const existing = t.people.find((p) => p.id === id);
  if (existing) {
    if (existing.kind !== kind) die(`id "${id}" is already tracked as ${existing.kind}; ids are unique across kinds`);
    Object.assign(existing, {
      name: arg("name", existing.name), org: arg("org", existing.org),
      contact: arg("contact", existing.contact), why, evidence,
      role: arg("role", existing.role || ""), template: arg("template", existing.template || ""),
      // Re-adding never silently re-approves. An approved candidate that gets new evidence goes back to proposed.
      status: existing.status === "approved" && existing.evidence === evidence ? "approved" : "proposed",
    });
    writeJSON(TRACKER, t);
    console.log(`updated ${kind}: ${id}  — "${why}"`);
    return;
  }
  t.people.push({ id, kind, name: arg("name", ""), org: arg("org", ""), contact: arg("contact", ""), why,
    evidence, role: arg("role", ""), template: arg("template", ""), status: "proposed",
    sent: false, nudged: false, starred: false, reply: null, interview_done: false, dropped: false });
  writeJSON(TRACKER, t);
  console.log(`proposed ${kind}: ${id}  — "${why}"`);
}

function flag(field, extra = {}) {
  const t = requireTracker(), id = process.argv[3];
  if (!id) die("which candidate? pass the id");
  const p = findPerson(t, id);
  // `dropped` is the ONE mutation a proposed candidate accepts — declining is not an action taken ON someone,
  // it is the absence of one, and requiring approval before you may drop would be exactly backwards.
  if (field !== "dropped") requireApproved(p, `mark ${field} for`);
  p[field] = true;
  Object.assign(p, extra);
  writeJSON(TRACKER, t);
  return p;
}

// M27 — mark today's batch. campaign-status floats starred-but-unsent to the top, so the day's list is the
// first thing on screen instead of something to re-derive each morning.
function cmdStar() {
  const t = requireTracker(), id = process.argv[3];
  if (!id) die("which candidate? pass the id");
  const p = findPerson(t, id);
  requireApproved(p, "star");
  p.starred = !p.starred;
  writeJSON(TRACKER, t);
  console.log(`${p.starred ? "starred" : "unstarred"} ${p.id} (${p.kind})${p.sent ? " — already sent" : ""}`);
}

// M27 — merge the stored --why into the right template and write a ready-to-send file into the gitignored
// sendbox. It INVENTS NOTHING: every word is either the committed template or the operator's own sentence.
const SENDBOX = ROOT + "campaign/sendbox";
function cmdDraft() {
  const t = requireTracker(), id = process.argv[3];
  if (!id) die("which candidate? pass the id");
  const p = findPerson(t, id);
  requireApproved(p, "draft");
  if (!p.why) die(`"${p.id}" has no --why. A draft without a reason-for-them is a cold ask; add one first:\n` +
                  `  node tools/campaign.mjs add ${p.kind} ${p.id} --why '…'`);

  const SECTION = { verifier: "1 · Verifier ask", interview: "2 · Interview ask",
                    custodian: "3 · Custodian ask", witness: "4 · Witness ask" };
  const tpl = readFileSync(ROOT + "campaign/TEMPLATES.md", "utf8");
  const head = [...tpl.matchAll(/^## (.+)$/gm)].find((m) => m[1].startsWith(SECTION[p.kind].split(" · ")[0]));
  if (!head) die(`no template section for kind "${p.kind}" in campaign/TEMPLATES.md`);
  const start = head.index + head[0].length;
  const nextIdx = tpl.indexOf("\n## ", start);
  const body = tpl.slice(start, nextIdx === -1 ? undefined : nextIdx);

  const subject = (body.match(/\*\*Subject:\*\*\s*(.+)/) || [, "(no subject line in template)"])[1].trim();
  // the quoted block is the letter; strip the leading "> " and drop the template's own placeholder line
  const letter = body.split("\n").filter((l) => l.startsWith(">")).map((l) => l.replace(/^>\s?/, ""))
    .filter((l) => !/^\*<.*>\*$/.test(l.trim()) || /sign-off/.test(l)).join("\n").trim();

  mkdirSync(SENDBOX, { recursive: true });
  const out = `${SENDBOX}/${p.kind}-${p.id}.txt`;
  writeFileSync(out,
`To:      ${p.name || "<name>"}${p.org ? ` (${p.org})` : ""}${p.contact ? ` <${p.contact}>` : ""}
Subject: ${subject}

${p.why}

${letter}

--
Draft for ${p.id} (${p.kind}). The first paragraph is YOUR sentence, stored with the candidate; everything below
it is campaign/TEMPLATES.md § ${SECTION[p.kind]}, unedited. Read it before sending — nothing here was invented.
${p.kind === "verifier" ? "Attach: the whole outreach/ready/verifier-NN/ folder (challenge + one-pager). NEVER the answer key.\n" : ""}`);
  console.log(`draft → ${out.replace(ROOT, "")}`);
  console.log(`  your sentence: "${p.why}"`);
  console.log(`  template:      campaign/TEMPLATES.md § ${SECTION[p.kind]}`);
  console.log(`  the sendbox is gitignored — people never enter this repository.`);
}

function cmdSend() {
  const p = flag("sent");
  console.log(`sent → ${p.id} (${p.kind})`);
  console.log(`  it is now in the follow-up queue: one nudge, one sentence, then stop.`);
}
function cmdNudge() {
  const p = flag("nudged");
  if (!p.sent) console.log("  warning: nudging someone with no recorded send.");
  console.log(`nudged → ${p.id}. That was the only one they get.`);
}
function cmdReply() {
  const v = process.argv[4];
  if (!["yes", "no", "later"].includes(v)) die("reply must be: yes | no | later");
  const p = flag("sent", { reply: v });
  console.log(`reply → ${p.id}: ${v}`);
  if (v === "yes" && p.kind === "verifier") console.log("  white-glove them now: send the challenge folder, offer to be on a call while they run it.");
  if (v === "no" && p.kind === "verifier") console.log("  if they were technically warm, the witness ask is the easier second yes (campaign/TEMPLATES.md §4).");
}
function cmdInterview() {
  const p = flag("interview_done");
  const note = `${NOTES}/${p.id}.md`;
  if (!existsSync(note)) {
    mkdirSync(NOTES, { recursive: true });
    writeFileSync(note, `# ${p.id}\n\n<!-- LOCAL ONLY. Verbatim quotes. Never committed. -->\n\n` +
      INTERVIEW_Q.map((q, i) => `## ${i + 1}. ${q}\n\n`).join(""));
  }
  console.log(`interview done → ${p.id}`);
  console.log(`  notes: campaign/notes/${p.id}.md (created with the script; fill it in while it is fresh, verbatim)`);
}
function cmdDrop() {
  const p = flag("dropped", { reply: null, name: "", org: "", contact: "", why: "" });
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
  const g = loadGates(), t = loadTracker(), board = boardCounts();
  return g.gates.map((x) => {
    const n = gateCount(x, t, board);
    const state = x.status === "closed" ? (x.result || "closed")
      : n === null ? "UNTRACKED"
      : n >= x.threshold ? "BAR MET — record the reading"
      : "open";
    return { ...x, n, state };
  });
}
function cmdGates() {
  console.log(`\nGATE REGISTER   bars, not deadlines — a reading is recorded in the open, whatever it says\n${bar}`);
  for (const r of gateRows()) {
    console.log(`  ${r.id}  ${r.name}`);
    console.log(`      ${(r.n === null ? "—" : `${r.n}/${r.threshold}`).padEnd(8)} ${r.target}`);
    console.log(`      ${r.state}`);
    console.log(`      source: ${r.source}`);
    if (r.history?.length) for (const h of r.history) console.log(`      recorded — ${h.reading} at ${h.count}: ${h.reason}`);
  }
  console.log(bar + "\n");
}
function cmdRecord() {
  const id = (process.argv[3] || "").toUpperCase(), reading = process.argv[4], reason = arg("reason", "");
  const g = loadGates(), gate = g.gates.find((x) => x.id === id);
  if (!gate) die(`no gate "${id}" (have: ${g.gates.map((x) => x.id).join(", ")})`);
  if (!["continuing", "met", "missed"].includes(reading)) die("the reading must be: continuing | met | missed");
  if (!reason) die("--reason is required. A gate is read in the OPEN or not at all — the written reason is the whole point.");
  const live = gateRows().find((x) => x.id === id);
  gate.history = gate.history || [];
  gate.history.push({ reading, count: live.n === null ? "untracked" : `${live.n}/${gate.threshold}`, reason });
  if (reading !== "continuing") { gate.status = "closed"; gate.result = reading.toUpperCase(); }
  writeJSON(GATES, g);
  renderDocs(false);
  console.log(`${id} recorded: ${reading.toUpperCase()} at ${gate.history.at(-1).count}`);
  console.log(`  reason recorded: "${reason}"`);
  console.log(`  campaign/GATES.md regenerated — commit it, so the reading is public.`);
}

// ── generated document blocks (lockstep: `render --check` fails CI if a doc drifts from the data) ─────────────────
function stepsTable() {
  const rows = STEPS.map((s) => `| **${s.n}** | **${s.title}** | ${s.do} | ${s.target} |`);
  return ["| Step | | What it is | Done looks like |", "|---|---|---|---|", ...rows].join("\n");
}
function gatesTable() {
  const g = loadGates();
  const rows = g.gates.map((x) => `| **${x.id}** | ${x.name} | ${x.threshold} — ${x.target} | ${x.source} |`);
  const hist = g.gates.flatMap((x) => (x.history || []).map((h) => `| ${x.id} | ${h.reading} | ${h.count} | ${h.reason} |`));
  return ["| Gate | What it tests | Bar | Where the count comes from |", "|---|---|---|---|", ...rows].join("\n") +
    "\n\n### Readings\n\n" + (hist.length
      ? ["| Gate | Reading | Count at the reading | Reason |", "|---|---|---|---|", ...hist].join("\n")
      : "_None yet. If this table stays empty it means the campaign has not reached a reading — not that one went unrecorded._");
}
const MARK = (name) => ({ begin: `<!-- ${name}:BEGIN — generated by tools/campaign.mjs render; do not edit by hand -->`, end: `<!-- ${name}:END -->` });
function spliceBlock(path, name, body) {
  const m = MARK(name), text = readFileSync(path, "utf8");
  const i = text.indexOf(m.begin), j = text.indexOf(m.end);
  if (i < 0 || j < 0) die(`${path} is missing its ${name} markers`);
  return text.slice(0, i) + m.begin + "\n\n" + body + "\n\n" + text.slice(j);
}
function renderDocs(check) {
  const targets = [[ROOT + "campaign/PLAN.md", "STEPS", stepsTable()], [ROOT + "campaign/GATES.md", "GATES", gatesTable()]];
  let drift = 0;
  for (const [path, name, body] of targets) {
    const next = spliceBlock(path, name, body);
    if (readFileSync(path, "utf8") === next) { console.log(`  ✓ ${path.replace(ROOT, "")} in lockstep with the data`); continue; }
    if (check) { console.error(`  ✗ ${path.replace(ROOT, "")} is stale — run \`node tools/campaign.mjs render\``); drift++; continue; }
    writeFileSync(path, next);
    console.log(`  ↻ ${path.replace(ROOT, "")} regenerated`);
  }
  if (drift) { console.error("\nCAMPAIGN RENDER FAILED: a generated block drifted from campaign/gates.json / the sequence."); process.exit(1); }
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

// ── status: the driver ───────────────────────────────────────────────────────────────────────────────────────────
function cmdStatus() {
  const t = loadTracker(), board = boardCounts(), w = witnessCandidacies();
  const stepNo = t?.step ?? 1;
  const step = STEPS.find((s) => s.n === stepNo);
  const people = (f) => (t ? t.people.filter((p) => !p.dropped).filter(f) : []);
  const n = (f) => (t ? people(f).length : null);
  const show = (v) => (v === null ? "—" : String(v));
  const submitted = intakeSubmitted();

  console.log(`\nAINRA CAMPAIGN   ${step ? `step ${stepNo} of ${STEPS.length}` : "the fourteen steps are spent — the K4 rhythm continues"}`);
  console.log(bar);

  if (step) {
    console.log(`  THIS STEP (${step.n})  ${step.title}`);
    console.log(`                 ${step.do}`);
    for (const c of step.cmds) console.log(`                 → ${c}`);
    console.log(`                 done looks like: ${step.target}`);
    if (t) console.log(`                 when it is: node tools/campaign.mjs step ${step.n + 1}`);
  } else {
    console.log(`  What remains is the K4 rhythm: keep the follow-up queue empty, custodian conversations to ≥5`);
    console.log(`  confirmed, and the soak — whose clock starts on genesis day, not before.`);
  }

  console.log(`\n  THE THREE ROWS   read-only — no command in this tool can move one of them`);
  console.log(`    external verifiers    ${show(board.verifiers)} / 3 confirmed   (${submitted ? `${submitted} submitted to evidence/verifier/, awaiting the private answer-key check` : "no attestations submitted yet"})`);
  console.log(`    recorded ceremony     ${board.ceremony}${t ? `   · custodians confirmed ${people((p) => p.kind === "custodian" && p.reply === "yes").length} / 9` : ""}`);
  console.log(`    14-day / 3-region soak  ${board.soakRegions ? `${board.soakRegions} region-run(s) collected` : "not started"} — the clock starts on genesis day`);
  console.log(`    witness candidacies   ${show(w)}   witnesses/candidates.json`);

  // The public surface is a row too. Everything above is read from registries and trackers; this is read from the
  // deployed site, because M27 established that the two can disagree for months without anything noticing. It
  // reports the last walk THIS machine did — never CI's, which it cannot see, and never a guess. No walk, no claim.
  {
    const last = readJSON(ROOT + "build/stranger-last.json", null);
    if (!last) console.log(`\n  PUBLIC SURFACE   never walked from this machine — \`make stranger\``);
    else {
      const mins = Math.round((Date.now() - Date.parse(last.checked_at)) / 60000);
      const when = mins < 60 ? `${mins} min ago` : mins < 2880 ? `${Math.round(mins / 60)} h ago` : `${Math.round(mins / 1440)} days ago`;
      const n = (last.site_failures?.length || 0) + (last.record_failures?.length || 0);
      console.log(`\n  PUBLIC SURFACE   checked ${when} → ${last.verdict}${n ? `   (${n} problem${n === 1 ? "" : "s"})` : ""}`);
      console.log(`    ${last.base}   ${last.journeys_run}/${last.journeys_total} journeys · daily in CI (.github/workflows/stranger.yml)`);
    }
  }

  console.log(`\n  GATES   bars, not deadlines`);
  for (const r of gateRows())
    console.log(`    ${r.id}  ${(r.n === null ? "—" : `${r.n}/${r.threshold}`).padEnd(7)} ${r.name.replace(/ —.*/, "").padEnd(34)} ${r.state}`);

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
    // M27: today's batch first. Starred-but-unsent is the only list that is about to become action, so it goes
    // above the follow-up queue rather than being re-derived by eye every morning.
    const starred = people((p) => p.starred && !p.sent && !p.dropped);
    if (starred.length) {
      console.log(`\n  STARRED · NOT YET SENT   today's batch`);
      for (const p of starred) {
        const has = existsSync(`${SENDBOX}/${p.kind}-${p.id}.txt`);
        console.log(`    ${p.id.padEnd(26)} ${p.kind.padEnd(10)} ${has ? "draft ready" : "no draft yet → node tools/campaign.mjs draft " + p.id}`);
      }
    }
    const due = people((p) => p.sent && !p.nudged && !p.reply);
    console.log(`\n  FOLLOW-UP QUEUE   one nudge each, one sentence, then stop`);
    if (!due.length) console.log(`    empty.`);
    for (const p of due) console.log(`    ${p.id.padEnd(26)} asked, no reply yet   → node tools/campaign.mjs nudge ${p.id}`);
    for (const p of people((p) => p.reply === "yes" && p.kind === "verifier"))
      console.log(`    ${p.id.padEnd(26)} SAID YES — send the challenge folder and stay on the line`);
  }

  const blocking = [];
  // Fail closed: a missing memo is not "decided", it is a missing memo — say so rather than silently dropping the row.
  const jurPath = ROOT + "campaign/JURISDICTION.md";
  if (!existsSync(jurPath)) blocking.push("campaign/JURISDICTION.md is missing — the legal-entity decision has nowhere to live");
  else if (/^- \*\*Decision:\*\* _undecided_/m.test(readFileSync(jurPath, "utf8")))
    blocking.push("legal entity undecided — campaign/JURISDICTION.md (step 4; every grant, the letter, and the custodian paperwork block on it)");
  if (t) {
    const iv = people((p) => p.kind === "interview" && p.sent).length;
    if (stepNo >= 5 && iv < 25) blocking.push(`interview asks out: ${iv}/30 — K1 needs most of them in flight before interviews can land`);
    const vf = people((p) => p.kind === "verifier" && p.sent).length;
    if (stepNo >= 9 && vf < 20) blocking.push(`verifier asks out: ${vf}/20 — K4 wants all twenty in flight by this point`);
  }
  if (blocking.length) { console.log(`\n  BLOCKING`); for (const b of blocking) console.log(`    ✗ ${b}`); }

  console.log(`\n${bar}`);
  console.log(`  the counts above come from: the genesis board, evidence/verifier/, witnesses/candidates.json,`);
  console.log(`  and your local tracker. Nothing on this line was asserted by hand.\n`);
}


// ── L5: proposed → approved is a HUMAN act, and it gates everything downstream ───────────────────────────────
// Research proposes; a person disposes. A candidate arrives as `proposed` and nothing may be drafted, starred or
// sent for them until the maintainer has looked at the evidence URL and said yes. This is not ceremony: the whole
// risk of researching real people is that a confident machine writes a plausible sentence about someone who never
// said it, and the only reliable check is a human opening the link. So the gate is on the tool, not in a doc.
function cmdApprove() {
  const t = requireTracker(), id = process.argv[3];
  if (!id) die("which candidate? pass the id — or `approve --all-verifier` etc. is deliberately NOT offered:\n" +
               "  approving in bulk is the same as not approving.");
  const p = findPerson(t, id);
  if (!p.evidence) die(`"${id}" has no evidence URL — it predates the citation rule. Re-add it with --evidence.`);
  p.status = "approved";
  writeJSON(TRACKER, t);
  console.log(`approved ${p.kind}: ${id}\n  evidence: ${p.evidence}`);
}

// Everything that acts on a person refuses while they are merely proposed.
function requireApproved(p, verb) {
  if (p.status && p.status !== "approved")
    die(`"${p.id}" is ${p.status}, not approved — nothing happens to a candidate before a human approves them.\n` +
        `  open the evidence first:  ${p.evidence || "(none recorded)"}\n` +
        `  then:                     node tools/campaign.mjs approve ${p.id}\n` +
        `  refusing to ${verb}.`);
}

// ── dispatch ─────────────────────────────────────────────────────────────────────────────────────────────────────
const cmd = process.argv[2] || "status";
({
  status: cmdStatus, init: cmdInit, step: cmdStep, add: cmdAdd, send: cmdSend, nudge: cmdNudge, reply: cmdReply,
  star: cmdStar, draft: cmdDraft, approve: cmdApprove,
  interview: cmdInterview, drop: cmdDrop, gates: cmdGates, record: cmdRecord, check: cmdCheck,
  render: () => renderDocs(has("check")),
}[cmd] || (() => die(`unknown command "${cmd}". Try: status | init | step | add | approve | draft | star | send | nudge | reply | interview | drop | gates | record | render | check`)))();
