// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The owner's morning page: what is due today, what unlocks this week, and whether everything is still green —
// written to ~/Desktop/ainra-today.md (never into the repository: it names people, D-036). Run by a systemd user
// timer (tools/install-daily-digest.sh) or by hand:  node tools/daily-digest.mjs
//
// It READS only. It sends nothing to anyone, changes no state, and every section says what it could not check
// rather than going quiet about it.
import { readFileSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const OUT = process.env.AINRA_DIGEST_OUT ?? join(homedir(), "Desktop", "ainra-today.md");
const d = new Date();
const today = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
const inDays = (n) => { const x = new Date(d); x.setDate(x.getDate() + n); return x.toISOString().slice(0, 10); };
const sh = (cmd, args, opts = {}) => { try { return execFileSync(cmd, args, { cwd: ROOT, encoding: "utf8", timeout: 20000, stdio: ["ignore", "pipe", "ignore"], ...opts }).trim(); } catch { return null; } };
const lines = [`# AINRA — ${today}`, "", `_Written ${d.toLocaleTimeString()} by tools/daily-digest.mjs. It reads only; nothing was sent._`, ""];

// ── 1 · the send queue (the page's own data, minus what the tracker already records) ────────────────────────────
const page = join(ROOT, "outreach/ready/automation/COMPOSE.html");
let Q = null;
if (existsSync(page)) {
  const m = readFileSync(page, "utf8").match(/^const Q = (.*);$/m);
  try { Q = m ? JSON.parse(m[1]) : null; } catch { Q = null; }
}
if (!Q) lines.push("## Emails", "", "Could not read the send page — run `python3 outreach/ready/automation/build.py`.", "");
else {
  const due = Q.filter((x) => x.not_before <= today);
  const soon = Q.filter((x) => x.not_before > today && x.not_before <= inDays(7));
  const how = { reply: "reply in thread", email: "new email", form: "contact form", link: "message or booking", slack: "Slack DM" };
  lines.push(`## Emails — ${due.length} ready, ${soon.length} unlock this week`, "");
  lines.push("Open **http://127.0.0.1:7777** (the AINRA desk — it saves every click to the tracker and paces you). Best window: Tue–Thu, 9–11 their time.", "");
  if (due.length) { lines.push("**Ready now**", ""); for (const x of due) lines.push(`- ${x.who} (${x.org}) — ${how[x.channel] ?? x.channel}`); lines.push(""); }
  if (soon.length) { lines.push("**Unlocking this week**", ""); for (const x of soon) lines.push(`- ${x.not_before} · ${x.who} — ${how[x.channel] ?? x.channel}`); lines.push(""); }
}
const logs = existsSync(join(homedir(), "Downloads")) ? readdirSync(join(homedir(), "Downloads")).filter((f) => /^ainra-sent-log.*\.json$/.test(f)) : [];
if (logs.length) lines.push(`**${logs.length} sent-log(s) in Downloads not applied yet** — run \`python3 outreach/ready/automation/build.py\`.`, "");

// ── 2 · is everything still green? ──────────────────────────────────────────────────────────────────────────────
lines.push("## Health", "");
const ci = sh("gh", ["run", "list", "--branch", "main", "--limit", "8", "--json", "headSha,name,status,conclusion"]);
if (ci === null) lines.push("- CI: could not ask GitHub (gh not signed in, or offline)");
else {
  const runs = JSON.parse(ci);
  const head = runs[0]?.headSha;
  const mine = runs.filter((r) => r.headSha === head);
  const bad = mine.filter((r) => r.status === "completed" && !["success", "skipped"].includes(r.conclusion));
  const running = mine.filter((r) => r.status !== "completed");
  lines.push(`- CI on main (${String(head).slice(0, 7)}): ${bad.length ? "**RED — " + bad.map((r) => `${r.name} ${r.conclusion}`).join(", ") + "**" : running.length ? "running" : "green"}`);
}
const unpushed = sh("git", ["rev-list", "--count", "origin/main..HEAD"]);
lines.push(`- Unpushed commits: ${unpushed ?? "could not tell"}`);
const live = sh("bash", ["tools/live.sh", "status"]);
lines.push(`- Live network (wall clock, :4970): ${live ? live.split("\n").slice(-1)[0].trim() : "DOWN — `make live-up` to start it"}`);
const stage = sh("systemctl", ["--user", "is-active", "ainra-stage.target"]);
lines.push(`- Staging network (pinned): ${stage ?? "not running"}`);
lines.push("");

writeFileSync(OUT, lines.join("\n") + "\n");
console.log(`wrote ${OUT}`);
