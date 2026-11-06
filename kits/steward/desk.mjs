#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The steward's desk (PLAN-M53 step 2, D-099): one local screen for everything the steward watches, and the
// emergency playbooks drafted in one action. It holds NO key and publishes nothing: AINRA has no admin button and must
// not have one (D-034). A playbook writes drafts into this desk's own folder and runs read-only checks; the last step
// of every playbook is a command a registrar or the custodians run themselves.
//
//   node kits/steward/desk.mjs --net <dir|url> --roots <pinned roots.json> --home <dir> [--site <dir|url>] [--port 4979]
//
//   --net    the published read contract (…/net) · --roots the roots the steward pins · --home this desk's own folder
//            (ctl memory, drafts/, ladders/, requests/) · --site where incidents.json is served (default: --net/..)
//
// It binds 127.0.0.1 only and answers only requests whose Host is that address (a page elsewhere cannot reach it by
// DNS rebinding); a playbook also needs a same-origin request. The screen is read from:
//   · `ainra ctl status` (the control room, with this desk's memory)          · the epoch log and its cosignatures (D-097)
//   · the incident log, with each entry's deadline from the runbook (D-095)     · compliance ladders in home/ladders (D-096)
//   · change requests in home/requests, each checked now and aged against D-094's 90 days · the latest monthly report
//
// Playbooks: delegate-compromised · log-forked (builds the D-098 fork proof and checks the emergency request) ·
// share-lost · site-defaced. WITNESS: tools/desk-drill.mjs.
import { createServer } from "node:http";
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from "node:fs";
import { join, dirname, resolve, basename } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const argv = process.argv.slice(2), A = (k, d = null) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : d; };
const NET = A("net"), ROOTS = A("roots"), HOME = A("home"), PORT = Number(A("port", "4979")), HOST = A("host", "127.0.0.1");
const SITE = A("site", NET && !/^https?:/.test(NET) ? resolve(NET, "..") : NET?.replace(/\/net\/?$/, ""));
const BIN = process.env.AINRA_BIN || join(ROOT, "target/release/ainra");
if (!NET || !ROOTS || !HOME) { console.error("usage: desk.mjs --net <dir|url> --roots <pinned roots.json> --home <dir> [--site <dir|url>] [--port 4979]"); process.exit(2); }
if (HOST !== "127.0.0.1") { console.error(`desk: refusing to bind ${HOST} — the desk is for the steward's own machine (loopback only)`); process.exit(2); }
for (const d of ["drafts", "ladders", "requests"]) mkdirSync(join(HOME, d), { recursive: true });

const DAY = 86400, now = () => Math.floor(Date.now() / 1000), iso = () => new Date().toISOString().replace(/[:.]/g, "-");
const read = async (base, path) => /^https?:/.test(base) ? (await fetch(`${base.replace(/\/$/, "")}/${path}`)).text() : readFileSync(join(base, path), "utf8");
const json = async (base, path) => { try { return JSON.parse(await read(base, path)); } catch { return null; } };
const ainra = (...args) => { const r = spawnSync(BIN, args, { encoding: "utf8", timeout: 120000 }); return { code: r.status, out: (r.stdout || "") + (r.stderr || "") }; };

// ── the screen ───────────────────────────────────────────────────────────────────────────────────────────────────
async function state() {
  const ctl = ainra("ctl", "status", "--net", NET, "--roots", ROOTS, "--state", join(HOME, "ctl-seen.json"));
  const lines = ctl.out.split("\n").filter((l) => /^\s+(ok|·|warn|ALARM)\s/.test(l)).map((l) => ({ kind: l.trim().split(/\s+/)[0], text: l.trim().replace(/^(ok|·|warn|ALARM)\s+/, "") }));
  const head = await json(NET, "epoch-log.json"), cos = await json(NET, "epoch-log-cosignatures.json");
  const inc = await json(SITE, "incidents.json");
  let deadlines = null; try { const { parsePolicy } = await import(join(ROOT, "tools/incident-check.mjs")); deadlines = parsePolicy(readFileSync(join(ROOT, "deploy/runbooks/root-incident.md"), "utf8")); } catch { /* the desk still shows the log */ }
  const incidents = (inc?.entries || []).map((e) => { const age = Math.floor((now() - Date.parse(`${e.opened}T00:00:00Z`) / 1000) / DAY), d = deadlines?.[e.class];
    return { id: e.id, class: e.class, title: e.title, open: e.fixed === null, age, fix_deadline_days: d?.fix ?? null, late: e.fixed === null && d && age > d.fix }; });
  const ladders = readdirSync(join(HOME, "ladders")).filter((f) => f.endsWith(".json") && !/-notice-\d+\.json$/.test(f)).map((f) => { try { const l = JSON.parse(readFileSync(join(HOME, "ladders", f), "utf8")); return { registrar: l.registrar, stage: l.stage, notices: l.notices.length, cure_window_ends: l.cure_window_ends }; } catch { return { file: f, error: "unreadable" }; } });
  try { writeFileSync(join(HOME, "current-directory.json"), await read(NET, "directory.json")); } catch { /* the requests panel then says why */ }
  const requests = readdirSync(join(HOME, "requests")).filter((f) => f.endsWith(".json")).map((f) => {
    const p = join(HOME, "requests", f); let r = {}; try { r = JSON.parse(readFileSync(p, "utf8")); } catch { /* shown as unreadable */ }
    const chk = ainra("directory", "check-request", p, "--directory", join(HOME, "current-directory.json"), "--roots", ROOTS);
    const age = r.filed_at ? Math.floor((now() - r.filed_at) / DAY) : null;
    return { file: f, type: r.type ?? r.change_type, registrar: r.registrar, filer: r.filer, age_days: age, overdue: age !== null && age > 90, check: chk.code === 0 ? "passes" : (chk.out.match(/REFUSED[^\n]*/) || [chk.out.trim().split("\n").pop()])[0] };
  });
  let report = null; try { const dir = join(ROOT, "reports/monthly"); const f = readdirSync(dir).filter((x) => x.endsWith(".md")).sort().pop(); report = { file: `reports/monthly/${f}`, first: (readFileSync(join(dir, f), "utf8").split("\n").find((l) => l.startsWith("**Age")) || "").replace(/\*\*/g, "") }; } catch { /* none yet */ }
  return { at: new Date().toISOString(), net: NET, ctl: { exit: ctl.code, lines }, epoch_log: head ? { size: head.size, root: head.root, cosignatures: (cos?.cosignatures || []).length } : null,
    incidents, ladders, requests, report };
}

// ── the playbooks: drafts only, into home/drafts/<time>-<name>/ ──────────────────────────────────────────────────
const incidentDraft = (cls, surface, title) => ({ id: "INC-YYYY-NNN", class: cls, surface, title, opened: new Date().toISOString().slice(0, 10), disclosed: null, fixed: null, released: null, record: null,
  _note: "add to site/incidents.json within the class's entry deadline (HIGH: 3 days) with disclosed set to the day it is published; make incident-check" });
const PLAYBOOKS = {
  "delegate-compromised": async (b, out) => {
    const reg = String(b.registrar || "").replace(/[^a-z0-9-]/g, "");
    if (!reg) throw new Error("registrar is required");
    return { incident: incidentDraft("HIGH", `registrar ${reg}: online delegate key`, `${reg}: a delegate key is suspected compromised`),
      commands: [`# the registrar runs these; the desk cannot (it holds no key)`,
        `ainra directory request REVOKE_DELEGATE --registrar <${reg} home> --cert <the delegate's certificate.json> --filed-at ${now()} --out revoke-delegate.json`,
        `ainra directory check-request revoke-delegate.json --directory <current directory.json> --roots <pinned roots>`],
      checklist: ["The registrar rotates its write token and issues a new delegate certificate from its log root.", "The request goes on the next ceremony agenda as an emergency: it only closes things, so it skips the notice wait (R3), never the publication.",
        "Watch ctl until the epoch carrying the revocation is published.", "Publish the incident entry within 3 days."] };
  },
  "log-forked": async (b, out) => {
    const reg = String(b.registrar || "").replace(/[^a-z0-9-]/g, ""), leaf = Number(b.leaf);
    if (!reg || !Number.isInteger(leaf) || leaf < 0) throw new Error("registrar and a whole-number leaf are required");
    const cp = (x) => { const r = typeof x === "string" ? JSON.parse(x) : x; if (r.checkpoint && r.checkpoint_sig) return { checkpoint: r.checkpoint, checkpoint_sig: r.checkpoint_sig };
      if (r.log_origin && r.checkpoint_sig) return { checkpoint: { origin: r.log_origin, size: r.checkpoint_size, root: r.checkpoint_root }, checkpoint_sig: r.checkpoint_sig };
      throw new Error("each side must be a presentation record or a {checkpoint, checkpoint_sig}"); };
    const ev = { compliance: { fork_proof: { a: cp(b.a), b: cp(b.b) } } };
    writeFileSync(join(out, "evidence.json"), JSON.stringify(ev, null, 2) + "\n");
    writeFileSync(join(out, "current-directory.json"), await read(NET, "directory.json"));
    const req = ainra("directory", "request", "DISTRUST_FROM_LEAF", "--subject", reg, "--filer", "steward", "--leaf", String(leaf), "--filed-at", String(now()), "--evidence", join(out, "evidence.json"), "--out", join(out, "request.json"));
    if (req.code !== 0) throw new Error(`the request could not be written: ${req.out.trim()}`);
    const chk = ainra("directory", "check-request", join(out, "request.json"), "--directory", join(out, "current-directory.json"), "--roots", ROOTS);
    return { incident: incidentDraft("HIGH", `registrar ${reg}: its log`, `${reg}: two signed checkpoints of its log at one size with different roots`),
      check: { passes: chk.code === 0, output: chk.out.trim() },
      commands: chk.code === 0 ? ["ainra directory propose … (put request.json on an emergency epoch; R3: no notice wait, never unpublished)", "the custodians fetch and sign it as in every ceremony; the remote emergency protocol is PLAN-M53 step 4"] : ["fix the evidence: the checker's reason is above"],
      checklist: ["Copy the two checkpoints and where each was served from into the incident record.", "Tell holders of the registrar's passports that they can move (the transfer door, PLAN-M53 step 7).", "Publish the incident entry within 3 days."] };
  },
  "share-lost": async (b) => ({ incident: incidentDraft(b.stolen ? "HIGH" : "MEDIUM", "root custody: one FROST share", b.stolen ? "a custodian's share may be stolen" : "a custodian's share is lost"),
    commands: ["# one share signs nothing alone; five or more custodians run a share refresh that leaves it out (ThresholdRoot::refresh, D-094 item 9)"],
    checklist: ["Confirm the other custodians' shares are intact.", "Schedule the refresh within the class's fix deadline (HIGH 14 days, MEDIUM 30).", "Bring in a standby custodian.", "Publish the incident entry."] }),
  "site-defaced": async () => ({ incident: incidentDraft("HIGH", "the public site", "the site or a static host serves altered content"),
    commands: ["ainra ctl status --net <the second host>/net --roots <pinned roots>   # from a signed release, not from the site", "ainra ctl status --net https://ainra.org/net --roots <pinned roots>"],
    checklist: ["A root is never announced by message: say so on every other channel.", "Compare root fingerprints out of band.", "Restore the site from the repository export; byte-verify every mirror.", "Publish the incident entry within 3 days."] }),
};

// ── the page ─────────────────────────────────────────────────────────────────────────────────────────────────────
const PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Steward's desk</title>
<style>:root{--bg:#F4F4F1;--card:#fff;--ink:#0B1220;--soft:#4A5260;--line:#D8DAD4;--red:#A83A2C;--green:#1A6B4E;--amber:#8A6100}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.45 system-ui,sans-serif}
header{padding:20px 24px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap}h1{margin:0;font-size:20px;font-weight:600}header p{margin:4px 0 0;color:var(--soft)}
main{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:14px;padding:16px 24px}section{background:var(--card);border:1px solid var(--line);padding:16px}h2{margin:0 0 10px;font-size:15px;text-transform:uppercase;letter-spacing:.06em}
li{margin:3px 0}.ALARM,.late,.bad{color:var(--red);font-weight:600}.warn{color:var(--amber)}.ok,.good{color:var(--green)}code,pre{font:12px/1.4 ui-monospace,monospace;white-space:pre-wrap;word-break:break-word}
form{display:grid;gap:6px;margin:8px 0 14px}input,textarea,select{font:inherit;padding:6px;border:1px solid var(--line)}textarea{min-height:60px}button{font:inherit;padding:8px 12px;border:1px solid var(--ink);background:var(--ink);color:#fff;cursor:pointer}</style></head>
<body><header><div><h1>Steward's desk</h1><p>Reads everything; drafts every emergency; holds no key and publishes nothing.</p></div><p id="at"></p></header><main id="m"><section>Loading…</section></main>
<script>
const esc=(s)=>String(s??"").replace(/[&<>"]/g,(c)=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const sec=(h,body)=>'<section><h2>'+h+'</h2>'+body+'</section>';
async function load(){const s=await (await fetch('/api/state')).json();document.getElementById('at').textContent='read '+s.at+' · '+s.net;
let h=sec('Control room · ctl exit '+s.ctl.exit,'<ul>'+s.ctl.lines.map(l=>'<li class="'+esc(l.kind)+'">'+(l.kind==='·'?'':esc(l.kind)+' · ')+esc(l.text)+'</li>').join('')+'</ul>');
h+=sec('Epoch log',s.epoch_log?'size '+esc(s.epoch_log.size)+' · root <code>'+esc(String(s.epoch_log.root).slice(0,16))+'…</code> · '+esc(s.epoch_log.cosignatures)+' cosignature(s)':'none served');
h+=sec('Incidents','<ul>'+s.incidents.map(i=>'<li class="'+(i.late?'late':i.open?'warn':'')+'">'+esc(i.id)+' '+esc(i.class)+(i.open?' · OPEN, day '+i.age+' of '+i.fix_deadline_days:' · fixed')+' — '+esc(i.title)+'</li>').join('')+'</ul>');
h+=sec('Compliance ladders',s.ladders.length?'<ul>'+s.ladders.map(l=>'<li>'+esc(l.registrar)+' · '+esc(l.stage)+' · '+esc(l.notices)+' notice(s)</li>').join('')+'</ul>':'none open');
h+=sec('Requests',s.requests.length?'<ul>'+s.requests.map(r=>'<li class="'+(r.overdue?'late':'')+'">'+esc(r.type)+' '+esc(r.registrar)+' by '+esc(r.filer)+' · day '+esc(r.age_days)+' of 90 · '+esc(r.check)+'</li>').join('')+'</ul>':'none filed');
h+=sec('Monthly report',s.report?esc(s.report.file)+'<br>'+esc(s.report.first):'none');
h+=sec('Emergency playbooks','<p>Each writes drafts into this desk\\'s folder and runs read-only checks. The last step is always a command someone with a key runs.</p>'+
'<form data-p="log-forked"><b>A registrar\\'s log forked</b><input name="registrar" placeholder="registrar-11" required><input name="leaf" placeholder="cutoff leaf (at or below the fork size)" required><textarea name="a" placeholder="checkpoint A: a presentation record, or {checkpoint, checkpoint_sig}" required></textarea><textarea name="b" placeholder="checkpoint B" required></textarea><button>Draft the emergency stop</button></form>'+
'<form data-p="delegate-compromised"><b>A registrar delegate compromised</b><input name="registrar" placeholder="registrar-07" required><button>Draft</button></form>'+
'<form data-p="share-lost"><b>A root share lost</b><label><input type="checkbox" name="stolen"> may be stolen, not only lost</label><button>Draft</button></form>'+
'<form data-p="site-defaced"><b>The site defaced</b><button>Draft</button></form><pre id="out"></pre>');
document.getElementById('m').innerHTML=h;
document.querySelectorAll('form[data-p]').forEach(f=>f.onsubmit=async(e)=>{e.preventDefault();const b=Object.fromEntries(new FormData(f));if(f.stolen)b.stolen=f.stolen.checked;
const r=await fetch('/api/playbook/'+f.dataset.p,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});document.getElementById('out').textContent=JSON.stringify(await r.json(),null,2);});}
load();setInterval(load,60000);</script></body></html>`;

// ── the server ───────────────────────────────────────────────────────────────────────────────────────────────────
const send = (res, code, body, type = "application/json") => { res.writeHead(code, { "content-type": type, "cache-control": "no-store", "x-content-type-options": "nosniff", "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'" }); res.end(typeof body === "string" ? body : JSON.stringify(body, null, 2)); };
const server = createServer(async (req, res) => {
  const self = `127.0.0.1:${server.address().port}`;
  if (req.headers.host !== self) return send(res, 421, { error: `this desk answers only Host ${self}` });
  const url = new URL(req.url, `http://${self}`);
  try {
    if (req.method === "GET" && url.pathname === "/") return send(res, 200, PAGE, "text/html; charset=utf-8");
    if (req.method === "GET" && url.pathname === "/api/state") return send(res, 200, await state());
    const m = url.pathname.match(/^\/api\/playbook\/([a-z-]+)$/);
    if (req.method === "POST" && m && PLAYBOOKS[m[1]]) {
      if (req.headers.origin && req.headers.origin !== `http://${self}`) return send(res, 403, { error: "a playbook runs only from this desk's own page" });
      if (!/^application\/json/.test(req.headers["content-type"] || "")) return send(res, 415, { error: "JSON only" });
      let body = ""; for await (const c of req) { body += c; if (body.length > 65536) return send(res, 413, { error: "too large" }); }
      const out = join(HOME, "drafts", `${iso()}-${m[1]}`); mkdirSync(out, { recursive: true });
      const r = await PLAYBOOKS[m[1]](JSON.parse(body || "{}"), out);
      writeFileSync(join(out, "incident-draft.json"), JSON.stringify(r.incident, null, 2) + "\n");
      writeFileSync(join(out, "playbook.json"), JSON.stringify(r, null, 2) + "\n");
      return send(res, 200, { playbook: m[1], drafts: out, ...r });
    }
    return send(res, 404, { error: "no such route" });
  } catch (e) { return send(res, 400, { error: e.message }); }
});
server.listen(PORT, HOST, () => console.log(`steward's desk: http://127.0.0.1:${server.address().port}/  (loopback only; drafts in ${join(HOME, "drafts")})`));
