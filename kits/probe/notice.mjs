// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The compliance ladder (PLAN-M52 step 11, D-096): probe reports in, fact notices out, one ladder per registrar.
//
// A registrar that fails its accreditation invariants is not distrusted on one bad reading. The ladder, at the
// numbers the owner accepted in D-094 item 11:
//
//   notice 1    a failure CONFIRMED in one cycle — the same check failing from at least two vantage points on
//               distinct networks. It starts the cure window: at least 30 days.
//   notice 2    the failure confirmed again, at least 14 days after notice 1.
//   notice 3    the public breach record: the failure confirmed again after the cure window has closed. From here a
//               DISTRUST_FROM_LEAF request may be drafted (D-044); its evidence is this ladder.
//   WITHDRAW    at least 90 days after the breach record, so holders can move to another registrar first.
//   cured       a cycle in which two vantage points on distinct networks read COMPLIANT closes the ladder.
//
// A failure seen from one vantage point, or from two on one network, is a reading, not a fact: it produces no
// notice. The ladder never shortens a window, and it writes evidence in exactly the shape `ainra directory
// check-request` reads (`evidence.compliance`), which refuses the same early or thin records on its own (the
// workbench checks adverse-notice-chain, adverse-vantage and adverse-grace).
//
//   node kits/probe/notice.mjs step --state <ladder.json> --now <unix> --registrar <id> <probe-report.json …>
//        reads this cycle's reports, advances the ladder by at most one rung, writes it back, prints what it did
//   node kits/probe/notice.mjs evidence --state <ladder.json> --for DISTRUST_FROM_LEAF|WITHDRAW --now <unix> --out <f>
//        writes the evidence a request carries — or refuses, by name, while the ladder does not yet allow it
//   node kits/probe/notice.mjs --drill
//
// WITNESS (--drill): a registrar that degrades is noticed in the first cycle both vantage points see it; a failure
// from one vantage point, or from two on one network, produces no notice; notice 2 is refused before 14 days; the
// breach record is refused before the cure window closes; DISTRUST evidence is refused before the breach record and
// WITHDRAW evidence before 90 days after it; a cycle read COMPLIANT from two networks cures the ladder; and the
// evidence the full ladder writes has the numbers the workbench requires. Remove any of those conditions and the
// drill names it.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";

export const DAY = 86_400, CURE = 30 * DAY, GAP = 14 * DAY, GRACE = 90 * DAY;
const sha = (b) => createHash("sha256").update(b).digest("hex");
const canon = (o) => JSON.stringify(o, Object.keys(o).sort());

/** what one cycle's reports say about one registrar: confirmed failure, confirmed pass, or only readings */
export function reading(reports) {
  const failed = new Map(), passed = [];
  for (const { report: r, sha256 } of reports) {
    if (!r.vantage || !r.vantage.id || !r.vantage.network || r.vantage.network === "unstated") continue; // no place, no weight
    const at = Math.floor(Date.parse(r.ran_at) / 1000);
    if (r.verdict === "COMPLIANT") passed.push({ ...r.vantage, at, sha256 });
    else if (r.verdict === "NON-COMPLIANT") for (const c of r.checks.filter((c) => c.pass === false))
      (failed.get(c.id) || failed.set(c.id, []).get(c.id)).push({ ...r.vantage, at, sha256 });
  }
  const spread = (xs) => new Set(xs.map((x) => x.id)).size >= 2 && new Set(xs.map((x) => x.network)).size >= 2;
  const confirmed = [...failed].filter(([, xs]) => spread(xs));
  if (confirmed.length) {
    const reps = new Map(); for (const [, xs] of confirmed) for (const x of xs) reps.set(x.sha256, x);
    return { kind: "failure", checks: confirmed.map(([id]) => id).sort(), reproductions: [...reps.values()].sort((a, b) => a.at - b.at) };
  }
  if (failed.size) return { kind: "reading", checks: [...failed.keys()].sort(), why: "seen from one vantage point or one network only — a reading, not a fact; no notice" };
  if (spread(passed)) return { kind: "pass" };
  return { kind: "none", why: "fewer than two vantage points on distinct networks reported" };
}

const notice = (state, n, now, rd, extra = {}) => {
  const body = { kind: "ainra/compliance-notice/v1", registrar: state.registrar, n, at: now, failing_checks: rd.checks,
    reports: rd.reproductions.map((x) => ({ vantage: x.id, network: x.network, at: x.at, report_sha256: x.sha256 })), ...extra };
  return { n, at: now, sha256: sha(canon(body)), body };
};

/** step(state, reports, now) → { state, did } — advances the ladder by at most one rung */
export function step(state, reports, now) {
  const s = JSON.parse(JSON.stringify(state)), rd = reading(reports), N = s.notices.length;
  if (s.stage === "cured") return { state: s, did: "the ladder is closed (cured); a new failure starts a new ladder file" };
  if (rd.kind === "pass" && N && N < 3) { s.stage = "cured"; s.cured_at = now; return { state: s, did: `cured: read COMPLIANT from two networks at ${now}` }; }
  if (rd.kind !== "failure") return { state: s, did: rd.why || "nothing confirmed this cycle" };
  if (N === 0) { const x = notice(s, 1, now, rd, { cure_window_ends: now + CURE }); s.notices.push(x); s.cure_window_ends = now + CURE; s.stage = "notice-1";
    return { state: s, did: `notice 1 (failing: ${rd.checks.join(", ")}); the cure window runs to ${now + CURE}` }; }
  if (N === 1) { if (now - s.notices[0].at < GAP) return { state: s, did: `refused: notice 2 is at least 14 days after notice 1 (${Math.floor((now - s.notices[0].at) / DAY)} day(s) so far)` };
    s.notices.push(notice(s, 2, now, rd)); s.stage = "notice-2"; return { state: s, did: "notice 2" }; }
  if (N === 2) { if (now <= s.cure_window_ends) return { state: s, did: `refused: the breach record comes only after the cure window closes at ${s.cure_window_ends}` };
    if (now - s.notices[1].at < GAP) return { state: s, did: "refused: notice 3 is at least 14 days after notice 2" };
    const after = rd.reproductions.filter((x) => x.at > s.cure_window_ends);
    if (new Set(after.map((x) => x.id)).size < 2 || new Set(after.map((x) => x.network)).size < 2) return { state: s, did: "refused: the breach record needs reproductions after the cure window from two networks" };
    s.notices.push(notice(s, 3, now, { ...rd, reproductions: after }, { breach_record: true })); s.reproductions = after; s.stage = "breach";
    return { state: s, did: "notice 3: the public breach record — a DISTRUST_FROM_LEAF request may now be drafted" }; }
  return { state: s, did: "the ladder is at the breach record; later cycles add nothing to it" };
}

/** evidence(state, type, now) → the `evidence` object a request carries, or throws a refusal by name */
export function evidence(state, type, now) {
  const breach = state.notices.find((n) => n.n === 3);
  if (!breach) throw new Error(`refused: ${type} evidence comes only after the public breach record (notice 3); the ladder is at ${state.stage}`);
  if (type === "WITHDRAW" && now < breach.at + GRACE) throw new Error(`refused: WITHDRAW comes at least 90 days after the breach record (${Math.floor((now - breach.at) / DAY)} day(s) so far)`);
  if (type !== "DISTRUST_FROM_LEAF" && type !== "WITHDRAW") throw new Error(`refused: ${type} is not an adverse request`);
  return { compliance: { notices: state.notices.map(({ n, at, sha256 }) => ({ n, at, sha256 })), cure_window_ends: state.cure_window_ends,
    reproductions: state.reproductions.map((x) => ({ vantage: x.id, network: x.network, at: x.at, report_sha256: x.sha256 })) } };
}

export const fresh = (registrar) => ({ kind: "ainra/compliance-ladder/v1", registrar, stage: "watching", notices: [], cure_window_ends: null, reproductions: [] });

// ── the drill ────────────────────────────────────────────────────────────────────────────────────────────────────
function drill() {
  let bad = 0; const ok = (c, m) => { if (c) console.log(`  ok    ${m}`); else { console.error(`  ✗ ${m}`); bad++; } };
  const T0 = 1_800_000_000;
  const rep = (id, network, at, fail) => { const report = { kind: "ainra/compliance-probe/v1", registrar_id: "registrar-11", vantage: { id, network },
    ran_at: new Date(at * 1000).toISOString(), verdict: fail ? "NON-COMPLIANT" : "COMPLIANT", checks: [{ id: "P3", pass: !fail }, { id: "P5", pass: true }] };
    return { report, sha256: sha(JSON.stringify(report)) }; };
  const both = (at, fail = true) => [rep("vp-a", "net-1", at, fail), rep("vp-b", "net-2", at + 60, fail)];
  let L = fresh("registrar-11"), r;
  r = step(L, [rep("vp-a", "net-1", T0, true), rep("vp-b", "net-2", T0, false)], T0); ok(r.state.notices.length === 0, `a failure from one vantage point → no notice ("${r.did.slice(0, 60)}…")`);
  r = step(L, [rep("vp-a", "net-1", T0, true), rep("vp-b", "net-1", T0, true)], T0); ok(r.state.notices.length === 0, "two vantage points on ONE network → no notice");
  r = step(L, both(T0), T0); L = r.state; ok(L.notices.length === 1 && L.cure_window_ends === T0 + CURE, "a degraded registrar seen from two networks → notice 1 in that same cycle; cure window 30 days");
  let t = T0 + 10 * DAY; r = step(L, both(t), t); ok(r.state.notices.length === 1 && /refused/.test(r.did), "notice 2 at 10 days is refused (14 days apart)");
  t = T0 + 15 * DAY; r = step(L, both(t), t); L = r.state; ok(L.notices.length === 2, "notice 2 at 15 days");
  try { evidence(L, "DISTRUST_FROM_LEAF", t); ok(false, "DISTRUST evidence before the breach record was written"); } catch (e) { ok(/refused/.test(e.message), "DISTRUST evidence before the breach record is refused"); }
  t = T0 + 29 * DAY; r = step(L, both(t), t); ok(r.state.notices.length === 2 && /cure window/.test(r.did), "the breach record inside the cure window is refused");
  t = T0 + 31 * DAY; r = step(L, both(t), t); L = r.state; ok(L.notices.length === 3 && L.stage === "breach", "after the cure window, confirmed again → notice 3, the breach record");
  const ev = evidence(L, "DISTRUST_FROM_LEAF", t + DAY).compliance;
  const gaps = ev.notices.slice(1).every((n, i) => n.at - ev.notices[i].at >= GAP);
  const reps = ev.reproductions.filter((x) => x.at > ev.cure_window_ends);
  ok(ev.notices.length >= 2 && gaps && ev.cure_window_ends - ev.notices[0].at >= CURE && new Set(reps.map((x) => x.network)).size >= 2,
    "the DISTRUST evidence has the workbench's numbers: ≥ 2 notices 14 days apart, a 30-day cure, reproductions from two networks after it");
  try { evidence(L, "WITHDRAW", t + 60 * DAY); ok(false, "WITHDRAW evidence at 60 days was written"); } catch (e) { ok(/90 days/.test(e.message), "WITHDRAW evidence 60 days after the breach record is refused"); }
  ok(!!evidence(L, "WITHDRAW", t + 91 * DAY), "WITHDRAW evidence 91 days after the breach record is written");
  let C = step(fresh("registrar-11"), both(T0), T0).state; C = step(C, both(T0 + 20 * DAY, false), T0 + 20 * DAY).state;
  ok(C.stage === "cured", "a cycle read COMPLIANT from two networks cures the ladder");
  if (bad) { console.error("NOTICE-LADDER DRILL FAILED"); process.exit(1); }
  console.log("NOTICE-LADDER DRILL OK — one vantage point never notices; each rung waits for its days; the evidence carries the workbench's numbers");
}

// ── the command line ─────────────────────────────────────────────────────────────────────────────────────────────
const argv = process.argv.slice(2), A = (n) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : null; };
if (process.argv[1] && process.argv[1].endsWith("notice.mjs")) {
  if (argv.includes("--drill")) drill();
  else if (argv[0] === "step") {
    const file = A("state"), now = Number(A("now")), reg = A("registrar");
    if (!file || !now || !reg) { console.error("usage: notice.mjs step --state <ladder.json> --now <unix> --registrar <id> <probe-report.json …>"); process.exit(2); }
    const state = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : fresh(reg);
    const flags = new Set(["--state", "--now", "--registrar"]);
    const files = argv.slice(1).filter((x, i, a) => !x.startsWith("--") && !flags.has(a[i]));
    const reports = files.map((f) => { const b = readFileSync(f); return { report: JSON.parse(b.toString("utf8")), sha256: sha(b) }; }).filter((x) => x.report.registrar_id === reg || x.report.registrar_id == null);
    const { state: next, did } = step(state, reports, now);
    mkdirSync(dirname(file) || ".", { recursive: true }); writeFileSync(file, JSON.stringify(next, null, 2) + "\n");
    for (const n of next.notices.slice(state.notices.length)) { const out = join(dirname(file), `${reg}-notice-${n.n}.json`); writeFileSync(out, JSON.stringify(n.body, null, 2) + "\n"); console.log(`wrote ${out} (sha256 ${n.sha256})`); }
    console.log(`${reg}: ${did}`);
  } else if (argv[0] === "evidence") {
    const state = JSON.parse(readFileSync(A("state"), "utf8"));
    try { writeFileSync(A("out"), JSON.stringify(evidence(state, A("for"), Number(A("now"))), null, 2) + "\n"); console.log(`wrote ${A("out")}`); }
    catch (e) { console.error(e.message); process.exit(1); }
  } else { console.error("usage: notice.mjs step … | evidence … | --drill"); process.exit(2); }
}
