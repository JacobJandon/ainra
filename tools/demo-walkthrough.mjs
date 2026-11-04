// SPDX-License-Identifier: Apache-2.0 OR MIT
// M17 Task 2 — headless full-lifecycle walkthrough against a LIVE staging registrar's PUBLIC demo door.
// Proves, with real cryptography, the five state transitions a visitor completes on /demo:
//   issue (public door) → logged-before-valid (leaf + checkpoint height) → VERIFY (real SDK, locally)
//   → revoke (public door) → RE-VERIFY (fail-closed, named reason).
// Emits the ONE canonical M16 verdict-event envelope at each verify, so the walkthrough doubles as documentation of
// the shape. Exits non-zero if any transition is wrong — the demo must never rot silently.
//   node tools/demo-walkthrough.mjs [registrarBase] [registrarId]   (defaults: http://127.0.0.1:4907 registrar-07)
//   node tools/demo-walkthrough.mjs --negative   offline: plants wrong door answers; every one MUST fail its step
//
// WITNESS: `--negative` needs no registrar. It starts a stand-in door on loopback that replays recorded answers
// built from the committed conformance vector vectors/v1/valid-0000.json (its anchors as the accreditation, its
// presentation before the revoke, and the same presentation with its status bit set after it), then runs THIS tool
// as a child process against that door — so the five pass rules in RULES, step(), the failure count and the exit
// code are all the ones a live run uses, with real crypto. It plants nine wrong answers: an issue with no sub, an
// issue at tier L3, a record lookup for another sub, a record at checkpoint height 0, a FIRST verify that comes
// back revoked, a first verify of claims edited to tier L4, a revoke that names no sub (and revokes nothing), a
// RE-verify that is still VALID (the switch did not flip), and a re-verify refused for the wrong reason (expired,
// not revoked). Each must exit 1 with exactly the steps it breaks marked ✗ and every other step it reaches ✓; a
// crash or a door error (exit 2) does not count. The honest replay must exit 0 with all five ✓ and the GREEN line,
// so a check that fails everything cannot pass. If any rule, the count or the exit stops failing closed, a plant
// exits 0 and the negative control goes red.
import { readFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { inflateSync, deflateSync } from "node:zlib";
import { conformance, verdictEvent, serializeVerdictEvent } from "../site/vendor/ainra-sdk.js";
const { runVector } = conformance;

const REG = process.argv[2] || process.env.AINRA_REG || "http://127.0.0.1:4907";
const REGID = process.argv[3] || process.env.AINRA_REGID || "registrar-07";
const NOW = Number(process.env.AINRA_NOW || 1776729600); // staging's default verification time (nbf + 10d)
const j = async (u, o) => (await fetch(u, o)).json();

let failed = 0;
const step = (n, label, ok, detail) => {
  console.log(`  ${ok ? "✓" : "✗"} ${n}. ${label}${detail ? " — " + detail : ""}`);
  if (!ok) failed++;
};

// The pass rule of each transition — the walkthrough's whole detection logic, shared with the negative control.
const RULES = {
  issued: (rec) => !!rec.sub && rec.tier === "L1",
  logged: (rec, recCheck) => recCheck.sub === rec.sub && rec.checkpoint_size >= 1,
  verified: (v) => v.verdict === "valid",
  revoked: (rv, sub) => rv.revoked === sub,
  refused: (v) => v.verdict === "invalid" && v.reason === "revoked",
};

// ── the negative control (see WITNESS above): a recorded door on loopback, a real run of this tool per plant ──
async function negative() {
  const SELF = fileURLToPath(import.meta.url);
  const good = JSON.parse(readFileSync(new URL("../vectors/v1/valid-0000.json", import.meta.url), "utf8"));
  const [regId] = Object.keys(good.anchors);
  const claims = JSON.parse(Buffer.from(good.presentation.claims, "base64url").toString("utf8"));
  const pres = good.presentation;
  // After the revoke the door presents the same credential with its status bit set (bit idx, least significant first).
  const idx = claims.status.status_list.idx;
  const bits = inflateSync(Buffer.from(pres.status_list, "base64url"));
  bits[idx >> 3] |= 1 << (idx & 7);
  const presRevoked = { ...pres, status_list: deflateSync(bits).toString("base64url") };
  const issued = { sub: claims.sub, tier: claims.tier, checkpoint_size: pres.checkpoint.size, leaf_index: pres.leaf_index };
  // The honest door. A plant replaces one answer; `st.revoked` is what the door's revoke switch has done so far.
  const honest = {
    accreditation: () => good.anchors[regId],
    issue: () => issued,
    health: () => ({ records: 1 }),
    record: (q) => ({ sub: q.get("sub") }),
    present: (q, st) => (st.revoked ? presRevoked : pres),
    revoke: (body, st) => { st.revoked = true; return { revoked: body.sub }; },
  };
  let door = honest, st = {};
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (d) => (raw += d));
    req.on("end", () => {
      const u = new URL(req.url, "http://door"), route = { "/accreditation": "accreditation", "/demo/issue": "issue", "/health": "health", "/record": "record", "/present": "present", "/demo/revoke": "revoke" }[u.pathname];
      if (!route) { res.writeHead(404); res.end("{}"); return; }
      const answer = door[route](route === "revoke" ? JSON.parse(raw || "{}") : u.searchParams, st);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(answer));
    });
  });
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  const base = `http://127.0.0.1:${server.address().port}`;
  const run = (over) => new Promise((ok) => {
    door = { ...honest, ...over }; st = {};
    const c = spawn(process.execPath, [SELF, base, regId], { env: { ...process.env, AINRA_NOW: String(pres.now) } });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", (d) => (err += d));
    c.on("close", (code) => {
      const marks = [...out.matchAll(/^ {2}([✓✗]) (\d)\. /gm)].map((m) => [m[1], Number(m[2])]);
      ok({ code, out, err: err.trim(), passed: marks.filter(([m]) => m === "✓").map(([, n]) => n), failedSteps: marks.filter(([m]) => m === "✗").map(([, n]) => n) });
    });
  });
  // [label, the one answer the door gets wrong, the steps that must be ✗, the steps that must be ✓]
  const plants = [
    ["1. issue answered with no sub", { issue: () => ({ error: "door closed" }) }, [1], []],
    ["1. issue minted tier L3, not a low-tier specimen", { issue: () => ({ ...issued, tier: "L3" }) }, [1], [2, 3, 4, 5]],
    ["2. record lookup returned another sub", { record: (q) => ({ sub: q.get("sub") + "-other" }) }, [2], [1, 3, 4, 5]],
    ["2. record at checkpoint height 0", { issue: () => ({ ...issued, checkpoint_size: 0 }) }, [2], [1, 3, 4, 5]],
    ["3. first verify comes back revoked", { present: () => presRevoked }, [3], [1, 2, 4, 5]],
    ["3. first verify of claims edited to tier L4", { present: (q, s) => (s.revoked ? presRevoked : { ...pres, claims: Buffer.from(JSON.stringify({ ...claims, tier: "L4" })).toString("base64url") }) }, [3], [1, 2, 4, 5]],
    ["4. revoke answered without naming the sub (and revoked nothing)", { revoke: () => ({ error: "not found" }) }, [4, 5], [1, 2, 3]],
    ["5. re-verify still VALID after the revoke", { present: () => pres }, [5], [1, 2, 3, 4]],
    ["5. re-verify refused as expired, not revoked", { present: (q, s) => (s.revoked ? { ...pres, now: claims.exp + 1 } : pres) }, [5], [1, 2, 3, 4]],
  ];
  const same = (a, b) => a.join() === b.join();
  let missed = 0;
  const control = await run({});
  if (control.code === 0 && same(control.passed, [1, 2, 3, 4, 5]) && !control.failedSteps.length && control.out.includes("✓ /demo lifecycle GREEN")) console.log("ok control: the honest recorded door — all five steps ✓, GREEN, exit 0");
  else { console.error(`MISSED control: the honest recorded door — exit ${control.code}, ✗ at ${control.failedSteps.join(", ") || "none"} ${control.err}`); missed++; }
  for (const [label, over, wantFail, wantPass] of plants) {
    const r = await run(over);
    const tally = wantPass.length ? r.out.includes(`✗ ${wantFail.length} transition(s) failed`) : true; // a run stopped at step 1 prints no tally
    if (r.code === 1 && same(r.failedSteps, wantFail) && same(r.passed, wantPass) && tally) console.log(`ok caught step ${label} — ✗ at ${wantFail.join(", ")}, exit 1`);
    else { console.error(`MISSED step ${label} — exit ${r.code}, ✗ at ${r.failedSteps.join(", ") || "none"}, ✓ at ${r.passed.join(", ") || "none"}${r.err ? ` (${r.err.split("\n")[0]})` : ""}; wanted exit 1, ✗ at ${wantFail.join(", ")}`); missed++; }
  }
  server.close();
  if (missed) { console.error(`\ndemo-walkthrough negative control FAILED: ${missed} of ${plants.length + 1} not as required`); process.exit(1); }
  console.log(`\ndemo-walkthrough negative control OK: all ${plants.length} planted wrong answers fail exactly their step(s) and exit 1, the honest replay is GREEN.`);
  process.exit(0);
}

const main = async () => {
  const acc = await j(`${REG}/accreditation`).catch(() => ({}));
  if (!acc.issuer_key || !acc.log_root_key) {
    console.error(`  ✗ no accreditation from ${REG} — is the staging network up?  run:  make stage-up`);
    process.exit(2);
  }
  const anchors = { [REGID]: { issuer_key: acc.issuer_key, log_root_key: acc.log_root_key } };
  console.log(`AINRA /demo lifecycle walkthrough · ${REG} (${REGID}) · TEST-ROOT · real crypto\n`);

  // 1. ISSUE via the public door — no token, a low-tier specimen
  const rec = await j(`${REG}/demo/issue`, { method: "POST" });
  const sub = rec.sub;
  step(1, "issue (public door)", RULES.issued(rec), sub ? `${sub}  tier ${rec.tier}` : JSON.stringify(rec));
  if (!sub) process.exit(1);

  // 2. LOGGED-BEFORE-VALID — the leaf exists and the checkpoint height is real
  const health = await j(`${REG}/health`);
  const recCheck = await j(`${REG}/record?sub=${encodeURIComponent(sub)}`);
  step(2, "logged before valid", RULES.logged(rec, recCheck), `leaf at checkpoint height ${rec.checkpoint_size}, records=${health.records}`);

  // 3. VERIFY (real SDK, locally) — the browser fetches /present and recomputes the inclusion proof itself
  const pres1 = await j(`${REG}/present?sub=${encodeURIComponent(sub)}&now=${NOW}`);
  const v1 = runVector({ name: sub, expect: {}, anchors, presentation: pres1 });
  step(3, "verify (real SDK)", RULES.verified(v1), `verdict-event ${serializeVerdictEvent(verdictEvent(pres1, v1, NOW))}`);

  // 4. REVOKE via the public door
  const rv = await j(`${REG}/demo/revoke`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ sub, now: NOW }) });
  step(4, "revoke (public door)", RULES.revoked(rv, sub), rv.revoked ? `revoked ${sub.split(":").pop()}` : JSON.stringify(rv));

  // 5. RE-VERIFY — must fail closed with the named reason
  const pres2 = await j(`${REG}/present?sub=${encodeURIComponent(sub)}&now=${NOW}`);
  const v2 = runVector({ name: sub, expect: {}, anchors, presentation: pres2 });
  step(5, "re-verify fails closed", RULES.refused(v2), `verdict-event ${serializeVerdictEvent(verdictEvent(pres2, v2, NOW))}`);

  console.log();
  console.log(failed === 0
    ? "✓ /demo lifecycle GREEN — 5/5 transitions against the live public door with real crypto (the switch beats the calendar)"
    : `✗ ${failed} transition(s) failed`);
  process.exit(failed ? 1 : 0);
};
if (process.argv.includes("--negative")) await negative();
else main().catch((e) => { console.error("walkthrough error:", e.message); process.exit(2); });
