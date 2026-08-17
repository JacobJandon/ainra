// SPDX-License-Identifier: Apache-2.0 OR MIT
// AINRA COMPLIANCE PROBE (D-046). It measures a registrar's accreditation invariants ADVERSARIALLY: from outside,
// through the same door a stranger uses, holding nothing the registrar issued it. Every accreditation regime that
// relied on self-report and an annual audit was corrected from the outside — by monitors and by people reading the
// logs, not by the reports. This is the instrument that does that reading, and the reason it can exist is that
// AINRA's evidence is public by construction.
//
//   node probe.mjs --registrar <url> --directory <dir.json> --roots <roots.json> --now <unix>
//                  [--slo-revocation-sec 60] [--poll-ms 200] [--timeout-sec 240] [--out <dir>]
//
// The two properties that make it a probe and not a health check:
//
//   1. NO CREDENTIAL. It sends no Authorization header, ever, and it proves the write door is shut to it before it
//      measures anything (P0). If `POST /issue` had answered, the run would be an insider's and it aborts — an
//      operator measuring itself with its own token is exactly the self-report this replaces.
//   2. INDISTINGUISHABLE. It mints through the public door with an ordinary-looking lineage. A registrar that can
//      tell a probe from a customer will, eventually, treat them differently — so the term in docs/PROBES.md is
//      that the probe carries no marking, and the schedule is unannounced.
//
// Every verdict comes from a REAL root-dark verifier (published @ainra/sdk) built from the root-signed directory: it
// holds the ceremony root keys and nothing else from this registrar. Latency is wall-clock measured. Nothing here is
// asserted from a report the registrar wrote about itself.
//
// Honest scope, stated in the report too: a run proves these invariants held for ONE unmarked lineage at ONE moment.
// It does not prove they always hold. That is why the value is in the schedule, not in any single run.

import { writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { Verifier } from "@ainra/sdk";

const A = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : d; };
const registrar = (A("registrar") || "").replace(/\/$/, "");
const now = Number(A("now"));
const outDir = A("out", "out");
const sloSec = Number(A("slo-revocation-sec", "60"));
const pollMs = Number(A("poll-ms", "200"));
const timeoutSec = Number(A("timeout-sec", "240"));
if (!registrar || !now || !A("directory") || !A("roots")) {
  console.error("usage: probe.mjs --registrar <url> --directory <f> --roots <f> --now <unix> [--slo-revocation-sec 60]");
  process.exit(2);
}
mkdirSync(outDir, { recursive: true });

const directory = JSON.parse(readFileSync(A("directory"), "utf8"));
const roots = JSON.parse(readFileSync(A("roots"), "utf8"));
// The strictest policy a verifier can hold: F1 freshness (30 s) and currency mode ON (fresh-head bound to the list,
// monotonic seq enforced). A probe that measured with a lax policy would report compliance the strict edge does not get.
const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F1", true);
if (!verifier) { console.error("probe: the directory is not anchored by these roots — refusing to measure"); process.exit(2); }

const checks = [];
let aborted = null;
function check(id, title, pass, observed, proves) {
  checks.push({ id, title, pass: !!pass, observed, proves });
  console.log(`  ${pass ? "PASS" : "FAIL"}  ${id}  ${title}`);
  if (!pass) console.log(`        observed: ${observed}`);
  return !!pass;
}
// A check that cannot be false in this run's conditions is recorded as SKIP, never as PASS. It carries `pass: null`,
// it is excluded from the verdict, and it prints its reason — because a control that could not have failed reported as
// a pass is exactly how a green board stops meaning anything.
function skip(id, title, why, proves) {
  checks.push({ id, title, pass: null, skipped: why, proves });
  console.log(`  SKIP  ${id}  ${title}`);
  console.log(`        ${why}`);
}

// Every request goes out bare. `headers` is deliberately absent on GETs and content-type-only on POSTs; if a future
// edit adds an Authorization header here, P0 stops being true and the whole run stops meaning anything.
async function get(path) {
  const r = await fetch(`${registrar}${path}`);
  const text = await r.text();
  let json = null; try { json = JSON.parse(text); } catch { /* non-JSON body is itself an observation */ }
  return { status: r.status, json, text };
}
async function post(path, body) {
  const r = await fetch(`${registrar}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const text = await r.text();
  let json = null; try { json = JSON.parse(text); } catch { /* ditto */ }
  return { status: r.status, json, text };
}
const presentOf = (sub) => get(`/present?sub=${encodeURIComponent(sub)}&now=${now}`);
const verdictOf = (bundle) => verifier.verify(bundle, now);
const sha256hex = (s) => createHash("sha256").update(s).digest("hex");

console.log(`probe: ${registrar} · root-dark verifier (F1, currency ON) · SLO revocation < ${sloSec}s\n`);

// Sampled before anything is minted, so P5 has a real "before" to compare against at the end of the run.
const seqStart = (await get("/health")).json?.status_seq ?? null;

// ── P0 · the probe is a stranger ─────────────────────────────────────────────────────────────────────────────────
// Not a formality. This is the check that makes every check below it adversarial, and it is the one an operator running the
// probe against its own box is most likely to skip.
const writeDoor = await post("/issue", { operator: "probe", lineage: "unauthorized", version: "1.0.0", tier: "L1", auth_class: "A2", principal_proof: "00", capabilities: [], scope_ceiling: [], hops: [] });
const strangerOk = check(
  "P0", "the write door is shut to us (no credential held)",
  writeDoor.status === 401 || writeDoor.status === 403,
  `POST /issue with no Authorization → HTTP ${writeDoor.status}`,
  "the measurements below are an outsider's; if this had answered 200 the run would be a self-report",
);
if (!strangerOk && writeDoor.status === 200) {
  aborted = "the write door answered an unauthenticated POST /issue — this probe holds effective write access, so nothing it measures is adversarial. Fix the registrar's auth before trusting any run.";
}

// ── P1 · mint through the public door ────────────────────────────────────────────────────────────────────────────
let sub = null, preBundle = null;
if (!aborted) {
  // An ordinary-looking name. No "probe", no "monitor", nothing a grep on the registrar's side could special-case.
  const tag = Date.now().toString(36).slice(-5);
  const mint = await post("/demo/issue", { operator: "meadowlark", lineage: `ledger-sync-${tag}` });
  sub = mint.json?.sub ?? null;
  check("P1", "an unmarked lineage can be minted through the public door", mint.status === 200 && !!sub,
    `POST /demo/issue → HTTP ${mint.status}${sub ? ` · ${sub}` : ` · ${mint.text.slice(0, 120)}`}`,
    "the retail path is open to a party the registrar has no relationship with");
  if (!sub) aborted = aborted ?? "could not mint through the public door — the probe has nothing to measure. On a real registrar this is the accreditation term being unmet, not a probe failure.";
}

// ── P2 · logged before valid, and the log commits to what was issued ─────────────────────────────────────────────
if (!aborted) {
  const p = await presentOf(sub);
  preBundle = p.json;
  const v = p.status === 200 && preBundle ? verdictOf(preBundle) : { verdict: "invalid", reason: `HTTP ${p.status}` };
  const positive = v.verdict === "valid";
  check("P2a", "the freshly minted passport verifies against the root-signed directory", positive,
    `verdict = ${v.verdict}${v.reason ? "/" + v.reason : ""} (leaf_index ${preBundle?.leaf_index}, checkpoint size ${preBundle?.checkpoint?.size})`,
    "issuance reached the log and the delegate chain holds, measured by a verifier that trusts only the ceremony roots");

  if (positive) {
    // The positive result above is worth nothing on its own: a verifier that ignored the log would also say `valid`.
    // The controls below prove the acceptance DEPENDED on the log, at this registrar, in this run.
    //
    // Claim a different position in the tree. This is the mutation that stays load-bearing at EVERY tree size, which
    // is why it is the primary control: the verifier recomputes the root from the leaf at the claimed index, so a
    // wrong index cannot produce the committed root.
    const vMoved = verdictOf({ ...preBundle, leaf_index: preBundle.leaf_index + 1 });
    check("P2b", "the same passport, claiming a different position in the log, is REFUSED", vMoved.verdict === "invalid",
      `leaf_index ${preBundle.leaf_index} → ${preBundle.leaf_index + 1}: verdict = ${vMoved.verdict}${vMoved.reason ? "/" + vMoved.reason : ""}`,
      "inclusion is recomputed, not trusted — the passport is bound to one proven position in the committed tree");

    // Removing the proof only means something once the tree has more than one leaf: in a single-leaf tree the proof is
    // legitimately empty and the root IS the leaf, so an "empty proof" is not a manipulation and a check that asserted
    // on it would be asserting something that cannot be false. That is a skip, and it says so.
    if (preBundle.inclusion_proof?.length > 0) {
      const vNoProof = verdictOf({ ...preBundle, inclusion_proof: [] });
      check("P2d", "the same passport with its inclusion proof removed is REFUSED", vNoProof.verdict === "invalid",
        `${preBundle.inclusion_proof.length}-node proof → []: verdict = ${vNoProof.verdict}${vNoProof.reason ? "/" + vNoProof.reason : ""}`,
        "the proof path itself is verified, not merely carried");
    } else {
      skip("P2d", "the same passport with its inclusion proof removed is REFUSED",
        `the log holds ${preBundle.checkpoint?.size} leaf/leaves, so a correct proof for index ${preBundle.leaf_index} is EMPTY — deleting it changes nothing and could not fail. P2b covers inclusion at this size.`,
        "not skipped for convenience: at size 1 the root is the leaf, so this mutation is not a manipulation");
    }

    // Flip one byte of the signed claims. If the leaf did not commit to these exact claims, this would still pass —
    // which is the regression class that bit a major signing ecosystem: a log entry that did not bind its artifact.
    const c = preBundle.claims;
    const i = Math.floor(c.length / 2);
    const alt = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const flipped = c.slice(0, i) + alt[(alt.indexOf(c[i]) + 1 + alt.length) % alt.length] + c.slice(i + 1);
    const vFlipped = verdictOf({ ...preBundle, claims: flipped });
    check("P2c", "one flipped claims byte is REFUSED (the leaf binds the actual document)", vFlipped.verdict === "invalid",
      `verdict = ${vFlipped.verdict}${vFlipped.reason ? "/" + vFlipped.reason : ""}`,
      "the logged leaf commits to the issued claims, so the registrar cannot log one thing and issue another");
  }
}

// ── P3 · revocation reaches a stranger, and how long it took ─────────────────────────────────────────────────────
let latencyMs = null;
if (!aborted && preBundle) {
  const rev = await post("/demo/revoke", { sub, now });
  const t0 = process.hrtime.bigint();
  if (rev.status !== 200) {
    check("P3", "revocation is accepted through the same public door", false,
      `POST /demo/revoke → HTTP ${rev.status} · ${rev.text.slice(0, 120)}`,
      "a party that can mint can also revoke; otherwise the lifecycle is not testable from outside");
  } else {
    const deadline = Date.now() + timeoutSec * 1000;
    let seen = null;
    while (Date.now() < deadline) {
      const p = await presentOf(sub);
      const v = p.json ? verdictOf(p.json) : null;
      if (v && v.verdict === "invalid") { seen = v; latencyMs = Number(process.hrtime.bigint() - t0) / 1e6; break; }
      await new Promise((r) => setTimeout(r, pollMs));
    }
    const withinSlo = latencyMs !== null && latencyMs / 1000 < sloSec;
    check("P3", `the revocation becomes visible to an outside verifier in < ${sloSec}s`, withinSlo,
      latencyMs === null
        ? `not observed within ${timeoutSec}s — the revocation never reached a verifier that only reads what the registrar publishes`
        : `${(latencyMs / 1000).toFixed(3)}s (reason: ${seen.reason})`,
      "the published revocation fabric — not the registrar's internal state — is what a stranger's verdict follows");
  }
}

// ── P4 · the pre-revocation snapshot stops working (currency, D-021) ─────────────────────────────────────────────
if (!aborted && preBundle && latencyMs !== null) {
  // Replay the exact bytes that were valid a moment ago, through the SAME verifier instance, at the SAME clock.
  // Currency mode remembers the newest fresh-head seq it has seen, so a genuine older snapshot is a replay now.
  const vReplay = verdictOf(preBundle);
  check("P4", "the pre-revocation bundle, replayed at the same clock, is REFUSED", vReplay.verdict === "invalid",
    `verdict = ${vReplay.verdict}${vReplay.reason ? "/" + vReplay.reason : ""}`,
    "a genuine pre-revocation snapshot cannot be replayed past the revocation — the fresh-head seq closes the window");
}

// ── P5 · the status sequence only moves forward (the outside shadow of D-045) ─────────────────────────────────────
let seqEnd = null;
if (!aborted) {
  seqEnd = (await get("/health")).json?.status_seq ?? null;
  // Two claims, and the second is the sharper one. Non-decreasing catches a rewind; strictly-greater-after-a-
  // -revocation catches the subtler failure of a registrar that accepted our revoke, answered 200, and published
  // nothing — a history that stands still while it is being written to is also a history that cannot be trusted.
  const nonDecreasing = Number.isFinite(seqStart) && Number.isFinite(seqEnd) && seqEnd >= seqStart;
  const advanced = latencyMs === null || (Number.isFinite(seqEnd) && seqEnd > seqStart);
  check("P5", "the published status sequence only moved forward, and it did move", nonDecreasing && advanced,
    `status_seq ${seqStart} → ${seqEnd}${latencyMs !== null ? " (one revocation published in between)" : ""}`,
    "a shorter or older status history served after an outage is a split view, not a recovery (D-045, seen from outside)");
}

// ── report ───────────────────────────────────────────────────────────────────────────────────────────────────────
const failed = checks.filter((c) => c.pass === false);
const skipped = checks.filter((c) => c.pass === null);
const report = {
  kind: "ainra/compliance-probe/v1",
  registrar_url: registrar,
  registrar_id: sub?.split(":")[1] ?? null, // from the signed name the verifier accepted, not from /health
  ran_at: new Date().toISOString(),
  verifier_now: now,
  policy: { freshness: "F1", currency: true, slo_revocation_sec: sloSec, timeout_sec: timeoutSec },
  subject_sha256: sub ? sha256hex(sub) : null, // the lineage is not published: a named probe subject is a marked probe
  aborted,
  measured: {
    revocation_visible_ms: latencyMs === null ? null : Number(latencyMs.toFixed(1)),
    status_seq: { start: seqStart, end: seqEnd },
  },
  checks,
  skipped: skipped.map((c) => ({ id: c.id, why: c.skipped })), // surfaced, so a thin run cannot look like a full one
  verdict: aborted ? "INVALID-RUN" : failed.length === 0 ? "COMPLIANT" : "NON-COMPLIANT",
  scope: "One unmarked lineage, one moment, one vantage point. Proves these invariants HELD here; proves nothing about always. The value is in an unannounced schedule, not in any single run — and in the probe holding no credential (P0), which is what separates this from the registrar's own report.",
};
writeFileSync(`${outDir}/probe-report.json`, JSON.stringify(report, null, 2) + "\n");

console.log(`\nprobe verdict: ${report.verdict}${latencyMs !== null ? ` · revocation visible in ${(latencyMs / 1000).toFixed(3)}s` : ""}`);
if (aborted) console.log(`ABORTED: ${aborted}`);
if (failed.length) console.log(`failed: ${failed.map((c) => c.id).join(", ")}`);
if (skipped.length) console.log(`skipped (not counted either way): ${skipped.map((c) => c.id).join(", ")}`);
console.log(`wrote ${outDir}/probe-report.json`);
process.exit(report.verdict === "COMPLIANT" ? 0 : 1); // fail closed
