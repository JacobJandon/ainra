// SPDX-License-Identifier: Apache-2.0 OR MIT
// M17 Task 2 — headless full-lifecycle walkthrough against a LIVE staging registrar's PUBLIC demo door.
// Proves, with real cryptography, the five state transitions a visitor completes on /demo:
//   issue (public door) → logged-before-valid (leaf + checkpoint height) → VERIFY (real SDK, locally)
//   → revoke (public door) → RE-VERIFY (fail-closed, named reason).
// Emits the ONE canonical M16 verdict-event envelope at each verify, so the walkthrough doubles as documentation of
// the shape. Exits non-zero if any transition is wrong — the demo must never rot silently.
//   node tools/demo-walkthrough.mjs [registrarBase] [registrarId]   (defaults: http://127.0.0.1:4907 registrar-07)
import { runVector, verdictEvent, serializeVerdictEvent } from "../site/vendor/ainra-sdk.js";

const REG = process.argv[2] || process.env.AINRA_REG || "http://127.0.0.1:4907";
const REGID = process.argv[3] || process.env.AINRA_REGID || "registrar-07";
const NOW = Number(process.env.AINRA_NOW || 1776729600); // staging's default verification time (nbf + 10d)
const j = async (u, o) => (await fetch(u, o)).json();

let failed = 0;
const step = (n, label, ok, detail) => {
  console.log(`  ${ok ? "✓" : "✗"} ${n}. ${label}${detail ? " — " + detail : ""}`);
  if (!ok) failed++;
};

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
  step(1, "issue (public door)", !!sub && rec.tier === "L1", sub ? `${sub}  tier ${rec.tier}` : JSON.stringify(rec));
  if (!sub) process.exit(1);

  // 2. LOGGED-BEFORE-VALID — the leaf exists and the checkpoint height is real
  const health = await j(`${REG}/health`);
  const recCheck = await j(`${REG}/record?sub=${encodeURIComponent(sub)}`);
  step(2, "logged before valid", recCheck.sub === sub && rec.checkpoint_size >= 1, `leaf at checkpoint height ${rec.checkpoint_size}, records=${health.records}`);

  // 3. VERIFY (real SDK, locally) — the browser fetches /present and recomputes the inclusion proof itself
  const pres1 = await j(`${REG}/present?sub=${encodeURIComponent(sub)}&now=${NOW}`);
  const v1 = runVector({ name: sub, expect: {}, anchors, presentation: pres1 });
  step(3, "verify (real SDK)", v1.verdict === "valid", `verdict-event ${serializeVerdictEvent(verdictEvent(pres1, v1, NOW))}`);

  // 4. REVOKE via the public door
  const rv = await j(`${REG}/demo/revoke`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ sub, now: NOW }) });
  step(4, "revoke (public door)", rv.revoked === sub, rv.revoked ? `revoked ${sub.split(":").pop()}` : JSON.stringify(rv));

  // 5. RE-VERIFY — must fail closed with the named reason
  const pres2 = await j(`${REG}/present?sub=${encodeURIComponent(sub)}&now=${NOW}`);
  const v2 = runVector({ name: sub, expect: {}, anchors, presentation: pres2 });
  step(5, "re-verify fails closed", v2.verdict === "invalid" && v2.reason === "revoked", `verdict-event ${serializeVerdictEvent(verdictEvent(pres2, v2, NOW))}`);

  console.log();
  console.log(failed === 0
    ? "✓ /demo lifecycle GREEN — 5/5 transitions against the live public door with real crypto (the switch beats the calendar)"
    : `✗ ${failed} transition(s) failed`);
  process.exit(failed ? 1 : 0);
};
main().catch((e) => { console.error("walkthrough error:", e.message); process.exit(2); });
