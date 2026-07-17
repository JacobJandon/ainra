// SPDX-License-Identifier: Apache-2.0 OR MIT
// Verify a soak run WITHOUT trusting the runner. The runner self-signs with an ephemeral key, so the signature alone
// proves only internal consistency; a THIRD party pins the SLO and the expected challenge/key OUT OF BAND. This tool:
//   (0) requires the report + the log's soak-start to carry the CHALLENGE we pinned (binds this run to a nonce we
//       issued — a fabricated run for a challenge we never issued is rejected);
//   (1) checks the append-only hash chain is unbroken (edit / insert / middle-drop breaks it);
//   (2) verifies the report's Ed25519 signature over the WHOLE body (recursive canonical) — optionally under a
//       reporter key we pinned;
//   (3) confirms log_head_hash == the chain tip AND the log's measure-count == the report's (catches a trailing drop);
//   (4) recomputes the SLO verdict using OUR pinned target (never the report's self-reported threshold) and requires
//       both that it PASSES and that the report's own claim matches it.
//
//   node verify-log.mjs --log <soak-log.jsonl> --report <soak-report.json> --slo-p95-sec <pin> --challenge <nonce>
//                       [--reporter-pubkey <spki-b64 you were given out of band>]

import { readFileSync } from "node:fs";
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";

const A = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : d; };
// --consistency-only: re-check a FINISHED report's signature + tamper-evident structure WITHOUT the out-of-band pins
// (used by `make soak-verify`). It catches every tamper (edited line, dropped measurement, re-signed body) and checks
// the report's numbers are recomputable FROM ITS OWN log, but it does NOT gate an SLO verdict — that still requires a
// third party to pin the target + challenge themselves (`--slo-p95-sec` + `--challenge`), because trusting the report's
// own threshold is exactly the fail-open the M9 review closed (D-024).
const consistencyOnly = process.argv.includes("--consistency-only");
const logPath = A("log"), repPath = A("report");
const sloPin = A("slo-p95-sec") !== undefined ? Number(A("slo-p95-sec")) : undefined; // pinned by US, not the report
const expectChallenge = A("challenge"); // pinned nonce we issued for this run
const pinnedKey = A("reporter-pubkey"); // optional: the reporter key we were given out of band
if (!logPath || !repPath || (!consistencyOnly && (sloPin === undefined || Number.isNaN(sloPin) || !expectChallenge))) {
  console.error("usage: verify-log.mjs --log <f> --report <f> {--slo-p95-sec <pin> --challenge <nonce> | --consistency-only} [--reporter-pubkey <spki-b64>]");
  process.exit(2);
}
const sha256hex = (b) => createHash("sha256").update(b).digest("hex");
function canonicalJSON(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalJSON).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalJSON(v[k])).join(",") + "}";
}
let ok = true;
const pass = (m) => console.log("  ✓ " + m);
const fail = (m) => { console.error("  ✗ " + m); ok = false; };

const lines = readFileSync(logPath, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
const report = JSON.parse(readFileSync(repPath, "utf8"));
const body = report.body || {};

// (0) challenge binding — the report AND the log's soak-start must carry the nonce we issued. In consistency-only
// mode we don't have an external pin, so we require the report and its log agree with EACH OTHER (internal binding).
const start = lines.find((l) => l.event === "soak-start");
if (consistencyOnly) {
  body.challenge !== undefined && start && start.challenge === body.challenge
    ? pass(`report + log soak-start agree on the run's challenge (${JSON.stringify(body.challenge)}) — internally consistent`)
    : fail(`report challenge ${JSON.stringify(body.challenge)} != log-start ${JSON.stringify(start && start.challenge)}`);
} else {
  body.challenge === expectChallenge && start && start.challenge === expectChallenge
    ? pass("report + log soak-start carry the challenge we issued (this run is ours, not fabricated)")
    : fail(`challenge mismatch — report ${JSON.stringify(body.challenge)}, log-start ${JSON.stringify(start && start.challenge)}, expected the pinned nonce`);
}

// (1) hash chain — each line commits to the previous; the this_hash is over the line minus this_hash (canonical).
let prev = "genesis", chainOk = true, tip = "genesis";
for (const [i, line] of lines.entries()) {
  const { this_hash, ...rest } = line;
  const recomputed = sha256hex(canonicalJSON(rest));
  if (line.prev_hash !== prev) { fail(`log line ${i}: prev_hash breaks the chain`); chainOk = false; break; }
  if (recomputed !== this_hash) { fail(`log line ${i}: this_hash does not match its contents (edited?)`); chainOk = false; break; }
  prev = this_hash; tip = this_hash;
}
if (chainOk) pass(`append-only hash chain intact over ${lines.length} entries (tip ${tip.slice(0, 16)}…)`);

// (2) report signature over the whole body; if we were given the reporter's key out of band, it must be THAT key.
try {
  if (pinnedKey && pinnedKey !== report.reporter_pubkey_spki_b64) fail("reporter key != the key pinned out of band");
  const pub = createPublicKey({ key: Buffer.from(report.reporter_pubkey_spki_b64 || "", "base64"), format: "der", type: "spki" });
  edVerify(null, Buffer.from(canonicalJSON(body)), pub, Buffer.from(report.sig_ed25519_b64 || "", "base64"))
    ? pass("soak-report signature covers the whole body") : fail("soak-report signature does NOT verify");
} catch (e) { fail("report signature errored: " + e.message); }

// (3) head-hash + measurement-count binding (a dropped trailing measurement changes the count).
body.log_head_hash === tip ? pass("report log_head_hash == the log's chain tip") : fail("report log_head_hash != the log tip");
const measRows = lines.filter((l) => l.event === "measure");
measRows.length === body.measurements ? pass(`measurement count matches the log (${measRows.length})`)
  : fail(`report claims ${body.measurements} measurements but the log has ${measRows.length} (trailing drop / mismatch)`);

// (4) recompute the p95 FROM THE LOG. Full mode: gate against OUR pinned target. Consistency-only: require the report's
// own numbers recompute from its own log (catches a report lying about its data) but do NOT assert an SLO verdict —
// gating on the report's self-declared threshold is the fail-open the M9 review closed (D-024).
const meas = measRows.map((l) => (l.observed ? l.latency_ms : Infinity));
const finite = meas.filter(Number.isFinite);
const pctv = (arr, p) => { if (!arr.length) return Infinity; const s = [...arr].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)]; };
const p95 = pctv(meas, 95) / 1000;
const misses = meas.length - finite.length;
const p95str = Number.isFinite(p95) ? p95.toFixed(3) + "s" : "MISS";
if (consistencyOnly) {
  const claimed = body.slo?.measured_p95_sec;
  const recomputed = Number.isFinite(p95) ? Number(p95.toFixed(3)) : null;
  claimed === recomputed
    ? pass(`report's measured p95 (${claimed}s) recomputes from its own log (misses ${misses})`)
    : fail(`report claims measured p95 ${claimed}s but its log recomputes ${recomputed}s (report lies about its own data)`);
  console.log("");
  if (ok) { console.log(`SOAK VERIFY (consistency): PASS — signed, tamper-evident, self-consistent. NOTE: the SLO verdict here is the report's OWN claim (measured p95 ${p95str}); to GATE it, re-run with --slo-p95-sec <your pin> --challenge <nonce you pinned>.`); process.exit(0); }
  console.error("SOAK VERIFY (consistency): FAIL — the report or its log was tampered with."); process.exit(1);
}
const pinnedPass = Number.isFinite(p95) && p95 < sloPin && misses === 0;
if (!pinnedPass) fail(`SLO recomputed against OUR pin (<${sloPin}s): p95 ${p95str}, misses ${misses} → BREACH`);
else if (body.slo?.pass !== true) fail(`log meets our pinned SLO but the report claims pass=${body.slo?.pass}`);
else pass(`SLO verdict recomputed against OUR pinned target (<${sloPin}s): p95 ${p95str}, misses ${misses} → PASS`);

console.log("");
if (ok) { console.log("SOAK VERIFY: PASS — challenge-bound, tamper-evident log; report signed + consistent; SLO passes against our pinned target."); process.exit(0); }
console.error("SOAK VERIFY: FAIL");
process.exit(1);
