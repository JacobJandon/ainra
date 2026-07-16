// SPDX-License-Identifier: Apache-2.0 OR MIT
// Verify a soak run WITHOUT trusting the runner: (1) the append-only log is an unbroken hash chain (any edited,
// inserted, or dropped line breaks it); (2) the signed report's Ed25519 signature verifies; (3) the report's
// log_head_hash equals the actual chain tip; (4) the report's SLO verdict is recomputed from the log's measurements.
//
//   node verify-log.mjs --log <soak-log.jsonl> --report <soak-report.json>

import { readFileSync } from "node:fs";
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";

const A = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : d; };
const logPath = A("log"), repPath = A("report");
if (!logPath || !repPath) { console.error("usage: verify-log.mjs --log <f> --report <f>"); process.exit(2); }
const sha256hex = (b) => createHash("sha256").update(b).digest("hex");
const sortedStringify = (o) => JSON.stringify(o, Object.keys(o).sort());
let ok = true;
const pass = (m) => console.log("  ✓ " + m);
const fail = (m) => { console.error("  ✗ " + m); ok = false; };

// (1) hash chain
const lines = readFileSync(logPath, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
let prev = "genesis";
let chainOk = true, tip = "genesis";
for (const [i, line] of lines.entries()) {
  const { this_hash, ...rest } = line;
  const recomputed = sha256hex(JSON.stringify(rest, Object.keys(rest).sort()));
  if (line.prev_hash !== prev) { fail(`log line ${i}: prev_hash breaks the chain`); chainOk = false; break; }
  if (recomputed !== this_hash) { fail(`log line ${i}: this_hash does not match its contents (edited?)`); chainOk = false; break; }
  prev = this_hash; tip = this_hash;
}
if (chainOk) pass(`append-only hash chain intact over ${lines.length} entries (tip ${tip.slice(0, 16)}…)`);

// (2) report signature + (3) head hash
const report = JSON.parse(readFileSync(repPath, "utf8"));
try {
  const pub = createPublicKey({ key: Buffer.from(report.reporter_pubkey_spki_b64, "base64"), format: "der", type: "spki" });
  edVerify(null, Buffer.from(sortedStringify(report.body)), pub, Buffer.from(report.sig_ed25519_b64, "base64"))
    ? pass("soak-report signature verifies") : fail("soak-report signature does NOT verify");
} catch (e) { fail("report signature errored: " + e.message); }
report.body.log_head_hash === tip ? pass("report log_head_hash == the log's chain tip")
  : fail("report log_head_hash != the actual log tip (report/log mismatch)");

// (4) recompute the SLO verdict from the log's measurements (don't trust the report's own claim)
const meas = lines.filter((l) => l.event === "measure").map((l) => (l.observed ? l.latency_ms : Infinity));
const finite = meas.filter(Number.isFinite);
const pctv = (arr, p) => { if (!arr.length) return Infinity; const s = [...arr].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)]; };
const p95 = pctv(meas, 95) / 1000;
const misses = meas.length - finite.length;
const slo = report.body.slo.revocation_p95_sec;
const recomputedPass = Number.isFinite(p95) && p95 < slo && misses === 0;
recomputedPass === report.body.slo.pass
  ? pass(`SLO verdict recomputed from the log matches the report (p95 ${Number.isFinite(p95) ? p95.toFixed(3) + "s" : "MISS"} vs <${slo}s → ${recomputedPass ? "PASS" : "BREACH"})`)
  : fail(`report SLO verdict (${report.body.slo.pass}) does NOT match the log-recomputed verdict (${recomputedPass})`);

console.log("");
if (ok) { console.log("SOAK VERIFY: PASS — the log is tamper-evident, the report is signed and consistent, and the SLO verdict is reproducible from the data."); process.exit(0); }
console.error("SOAK VERIFY: FAIL");
process.exit(1);
