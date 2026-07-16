// SPDX-License-Identifier: Apache-2.0 OR MIT
// AINRA revocation-propagation SOAK HARNESS. It is an INSTRUMENT: it continuously issues + revokes real lineages and
// measures, from >=3 vantage points, the REAL wall-clock time from a revocation to when a root-dark verifier at that
// vantage point first sees the passport as INVALID. Every measurement is appended to a hash-chained (append-only,
// tamper-evident) log; the report and the live status page are rendered FROM those measurements. No latency number
// is ever hardcoded — the SLO verdict (revocation p95 < target) is computed from the data and fails closed if missed.
//
//   node soak.mjs --registrar <url> --directory <dir.json> --roots <roots.json> --now <unix>
//                 [--vantages a,b,c] [--cycles N | --duration-sec S] [--poll-ms 200] [--slo-p95-sec 60] [--out <dir>]
//
// A vantage point is a real AINRA verifier (published @ainra/sdk). Locally they all poll one registrar (real host
// latency). For a real 3-region soak, run one process per region against the registrar's public URL / a regional
// mirror — the report then reflects what each region actually observed.

import { writeFileSync, appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { createHash, generateKeyPairSync, sign as edSign } from "node:crypto";
import { Verifier } from "@ainra/sdk";

const A = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : d; };
const registrar = A("registrar");
const now = Number(A("now"));
const outDir = A("out", "out");
const vantages = A("vantages", "local-a,local-b,local-c").split(",").map((s) => s.trim()).filter(Boolean);
const cycles = A("cycles") ? Number(A("cycles")) : null;
const durationSec = A("duration-sec") ? Number(A("duration-sec")) : null;
const pollMs = Number(A("poll-ms", "150"));
const sloP95Sec = Number(A("slo-p95-sec", "60"));
const challenge = A("challenge", ""); // a run identifier the collector pins out of band (binds the log + report)
if (!registrar || !now || !A("directory") || !A("roots")) {
  console.error("usage: soak.mjs --registrar <url> --directory <f> --roots <f> --now <unix> [...]");
  process.exit(2);
}
if (vantages.length < 3) { console.error("need >=3 vantage points (§29)"); process.exit(2); }
mkdirSync(outDir, { recursive: true });

const directory = JSON.parse(readFileSync(A("directory"), "utf8"));
const roots = JSON.parse(readFileSync(A("roots"), "utf8"));
// One independent root-dark verifier per vantage point (each holds only the directory + roots).
const verifiers = Object.fromEntries(vantages.map((v) => [v, Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh)]));
if (Object.values(verifiers).some((v) => !v)) { console.error("directory not trust-anchored by roots"); process.exit(2); }

const sha256hex = (b) => createHash("sha256").update(b).digest("hex");
const logPath = `${outDir}/soak-log.jsonl`;
let prevHash = "genesis";
function logEntry(obj) {
  // hash chain: each line commits to the previous, so the append-only log is tamper-evident end to end.
  const line = { ...obj, prev_hash: prevHash };
  line.this_hash = sha256hex(JSON.stringify(line, Object.keys(line).sort()));
  prevHash = line.this_hash;
  appendFileSync(logPath, JSON.stringify(line) + "\n");
  return line;
}
const jitter = () => `${Date.now().toString(36)}${Math.floor(process.hrtime()[1]).toString(36)}`; // uniq lineage id (kit layer only)

async function post(path, body) {
  const r = await fetch(`${registrar}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`POST ${path} → ${r.status}`);
  return r.json();
}
async function presentVerdict(sub, verifier) {
  const r = await fetch(`${registrar}/present?sub=${encodeURIComponent(sub)}&now=${now}`);
  if (!r.ok) throw new Error(`present → ${r.status}`);
  const bundle = await r.json();
  return verifier.verify(bundle, now);
}

const measurements = []; // {vantage, latency_ms}
const startWall = Date.now();
logEntry({ ts: new Date(startWall).toISOString(), event: "soak-start", challenge, registrar, vantages, host: process.env.HOSTNAME || "local", now, slo_p95_sec: sloP95Sec });

let cycle = 0;
const keepGoing = () => (cycles !== null ? cycle < cycles : (Date.now() - startWall) / 1000 < durationSec);
console.log(`soak: ${vantages.length} vantage points · ${cycles !== null ? cycles + " cycles" : durationSec + "s"} · SLO p95 < ${sloP95Sec}s`);

while (keepGoing()) {
  cycle++;
  const op = `op${cycle % 90}`; // stay within the registrar's status capacity by cycling the lineage id space
  const lineage = `soak${jitter()}`;
  const sub = `ainra:${directory.entries[0].registrar}:${op}:${lineage}@1.0.0`;
  try {
    await post("/issue", { operator: op, lineage, version: "1.0.0", tier: "L1", auth_class: "A2", principal_proof: "0011223344556677", capabilities: ["read:x"], scope_ceiling: ["read:x"], hops: [] });
    // sanity: it must be VALID before revocation (else we are not measuring a real revocation)
    const pre = await presentVerdict(sub, verifiers[vantages[0]]);
    if (pre.verdict !== "valid") { logEntry({ ts: new Date().toISOString(), event: "skip", cycle, reason: `pre-revoke verdict ${pre.verdict}` }); continue; }

    const tRevoke = process.hrtime.bigint();
    await post("/revoke", { sub, now });
    // each vantage point independently races to observe the revocation.
    await Promise.all(vantages.map(async (v) => {
      let latencyMs = null;
      const deadline = Date.now() + sloP95Sec * 1000 * 4; // give up well past the SLO; a miss is recorded as such
      while (Date.now() < deadline) {
        const verdict = await presentVerdict(sub, verifiers[v]);
        if (verdict.verdict === "invalid" && verdict.reason === "revoked") {
          latencyMs = Number(process.hrtime.bigint() - tRevoke) / 1e6;
          break;
        }
        await new Promise((r) => setTimeout(r, pollMs));
      }
      const entry = logEntry({ ts: new Date().toISOString(), event: "measure", cycle, vantage: v, sub, latency_ms: latencyMs, observed: latencyMs !== null });
      if (latencyMs !== null) measurements.push({ vantage: v, latency_ms: latencyMs });
      else measurements.push({ vantage: v, latency_ms: Infinity }); // an un-propagated revocation is a max miss
      void entry;
    }));
  } catch (e) {
    logEntry({ ts: new Date().toISOString(), event: "error", cycle, error: String(e.message || e) });
  }
}

// ── percentiles (computed from the measured log, never hardcoded) ────────────────────────────────────────────────
function pct(arr, p) {
  if (!arr.length) return null;
  const s = [...arr].sort((a, b) => a - b);
  const i = Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1);
  return s[i];
}
function summarize(rows) {
  const lat = rows.map((r) => r.latency_ms);
  const finite = lat.filter((x) => Number.isFinite(x));
  return { count: rows.length, observed: finite.length, misses: lat.length - finite.length,
    p50_ms: pct(finite, 50), p95_ms: pct(lat, 95), p99_ms: pct(lat, 99), max_ms: finite.length ? Math.max(...finite) : null };
}
const overall = summarize(measurements);
const perVantage = Object.fromEntries(vantages.map((v) => [v, summarize(measurements.filter((m) => m.vantage === v))]));
const p95Sec = Number.isFinite(overall.p95_ms) ? overall.p95_ms / 1000 : Infinity;
const sloPass = p95Sec < sloP95Sec && overall.misses === 0;

const reportBody = {
  kind: "ainra/soak-report/v1",
  challenge, // pinned out of band by the collector; also stamped in the log's soak-start entry (binds log↔report)
  host: process.env.HOSTNAME || "local",
  registrar, vantages, now,
  wall_start: new Date(startWall).toISOString(), wall_end: new Date().toISOString(),
  cycles: cycle, measurements: measurements.length,
  slo: { revocation_p95_sec: sloP95Sec, measured_p95_sec: Number.isFinite(p95Sec) ? Number(p95Sec.toFixed(3)) : null, pass: sloPass },
  overall, per_vantage: perVantage,
  log_head_hash: prevHash, // the tip of the append-only hash chain (verifiable against soak-log.jsonl)
  note: "All latencies MEASURED (wall-clock revoke→observed-INVALID); nothing hardcoded. Local vantage points measure single-host latency; a real 3-region soak measures regional propagation. A THIRD PARTY must pin the SLO + the expected challenge/key out of band — a self-signed report proves internal consistency + tamper-evidence, not that the operator didn't fabricate the run.",
};
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
// FULL recursive canonical JSON (an array replacer would drop nested keys — the slo/overall/per_vantage objects).
function canonicalJSON(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalJSON).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalJSON(v[k])).join(",") + "}";
}
const sig = edSign(null, Buffer.from(canonicalJSON(reportBody)), privateKey).toString("base64");
const report = { body: reportBody, reporter_pubkey_spki_b64: publicKey.export({ type: "spki", format: "der" }).toString("base64"), sig_ed25519_b64: sig };
writeFileSync(`${outDir}/soak-report.json`, JSON.stringify(report, null, 2) + "\n");

// ── live status page rendered FROM the measured data ─────────────────────────────────────────────────────────────
const rows = vantages.map((v) => { const s = perVantage[v]; return `<tr><td>${v}</td><td>${s.observed}/${s.count}</td><td>${s.p50_ms?.toFixed(1) ?? "—"}</td><td>${Number.isFinite(s.p95_ms) ? s.p95_ms.toFixed(1) : "MISS"}</td><td>${Number.isFinite(s.p99_ms) ? s.p99_ms.toFixed(1) : "MISS"}</td></tr>`; }).join("");
writeFileSync(`${outDir}/soak-status.html`, `<!doctype html><meta charset=utf8><title>AINRA soak status</title><style>body{font:14px system-ui;margin:2rem;max-width:60rem}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:.4rem .6rem;text-align:right}td:first-child,th:first-child{text-align:left}.slo{padding:.5rem 1rem;border-radius:.4rem;color:#fff;display:inline-block}.ok{background:#177245}.bad{background:#a11}</style>
<h1>AINRA revocation-propagation soak</h1>
<p>host ${reportBody.host} · registrar ${registrar} · ${cycle} cycles · ${measurements.length} measurements · window ${reportBody.wall_start} → ${reportBody.wall_end}</p>
<p class="slo ${sloPass ? "ok" : "bad"}">SLO revocation p95 &lt; ${sloP95Sec}s: measured p95 = ${Number.isFinite(p95Sec) ? p95Sec.toFixed(3) + "s" : "MISS"} → ${sloPass ? "PASS" : "BREACH"}</p>
<table><tr><th>vantage</th><th>observed</th><th>p50 ms</th><th>p95 ms</th><th>p99 ms</th></tr>${rows}</table>
<p style="color:#666">Rendered from soak-log.jsonl (append-only, hash-chained head ${prevHash.slice(0, 16)}…). Nothing here is asserted; every number is measured.</p>`);

console.log(`\nmeasured p95 = ${Number.isFinite(p95Sec) ? p95Sec.toFixed(3) + "s" : "MISS"} (SLO < ${sloP95Sec}s) · misses ${overall.misses} · → ${sloPass ? "PASS" : "BREACH"}`);
console.log(`wrote ${outDir}/soak-report.json (signed) + soak-status.html + soak-log.jsonl`);
process.exit(sloPass ? 0 : 1); // fail closed on a missed SLO
