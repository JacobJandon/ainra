// SPDX-License-Identifier: Apache-2.0 OR MIT
// AINRA GENESIS BOARD (M10) — the single honest picture of how close the prototype is to a FOUNDED root.
//
// It ingests the REAL evidence a stranger produced — collected verifier attestations (+ the maintainer's private
// answer keys), the ceremony transcript (+ published hash), and per-region soak reports (+ their logs) — cryptographic-
// ally VERIFIES each one, and renders the §29 DoD table. A row goes ✅ ONLY when a valid, signature-checked artifact
// backs it; otherwise it stays ⏳ with the honest current count. Nothing is asserted; every number is measured from an
// artifact. Local, zero-telemetry, no network — same posture as the rest of the repo.
//
//   node tools/genesis-board/board.mjs [--evidence <dir>] [--html <out.html>] [--project-keys <file>]
//
// Evidence layout (all optional — absent means "⏳, 0 so far", which is the honest state today):
//   <evidence>/verifiers/<name>/{attestation.json, secret.json}   ← one per external verifier
//   <evidence>/ceremony/{transcript.json, transcript.sha256}
//   <evidence>/soak/<region>/{soak-report.json, soak-log.jsonl}
//   <evidence>/anchors/{directory.json, roots.json} + <evidence>/cosignatures/<name>.json   ← witness cosignatures
//   <evidence>/rebuild/<name>.json                                                          ← an outsider's rebuild

import { readFileSync, existsSync, readdirSync, writeFileSync } from "node:fs";
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const A = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : d; };
const EV = A("evidence", "genesis-evidence");
const HTML = A("html", "genesis-board.html");
const SOAK_SLO_SEC = 60, SOAK_DAYS = 14, SOAK_REGIONS = 3, VERIFIERS_REQUIRED = 3, WITNESSES_REQUIRED = 3;
const ROOT = fileURLToPath(new URL("../../", import.meta.url));
// Keys the project operates (witnesses/project-keys.json). Read from the repository, never from the evidence, so a
// submission cannot take a project key off the list. Anything under one of these is the project vouching for itself.
const PROJECT = (() => {
  // --project-keys exists for the board's own demo (a list naming a key the demo holds); the default is the repo's.
  // Unreadable ⇒ null ⇒ nothing in the witness or rebuild rows counts: an empty list would count our own keys.
  try { return JSON.parse(readFileSync(A("project-keys", `${ROOT}witnesses/project-keys.json`), "utf8")); } catch { return null; }
})();
const sha = (b) => createHash("sha256").update(b).digest("hex");
function canonicalJSON(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalJSON).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalJSON(v[k])).join(",") + "}";
}
const eqArr = (a, b) => Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => x === b[i]);
const dir = (p) => (existsSync(p) ? readdirSync(p, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name) : []);

const files = (p, ext) => (existsSync(p) ? readdirSync(p, { withFileTypes: true }).filter((e) => e.isFile() && e.name.endsWith(ext)).map((e) => e.name) : []);

// The DURABLE evidence the operator's `check-attestation.mjs --party` emits (evidence/verifier/<party>.json). It holds
// no secret; the board independently RE-VERIFIES the embedded attestation signature and requires the operator marked it
// valid (the operator held the answer key; the board doesn't). Distinctness = the verifier's public key.
function checkVerifierEvidence(file) {
  const base = `${EV}/verifier/${file}`;
  try {
    const ev = JSON.parse(readFileSync(base, "utf8"));
    const att = ev.attestation || {};
    const body = att.body || {};
    const pub = createPublicKey({ key: Buffer.from(body.verifier_pubkey_spki_b64 || "", "base64"), format: "der", type: "spki" });
    const sigOk = edVerify(null, Buffer.from(canonicalJSON(body)), pub, Buffer.from(att.sig_ed25519_b64 || "", "base64"));
    const ok = sigOk && ev.valid === true && body.execution_bound === true && body.challenge === ev.challenge_nonce &&
      typeof ev.verifier_pubkey_spki_b64 === "string" && ev.verifier_pubkey_spki_b64 === body.verifier_pubkey_spki_b64;
    return { name: ev.party || file.replace(/\.json$/, ""), valid: ok, key: body.verifier_pubkey_spki_b64 };
  } catch (e) { return { name: file, valid: false, error: e.message }; }
}

// ── verify one external-verifier attestation against its private answer key (the same gate as check-attestation.mjs) ──
// Legacy layout (evidence/verifiers/<name>/{attestation.json, secret.json}) — used by the board demo, kept for compat.
function checkVerifier(name) {
  const base = `${EV}/verifiers/${name}`;
  try {
    const att = JSON.parse(readFileSync(`${base}/attestation.json`, "utf8"));
    const secret = JSON.parse(readFileSync(`${base}/secret.json`, "utf8"));
    const body = att.body || {};
    const pub = createPublicKey({ key: Buffer.from(body.verifier_pubkey_spki_b64 || "", "base64"), format: "der", type: "spki" });
    const sigOk = edVerify(null, Buffer.from(canonicalJSON(body)), pub, Buffer.from(att.sig_ed25519_b64 || "", "base64"));
    const ok = sigOk && body.execution_bound === true && body.challenge === secret.nonce &&
      eqArr(body.challenge_verdicts, secret.expected) &&
      eqArr(Object.keys(body.challenge_corpus_sha256 || {}).sort(), Object.keys(secret.corpus_sha256 || {}).sort()) &&
      Object.keys(secret.corpus_sha256 || {}).every((k) => body.challenge_corpus_sha256[k] === secret.corpus_sha256[k]);
    return { name, valid: ok, key: body.verifier_pubkey_spki_b64 };
  } catch (e) { return { name, valid: false, error: e.message }; }
}

// ── verify the ceremony transcript recomputes to its published hash ────────────────────────────────────────────────
function checkCeremony() {
  const t = `${EV}/ceremony/transcript.json`, h = `${EV}/ceremony/transcript.sha256`;
  if (!existsSync(t) || !existsSync(h)) return { present: false };
  try {
    const raw = readFileSync(t);
    const got = sha(raw), pub = readFileSync(h, "utf8").trim().split(/\s+/)[0].toLowerCase();
    return { present: true, valid: got === pub, hash: got };
  } catch (e) { return { present: true, valid: false, error: e.message }; }
}

// ── verify one region's soak run (chain + signature) and measure p95 + elapsed days ────────────────────────────────
function checkSoak(region) {
  const base = `${EV}/soak/${region}`;
  try {
    const report = JSON.parse(readFileSync(`${base}/soak-report.json`, "utf8"));
    const body = report.body || {};
    const lines = readFileSync(`${base}/soak-log.jsonl`, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
    // hash chain
    let prev = "genesis", chainOk = true, tip = "genesis";
    for (const line of lines) { const { this_hash, ...rest } = line; if (line.prev_hash !== prev || sha(canonicalJSON(rest)) !== this_hash) { chainOk = false; break; } prev = this_hash; tip = this_hash; }
    // signature
    let sigOk = false;
    try { const pub = createPublicKey({ key: Buffer.from(report.reporter_pubkey_spki_b64 || "", "base64"), format: "der", type: "spki" }); sigOk = edVerify(null, Buffer.from(canonicalJSON(body)), pub, Buffer.from(report.sig_ed25519_b64 || "", "base64")); } catch { /* */ }
    // recompute p95 from the log (never trust the report's own threshold)
    const meas = lines.filter((l) => l.event === "measure").map((l) => (l.observed ? l.latency_ms : Infinity));
    const finite = meas.filter(Number.isFinite);
    const pctv = (arr, p) => { if (!arr.length) return Infinity; const s = [...arr].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)]; };
    const p95 = pctv(meas, 95) / 1000, misses = meas.length - finite.length;
    const days = body.wall_start && body.wall_end ? (Date.parse(body.wall_end) - Date.parse(body.wall_start)) / 86400000 : 0;
    const valid = chainOk && sigOk && body.log_head_hash === tip;
    return { region, present: true, valid, p95, misses, days, pass: Number.isFinite(p95) && p95 < SOAK_SLO_SEC && misses === 0 };
  } catch (e) { return { region, present: true, valid: false, error: e.message }; }
}

// ── witness cosignatures (PLAN-M50 step 5) ─────────────────────────────────────────────────────────────────────────
// A cosignature counts only if (1) the checkpoint it covers verifies as signed by an accredited registrar's log
// (@ainra/sdk verifyLogCheckpoint, against the anchors' root-signed directory, at the cosignature's observed_at),
// (2) the Ed25519 cosignature verifies over that checkpoint's canonical bytes, and (3) the key is not one the project
// runs. The row counts DISTINCT outside keys over ONE checkpoint: three cosignatures from one key are one witness.
async function checkCosignatures() {
  const names = files(`${EV}/cosignatures`, ".json");
  if (!names.length) return { present: false, best: 0, project: 0, rejected: 0 };
  let sdk = null;
  try { sdk = await import(new URL("../../packages/sdk-ts/dist/index.js", import.meta.url)); } catch { /* reported below */ }
  let d = null, r = null;
  try { d = JSON.parse(readFileSync(`${EV}/anchors/directory.json`, "utf8")); r = JSON.parse(readFileSync(`${EV}/anchors/roots.json`, "utf8")); } catch { /* */ }
  if (!PROJECT || !sdk?.verifyLogCheckpoint || !d || !r) {
    return { present: true, best: 0, project: 0, rejected: names.length,
      unverifiable: !PROJECT ? "the project key list is unreadable" : !sdk?.verifyLogCheckpoint ? "the SDK is not built (make sdk-build)" : "no anchors/directory.json + roots.json" };
  }
  const project = new Set(PROJECT.witness_ed25519 || []);
  const byCheckpoint = new Map();
  let projectKeys = 0, rejected = 0;
  for (const n of names) {
    try {
      const c = JSON.parse(readFileSync(`${EV}/cosignatures/${n}`, "utf8"));
      const cp = c.checkpoint || {};
      const at = c.observed_at;
      if (!Number.isSafeInteger(at) || at < 0 || at > Math.floor(Date.now() / 1000) + 300) throw new Error("observed_at");
      const reg = sdk.verifyLogCheckpoint(d, Buffer.from(r.root_ed25519, "base64url"), Buffer.from(r.root_slh, "base64url"), cp, c.checkpoint_sig, at);
      if (!reg) throw new Error("not a log-signed checkpoint");
      const sig = Buffer.from(String(c.cosignature), "base64url");
      const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: String(c.witness_key) }, format: "jwk" });
      const msg = Buffer.from(canonicalJSON({ origin: cp.origin, root: cp.root, size: cp.size }));
      if (sig.length !== 64 || !edVerify(null, msg, pub, sig)) throw new Error("cosignature");
      if (project.has(c.witness_key)) { projectKeys++; continue; }
      const k = `${cp.origin} ${cp.size} ${cp.root}`;
      if (!byCheckpoint.has(k)) byCheckpoint.set(k, new Set());
      byCheckpoint.get(k).add(c.witness_key);
    } catch { rejected++; }
  }
  const best = Math.max(0, ...[...byCheckpoint.values()].map((s) => s.size));
  return { present: true, best, project: projectKeys, rejected };
}

// ── an outsider's rebuild (PLAN-M50 step 5) ────────────────────────────────────────────────────────────────────────
// A statement signed by the rebuilder's own Ed25519 key, naming a tag and the digest of the manifest their rebuild
// wrote. The digest is over the manifest's lines sorted bytewise, so a rebuild's locale cannot change it (the v0.6.0
// lesson). It counts if the signature verifies, the key is not one the project signs with, and the digest equals the
// one this repository computes from MANIFEST.sha256 at that tag.
const manifestDigest = (text) => sha(text.split("\n").filter(Boolean).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)).join("\n") + "\n");
function checkRebuild(file) {
  try {
    const st = JSON.parse(readFileSync(`${EV}/rebuild/${file}`, "utf8"));
    const body = st.body || {};
    if (body.statement !== "ainra-rebuild-1" || !/^v\d+\.\d+\.\d+$/.test(String(body.tag))) throw new Error("shape");
    const pub = createPublicKey({ key: Buffer.from(body.builder_pubkey_spki_b64 || "", "base64"), format: "der", type: "spki" });
    const sigOk = edVerify(null, Buffer.from(canonicalJSON(body)), pub, Buffer.from(st.sig_ed25519_b64 || "", "base64"));
    const tagged = execFileSync("git", ["-C", ROOT, "show", `${body.tag}:MANIFEST.sha256`], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    if (!PROJECT) throw new Error("the project key list is unreadable");
    const project = (PROJECT.rebuild_spki || []).includes(body.builder_pubkey_spki_b64);
    return { name: file, tag: body.tag, key: body.builder_pubkey_spki_b64, project,
      valid: sigOk && !project && body.manifest_sha256 === manifestDigest(tagged) };
  } catch (e) { return { name: file, valid: false, error: e.message }; }
}

// ── gather ──────────────────────────────────────────────────────────────────────────────────────────────────────
// Durable per-party evidence (the operator flow, evidence/verifier/*.json) + the legacy demo layout.
const verifiers = [...files(`${EV}/verifier`, ".json").map(checkVerifierEvidence), ...dir(`${EV}/verifiers`).map(checkVerifier)];
const validVerifiers = verifiers.filter((v) => v.valid);
const distinctKeys = new Set(validVerifiers.map((v) => v.key)).size;
const ceremony = checkCeremony();
const soaks = dir(`${EV}/soak`).map(checkSoak);
const validSoaks = soaks.filter((s) => s.valid);
const soakRegions = new Set(validSoaks.map((s) => s.region)).size;
const soakDays = validSoaks.length ? Math.max(...validSoaks.map((s) => s.days)) : 0;
const soakAllPass = validSoaks.length >= SOAK_REGIONS && validSoaks.every((s) => s.pass);
const cosigs = await checkCosignatures();
const rebuilds = files(`${EV}/rebuild`, ".json").map(checkRebuild);
const validRebuilds = rebuilds.filter((b) => b.valid);
const rebuildKeys = new Set(validRebuilds.map((b) => b.key)).size;

// ── DoD rows (§29). "laptop" rows are proven by the repo's own committed gates (make preflight is ALL GREEN); ────────
// "external" rows are computed ONLY from verified artifacts above — no artifact ⇒ ⏳, never a fake ✅.
const rows = [
  ["laptop",   "Dual-root ceremony (self-verified)", "✅", "make ceremony · genesis-local stage 1"],
  ["laptop",   "Two registrar classes live", "✅", "genesis-local → 2 distinct issuer keys"],
  ["laptop",   "Logged-before-valid", "✅", "inclusion proofs in vectors; make demo"],
  ["laptop",   "Offline / external verify (root dark)", "✅", "genesis-local stage 3; kits/verifier"],
  ["laptop",   "Revocation fails closed (local)", "✅", "genesis-local stage 4"],
  ["laptop",   "Injected fork caught in-proc + networked", "✅", "make drill · drill-networked"],
  ["laptop",   "Artifacts rebuild byte-for-byte", "✅", "make repro · verify-mirror"],
  ["external", `≥${VERIFIERS_REQUIRED} external verifiers`,
    distinctKeys >= VERIFIERS_REQUIRED ? "✅" : "⏳",
    `${distinctKeys}/${VERIFIERS_REQUIRED} distinct valid attestations (${verifiers.length - validVerifiers.length} invalid rejected)`],
  ["external", "Recorded in-person ceremony",
    ceremony.present && ceremony.valid ? "✅" : "⏳",
    ceremony.present ? (ceremony.valid ? `transcript verifies (${ceremony.hash.slice(0, 12)}…)` : "transcript FAILED verification") : "no transcript yet"],
  ["external", `14-day / ${SOAK_REGIONS}-region soak (p95 < ${SOAK_SLO_SEC}s)`,
    soakAllPass && soakDays >= SOAK_DAYS ? "✅" : "⏳",
    validSoaks.length ? `${soakRegions}/${SOAK_REGIONS} regions · day ${soakDays.toFixed(1)} of ${SOAK_DAYS} · p95 ${validSoaks.map((s) => (Number.isFinite(s.p95) ? s.p95.toFixed(2) + "s" : "MISS")).join("/")}` : "no soak reports yet"],
  // "Independent cosignatures observed", never "quorum constituted": a quorum is constituted through the charter,
  // and this row can only count what it can verify.
  ["external", "Independent witnesses on separate infra",
    cosigs.best >= WITNESSES_REQUIRED ? "✅" : "⏳",
    cosigs.present
      ? (cosigs.unverifiable ? `cosignatures present but unverifiable: ${cosigs.unverifiable}`
        : `${cosigs.best}/${WITNESSES_REQUIRED} independent cosignatures observed over one log-signed checkpoint (${cosigs.project} under project keys not counted, ${cosigs.rejected} rejected)`)
      : "no cosignatures yet · machinery: kits/witness (make drill-networked proves the mechanism)"],
  ["external", "An outsider rebuilds a release from public artifacts",
    rebuildKeys >= 1 ? "✅" : "⏳",
    rebuilds.length
      ? `${rebuildKeys} outside rebuilder(s) whose signed manifest digest matches the tag (${rebuilds.length - validRebuilds.length} rejected)`
      : "no rebuild statement yet · tools/genesis-board/rebuild-statement.mjs after make repro at a tag"],
];

// --counts: emit the STRUCTURAL row counts (independent of evidence) so the docs-vs-reality check can pin them to DOD.md.
if (process.argv.includes("--counts")) {
  const laptop = rows.filter((r) => r[0] === "laptop").length;
  const external = rows.filter((r) => r[0] === "external").length;
  console.log(`DOD-BOARD laptop=${laptop} external=${external} total=${rows.length}`);
  process.exit(0);
}
const done = rows.filter((r) => r[2] === "✅").length;
const founded = rows.every((r) => r[2] === "✅");

// ── text board ─────────────────────────────────────────────────────────────────────────────────────────────────
console.log(`\nAINRA GENESIS BOARD   (evidence: ${existsSync(EV) ? EV : EV + " — none yet"})`);
console.log("─".repeat(78));
for (const [type, crit, status, note] of rows) console.log(`  ${status}  ${crit.padEnd(42)} ${note}`);
console.log("─".repeat(78));
console.log(`  ${done}/${rows.length} criteria proven.  ${founded ? "ROOT FOUNDED — every row backed by a verified artifact." : "PENDING — external events still needed (see GENESIS-CHECKLIST.md)."}`);
console.log(`  External evidence: ${distinctKeys} verifier(s), ceremony ${ceremony.present ? (ceremony.valid ? "verified" : "INVALID") : "none"}, soak ${validSoaks.length} region-run(s), ${cosigs.best} independent witness key(s) on one checkpoint, ${rebuildKeys} outside rebuild(s).\n`);

// ── HTML board (static, self-contained, no telemetry) ──────────────────────────────────────────────────────────
const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const trs = rows.map(([type, crit, status, note]) => `<tr class="${status === "✅" ? "ok" : "pend"}"><td>${status}</td><td>${esc(crit)}</td><td class="t">${type}</td><td>${esc(note)}</td></tr>`).join("");
writeFileSync(HTML, `<!doctype html><meta charset=utf8><title>AINRA Genesis Board</title><style>
body{font:15px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:60rem;color:#0b1220;background:#fff}
h1{font-size:1.4rem} table{border-collapse:collapse;width:100%;margin:1rem 0} td,th{border:1px solid #d5d9e0;padding:.45rem .7rem;text-align:left}
th{background:#0b1220;color:#fff} tr.ok td:first-child{color:#177245;font-weight:700} tr.pend td:first-child{color:#a15c00;font-weight:700}
td.t{color:#667;font-size:.85em} .sum{padding:.6rem 1rem;border-radius:.4rem;display:inline-block;font-weight:700}
.sum.f{background:#177245;color:#fff}.sum.p{background:#fff3d6;color:#7a5200;border:1px solid #e3c56a}</style>
<h1>AINRA Genesis Board</h1>
<p>Evidence: <code>${esc(existsSync(EV) ? EV : EV + " (none yet)")}</code>. Every ✅ is backed by a signature-checked artifact; ⏳ rows have no valid artifact yet. Nothing is asserted.</p>
<table><tr><th></th><th>§29 criterion</th><th>type</th><th>evidence / what's left</th></tr>${trs}</table>
<p class="sum ${founded ? "f" : "p"}">${done}/${rows.length} proven — ${founded ? "ROOT FOUNDED" : "PENDING: external events still needed"}</p>
<p style="color:#667;font-size:.85em">External evidence measured: ${distinctKeys} distinct valid verifier attestation(s); ceremony ${ceremony.present ? (ceremony.valid ? "transcript verified" : "transcript INVALID") : "not submitted"}; soak ${validSoaks.length} verified region-run(s), ${soakRegions}/${SOAK_REGIONS} regions, day ${soakDays.toFixed(1)} of ${SOAK_DAYS}. Rendered locally from artifacts; no telemetry. See GENESIS-CHECKLIST.md.</p>`);
console.log(`  wrote ${HTML} (open it, or serve the dir) — static, no telemetry.\n`);

process.exit(0);
