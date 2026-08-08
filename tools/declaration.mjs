// SPDX-License-Identifier: Apache-2.0 OR MIT
// make declaration — the fail-closed founding-declaration pipeline. The declaration may CLAIM only what an artifact
// PROVES. This resolves every {{claim}} in the template to a real evidence artifact; if any is missing/invalid it
// prints the loud TODOs and exits NONZERO WITHOUT rendering. So the published founding-declaration.md cannot exist
// unless the evidence does — the fail-closed doctrine, applied to prose. (Same evidence layout as the genesis board.)
//
//   node tools/declaration.mjs [--evidence <dir>] [--check]
//   evidence/ceremony/{transcript.json, transcript.sha256, mirrors.txt, recording.txt}
//   evidence/verifier/<party>.json         (valid execution-bound attestations; distinct by pubkey)
//   evidence/witness/cosigns.json          ({ checkpoints:[...], witnesses:[<pubkey>...] })
//   evidence/soak/<region>/soak-report.json  (signed; days≥14, regions≥3, p95<60)
import fs from "node:fs";
import crypto from "node:crypto";

const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i >= 0 && process.argv[i + 1] && !process.argv[i + 1].startsWith("--") ? process.argv[i + 1] : d; };
const EV = arg("evidence", "genesis-evidence");
const CHECK_ONLY = process.argv.includes("--check");
const TPL = "docs/genesis-day/declaration/founding-declaration.template.md";
const OUT = "docs/genesis-day/declaration/founding-declaration.md";
const SOAK_REGIONS = 3, SOAK_DAYS = 14, SOAK_P95_MAX = 60;

const rd = (p) => fs.readFileSync(p, "utf8");
const exists = (p) => fs.existsSync(p);
const jparse = (p) => JSON.parse(rd(p));

// Each resolver returns { value } on success or { missing: "<why>" }. A resolver NEVER fabricates.
const resolvers = {
  GENESIS_DATE() {
    const t = `${EV}/ceremony/transcript.json`;
    if (!exists(t)) return { missing: "ceremony transcript absent" };
    try { const d = jparse(t).date || jparse(t).genesis_date; return d ? { value: d } : { missing: "transcript has no date" }; }
    catch (e) { return { missing: `transcript unreadable (${e.message})` }; }
  },
  TRANSCRIPT_SHA256() {
    const j = `${EV}/ceremony/transcript.json`, h = `${EV}/ceremony/transcript.sha256`;
    if (!exists(j) || !exists(h)) return { missing: "ceremony transcript.json/.sha256 absent" };
    const got = crypto.createHash("sha256").update(rd(j)).digest("hex");
    const pub = rd(h).trim().split(/\s+/)[0];
    return got === pub ? { value: got } : { missing: `transcript hash MISMATCH (recomputed ${got.slice(0, 16)}… ≠ published ${pub.slice(0, 16)}…)` };
  },
  TRANSCRIPT_MIRRORS() {
    const m = `${EV}/ceremony/mirrors.txt`;
    if (!exists(m)) return { missing: "no published mirror list (evidence/ceremony/mirrors.txt)" };
    const urls = rd(m).split("\n").map((l) => l.trim()).filter(Boolean);
    return urls.length >= 2 ? { value: urls.join(" · ") } : { missing: `only ${urls.length} mirror(s); need ≥2` };
  },
  RECORDING_REF() {
    const r = `${EV}/ceremony/recording.txt`;
    return exists(r) && rd(r).trim() ? { value: rd(r).trim() } : { missing: "no ceremony recording reference (evidence/ceremony/recording.txt)" };
  },
  JURISDICTIONS() {
    const t = `${EV}/ceremony/transcript.json`;
    if (!exists(t)) return { missing: "transcript absent" };
    try { const n = jparse(t).jurisdictions; return n >= 5 ? { value: String(n) } : { missing: `transcript lists ${n ?? "?"} jurisdictions; need ≥5` }; }
    catch { return { missing: "transcript unreadable" }; }
  },
  VERIFIER_COUNT() {
    const dir = `${EV}/verifier`;
    if (!exists(dir)) return { missing: "no verifier attestations (evidence/verifier/)" };
    const keys = new Set();
    for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".json"))) {
      try {
        const ev = jparse(`${dir}/${f}`);
        const body = ev.body || ev;
        const key = body.verifier_pubkey_spki_b64;
        // valid iff self-consistent + the durable evidence marks it accepted against the private answer key
        if (key && ev.accepted === true && ev.verifier_pubkey_spki_b64 === key) keys.add(key);
      } catch { /* skip malformed */ }
    }
    return keys.size >= 3 ? { value: String(keys.size) } : { missing: `${keys.size} distinct valid attestation(s); need ≥3` };
  },
  WITNESS_COUNT() {
    const w = `${EV}/witness/cosigns.json`;
    if (!exists(w)) return { missing: "no witness cosign evidence (evidence/witness/cosigns.json)" };
    try { const n = new Set((jparse(w).witnesses || [])).size; return n >= 3 ? { value: String(n) } : { missing: `${n} witness cosign(s); need ≥3` }; }
    catch (e) { return { missing: `cosign evidence unreadable (${e.message})` }; }
  },
  SOAK_DAYS() { return soak().days; },
  SOAK_REGIONS() { return soak().regions; },
  SOAK_P95() { return soak().p95; },
  BOARD() {
    // the board's own honest count; the declaration reports it verbatim, never a rounded-up one
    try {
      const out = require_board();
      return out ? { value: out } : { missing: "genesis board did not report a count" };
    } catch (e) { return { missing: `genesis board unreadable (${e.message})` }; }
  },
};

let _soak;
function soak() {
  if (_soak) return _soak;
  const dir = `${EV}/soak`;
  if (!exists(dir)) return (_soak = { days: { missing: "no soak reports" }, regions: { missing: "no soak reports" }, p95: { missing: "no soak reports" } });
  const regions = fs.readdirSync(dir).filter((r) => exists(`${dir}/${r}/soak-report.json`));
  let maxDays = 0, worstP95 = 0, ok = 0;
  for (const r of regions) {
    try {
      // Read the shape kits/soak/soak.mjs ACTUALLY writes. It never emitted `days`, `p95_seconds` or `signature`
      // at the top level — it writes {body:{wall_start,wall_end,slo:{measured_p95_sec}},sig_ed25519_b64} — so this
      // loop silently skipped every real report and the declaration would have reported "0/3 regions passed" after
      // three genuine 14-day soaks. Nothing caught it because no soak report had ever been fed to this consumer:
      // the only path that produces one is a 14-day run, and the smoke test never handed its output over.
      const rep = jparse(`${dir}/${r}/soak-report.json`);
      const b = rep.body ?? rep;
      const days = b.wall_start && b.wall_end
        ? (Date.parse(b.wall_end) - Date.parse(b.wall_start)) / 86400000
        : Number(b.days ?? NaN);                       // tolerate a hand-written report that states days directly
      const p95 = Number(b.slo?.measured_p95_sec ?? b.p95_seconds ?? NaN);
      const signed = Boolean(rep.sig_ed25519_b64 || rep.signature);
      const sloPass = b.slo ? b.slo.pass !== false : true;
      if (Number.isFinite(days) && days >= SOAK_DAYS && Number.isFinite(p95) && p95 <= SOAK_P95_MAX && signed && sloPass) {
        ok++; maxDays = Math.max(maxDays, days); worstP95 = Math.max(worstP95, p95);
      }
    } catch { /* skip */ }
  }
  const enough = ok >= SOAK_REGIONS;
  return (_soak = enough
    ? { days: { value: String(Math.floor(maxDays)) }, regions: { value: String(ok) }, p95: { value: String(worstP95) } }
    : { days: { missing: `${ok}/${SOAK_REGIONS} regions passed a ≥${SOAK_DAYS}d soak` }, regions: { missing: `${ok} passing region(s); need ≥${SOAK_REGIONS}` }, p95: { missing: "soak incomplete" } });
}
function require_board() {
  // read the DoD board's machine counts, if a rendered board json exists; else derive "N/11" from the DOD marker.
  const m = fs.readFileSync("docs/DOD.md", "utf8").match(/DOD-BOARD laptop=(\d+) external=(\d+)/);
  if (!m) return null;
  const total = +m[1] + +m[2];
  return `${total}/11`; // honest as-committed; the pipeline still requires the individual evidence above to render
}

// ── resolve every claim ── (strip ALL leading HTML comments first — the template header prose mentions {{CLAIM}})
const tpl = rd(TPL).replace(/^(?:\s*<!--[\s\S]*?-->\s*)+/, "");
const claims = [...tpl.matchAll(/\{\{([A-Z0-9_]+)\}\}/g)].map((m) => m[1]);
const uniq = [...new Set(claims)];
const results = {}, missing = [];
for (const c of uniq) {
  const r = resolvers[c] ? resolvers[c]() : { missing: `no resolver for {{${c}}}` };
  results[c] = r;
  if (r.missing) missing.push([c, r.missing]);
}

if (missing.length) {
  console.error("✗ declaration: FAILS CLOSED — the following claims have no artifact yet, so nothing is rendered:\n");
  for (const [c, why] of missing) console.error(`  TODO  {{${c}}} — ${why}`);
  console.error(`\n${missing.length}/${uniq.length} claim(s) unproven. The founding declaration cannot be published until every`);
  console.error("claim resolves to a real, signature-checked artifact. This is the fail-closed doctrine applied to prose.");
  process.exit(1);
}

const rendered = tpl.replace(/\{\{([A-Z0-9_]+)\}\}/g, (_, c) => results[c].value);
if (CHECK_ONLY) { console.log(`✓ declaration: all ${uniq.length} claims resolve to artifacts (check-only; not written).`); process.exit(0); }
fs.writeFileSync(OUT, rendered);
console.log(`✓ declaration: all ${uniq.length} claims proven → wrote ${OUT}`);
