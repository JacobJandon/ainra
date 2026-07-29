// SPDX-License-Identifier: Apache-2.0 OR MIT
// Suite Migration Drill 01 — the staging half (T2c-b): audit the LIVE network's signature suite.
//
// Reads the public contract (:8091) for the live subjects, then fetches each one's presentation bundle from the
// registrar daemons and inspects the actual signatures: a hybrid credential carries an ML-DSA-65 signature
// (kilobytes) alongside the 64-byte Ed25519 one. Confirms the network is already on the new suite and counts any
// legacy straggler that would need REISSUE (expected 0). Skips cleanly (exit 0) when staging isn't running, so it
// never blocks an offline gate — the LOCAL migration mechanics are proven by tools/suite-migration-drill.mjs.
//
//   node tools/staging-suite-audit.mjs
const ART = 'http://127.0.0.1:8091';
const DAEMONS = [4907, 4911];

function sigs(o, path = '', acc = []) {
  if (o && typeof o === 'object') for (const k of Object.keys(o)) {
    const v = o[k];
    if (typeof v === 'string' && /^[A-Za-z0-9+/_-]{40,}={0,2}$/.test(v)) acc.push([path + k, Buffer.from(v, 'base64').length]);
    else if (v && typeof v === 'object') sigs(v, path + k + '.', acc);
  }
  return acc;
}
const reach = async u => { try { const r = await fetch(u, { signal: AbortSignal.timeout(1500) }); return r.ok ? r : null; } catch { return null; } };

const head = await reach(ART + '/');
if (!head) { console.log('staging not running on :8091 — skipping the live audit (local mechanics proven separately).'); process.exit(0); }
const root = head.headers.get('x-ainra-root') || '(none)';
const reg = await (await fetch(ART + '/registry.json')).json();
const subs = [...new Set(JSON.stringify(reg).match(/ainra:[a-z0-9:._-]+@[0-9.]+/gi) || [])];
console.log(`network root header : ${root}`);
console.log(`public contract     : ${subs.length} versioned subjects\n`);

let hybrid = 0, legacy = 0, inspected = 0, edSig = 0;
for (const sub of subs) {
  let bundle = null;
  for (const p of DAEMONS) { const r = await reach(`http://127.0.0.1:${p}/present?sub=` + encodeURIComponent(sub)); if (r) { bundle = await r.json(); break; } }
  if (!bundle || bundle.error) continue;
  inspected++;
  const ss = sigs(bundle);
  const big = ss.filter(([, n]) => n > 2000);      // an ML-DSA-65 signature is kilobytes
  const small = ss.filter(([, n]) => n >= 60 && n <= 100); // an Ed25519 signature is 64 bytes
  const isHybrid = big.length > 0;
  if (isHybrid) { hybrid++; if (small.length) edSig = small[0][1]; } else legacy++;
  if (inspected <= 3) console.log(`  ${sub}  ⇒ ${isHybrid ? `HYBRID (ML-DSA present + Ed25519 ${small[0] ? small[0][1] : '?'}B)` : 'LEGACY — no PQC half'}`);
}
console.log(`\naudit: inspected ${inspected} live presentations · HYBRID ${hybrid} · legacy stragglers ${legacy} · Ed25519 sig ${edSig}B`);
const okState = inspected > 0 && legacy === 0 && hybrid > 0;
console.log(okState ? '✓ staging is already hybrid — 0 stragglers to REISSUE (confirms PLAN-M23 Task 0)' : (inspected === 0 ? '· no presentations reachable — daemons down' : '⚠ a legacy straggler is live — REISSUE it before flipping the policy'));
process.exit(inspected > 0 && legacy > 0 ? 1 : 0); // fail only if a real legacy straggler is live
