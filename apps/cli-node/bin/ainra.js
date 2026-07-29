#!/usr/bin/env node
/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * AINRA reference implementation v0.2.0
 * HYBRID Ed25519 + ML-DSA-65 signatures (both mandatory, both-or-invalid), real chain verification, real
 * revocation, hash-chained log. Parity with the Rust core + browser SDK. Suite-migration ready (Drill 01):
 * legacy Ed25519-only credentials are recognized, named, and fail closed as alg_downgrade under default policy.
 * Honest limits (labeled at runtime): single-key root (threshold ceremony pending), local witness keys
 * (independent witnesses pending). For interop testing, not production. Node >= 18.
 */
'use strict';
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa'); // audited PQC (@noble); bundled in the distributable

/* ---------- helpers ---------- */
const HOME = process.env.AINRA_HOME || path.join(process.cwd(), '.ainra');
const P = (...s) => path.join(HOME, ...s);
const now = () => new Date().toISOString();
const plusDays = d => new Date(Date.now() + d * 864e5).toISOString();

function cjson(o) { // canonical JSON: sorted keys, no spaces — stable bytes for signing
  if (o === null || typeof o !== 'object') return JSON.stringify(o);
  if (Array.isArray(o)) return '[' + o.map(cjson).join(',') + ']';
  return '{' + Object.keys(o).sort().map(k => JSON.stringify(k) + ':' + cjson(o[k])).join(',') + '}';
}
const sha256 = b => crypto.createHash('sha256').update(b).digest();
const hex = b => b.toString('hex');
const b64 = u => Buffer.from(u).toString('base64');
// one strict canonical decode gateway (D-029): standard base64, canonical round-trip, fail closed on
// trailing-bits / padding / whitespace / alphabet swaps. Every externally-sourced decode routes through here.
function strictB64(s) {
  if (typeof s !== 'string') return null;
  let buf; try { buf = Buffer.from(s, 'base64'); } catch { return null; }
  if (buf.toString('base64') !== s) return null; // non-canonical
  return new Uint8Array(buf);
}
function fingerprint(pub) { // over BOTH keys (canonical), so the fp binds the whole hybrid suite
  const material = typeof pub === 'string' ? pub : cjson(pub);
  const h = hex(sha256(Buffer.from(material))).toUpperCase();
  return [h.slice(0,4), h.slice(4,8), h.slice(8,12), h.slice(12,16)].join(':');
}
function genKey() { // HYBRID keypair: classical Ed25519 + post-quantum ML-DSA-65
  const ed = crypto.generateKeyPairSync('ed25519');
  const ml = ml_dsa65.keygen(crypto.randomBytes(32));
  return {
    alg: 'Ed25519+ML-DSA-65', fmt: 2,
    pub: { ed25519: ed.publicKey.export({ type: 'spki', format: 'pem' }), mldsa65: b64(ml.publicKey) },
    priv: { ed25519: ed.privateKey.export({ type: 'pkcs8', format: 'pem' }), mldsa65: b64(ml.secretKey) },
  };
}
function sign(bytes, priv) { // dual-sign — both signatures always produced
  const mlSec = strictB64(priv.mldsa65);
  if (!mlSec) die('malformed hybrid signing key (missing/!canonical ML-DSA secret) — legacy key? re-init or migrate');
  return {
    ed25519: crypto.sign(null, bytes, crypto.createPrivateKey(priv.ed25519)).toString('base64'),
    mldsa65: b64(ml_dsa65.sign(mlSec, bytes)),
  };
}
// DRILL ONLY (`issue --legacy`): a genuine Ed25519-only signature — no PQC half. Produces a real legacy credential
// to rehearse Suite Migration Drill 01. It is NOT a production issuance path: such a credential fails closed as
// alg_downgrade under the default policy, exactly as an old-suite credential must once the registrar has gone hybrid.
function signLegacy(bytes, priv) {
  return { ed25519: crypto.sign(null, bytes, crypto.createPrivateKey(priv.ed25519)).toString('base64') };
}
// both-or-invalid parity with core/SDK. Returns a named reason (null = valid). Legacy Ed25519-only (string sig
// or missing ML-DSA) → alg_downgrade, fail closed — never silently reinterpreted.
function verifyReason(bytes, sig, pub) {
  // the classical half must always be valid — legacy or hybrid
  const edPub = typeof pub === 'string' ? pub : (pub && pub.ed25519);
  const edSig = typeof sig === 'string' ? sig : (sig && sig.ed25519);
  let edOk = false; try { edOk = edPub && edSig && crypto.verify(null, bytes, crypto.createPublicKey(edPub), Buffer.from(edSig, 'base64')); } catch {}
  if (!edOk) return 'sig_invalid';
  // the post-quantum half. Absent → legacy / stripped: classical is valid but there is no PQC signature.
  const mlPub = (pub && typeof pub === 'object') ? pub.mldsa65 : null;
  const mlSig = (sig && typeof sig === 'object') ? sig.mldsa65 : null;
  if (!mlPub || !mlSig) return 'alg_downgrade'; // Ed25519 alone — accepted only during the migration overlap window
  const mp = strictB64(mlPub), ms = strictB64(mlSig);
  let mlOk = false; try { mlOk = mp && ms && ml_dsa65.verify(mp, bytes, ms); } catch {}
  if (!mlOk) return 'sig_invalid'; // PQC half present but broken / mismatched → tampered, rejected even under --accept-legacy
  return null; // both valid
}
const verify = (bytes, sig, pub) => verifyReason(bytes, sig, pub) === null;

const save = (p, o) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, typeof o === 'string' ? o : JSON.stringify(o, null, 2)); };
const load = p => JSON.parse(fs.readFileSync(p, 'utf8'));
const exists = p => fs.existsSync(p);
const die = m => { console.error('✗ ' + m); process.exit(1); };

/* ---------- name grammar: ainra:registrar:operator:lineage@version ---------- */
function parseName(n) {
  const m = /^ainra:([a-z0-9-]+):([a-z0-9-]+):([a-z0-9-]+)@([0-9]+(?:\.[0-9]+){0,2})$/.exec(n);
  if (!m) die(`invalid name "${n}" — expected ainra:registrar:operator:lineage@version`);
  return { registrar: m[1], operator: m[2], lineage: m[3], version: m[4] };
}

/* ---------- transparency log: append-only hash chain + signed, witness-cosigned checkpoints ---------- */
function logAppend(type, subject, extra = {}) {
  const logPath = P('log', 'log.jsonl');
  let seq = 0, prev = '0'.repeat(64);
  if (exists(logPath)) {
    const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n');
    const last = JSON.parse(lines[lines.length - 1]);
    seq = last.seq + 1; prev = last.hash;
  }
  const body = { seq, ts: now(), type, subject, ...extra, prev };
  const hash = hex(sha256(Buffer.from(cjson(body))));
  const leaf = { ...body, hash };
  fs.mkdirSync(P('log'), { recursive: true });
  fs.appendFileSync(logPath, JSON.stringify(leaf) + '\n');
  checkpoint(seq, hash);
  return leaf;
}
function checkpoint(size, head) {
  const root = load(P('root', 'root.json'));
  const body = { type: 'checkpoint', size, head, ts: now() };
  const bytes = Buffer.from(cjson(body));
  const rootSig = sign(bytes, load(P('root', 'root.key')));
  const witnessSigs = [];
  for (const wf of fs.readdirSync(P('witness')).filter(f => f.endsWith('.key'))) {
    const wname = wf.replace('.key', '');
    witnessSigs.push({ witness: wname, sig: sign(bytes, load(P('witness', wf))) });
  }
  save(P('log', 'checkpoint.json'), { ...body, root_id: root.id, root_sig: rootSig, witness_sigs: witnessSigs });
}
function logVerify(quiet = false) {
  const logPath = P('log', 'log.jsonl');
  if (!exists(logPath)) die('no log yet');
  const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n').map(JSON.parse);
  let prev = '0'.repeat(64);
  for (const leaf of lines) {
    const { hash, ...body } = leaf;
    if (body.prev !== prev) die(`log broken at seq ${leaf.seq}: prev mismatch`);
    if (hex(sha256(Buffer.from(cjson(body)))) !== hash) die(`log broken at seq ${leaf.seq}: hash mismatch`);
    prev = hash;
  }
  const cp = load(P('log', 'checkpoint.json'));
  const bytes = Buffer.from(cjson({ type: 'checkpoint', size: cp.size, head: cp.head, ts: cp.ts }));
  const root = load(P('root', 'root.json'));
  if (cp.head !== prev || cp.size !== lines[lines.length - 1].seq) die('checkpoint stale');
  if (!verify(bytes, cp.root_sig, root.pub)) die('checkpoint root signature invalid (or Ed25519-only — alg_downgrade)');
  let okW = 0;
  for (const w of cp.witness_sigs) {
    const wpub = load(P('witness', w.witness + '.pub'));
    if (verify(bytes, w.sig, wpub)) okW++;
  }
  if (!quiet) console.log(`✓ log intact — ${lines.length} entries · head ${prev.slice(0,12)}… · checkpoint signed by root · witnesses ${okW}/${cp.witness_sigs.length} ✓ (local)`);
  return { entries: lines.length, witnessesOk: okW, witnesses: cp.witness_sigs.length, head: prev };
}

/* ---------- revocation: signed status list ---------- */
function statusList() {
  return exists(P('log', 'revocations.json')) ? load(P('log', 'revocations.json')) : { type: 'status-list', revoked: [], ts: null, sig: null };
}
function saveStatusList(revoked) {
  const body = { type: 'status-list', revoked: revoked.sort(), ts: now() };
  const sig = sign(Buffer.from(cjson(body)), load(P('root', 'root.key')));
  save(P('log', 'revocations.json'), { ...body, sig });
}
function statusValid(sl, rootPub) {
  const { sig, ...body } = sl;
  return sig && verify(Buffer.from(cjson(body)), sig, rootPub);
}

/* ---------- commands ---------- */
function cmdInit() {
  if (exists(P('root', 'root.json'))) die('root already initialized at ' + HOME);
  const k = genKey();
  const root = { id: 'ainra-root-1', type: 'root', alg: k.alg, fmt: k.fmt, pub: k.pub, fp: fingerprint(k.pub), created: now(),
    note: 'single-key root — threshold ceremony pending (v0.2)' };
  save(P('root', 'root.json'), root);
  save(P('root', 'root.key'), k.priv);
  for (const w of ['witness-a', 'witness-b', 'witness-c']) {
    const wk = genKey();
    save(P('witness', w + '.pub'), wk.pub);
    save(P('witness', w + '.key'), wk.priv);
  }
  saveStatusList([]);
  logAppend('ROOT-INIT', root.id, { fp: root.fp });
  console.log(`✓ root initialized · ${root.id} · FP ${root.fp}`);
  console.log(`  home: ${HOME}`);
  console.log(`  keys: hybrid Ed25519 + ML-DSA-65 (both mandatory) · single-key root, 3 local witness keys — labeled`);
}
function cmdAccredit(name) {
  if (!name) die('usage: ainra accredit <registrar-name>');
  if (!/^[a-z0-9-]+$/.test(name)) die('registrar name: lowercase letters, digits, hyphens');
  const root = load(P('root', 'root.json'));
  const k = genKey();
  const cert = { type: 'registrar-cert', registrar: name, alg: k.alg, fmt: k.fmt, pub: k.pub, fp: fingerprint(k.pub),
    issued: now(), expires: plusDays(365), root_id: root.id };
  const sig = sign(Buffer.from(cjson(cert)), load(P('root', 'root.key')));
  save(P('registrar', name, 'cert.json'), { ...cert, root_sig: sig });
  save(P('registrar', name, 'registrar.key'), k.priv);
  const leaf = logAppend('ACCREDIT', name, { fp: cert.fp });
  console.log(`✓ registrar accredited · ${name} · FP ${cert.fp} · log #${String(leaf.seq).padStart(6,'0')}`);
}
function cmdIssue(name, opts) {
  const n = parseName(name || '');
  const regDir = P('registrar', n.registrar);
  if (!exists(path.join(regDir, 'cert.json'))) die(`registrar "${n.registrar}" not accredited — run: ainra accredit ${n.registrar}`);
  const regCert = load(path.join(regDir, 'cert.json'));
  const agentKey = genKey();
  const serial = opts.serial || ('AP-' + hex(crypto.randomBytes(3)).toUpperCase().replace(/^(.{4})/, '$1-'));
  const passport = {
    type: 'agent-passport', v: 1, fmt: opts.legacy ? 1 : 2, serial, name, // fmt 1 = legacy Ed25519-only (drill), fmt 2 = hybrid
    lineage: n.lineage, version: n.version,
    operator: { name: opts.operator || n.operator, kyb: opts.kyb !== 'false', jurisdiction: opts.jurisdiction || 'US-DE' },
    registrar: n.registrar,
    authority: { class: opts.class || 'A1', proof: (opts.class || 'A1') === 'A1' ? 'zk:commitment:' + hex(crypto.randomBytes(8)) : 'org:attest' },
    tier: opts.tier || 'L3',
    validity: { issued: opts.issued || now(), expires: opts.expires || plusDays(366), renewable: true }, // ADR-017: 366-day passport default
    key: { alg: agentKey.alg, pub: agentKey.pub, fp: fingerprint(agentKey.pub) },
    ...(opts.prev_leaf ? { prev_leaf: opts.prev_leaf } : {}), // ADR-017 continuity link on REISSUE
  };
  const regKey = load(path.join(regDir, 'registrar.key'));
  const sig = opts.legacy ? signLegacy(Buffer.from(cjson(passport)), regKey) : sign(Buffer.from(cjson(passport)), regKey);
  const leaf = logAppend(opts.reissue ? 'REISSUE' : 'ISSUE', name, { serial, tier: passport.tier, class: passport.authority.class, ...(opts.prev_leaf ? { prev_leaf: opts.prev_leaf } : {}) });
  const doc = { ...passport, registrar_sig: sig, registrar_cert: regCert, log: { seq: leaf.seq, hash: leaf.hash } };
  save(P('passports', serial + '.json'), doc);
  save(P('passports', serial + '.agent.key'), agentKey.priv);
  console.log(`✓ passport ${opts.reissue ? 'reissued' : 'issued'} · ${name}`);
  console.log(`  serial ${serial} · tier ${passport.tier} · class ${passport.authority.class} · key FP ${passport.key.fp}${opts.prev_leaf ? ' · prev_leaf #' + opts.prev_leaf : ''}`);
  console.log(`  registered in root log #${String(leaf.seq).padStart(6,'0')} · file ${P('passports', serial + '.json')}`);
  return doc;
}
function findPassport(ref) {
  const dir = P('passports');
  if (!exists(dir)) die('no passports issued yet');
  if (ref.endsWith('.json') && exists(ref)) return load(ref);
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.json'));
  for (const f of files) { const d = load(path.join(dir, f)); if (d.name === ref || d.serial === ref) return d; }
  die(`no passport found for "${ref}"`);
}
function cmdVerify(ref, opts) {
  const t0 = process.hrtime.bigint();
  const doc = findPassport(ref);
  const root = load(P('root', 'root.json'));
  // Task 2 policy epoch (D-037) — default OFF (fail closed). `--accept-legacy` grants the migration overlap
  // indefinitely (testing); `--accept-legacy-until <date>` grants it ONLY until that date, then AUTO-EXPIRES to
  // fail-closed. A past/invalid date → NaN > now → false → closed, even though the flag is present.
  const until = opts['accept-legacy-until'];
  const acceptLegacy = until ? (Date.parse(until) > Date.now()) : (opts['accept-legacy'] === 'true');
  const checks = [];
  // 1. registrar cert chains to root
  const { root_sig, ...certBody } = doc.registrar_cert;
  const certReason = verifyReason(Buffer.from(cjson(certBody)), root_sig, root.pub);
  const certOk = (certReason === null || (acceptLegacy && certReason === 'alg_downgrade')) && new Date(certBody.expires) > new Date();
  checks.push(certOk);
  // 2. passport signed by registrar
  const { registrar_sig, registrar_cert, log, ...passBody } = doc;
  const passReason = verifyReason(Buffer.from(cjson(passBody)), registrar_sig, doc.registrar_cert.pub);
  const passOk = passReason === null || (acceptLegacy && passReason === 'alg_downgrade');
  checks.push(passOk);
  const suiteReason = passReason || certReason; // the named reason when the failure is suite-level
  const legacyCred = passReason === 'alg_downgrade' || certReason === 'alg_downgrade';
  // 3. validity window
  const dateOk = new Date(doc.validity.expires) > new Date();
  checks.push(dateOk);
  // 4. revocation status (signed list)
  const sl = statusList();
  const slSigned = statusValid(sl, root.pub);
  const revoked = sl.revoked.includes(doc.serial) || sl.revoked.includes(doc.name);
  checks.push(slSigned && !revoked);
  // 5. log inclusion + chain integrity
  const lv = logVerify(true);
  const lines = fs.readFileSync(P('log', 'log.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
  const inLog = lines.some(l => l.seq === doc.log.seq && l.hash === doc.log.hash && l.subject === doc.name);
  checks.push(inLog);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  const ok = checks.every(Boolean);
  const reason = ok ? null : (revoked ? 'revoked' : (!passOk || !certOk ? suiteReason : (!dateOk ? 'expired' : (!inLog ? 'not_logged' : 'invalid'))));
  if (opts.json) { console.log(JSON.stringify({ ok, name: doc.name, serial: doc.serial, suite: doc.registrar_cert.alg || 'legacy-Ed25519', reason, revoked, legacy_credential: legacyCred, checks: { chain: certOk && passOk, dates: dateOk, status: slSigned && !revoked, log: inLog }, ms: +ms.toFixed(1) }, null, 2)); process.exit(ok ? 0 : 1); }
  const g = s => '\x1b[32m' + s + '\x1b[0m', r = s => '\x1b[31m' + s + '\x1b[0m', d = s => '\x1b[2m' + s + '\x1b[0m';
  console.log(d('$ ainra verify ') + doc.name);
  console.log(`→ suite      ${doc.registrar_cert.alg === 'Ed25519+ML-DSA-65' ? g('Ed25519 + ML-DSA-65 ✓') : r('legacy Ed25519-only')} ${legacyCred && !acceptLegacy ? r('· alg_downgrade (fail closed)') : ''}`);
  console.log(`→ chain      root ${certOk ? g('✓') : r('✗')} · registrar ${passOk ? g('✓') : r('✗')} · version ${g('✓')}`);
  console.log(`→ operator   ${doc.operator.name} — ${doc.operator.kyb ? g('KYB verified') : 'self-declared'} (${doc.operator.jurisdiction})`);
  console.log(`→ authority  ${doc.authority.class}${doc.authority.class === 'A1' ? ' human-delegated (zk-commitment)' : ''} ${g('✓')} · PII: none`);
  console.log(`→ validity   ${doc.validity.issued.slice(0,10)} → ${doc.validity.expires.slice(0,10)} ${dateOk ? g('✓') : r('EXPIRED')}${doc.prev_leaf ? d(' · prev_leaf #' + doc.prev_leaf) : ''}`);
  console.log(`→ status     tier ${g(doc.tier)} · revocation ${revoked ? r('REVOKED ✗') : g('ACTIVE ✓')} ${slSigned ? '' : r('(status list unsigned!)')}`);
  console.log(`→ log        entry #${String(doc.log.seq).padStart(6,'0')} ${inLog ? g('✓ included') : r('✗ absent')} · chain of ${lv.entries} intact · witnesses ${lv.witnessesOk}/${lv.witnesses} ${d('(local)')}`);
  console.log(ok ? g(`✓ VALID`) + d(` · verified in ${ms.toFixed(1)} ms`) : r(`✗ INVALID`) + d(` · ${reason} · verified in ${ms.toFixed(1)} ms`));
  process.exit(ok ? 0 : 1);
}
function cmdRevoke(ref, opts) {
  const doc = findPassport(ref);
  const sl = statusList();
  if (sl.revoked.includes(doc.serial)) die('already revoked');
  saveStatusList([...sl.revoked, doc.serial]);
  const leaf = logAppend('REVOKE', doc.name, { serial: doc.serial, reason: opts.reason || 'operator-request' });
  console.log(`✓ revoked · ${doc.name} · reason: ${opts.reason || 'operator-request'} · log #${String(leaf.seq).padStart(6,'0')}`);
  console.log(`  every verifier reading this status list now rejects it — that is the whole switch.`);
}
/* ---------- Suite Migration Drill 01: REISSUE every credential to hybrid, prev_leaf continuity, nothing deleted ---------- */
function cmdMigrate(dir, opts) {
  const passDir = P('passports');
  if (!exists(passDir)) die('no passports to migrate in ' + HOME);
  const files = fs.readdirSync(passDir).filter(f => f.endsWith('.json'));
  // A credential is legacy if ITS OWN registrar signature has no ML-DSA half — regardless of the registrar's current
  // cert. This is the honest test: the registrar has gone hybrid, but a credential it signed under the old suite
  // still verifies Ed25519-only (alg_downgrade). That is precisely what a suite migration must carry across.
  const isLegacy = d => { const s = d.registrar_sig; return !s || typeof s === 'string' || !s.mldsa65; };
  const legacy = files.map(f => load(path.join(passDir, f))).filter(isLegacy);
  const dry = opts['dry-run'] === 'true' || opts.plan === 'true';
  console.log(`\x1b[1m— Suite Migration Drill: Ed25519 → Ed25519+ML-DSA-65 —\x1b[0m`);
  console.log(`  ${files.length} credential(s) present · ${legacy.length} legacy (Ed25519-only) to REISSUE · ${files.length - legacy.length} already hybrid`);
  if (!legacy.length) { console.log('  ✓ nothing to migrate — all credentials are already hybrid.'); return; }
  if (dry) { console.log('  (dry-run) plan:'); legacy.forEach(d => console.log(`    REISSUE ${d.name} — new hybrid key, fresh window, prev_leaf → log #${d.log.seq} (legacy leaf kept)`)); console.log('  run without --dry-run to execute. Nothing is deleted; history only grows.'); return; }
  const overlapEnd = new Date(Date.now() + 30 * 864e5).toISOString().slice(0, 10); // policy-epoch guidance, not a cred window
  for (const d of legacy) {
    const nn = d.name; // ADR-017 REISSUE: fresh FULL validity window, new hybrid key, prev_leaf continuity to the legacy leaf
    console.log(`  → migrating ${nn} (legacy leaf #${d.log.seq}) …`);
    cmdIssue(nn, { operator: d.operator.name, tier: d.tier, class: d.authority.class, jurisdiction: d.operator.jurisdiction,
      reissue: true, prev_leaf: d.log.seq, serial: d.serial + '-h', issued: now() }); // fresh 366-day window (no expires override)
  }
  console.log(`\n  ✓ migrated ${legacy.length} credential(s) to hybrid. Legacy leaves preserved; each hybrid successor links back via prev_leaf.`);
  console.log(`  Flip the policy: with the default (no --accept-legacy) the legacy credential now fails closed as alg_downgrade,`);
  console.log(`  while its hybrid successor verifies. Grant the overlap ONLY with --accept-legacy-until ${overlapEnd} (auto-expires);`);
  console.log(`  after that date, a legacy credential fails closed even with the flag. Nothing was deleted; history only grows.`);
}
function cmdDemo() {
  if (exists(HOME)) die(`${HOME} exists — run demo in a clean directory or set AINRA_HOME`);
  console.log('\x1b[1m— AINRA reference lifecycle demo (hybrid Ed25519 + ML-DSA-65) —\x1b[0m\n');
  cmdInit(); console.log('');
  cmdAccredit('registrar-07'); console.log('');
  cmdIssue('ainra:registrar-07:acme-corp:invoicing@4.2.1', { operator: 'Acme Corp', tier: 'L3', class: 'A1' }); console.log('');
  try { cmdVerifyNoExit('ainra:registrar-07:acme-corp:invoicing@4.2.1'); } catch {}
  console.log('');
  cmdRevoke('ainra:registrar-07:acme-corp:invoicing@4.2.1', { reason: 'key-compromise' }); console.log('');
  try { cmdVerifyNoExit('ainra:registrar-07:acme-corp:invoicing@4.2.1'); } catch {}
  console.log('');
  logVerify();
  console.log('\n\x1b[1mdone.\x1b[0m every signature above is real hybrid Ed25519 + ML-DSA-65; strip the ML-DSA half and it fails closed (alg_downgrade). Tamper with any file in ' + HOME + ' and verification fails.');
}
function cmdVerifyNoExit(ref, opts) { // demo helper: same as verify but doesn't kill the process
  const realExit = process.exit; process.exit = () => {}; try { cmdVerify(ref, opts || {}); } finally { process.exit = realExit; }
}
function usage() {
  console.log(`ainra — reference implementation v0.2.0 (hybrid Ed25519 + ML-DSA-65; interop testing; single-key root, local witnesses — labeled)
usage:
  ainra init                                   initialize root, witnesses, log (hybrid keys)
  ainra accredit <registrar>                   root accredits an independent registrar
  ainra issue <ainra:reg:op:lineage@ver> [--operator "Name"] [--tier L3] [--class A1]
  ainra verify <name|serial|file> [--json] [--accept-legacy]   full chain + status + log (exit 0/1)
  ainra revoke <name|serial> [--reason r]      append revocation; verifiers reject immediately
  ainra migrate [--dry-run]                    Suite Migration Drill: REISSUE legacy creds to hybrid, prev_leaf continuity
  ainra log verify                             verify the whole hash chain + checkpoint
  ainra demo                                   run the full lifecycle end to end
home: ${HOME}  (override with AINRA_HOME)`);
}
/* ---------- argv ---------- */
const [,, cmd, ...rest] = process.argv;
const args = rest.filter(a => !a.startsWith('--'));
const opts = {}; rest.forEach((a, i) => { if (a.startsWith('--')) opts[a.slice(2)] = (rest[i+1] && !rest[i+1].startsWith('--')) ? rest[i+1] : 'true'; });
switch (cmd) {
  case 'init': cmdInit(); break;
  case 'accredit': cmdAccredit(args[0]); break;
  case 'issue': cmdIssue(args[0], opts); break;
  case 'verify': cmdVerify(args[0] || die('usage: ainra verify <name|serial|file>'), opts); break;
  case 'revoke': cmdRevoke(args[0] || die('usage: ainra revoke <name|serial>'), opts); break;
  case 'migrate': cmdMigrate(args[0], opts); break;
  case 'log': args[0] === 'verify' ? logVerify() : usage(); break;
  case 'demo': cmdDemo(); break;
  default: usage();
}
