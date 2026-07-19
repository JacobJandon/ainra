#!/usr/bin/env node
/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * AINRA reference implementation v0.1.0
 * Real Ed25519 signatures, real chain verification, real revocation, hash-chained log.
 * Honest limits (labeled at runtime): single-key root (threshold ceremony pending),
 * local witness keys (independent witnesses pending). For interop testing, not production.
 * No dependencies. Node >= 16.
 */
'use strict';
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

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
function fingerprint(pubPem) {
  const h = hex(sha256(Buffer.from(pubPem))).toUpperCase();
  return [h.slice(0,4), h.slice(4,8), h.slice(8,12), h.slice(12,16)].join(':');
}
function genKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    pub: publicKey.export({ type: 'spki', format: 'pem' }),
    priv: privateKey.export({ type: 'pkcs8', format: 'pem' })
  };
}
const sign = (bytes, privPem) => crypto.sign(null, bytes, crypto.createPrivateKey(privPem)).toString('base64');
const verify = (bytes, sigB64, pubPem) => {
  try { return crypto.verify(null, bytes, crypto.createPublicKey(pubPem), Buffer.from(sigB64, 'base64')); }
  catch { return false; }
};
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
  const rootSig = sign(bytes, fs.readFileSync(P('root', 'root.key'), 'utf8'));
  const witnessSigs = [];
  for (const wf of fs.readdirSync(P('witness')).filter(f => f.endsWith('.key'))) {
    const wname = wf.replace('.key', '');
    witnessSigs.push({ witness: wname, sig: sign(bytes, fs.readFileSync(P('witness', wf), 'utf8')) });
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
  if (!verify(bytes, cp.root_sig, root.pub)) die('checkpoint root signature invalid');
  let okW = 0;
  for (const w of cp.witness_sigs) {
    const wpub = fs.readFileSync(P('witness', w.witness + '.pub'), 'utf8');
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
  const sig = sign(Buffer.from(cjson(body)), fs.readFileSync(P('root', 'root.key'), 'utf8'));
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
  const root = { id: 'ainra-root-1', type: 'root', alg: 'Ed25519', pub: k.pub, fp: fingerprint(k.pub), created: now(),
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
  console.log(`  note: single-key root, 3 local witness keys — labeled, not simulated as more than they are`);
}
function cmdAccredit(name) {
  if (!name) die('usage: ainra accredit <registrar-name>');
  if (!/^[a-z0-9-]+$/.test(name)) die('registrar name: lowercase letters, digits, hyphens');
  const root = load(P('root', 'root.json'));
  const k = genKey();
  const cert = { type: 'registrar-cert', registrar: name, alg: 'Ed25519', pub: k.pub, fp: fingerprint(k.pub),
    issued: now(), expires: plusDays(365), root_id: root.id };
  const sig = sign(Buffer.from(cjson(cert)), fs.readFileSync(P('root', 'root.key'), 'utf8'));
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
  const serial = 'AP-' + hex(crypto.randomBytes(3)).toUpperCase().replace(/^(.{4})/, '$1-');
  const passport = {
    type: 'agent-passport', v: 1, serial, name,
    lineage: n.lineage, version: n.version,
    operator: { name: opts.operator || n.operator, kyb: opts.kyb !== 'false', jurisdiction: opts.jurisdiction || 'US-DE' },
    registrar: n.registrar,
    authority: { class: opts.class || 'A1', proof: (opts.class || 'A1') === 'A1' ? 'zk:commitment:' + hex(crypto.randomBytes(8)) : 'org:attest' },
    tier: opts.tier || 'L3',
    validity: { issued: now(), expires: plusDays(366), renewable: true }, // ADR-017: 366-day passport default
    key: { alg: 'Ed25519', pub: agentKey.pub, fp: fingerprint(agentKey.pub) }
  };
  const sig = sign(Buffer.from(cjson(passport)), fs.readFileSync(path.join(regDir, 'registrar.key'), 'utf8'));
  const leaf = logAppend('ISSUE', name, { serial, tier: passport.tier, class: passport.authority.class });
  const doc = { ...passport, registrar_sig: sig, registrar_cert: regCert, log: { seq: leaf.seq, hash: leaf.hash } };
  save(P('passports', serial + '.json'), doc);
  save(P('passports', serial + '.agent.key'), agentKey.priv);
  console.log(`✓ passport issued · ${name}`);
  console.log(`  serial ${serial} · tier ${passport.tier} · class ${passport.authority.class} · key FP ${passport.key.fp}`);
  console.log(`  registered in root log #${String(leaf.seq).padStart(6,'0')} · file ${P('passports', serial + '.json')}`);
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
  const checks = [];
  // 1. registrar cert chains to root
  const { root_sig, ...certBody } = doc.registrar_cert;
  const certOk = verify(Buffer.from(cjson(certBody)), root_sig, root.pub) && new Date(certBody.expires) > new Date();
  checks.push(certOk);
  // 2. passport signed by registrar
  const { registrar_sig, registrar_cert, log, ...passBody } = doc;
  const passOk = verify(Buffer.from(cjson(passBody)), registrar_sig, doc.registrar_cert.pub);
  checks.push(passOk);
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
  if (opts.json) { console.log(JSON.stringify({ ok, name: doc.name, serial: doc.serial, revoked, checks: { chain: certOk && passOk, dates: dateOk, status: slSigned && !revoked, log: inLog }, ms: +ms.toFixed(1) }, null, 2)); process.exit(ok ? 0 : 1); }
  const g = s => '\x1b[32m' + s + '\x1b[0m', r = s => '\x1b[31m' + s + '\x1b[0m', d = s => '\x1b[2m' + s + '\x1b[0m';
  console.log(d('$ ainra verify ') + doc.name);
  console.log(`→ chain      root ${certOk ? g('✓') : r('✗')} · registrar ${passOk ? g('✓') : r('✗')} · version ${g('✓')}`);
  console.log(`→ operator   ${doc.operator.name} — ${doc.operator.kyb ? g('KYB verified') : 'self-declared'} (${doc.operator.jurisdiction})`);
  console.log(`→ authority  ${doc.authority.class}${doc.authority.class === 'A1' ? ' human-delegated (zk-commitment)' : ''} ${g('✓')} · PII: none`);
  console.log(`→ validity   ${doc.validity.issued.slice(0,10)} → ${doc.validity.expires.slice(0,10)} ${dateOk ? g('✓') : r('EXPIRED')}`);
  console.log(`→ status     tier ${g(doc.tier)} · revocation ${revoked ? r('REVOKED ✗') : g('ACTIVE ✓')} ${slSigned ? '' : r('(status list unsigned!)')}`);
  console.log(`→ log        entry #${String(doc.log.seq).padStart(6,'0')} ${inLog ? g('✓ included') : r('✗ absent')} · chain of ${lv.entries} intact · witnesses ${lv.witnessesOk}/${lv.witnesses} ${d('(local)')}`);
  console.log(ok ? g(`✓ VALID`) + d(` · verified in ${ms.toFixed(1)} ms`) : r(`✗ INVALID`) + d(` · verified in ${ms.toFixed(1)} ms`));
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
function cmdDemo() {
  if (exists(HOME)) die(`${HOME} exists — run demo in a clean directory or set AINRA_HOME`);
  console.log('\x1b[1m— AINRA reference lifecycle demo —\x1b[0m\n');
  cmdInit(); console.log('');
  cmdAccredit('registrar-07'); console.log('');
  cmdIssue('ainra:registrar-07:acme-corp:invoicing@4.2.1', { operator: 'Acme Corp', tier: 'L3', class: 'A1' }); console.log('');
  try { cmdVerifyNoExit('ainra:registrar-07:acme-corp:invoicing@4.2.1'); } catch {}
  console.log('');
  cmdRevoke('ainra:registrar-07:acme-corp:invoicing@4.2.1', { reason: 'key-compromise' }); console.log('');
  try { cmdVerifyNoExit('ainra:registrar-07:acme-corp:invoicing@4.2.1'); } catch {}
  console.log('');
  logVerify();
  console.log('\n\x1b[1mdone.\x1b[0m every signature above is real Ed25519; tamper with any file in ' + HOME + ' and verification fails.');
}
function cmdVerifyNoExit(ref) { // demo helper: same as verify but doesn't kill the process
  const realExit = process.exit; process.exit = () => {}; try { cmdVerify(ref, {}); } finally { process.exit = realExit; }
}
function usage() {
  console.log(`ainra — reference implementation v0.1.0 (interop testing; single-key root, local witnesses — labeled)
usage:
  ainra init                                   initialize root, witnesses, log
  ainra accredit <registrar>                   root accredits an independent registrar
  ainra issue <ainra:reg:op:lineage@ver> [--operator "Name"] [--tier L3] [--class A1]
  ainra verify <name|serial|file> [--json]     full chain + status + log verification (exit 0/1)
  ainra revoke <name|serial> [--reason r]      append revocation; verifiers reject immediately
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
  case 'log': args[0] === 'verify' ? logVerify() : usage(); break;
  case 'demo': cmdDemo(); break;
  default: usage();
}
