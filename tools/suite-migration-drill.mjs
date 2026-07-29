// SPDX-License-Identifier: Apache-2.0 OR MIT
// Suite Migration Drill 01 — the reproducible harness (M23 / ADR-017 trap (ii)).
//
// Rehearses the exact event the protocol must survive: a cryptographic-suite migration over a RUNNING network.
// The root + registrar are hybrid from the start (as the real network already is); a genuine LEGACY credential
// (real Ed25519-only signature, `issue --legacy`) stands in for one the registrar signed before it went hybrid.
// We then migrate it — REISSUE to hybrid, fresh full window, `prev_leaf` continuity to the legacy leaf, nothing
// deleted — and prove: the legacy credential now fails closed (alg_downgrade) under the default policy while its
// hybrid successor verifies, the overlap is grantable ONLY through the auto-expiring policy epoch, and prev_leaf
// walks the boundary in the transparency log. Real crypto throughout; no network; asserts every claim (exit 1).
//
//   node tools/suite-migration-drill.mjs            → run + print the transcript
//   node tools/suite-migration-drill.mjs --quiet     → assert only (for CI)
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(ROOT, 'apps/cli-node/bin/ainra.js');
const HOME = mkdtempSync(join(tmpdir(), 'ainra-migration-drill-'));
const env = { ...process.env, AINRA_HOME: HOME, NODE_PATH: join(ROOT, 'packages/sdk-ts/node_modules') };
const QUIET = process.argv.includes('--quiet');

const strip = s => s.replace(/\x1b\[[0-9;]*m/g, '');
function cli(args, allowFail = false) {
  try { return { code: 0, out: strip(execFileSync('node', [CLI, ...args], { env, encoding: 'utf8' })) }; }
  catch (e) { if (!allowFail) throw e; return { code: e.status ?? 1, out: strip((e.stdout || '') + (e.stderr || '')) }; }
}
function verify(ref, ...flags) {
  const r = cli(['verify', ref, '--json', ...flags], true);
  let j = {}; try { j = JSON.parse(r.out); } catch {} return { code: r.code, ...j };
}
const passport = serial => JSON.parse(readFileSync(join(HOME, 'passports', serial + '.json'), 'utf8'));
const say = (...a) => { if (!QUIET) console.log(...a); };

let fails = 0;
function ok(label, cond) {
  if (cond) say(`  \x1b[32m✓\x1b[0m ${label}`);
  else { fails++; console.error(`  \x1b[31m✗ ${label}\x1b[0m`); }
}

const NAME = 'ainra:registrar-07:acme-corp:invoicing@4.2.1';
say('\x1b[1m— Suite Migration Drill 01 — Ed25519 → Ed25519 + ML-DSA-65 over a running network —\x1b[0m\n');

// ── 1. a hybrid root + hybrid registrar (mirrors the real network) ──────────────────────────────────────────────
cli(['init']); cli(['accredit', 'registrar-07']);
say('1. root + registrar accredited HYBRID (Ed25519 + ML-DSA-65) — the network is already on the new suite.');

// ── 2. a genuine legacy credential the registrar signed under the OLD suite ─────────────────────────────────────
cli(['issue', NAME, '--operator', 'Acme Corp', '--tier', 'L3', '--legacy']);
const LSER = readdirSync(join(HOME, 'passports')).find(f => f.endsWith('.json')).replace('.json', '');
const L = passport(LSER);
say(`2. issued a LEGACY credential  serial ${LSER}  fmt ${L.fmt}  sig halves [${Object.keys(L.registrar_sig)}]  log #${L.log.seq}`);
ok('legacy credential is fmt 1, Ed25519-only (no ML-DSA half)', L.fmt === 1 && !L.registrar_sig.mldsa65);

// ── 3. verify the legacy credential under every policy ──────────────────────────────────────────────────────────
say('\n3. verify the legacy credential:');
const preDefault = verify(LSER);
const preFlag    = verify(LSER, '--accept-legacy');
const preFuture  = verify(LSER, '--accept-legacy-until', '2035-01-01');
const prePast    = verify(LSER, '--accept-legacy-until', '2020-01-01');
say(`   default              → ok=${preDefault.ok} reason=${preDefault.reason}`);
say(`   --accept-legacy       → ok=${preFlag.ok} legacy_credential=${preFlag.legacy_credential}`);
say(`   --accept-legacy-until 2035-01-01 → ok=${preFuture.ok}   (overlap open)`);
say(`   --accept-legacy-until 2020-01-01 → ok=${prePast.ok} reason=${prePast.reason}  (overlap auto-expired → closed)`);
ok('default policy fails closed as alg_downgrade', preDefault.ok === false && preDefault.reason === 'alg_downgrade');
ok('overlap accepts it (flag) and flags it legacy', preFlag.ok === true && preFlag.legacy_credential === true);
ok('overlap accepts it while the epoch is open', preFuture.ok === true);
ok('overlap auto-expires: past epoch fails closed even with the flag', prePast.ok === false && prePast.reason === 'alg_downgrade');

// ── 4. migrate — REISSUE to hybrid, prev_leaf continuity, nothing deleted ───────────────────────────────────────
say('\n4. migrate:');
const dry = cli(['migrate', HOME, '--dry-run']);
ok('dry-run prints a plan and changes nothing', /dry-run/.test(dry.out) && readdirSync(join(HOME, 'passports')).filter(f => f.endsWith('.json')).length === 1);
cli(['migrate', HOME]);
const HSER = LSER + '-h';
const Hy = passport(HSER);
say(`   reissued HYBRID successor  serial ${HSER}  fmt ${Hy.fmt}  sig halves [${Object.keys(Hy.registrar_sig)}]  log #${Hy.log.seq}  prev_leaf #${Hy.prev_leaf}`);
ok('successor is hybrid (fmt 2, both signature halves)', Hy.fmt === 2 && !!Hy.registrar_sig.mldsa65 && !!Hy.registrar_sig.ed25519);
ok('successor prev_leaf points at the legacy leaf (continuity walks the boundary)', Hy.prev_leaf === L.log.seq);
ok('nothing deleted — legacy leaf preserved, both credentials on disk', readdirSync(join(HOME, 'passports')).filter(f => f.endsWith('.json')).length === 2);

// ── 5. flip the policy — legacy fails closed, hybrid successor verifies ─────────────────────────────────────────
say('\n5. after migration, default policy:');
const postLegacy = verify(LSER);
const postHybrid = verify(HSER);
say(`   legacy    ${LSER}   → ok=${postLegacy.ok} reason=${postLegacy.reason}`);
say(`   hybrid    ${HSER} → ok=${postHybrid.ok} suite=${postHybrid.suite}`);
ok('the once-valid legacy credential now fails closed (alg_downgrade)', postLegacy.ok === false && postLegacy.reason === 'alg_downgrade');
ok('its hybrid successor verifies on the new suite', postHybrid.ok === true && postHybrid.suite === 'Ed25519+ML-DSA-65');

// ── 6. the transparency log carries the boundary ────────────────────────────────────────────────────────────────
const lv = cli(['log', 'verify']);
ok('log chain intact', /intact|✓/.test(lv.out));

say(`\n\x1b[1mSuite mix now:\x1b[0m 1 legacy (fails closed) + 1 hybrid (valid), linked #${L.log.seq} → #${Hy.log.seq} by prev_leaf.`);
say(fails ? `\n\x1b[31m✗ ${fails} assertion(s) failed\x1b[0m` : `\n\x1b[32m✓ drill complete — every claim proven with real hybrid signatures\x1b[0m`);
process.exit(fails ? 1 : 0);
