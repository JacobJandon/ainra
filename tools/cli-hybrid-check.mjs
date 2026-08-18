// SPDX-License-Identifier: Apache-2.0 OR MIT
// CLI hybrid-suite conformance (M23 / Suite Migration Drill 01).
//
// Proves the DOWNLOADABLE reference CLI now enforces the same hybrid rule as the Rust core + browser SDK:
// Ed25519 + ML-DSA-65, both-signatures-or-invalid. It also proves the migration semantics the drill depends on —
// the CLI distinguishes a LEGACY / stripped credential (reason `alg_downgrade`, accepted ONLY during the overlap
// under `--accept-legacy`) from a TAMPERED one (reason `sig_invalid`, rejected under EVERY policy, incl. the flag).
//
// It runs the REAL CLI source — the exact file that ships bundled — against a live testbed, mutating only the
// passport's registrar signature. No network, no fixtures on disk. Exit 1 on any divergence.
//
// The core↔SDK differential corpus already proves this at the protocol level (24 `alg-downgrade-*` + `noncanon-*`
// vectors inside the corpus; `make diff`). This is the CLI reaching that same standard.
//
//   run:  node tools/cli-hybrid-check.mjs      (or `make cli-check`)
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(ROOT, 'apps/cli-node/bin/ainra.js');
// let the CLI source resolve @noble (the audited ML-DSA) from the SDK's install without a symlink (CJS NODE_PATH).
const env = { ...process.env, AINRA_HOME: mkdtempSync(join(tmpdir(), 'ainra-cli-hybrid-')), NODE_PATH: join(ROOT, 'packages/sdk-ts/node_modules') };

function cli(args, allowFail = false) {
  try { return { code: 0, out: execFileSync('node', [CLI, ...args], { env, encoding: 'utf8' }) }; }
  catch (e) { if (!allowFail) throw e; return { code: e.status ?? 1, out: (e.stdout || '') + (e.stderr || '') }; }
}
function verify(name, acceptLegacy) {
  const a = ['verify', name, '--json']; if (acceptLegacy) a.push('--accept-legacy');
  const r = cli(a, true); let j = {}; try { j = JSON.parse(r.out); } catch {} return { code: r.code, ...j };
}

// ── a live testbed: real root, real registrar, real hybrid passport ─────────────────────────────────────────────
const NAME = 'ainra:registrar-07:acme-corp:invoicing@4.2.1';
cli(['init']); cli(['accredit', 'registrar-07']);
cli(['issue', NAME, '--operator', 'Acme Corp', '--tier', 'L3']);
const passDir = join(env.AINRA_HOME, 'passports');
const passPath = join(passDir, readdirSync(passDir).find(f => f.endsWith('.json')));
const ORIGINAL = readFileSync(passPath, 'utf8');
const apply = (mut) => { const d = JSON.parse(ORIGINAL); if (mut) mut(d); writeFileSync(passPath, JSON.stringify(d, null, 2)); };

// ── the downgrade vectors: (mutation of registrar_sig) × (default policy | --accept-legacy overlap) ─────────────
const VECTORS = [
  { id: 'clean-hybrid',
    note: 'both signatures present and valid',
    mut: null,
    def: { ok: true,  reason: null },          leg: { ok: true,  reason: null } },
  { id: 'legacy-stripped-mldsa',
    note: 'ML-DSA half removed — Ed25519-only (a legacy credential)',
    mut: d => { delete d.registrar_sig.mldsa65; },
    // default: fails closed, named alg_downgrade. overlap: PASSES (reason null on a pass) but still flagged legacy.
    def: { ok: false, reason: 'alg_downgrade' }, leg: { ok: true,  reason: null, legacy: true } },
  { id: 'tampered-mldsa-canonical',
    note: 'ML-DSA sig canonical but wrong bytes — forged/broken PQC half',
    mut: d => { const b = Buffer.from(d.registrar_sig.mldsa65, 'base64'); b[0] ^= 0xff; d.registrar_sig.mldsa65 = b.toString('base64'); },
    def: { ok: false, reason: 'sig_invalid' },  leg: { ok: false, reason: 'sig_invalid' } },
  { id: 'noncanon-mldsa-b64',
    note: 'ML-DSA sig base64 non-canonical (trailing space) — D-029 strict gateway rejects',
    mut: d => { d.registrar_sig.mldsa65 = d.registrar_sig.mldsa65 + ' '; },
    def: { ok: false, reason: 'sig_invalid' },  leg: { ok: false, reason: 'sig_invalid' } },
];

let checks = 0, fails = 0;
const expect = (label, got, want) => {
  checks++;
  const okMatch = got.ok === want.ok;
  const reasonMatch = want.reason === undefined || (got.reason ?? null) === want.reason;
  const legacyMatch = want.legacy === undefined || got.legacy_credential === want.legacy;
  const pass = okMatch && reasonMatch && legacyMatch;
  if (!pass) { fails++; console.error(`  ✗ ${label} → ok=${got.ok} reason=${got.reason} legacy=${got.legacy_credential} (wanted ok=${want.ok} reason=${want.reason ?? '·'}${want.legacy !== undefined ? ' legacy=' + want.legacy : ''})`); }
  else console.log(`  ✓ ${label.padEnd(48)} ok=${String(got.ok).padEnd(5)} reason=${got.reason ?? '·'}`);
};

console.log('CLI hybrid-suite conformance — Ed25519 + ML-DSA-65, both-or-invalid\n');
for (const v of VECTORS) {
  apply(v.mut);
  expect(`${v.id} · default`,        verify(NAME, false), v.def);
  expect(`${v.id} · --accept-legacy`, verify(NAME, true),  v.leg);
}
apply(null); // leave the testbed clean

console.log(`\n${fails ? '✗' : '✓'} ${checks - fails}/${checks} checks pass — ${VECTORS.length} downgrade vectors × 2 policies` +
  (fails ? '' : '  (legacy⇒alg_downgrade, overlap-only; tampered⇒sig_invalid, always closed)'));
process.exit(fails ? 1 : 0);
