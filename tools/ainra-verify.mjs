// SPDX-License-Identifier: Apache-2.0 OR MIT
// `ainra-verify` — the CI/edge verification step. Verifies an AINRA presentation bundle against a dual-root-signed
// directory and exits 0 (VALID) or 1 (INVALID) — fail closed. Drop it into a pipeline as an `ainra-verify` step,
// or run it at an edge to gate a request. No network, no state, no telemetry.
//
//   node tools/ainra-verify.mjs --directory dir.json --roots roots.json --bundle bundle.json [--now T] [--quiet]
//
// Exit codes: 0 VALID · 1 INVALID (reason on stderr) · 2 usage/untrusted-directory.
//
//   node tools/ainra-verify.mjs --negative   offline: plants bad bundles; every one MUST be refused
//
// WITNESS: `--negative` copies the committed kits/verifier/sample-artifacts into a temp dir, plants seven defects —
// the revoked sample credential, claims edited to a higher tier, one byte flipped in the issuer's Ed25519 signature,
// one byte flipped in the log checkpoint root, a verify-time one second past expiry, a verify-time an hour after the
// status snapshot, and a roots file whose Ed25519 root key has one byte flipped — and runs THIS tool on each as a
// separate process. Each bundle plant must exit 1 AND print exactly `ainra-verify: INVALID (<reason>)` with the
// reason that defect should give (revoked, sig_invalid, sig_invalid, checkpoint_invalid, expired, stale_status);
// the roots plant must exit 2 AND say `untrusted directory`. So a crash, a parse error or a usage error never counts
// as a catch. Two controls must print exactly `ainra-verify: VALID` and exit 0: the untouched valid sample at its own
// `now`, and the same sample one minute later (so `--now` is really read, and a caller's own clock still works).
// A tool that refuses everything cannot pass; if the verdict check ever stops failing closed, a plant exits 0 and
// the negative control goes red.

import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Verifier } from "../packages/sdk-ts/dist/index.js";

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : def;
}
const has = (name) => process.argv.includes(`--${name}`);

if (has("negative")) negative();

// ── the negative control (see WITNESS above): every planted defect must be refused by a fresh run of this tool ──
function negative() {
  const SELF = fileURLToPath(import.meta.url);
  const SA = fileURLToPath(new URL("../kits/verifier/sample-artifacts/", import.meta.url));
  const read = (f) => JSON.parse(readFileSync(SA + f, "utf8"));
  const tmp = mkdtempSync(join(tmpdir(), "ainra-verify-neg-"));
  const flip = (s) => { const b = Buffer.from(s, "base64url"); b[b.length >> 1] ^= 0x01; return b.toString("base64url"); };
  const valid = read("bundle-valid.json");
  const claims = JSON.parse(Buffer.from(valid.claims, "base64url").toString("utf8"));
  const run = (name, { bundle = valid, roots = read("roots.json"), now = bundle.now }) => {
    const f = (k, v) => { const p = join(tmp, `${name}-${k}.json`); writeFileSync(p, JSON.stringify(v)); return p; };
    const r = spawnSync(process.execPath, [SELF, "--directory", SA + "directory.json", "--roots", f("roots", roots),
      "--bundle", f("bundle", bundle), "--now", String(now)], { encoding: "utf8" });
    return { code: r.status, out: (r.stdout + r.stderr).trim() };
  };
  // [label, plant, exit code wanted, exact output wanted] — the output is matched whole, so only the real refusal
  // for THAT defect counts; a crash or a "cannot read/parse" exit 2 does not.
  const invalid = (reason) => `ainra-verify: INVALID (${reason})`;
  const untrusted = "ainra-verify: untrusted directory (not signed by the expected roots)";
  const plants = [
    ["revoked credential (bundle-revoked.json)", { bundle: read("bundle-revoked.json") }, 1, invalid("revoked")],
    ["claims edited to tier L4", { bundle: { ...valid, claims: Buffer.from(JSON.stringify({ ...claims, tier: "L4" })).toString("base64url") } }, 1, invalid("sig_invalid")],
    ["issuer Ed25519 signature, one byte flipped", { bundle: { ...valid, issuer_sig: { ...valid.issuer_sig, ed25519: flip(valid.issuer_sig.ed25519) } } }, 1, invalid("sig_invalid")],
    ["checkpoint root, one byte flipped", { bundle: { ...valid, checkpoint: { ...valid.checkpoint, root: flip(valid.checkpoint.root) } } }, 1, invalid("checkpoint_invalid")],
    ["verify-time one second past exp", { now: claims.exp + 1 }, 1, invalid("expired")],
    ["verify-time one hour after the status snapshot", { now: valid.now + 3600 }, 1, invalid("stale_status")],
    ["roots file, Ed25519 root key one byte flipped", { roots: { ...read("roots.json"), root_ed25519: flip(read("roots.json").root_ed25519) } }, 2, untrusted],
  ];
  const controls = [
    ["the untouched valid sample at its own now", {}],
    ["the untouched valid sample one minute later (--now is read)", { now: valid.now + 60 }],
  ];
  let missed = 0;
  for (const [i, [label, plant]] of controls.entries()) {
    const r = run(`control${i}`, plant);
    if (r.code === 0 && r.out === "ainra-verify: VALID") console.log(`ok control: ${label} still exits 0 (${r.out})`);
    else { console.error(`MISSED control: ${label} exited ${r.code} (${r.out}) — a tool that refuses everything proves nothing`); missed++; }
  }
  for (const [i, [label, plant, want, say]] of plants.entries()) {
    const r = run(`plant${i}`, plant);
    if (r.code === want && r.out === say) console.log(`ok caught ${label} — exit ${r.code} (${r.out})`);
    else { console.error(`MISSED ${label} — exit ${r.code} (${r.out}), wanted exit ${want} (${say})`); missed++; }
  }
  rmSync(tmp, { recursive: true, force: true });
  if (missed) { console.error(`\nainra-verify negative control FAILED: ${missed} of ${plants.length + controls.length} not as required`); process.exit(1); }
  console.log(`\nainra-verify negative control OK: all ${plants.length} planted defects refused for the right reason, both valid controls accepted.`);
  process.exit(0);
}

const dirPath = arg("directory");
const rootsPath = arg("roots");
const bundlePath = arg("bundle");
const quiet = has("quiet");
if (!dirPath || !rootsPath || !bundlePath) {
  console.error("usage: ainra-verify --directory D --roots R --bundle B [--now T] [--quiet]");
  process.exit(2);
}

let directory, roots, bundle;
try {
  directory = JSON.parse(readFileSync(dirPath, "utf8"));
  roots = JSON.parse(readFileSync(rootsPath, "utf8"));
  bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
} catch (e) {
  console.error(`ainra-verify: cannot read/parse inputs: ${e.message}`);
  process.exit(2);
}
const now = arg("now") ? Number(arg("now")) : Math.floor(Date.now() / 1000);

const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh);
if (!verifier) {
  console.error("ainra-verify: untrusted directory (not signed by the expected roots)");
  process.exit(2);
}

// `--bench N` — time N verifies of this bundle (the "how cheap is verification" number: it's LOCAL CPU, once per
// relationship). Verification is client-side, so N devices verifying is N × this, and the root does zero work.
const benchN = arg("bench");
if (benchN) {
  const n = Number(benchN) || 10000;
  verifier.verify(bundle, now); // warm
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < n; i++) verifier.verify(bundle, now);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  console.log(`ainra-verify bench: ${(ms / n).toFixed(3)} ms/verify · ${Math.round(n / (ms / 1000))} verifies/s (local, 1 core)`);
  process.exit(0);
}

const verdict = verifier.verify(bundle, now);
if (verdict.verdict === "valid") {
  if (!quiet) console.log("ainra-verify: VALID");
  process.exit(0);
}
console.error(`ainra-verify: INVALID (${verdict.reason})`);
process.exit(1);
