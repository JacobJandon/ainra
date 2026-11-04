// SPDX-License-Identifier: Apache-2.0 OR MIT
// The sixty-second VERIFY path (M16 Task 1). One command, no account, no server, no config:
//   make verify                     → verifies bundled sample credentials, ROOT DARK          [LOCAL TESTBED]
//   AINRA_NET=http://host:8091 …    → fetches a live network's public record + verifies it     [STAGING · TEST-ROOT]
//
// It prints the REAL verifier's verdict (the published @ainra/sdk — the code that agrees byte-for-byte in the
// conformance differential) plus the named-reason legend, then points at the cookbook. Nothing is mocked; nothing
// phones home. A VALID and a revoked credential are both shown, so the fail-closed behaviour is visible, not asserted.
//   node tools/verify-60s.mjs --negative   offline: plants bad samples; every one MUST turn the run red
//
// WITNESS: each shown sample carries the verdict it must get (the valid credential VALID, the revoked one refused as
// `revoked`), and the run exits 1, naming why, if either is wrong or either is missing. `--negative` runs THIS tool
// as a child process for every plant, so the run's own decision and exit are what is tested. It never touches a
// real network: it starts a loopback server that answers 404 (so the child takes the LOCAL TESTBED path, reading a
// planted copy of the sample files through AINRA_VERIFY_SAMPLES) or serves a planted copy of the committed
// site/net/registry.json (so the child takes the STAGING path). Local plants: the valid sample's claims edited to
// tier L4, one byte flipped in its issuer Ed25519 signature, the revoked credential shown in the valid slot, the
// valid credential shown in the revoked slot (the fail-closed half silently passing), and a roots file with one byte
// flipped (the directory no longer anchored). Staging plants: every revoked record removed (only VALID would be
// shown), one byte flipped in the valid record's issuer Ed25519 signature, and a valid record served in the revoked
// slot. Each plant must exit 1 with exactly the red line its defect should give; a crash does not count. The
// untouched samples and the untouched registry must each exit 0 and show both VALID and `revoked`, so a check that
// fails everything cannot pass. If the decision ever stops failing closed, a plant exits 0 and the negative goes red.
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Verifier } from "../packages/sdk-ts/dist/index.js";
import { runVector } from "../packages/sdk-ts/dist/conformance.js";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const REASONS = JSON.parse(readFileSync(ROOT + "docs/reasons.json", "utf8"));
const NET = process.env.AINRA_NET || "http://127.0.0.1:8091"; // auto-tried; falls back to the bundled testbed
const bold = (s) => `\x1b[1m${s}\x1b[0m`;
const grn = (s) => `\x1b[32m${s}\x1b[0m`;
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;

const line = (v) => (v.verdict === "valid" ? grn("✓ VALID") : red(`✗ INVALID · ${v.reason}`));
const gloss = (v) => (v.verdict === "valid" ? REASONS.valid : REASONS[v.reason] || "");

function printOne(label, claimsSub, tier, v) {
  console.log(`  ${line(v).padEnd(30)} ${bold(claimsSub)}  ${dim(`tier ${tier}`)}`);
  console.log(`    ${dim("→ " + gloss(v))}`);
}

// ── STAGING path: verify a live network's published record with the real SDK (export-reverify, AINRAscan pattern) ──
function toWire(rec, R, now) {
  const enc = (u) => Buffer.from(u).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return {
    name: rec.sub, expect: {},
    anchors: { [R.registrar]: { issuer_key: R.accreditation.issuer_key, log_root_key: R.accreditation.log_root_key } },
    presentation: {
      claims: enc(new TextEncoder().encode(rec.claims)),
      issuer_sig: { ed25519: rec.issuer_sig_ed25519, mldsa65: rec.issuer_sig_mldsa65 },
      now, chain_keys: rec.chain_keys, hop_proofs: rec.hop_proofs,
      status_list: R.status_list.status_list_b64, status_len: R.status_list.bit_len, status_issued_at: R.status_list.issued_at,
      freshness: "F3",
      checkpoint: { origin: rec.log_origin, size: rec.checkpoint_size, root: rec.checkpoint_root },
      checkpoint_sig: rec.checkpoint_sig, leaf_index: rec.leaf_index, inclusion_proof: rec.inclusion_proof,
      mandate_revocations: [], revoked_delegates: [],
    },
  };
}

async function tryStaging() {
  let res;
  try {
    res = await fetch(NET.replace(/\/$/, "") + "/registry.json", { signal: AbortSignal.timeout(2500) });
    if (!res.ok) return null;
  } catch { return null; }
  const net = (res.headers.get("X-AINRA-Network") || "staging").toLowerCase();
  const root = res.headers.get("X-AINRA-Root") || "test-root";
  const reg = await res.json();
  const now = reg.generated_window.verified_at;
  const label = net === "production" ? `${net.toUpperCase()} NETWORK` : "STAGING · TEST-ROOT";
  const records = reg.registrars.flatMap((R) => R.records.map((e) => ({ R, rec: e.record })));
  const valid = records.find((x) => !x.rec.revoked);
  const revoked = records.find((x) => x.rec.revoked);
  return { label, root, net: NET, now, samples: [valid, revoked].filter(Boolean).map(({ R, rec }) => ({ rec, expect: rec.revoked ? "revoked" : "valid", v: runVector(toWire(rec, R, now)) })) };
}

// ── LOCAL TESTBED path: verify the committed sample bundles ROOT DARK with the full directory-anchored Verifier ──
// Returns null when the directory is not trust-anchored by its roots. AINRA_VERIFY_SAMPLES points it at another
// copy of the sample files (the negative control uses it for its planted copies).
const SAMPLES = process.env.AINRA_VERIFY_SAMPLES ? resolve(process.env.AINRA_VERIFY_SAMPLES) + "/" : ROOT + "kits/verifier/sample-artifacts/";
const readSample = (f) => JSON.parse(readFileSync(SAMPLES + f, "utf8"));
function localTestbed(j = readSample) {
  const directory = j("directory.json"), roots = j("roots.json");
  const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh);
  if (!verifier) return null;
  const claimsOf = (b) => JSON.parse(Buffer.from(b.claims, "base64url").toString("utf8")); // sample bundle claims are base64url (SD-JWT form)
  const mk = (f, expect) => { const b = j(f); const c = claimsOf(b); return { rec: { sub: c.sub, tier: c.tier }, expect, v: verifier.verify(b, b.now) }; }; // each bundle carries its own verify-time
  const now = j("bundle-valid.json").now;
  return { label: "LOCAL TESTBED", root: "sample-root", net: "(bundled sample-artifacts, no network)", now, samples: [mk("bundle-valid.json", "valid"), mk("bundle-revoked.json", "revoked")] };
}

// A sample is wrong when it does not get the verdict it must: the valid credential VALID, the revoked one refused
// with the named reason `revoked` — a revoked credential coming back VALID is the failure this run exists to show.
const wrong = (s) => (s.expect === "valid" ? s.v.verdict !== "valid" : !(s.v.verdict === "invalid" && s.v.reason === "revoked"));
const NOT_ANCHORED = "the sample directory is not trust-anchored by its roots — repo corrupt";

// The run's one decision: null when it is green, otherwise why it is red. Both halves must be SHOWN — a run that
// could only find a valid credential has not shown that it fails closed.
function whyRed(src) {
  if (!src) return NOT_ANCHORED;
  if (!src.samples.some((s) => s.expect === "valid")) return "no valid credential to show";
  if (!src.samples.some((s) => s.expect === "revoked")) return "no revoked credential to show — the fail-closed half is not visible";
  const bad = src.samples.filter(wrong);
  return bad.length ? bad.map((s) => `${s.expect} slot got ${s.v.verdict === "valid" ? "VALID" : `INVALID · ${s.v.reason}`}`).join("; ") : null;
}

// ── the negative control (see WITNESS above): every plant is a real run of this tool, offline, and must be red ──
async function negative() {
  const SELF = fileURLToPath(import.meta.url);
  const plain = (t) => t.replace(/\x1b\[[0-9;]*m/g, "").trim();
  const flip = (s) => { const b = Buffer.from(s, "base64url"); b[b.length >> 1] ^= 0x01; return b.toString("base64url"); };
  const committed = (f) => JSON.parse(readFileSync(ROOT + "kits/verifier/sample-artifacts/" + f, "utf8")); // never a planted copy
  const valid = committed("bundle-valid.json"), revoked = committed("bundle-revoked.json"), roots = committed("roots.json");
  const claims = JSON.parse(Buffer.from(valid.claims, "base64url").toString("utf8"));
  const registry = JSON.parse(readFileSync(ROOT + "site/net/registry.json", "utf8"));
  const tmp = mkdtempSync(join(tmpdir(), "ainra-verify60-neg-"));
  // The loopback "network": 404 when `body` is null (the child falls back to the local testbed), else the planted registry.
  let body = null;
  const server = createServer((_, res) => {
    if (body === null) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { "Content-Type": "application/json", "X-AINRA-Network": "staging", "X-AINRA-Root": "test-root" });
    res.end(body);
  });
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  const net = `http://127.0.0.1:${server.address().port}`;
  const child = (env) => new Promise((ok) => {
    const c = spawn(process.execPath, [SELF], { env: { ...process.env, AINRA_NET: net, ...env } });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", (d) => (err += d));
    c.on("close", (code) => ok({ code, out: plain(out), err: plain(err) }));
  });
  const local = async (name, over) => {
    const d = join(tmp, name); mkdirSync(d);
    for (const f of ["directory.json", "roots.json", "bundle-valid.json", "bundle-revoked.json"]) writeFileSync(join(d, f), JSON.stringify(f in over ? over[f] : committed(f)));
    body = null;
    return child({ AINRA_VERIFY_SAMPLES: d });
  };
  const staging = async (edit) => {
    const reg = structuredClone(registry); edit(reg);
    body = JSON.stringify(reg);
    return child({ AINRA_VERIFY_SAMPLES: join(tmp, "absent") }); // a staging run must never need the sample files
  };
  // Records as the staging path picks them: the first not revoked fills the valid slot, the first revoked the other.
  const records = (reg) => reg.registrars.flatMap((R) => R.records);
  const firstValid = (reg) => records(reg).find((e) => !e.record.revoked);
  const redLine = (why) => `✗ verify-60s red: ${why}`; // what the run prints on stderr when it is red
  const plants = [
    ["local: valid sample's claims edited to tier L4", () => local("tier", { "bundle-valid.json": { ...valid, claims: Buffer.from(JSON.stringify({ ...claims, tier: "L4" })).toString("base64url") } }), redLine("valid slot got INVALID · sig_invalid")],
    ["local: valid sample's issuer Ed25519 signature, one byte flipped", () => local("sig", { "bundle-valid.json": { ...valid, issuer_sig: { ...valid.issuer_sig, ed25519: flip(valid.issuer_sig.ed25519) } } }), redLine("valid slot got INVALID · sig_invalid")],
    ["local: revoked credential shown in the valid slot", () => local("swap-v", { "bundle-valid.json": revoked }), redLine("valid slot got INVALID · revoked")],
    ["local: valid credential shown in the revoked slot", () => local("swap-r", { "bundle-revoked.json": valid }), redLine("revoked slot got VALID")],
    ["local: roots file, Ed25519 root key one byte flipped", () => local("roots", { "roots.json": { ...roots, root_ed25519: flip(roots.root_ed25519) } }), NOT_ANCHORED],
    ["staging: every revoked record removed (only VALID shown)", () => staging((reg) => { for (const R of reg.registrars) R.records = R.records.filter((e) => !e.record.revoked); }), redLine("no revoked credential to show — the fail-closed half is not visible")],
    ["staging: valid record's issuer Ed25519 signature, one byte flipped", () => staging((reg) => { const r = firstValid(reg).record; r.issuer_sig_ed25519 = flip(r.issuer_sig_ed25519); }), redLine("valid slot got INVALID · sig_invalid")],
    ["staging: a valid record served in the revoked slot", () => staging((reg) => { const e = records(reg).find((x) => x.record.revoked); e.record = { ...structuredClone(firstValid(reg).record), revoked: true }; }), redLine("revoked slot got VALID")],
  ];
  const controls = [
    ["local: the untouched samples", () => local("control", {}), "[LOCAL TESTBED]"],
    ["staging: the untouched site/net/registry.json", () => staging(() => {}), "[STAGING · TEST-ROOT]"],
  ];
  let missed = 0;
  for (const [label, go, tag] of controls) {
    const r = await go();
    if (r.code === 0 && r.err === "" && r.out.includes(tag) && r.out.includes("✓ VALID") && r.out.includes("✗ INVALID · revoked")) console.log(`ok control: ${label} — exit 0, VALID and revoked both shown`);
    else { console.error(`MISSED control: ${label} — exit ${r.code} (${r.err || "wrong output"}) — a check that fails everything proves nothing`); missed++; }
  }
  for (const [label, go, want] of plants) {
    const r = await go();
    if (r.code === 1 && r.err === want) console.log(`ok caught ${label} — exit 1 (${r.err})`);
    else { console.error(`MISSED ${label} — exit ${r.code} (${r.err.split("\n")[0] || "no red line"}), wanted exit 1 (${want})`); missed++; }
  }
  server.close();
  rmSync(tmp, { recursive: true, force: true });
  if (missed) { console.error(`\nverify-60s negative control FAILED: ${missed} of ${plants.length + controls.length} not as required`); process.exit(1); }
  console.log(`\nverify-60s negative control OK: all ${plants.length} plants exit 1 for the right reason, both untouched sources exit 0.`);
  process.exit(0);
}
if (process.argv.includes("--negative")) await negative();

// ── run ──
const src = (await tryStaging()) || localTestbed();
if (!src) { console.error(red(NOT_ANCHORED)); process.exit(1); }
console.log(`\n${bold("AINRA — verify, in one command")}   ${dim("[" + src.label + "]")}`);
console.log(dim(`source: ${src.net} · root: ${src.root} · verifier: @ainra/sdk (offline, root-dark) · telemetry: none\n`));
for (const s of src.samples) printOne(src.label, s.rec.sub, s.rec.tier, s.v);
const why = whyRed(src);
console.log(`\n${dim("named-reason legend (the 20 frozen INVALID reasons):")}`);
for (const [k, txt] of Object.entries(REASONS)) if (k !== "_note" && k !== "valid") console.log(dim(`  ${k.padEnd(20)} ${txt}`));
console.log(`\n${dim("cookbook →")} docs/quickstarts/  ${dim("· issue your own →")} make issue-first`);
if (src.label !== "LOCAL TESTBED") console.log(dim(`honest label: this is a ${src.label} — no trust migrates to a production root, born only at the recorded genesis ceremony.`));
if (why) { console.error(red(`✗ verify-60s red: ${why}`)); process.exit(1); }
process.exit(0);
