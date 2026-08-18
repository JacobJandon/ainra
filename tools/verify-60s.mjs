// SPDX-License-Identifier: Apache-2.0 OR MIT
// The sixty-second VERIFY path (M16 Task 1). One command, no account, no server, no config:
//   make verify                     → verifies bundled sample credentials, ROOT DARK          [LOCAL TESTBED]
//   AINRA_NET=http://host:8091 …    → fetches a live network's public record + verifies it     [STAGING · TEST-ROOT]
//
// It prints the REAL verifier's verdict (the published @ainra/sdk — the code that agrees byte-for-byte in the
// conformance differential) plus the named-reason legend, then points at the cookbook. Nothing is mocked; nothing
// phones home. A VALID and a revoked credential are both shown, so the fail-closed behaviour is visible, not asserted.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Verifier, runVector } from "../packages/sdk-ts/dist/index.js";

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
  return { label, root, net: NET, now, samples: [valid, revoked].filter(Boolean).map(({ R, rec }) => ({ rec, v: runVector(toWire(rec, R, now)) })) };
}

// ── LOCAL TESTBED path: verify the committed sample bundles ROOT DARK with the full directory-anchored Verifier ──
function localTestbed() {
  const d = ROOT + "kits/verifier/sample-artifacts/";
  const j = (f) => JSON.parse(readFileSync(d + f, "utf8"));
  const directory = j("directory.json"), roots = j("roots.json");
  const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh);
  if (!verifier) { console.error(red("the sample directory is not trust-anchored by its roots — repo corrupt")); process.exit(1); }
  const claimsOf = (b) => JSON.parse(Buffer.from(b.claims, "base64url").toString("utf8")); // sample bundle claims are base64url (SD-JWT form)
  const mk = (f) => { const b = j(f); const c = claimsOf(b); return { rec: { sub: c.sub, tier: c.tier }, v: verifier.verify(b, b.now) }; }; // each bundle carries its own verify-time
  const now = j("bundle-valid.json").now;
  return { label: "LOCAL TESTBED", root: "sample-root", net: "(bundled sample-artifacts, no network)", now, samples: [mk("bundle-valid.json"), mk("bundle-revoked.json")] };
}

// ── run ──
const src = (await tryStaging()) || localTestbed();
console.log(`\n${bold("AINRA — verify, in one command")}   ${dim("[" + src.label + "]")}`);
console.log(dim(`source: ${src.net} · root: ${src.root} · verifier: @ainra/sdk (offline, root-dark) · telemetry: none\n`));
for (const s of src.samples) printOne(src.label, s.rec.sub, s.rec.tier, s.v);
const bad = src.samples.filter((s) => s.v.verdict !== "valid" && s.v.reason !== "revoked");
console.log(`\n${dim("named-reason legend (the 20 frozen INVALID reasons):")}`);
for (const [k, txt] of Object.entries(REASONS)) if (k !== "_note" && k !== "valid") console.log(dim(`  ${k.padEnd(20)} ${txt}`));
console.log(`\n${dim("cookbook →")} docs/quickstarts/  ${dim("· issue your own →")} make issue-first`);
if (src.label !== "LOCAL TESTBED") console.log(dim(`honest label: this is a ${src.label} — no trust migrates to a production root, born only at the recorded genesis ceremony.`));
process.exit(bad.length ? 1 : 0);
