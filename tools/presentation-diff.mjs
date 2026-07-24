// SPDX-License-Identifier: Apache-2.0 OR MIT
// M16 Task 4 — the one-verdict-event-shape differential. Proves the `ainra` CLI (Rust), the middleware, and the MCP
// server all serialize the SAME verdict event BYTE-IDENTICALLY (docs/PRESENTATION.md). Method: seed a real registry,
// emit every record's event from the Rust CLI (`ainra events`) AND from the SDK builder that middleware + MCP share,
// and assert every line matches — plus assert the three Node surfaces resolve to the same builder. Exit nonzero on
// any divergence. No new protocol semantics; one shape, everywhere.
import { execFileSync } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { runVector, verdictEvent as sdkEvent, serializeVerdictEvent } from "../packages/sdk-ts/dist/index.js";
import { verdictEvent as mwEvent } from "../packages/middleware/dist/index.js";
import { verdictEvent as mcpEvent } from "../packages/mcp/src/tools.mjs";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const BIN = ROOT + "target/release/ainra";
const TMP = ROOT + "target/m16-presentation-diff";
const enc = (u) => Buffer.from(u).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const die = (m) => { console.error("✗ " + m); process.exit(1); };

// 1. seed a real registry (real crypto; self-checked by the core verifier at seed time).
rmSync(TMP, { recursive: true, force: true });
execFileSync(BIN, ["seed", TMP], { encoding: "utf8" });
const reg = JSON.parse(readFileSync(`${TMP}/registry.json`, "utf8"));
const now = reg.generated_window.verified_at;

// 2. Rust CLI: one canonical event line per record.
const rustLines = execFileSync(BIN, ["events", `${TMP}/registry.json`], { encoding: "utf8" }).trim().split("\n");

// 3. SDK builder (what middleware + MCP share): the same events, from the same registry.
const bundleOf = (rec, R) => ({
  claims: enc(new TextEncoder().encode(rec.claims)),
  issuer_sig: { ed25519: rec.issuer_sig_ed25519, mldsa65: rec.issuer_sig_mldsa65 },
  now, chain_keys: rec.chain_keys, hop_proofs: rec.hop_proofs,
  status_list: R.status_list.status_list_b64, status_len: R.status_list.bit_len, status_issued_at: R.status_list.issued_at,
  freshness: "F3", checkpoint: { origin: rec.log_origin, size: rec.checkpoint_size, root: rec.checkpoint_root },
  checkpoint_sig: rec.checkpoint_sig, leaf_index: rec.leaf_index, inclusion_proof: rec.inclusion_proof,
  mandate_revocations: [], revoked_delegates: [],
});
const records = reg.registrars.flatMap((R) => R.records.map((e) => ({ R, rec: e.record })));
const sdkLines = records.map(({ R, rec }) => {
  const pres = bundleOf(rec, R);
  const v = runVector({ name: rec.sub, expect: {}, anchors: { [R.registrar]: { issuer_key: R.accreditation.issuer_key, log_root_key: R.accreditation.log_root_key } }, presentation: pres });
  return serializeVerdictEvent(sdkEvent(pres, v, now));
});

// 4. CLI (Rust) ≡ SDK, byte-for-byte, every record.
if (rustLines.length !== sdkLines.length) die(`record count mismatch: cli=${rustLines.length} sdk=${sdkLines.length}`);
let ok = 0;
for (let i = 0; i < sdkLines.length; i++) {
  if (rustLines[i] !== sdkLines[i]) die(`event mismatch on record ${i}\n  cli: ${rustLines[i]}\n  sdk: ${sdkLines[i]}`);
  ok++;
}

// 5. The three NODE surfaces resolve to one builder: SDK ≡ middleware ≡ MCP over a sample.
for (const { R, rec } of records.slice(0, 5)) {
  const pres = bundleOf(rec, R);
  const v = runVector({ name: rec.sub, expect: {}, anchors: { [R.registrar]: { issuer_key: R.accreditation.issuer_key, log_root_key: R.accreditation.log_root_key } }, presentation: pres });
  const a = serializeVerdictEvent(sdkEvent(pres, v, now));
  const b = serializeVerdictEvent(mwEvent(pres, v, now));
  const c = serializeVerdictEvent(mcpEvent(pres, v, now));
  if (a !== b || a !== c) die(`node surfaces diverge: sdk=${a} middleware=${b} mcp=${c}`);
}

rmSync(TMP, { recursive: true, force: true });
console.log(`✓ one verdict-event shape: CLI ≡ SDK byte-identical over ${ok} records; middleware ≡ MCP ≡ SDK confirmed.`);
console.log(`  e.g. ${sdkLines.find((l) => l.includes('"valid"')) || sdkLines[0]}`);
