// SPDX-License-Identifier: Apache-2.0 OR MIT
// M16 Task 4 — the one-verdict-event-shape differential. Proves the `ainra` CLI (Rust), the middleware, and the MCP
// server all serialize the SAME verdict event BYTE-IDENTICALLY (docs/PRESENTATION.md). Method: seed a real registry,
// emit every record's event from the Rust CLI (`ainra events`) AND from the SDK builder that middleware + MCP share,
// and assert every line matches — plus assert the three Node surfaces resolve to the same builder. Exit nonzero on
// any divergence. No new protocol semantics; one shape, everywhere.
//
// WITNESS (negative control): `node tools/presentation-diff.mjs --negative` seeds the same registry once and requires
// the real run to agree first (a control on a base that already diverges proves nothing). Then it plants drift in two
// ways, and every plant MUST be reported:
//   1. In memory, through the SAME two comparisons the positive run calls. The CLI plants are made on the CLI's raw
//      stdout, so they also pass through the gate's parsing: one byte changed per record (every record is compared,
//      not just the first); the first byte and the last byte; a leading space; a trailing space; a blank line at the
//      end; CRLF line endings; a missing final newline; a dropped line. The surface plants change one byte in the
//      middleware's event and, separately, in the MCP server's event, at every sample index, and drop one sample.
//   2. As a child process: an exact copy of this file runs in its positive mode from a planted root under target/.
//      There the `ainra` binary is a wrapper around the real one that bends its `events` output, and the middleware
//      and MCP modules are wrappers around the real ones that change one byte of one sample's event. Each child run
//      must exit 1 with the expected "✗" reason, and the unplanted child run must exit 0. This tests the positive
//      run's own wiring: its parsing, its loops, its sample size, and that a divergence reaches die().
// It prints "ok caught …" per plant and exits 1 if any plant passes as identical. A gate that skipped records or
// samples, trimmed, normalised whitespace, compared parsed JSON instead of bytes, or found a divergence but did not
// exit on it would let a plant through and turn this red.
//
//   node tools/presentation-diff.mjs              CLI ≡ SDK ≡ middleware ≡ MCP over a seeded registry
//   node tools/presentation-diff.mjs --negative   divergences planted: every one MUST be reported
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, rmSync, mkdirSync, writeFileSync, copyFileSync, symlinkSync, chmodSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { verdictEvent as sdkEvent, serializeVerdictEvent } from "../packages/sdk-ts/dist/index.js";
import { runVector } from "../packages/sdk-ts/dist/conformance.js";
import { verdictEvent as mwEvent } from "../packages/middleware/dist/index.js";
import { verdictEvent as mcpEvent } from "../packages/mcp/src/tools.mjs";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const BIN = ROOT + "target/release/ainra";
const TMP = ROOT + "target/m16-presentation-diff";
const NEGATIVE = process.argv.includes("--negative");
const SAMPLE = 5; // records whose event all three Node surfaces must serialize identically
const enc = (u) => Buffer.from(u).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const die = (m) => { console.error("✗ " + m); process.exit(1); };

// The two comparisons. Each returns null when the surfaces agree byte-for-byte, else the reason. The positive run and
// the negative control both call exactly these, so the control tests the gate, not a copy of it.
// The CLI's raw stdout goes in as it came out: one event per line, each line ending in exactly one "\n". Nothing is
// trimmed, so stray whitespace or a changed line ending is a divergence, not something the parsing hides.
const lineDivergence = (out, sdk) => {
  const cli = out.split("\n");
  if (cli.pop() !== "") return `cli output is not newline-terminated`;
  if (cli.length !== sdk.length) return `record count mismatch: cli=${cli.length} sdk=${sdk.length}`;
  for (let i = 0; i < sdk.length; i++) {
    if (cli[i] !== sdk[i]) return `event mismatch on record ${i}\n  cli: ${cli[i]}\n  sdk: ${sdk[i]}`;
  }
  return null;
};
// One [sdk, middleware, mcp] triple of serialized events per sampled record; every triple is compared.
const surfaceDivergence = (sample, want) => {
  if (sample.length !== want) return `sample size ${sample.length}, expected ${want}`;
  for (const [i, [a, b, c]] of sample.entries()) {
    if (a !== b || a !== c) return `node surfaces diverge on sample ${i}: sdk=${a} middleware=${b} mcp=${c}`;
  }
  return null;
};

// 1. seed a real registry (real crypto; self-checked by the core verifier at seed time).
rmSync(TMP, { recursive: true, force: true });
execFileSync(BIN, ["seed", TMP], { encoding: "utf8" });
const reg = JSON.parse(readFileSync(`${TMP}/registry.json`, "utf8"));
const now = reg.generated_window.verified_at;

// 2. Rust CLI: one canonical event line per record (raw stdout; lineDivergence splits it).
const cliOut = execFileSync(BIN, ["events", `${TMP}/registry.json`], { encoding: "utf8" });

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
{
  const m = lineDivergence(cliOut, sdkLines);
  if (m) die(m);
}
const ok = sdkLines.length;

// 5. The three NODE surfaces resolve to one builder: SDK ≡ middleware ≡ MCP over a sample.
const want = Math.min(SAMPLE, records.length);
const sample = records.slice(0, SAMPLE).map(({ R, rec }) => {
  const pres = bundleOf(rec, R);
  const v = runVector({ name: rec.sub, expect: {}, anchors: { [R.registrar]: { issuer_key: R.accreditation.issuer_key, log_root_key: R.accreditation.log_root_key } }, presentation: pres });
  return [serializeVerdictEvent(sdkEvent(pres, v, now)), serializeVerdictEvent(mwEvent(pres, v, now)), serializeVerdictEvent(mcpEvent(pres, v, now))];
});
{
  const m = surfaceDivergence(sample, want);
  if (m) die(m);
}

rmSync(TMP, { recursive: true, force: true });

// ── the negative control: drift planted in memory and in a child run; every plant MUST be reported ──────────────
if (NEGATIVE) {
  // The control's own verdict exits by itself, not through die(): a die() that stopped exiting 1 is one of the things
  // the child runs below catch, and it must not also silence the report that it was caught.
  const fail = (m) => { console.error("✗ negative control: " + m); process.exit(1); };
  // A different byte at position p, kept printable so the plant is a plausible serializer slip, not a binary glitch.
  const flip = (s, p) => s.slice(0, p) + (s[p] === "x" ? "y" : "x") + s.slice(p + 1);
  const lines = cliOut.slice(0, -1).split("\n"); // the real run agreed, so cliOut is exactly these lines + "\n" each
  const offset = (i) => lines.slice(0, i).reduce((n, l) => n + l.length + 1, 0); // where record i starts in cliOut
  const last = lines.length - 1;
  const plants = [];
  const line = (what, out) => plants.push([what, () => lineDivergence(out, sdkLines)]);
  for (let i = 0; i < lines.length; i++) line(`cli record ${i}: byte ${lines[i].length >> 1} changed`, flip(cliOut, offset(i) + (lines[i].length >> 1)));
  line(`cli record 0: first byte changed`, flip(cliOut, 0));
  line(`cli record ${last}: last byte changed`, flip(cliOut, cliOut.length - 2));
  line(`cli output: one leading space`, " " + cliOut);
  line(`cli record ${last}: one trailing space`, cliOut.slice(0, -1) + " \n");
  line(`cli output: one blank line at the end`, cliOut + "\n");
  line(`cli output: CRLF line endings`, cliOut.replace(/\n/g, "\r\n"));
  line(`cli output: final newline missing`, cliOut.slice(0, -1));
  line(`cli record ${last} dropped`, cliOut.slice(0, offset(last)));
  const surface = (what, s) => plants.push([what, () => surfaceDivergence(s, want)]);
  const withSample = (k, j) => sample.map((t, i) => (i === k ? t.map((e, n) => (n === j ? flip(e, e.length >> 1) : e)) : t));
  for (let k = 0; k < want; k++) {
    surface(`middleware event, sample ${k}: one byte changed`, withSample(k, 1));
    surface(`mcp event, sample ${k}: one byte changed`, withSample(k, 2));
  }
  surface(`sample ${want - 1} dropped`, sample.slice(0, -1));

  // The child runs. PLANTED is a root laid out like this checkout: this file copied byte for byte, the real SDK
  // linked in, and three wrappers that pass the real thing through unless PD_PLANT names them.
  const PLANTED = ROOT + "target/m16-presentation-diff-negative/";
  rmSync(PLANTED, { recursive: true, force: true });
  for (const d of ["tools", "target/release", "packages/middleware/dist", "packages/mcp/src", "seed"]) mkdirSync(PLANTED + d, { recursive: true });
  execFileSync(BIN, ["seed", PLANTED + "seed"], { encoding: "utf8" }); // seeded once; the wrapper's `seed` copies it
  copyFileSync(fileURLToPath(import.meta.url), PLANTED + "tools/presentation-diff.mjs");
  symlinkSync(ROOT + "packages/sdk-ts", PLANTED + "packages/sdk-ts");
  writeFileSync(PLANTED + "package.json", `{ "type": "commonjs" }\n`);
  writeFileSync(PLANTED + "target/release/ainra", `#!${process.execPath}
const { execFileSync } = require("node:child_process");
const flip = ${flip};
const [cmd, dir] = process.argv.slice(2);
if (cmd === "seed") { require("node:fs").cpSync(${JSON.stringify(PLANTED + "seed")}, dir, { recursive: true }); process.exit(0); }
let out = execFileSync(${JSON.stringify(BIN)}, process.argv.slice(2), { encoding: "utf8" });
const [kind, at] = (process.env.PD_PLANT || "").split(":");
if (cmd === "events") {
  const l = out.slice(0, -1).split("\\n");
  if (kind === "cli-byte") { l[at] = flip(l[at], l[at].length >> 1); out = l.join("\\n") + "\\n"; }
  if (kind === "cli-lead") out = " " + out;
  if (kind === "cli-trail") out = out.slice(0, -1) + " \\n";
  if (kind === "cli-blank") out += "\\n";
  if (kind === "cli-crlf") out = out.replace(/\\n/g, "\\r\\n");
  if (kind === "cli-drop") out = l.slice(0, -1).join("\\n") + "\\n";
}
process.stdout.write(out);
`);
  chmodSync(PLANTED + "target/release/ainra", 0o755);
  const wrap = (tag, real) => `import { verdictEvent as real } from ${JSON.stringify(pathToFileURL(real).href)};
const flip = ${flip};
const [kind, at] = (process.env.PD_PLANT || "").split(":");
let call = 0;
export const verdictEvent = (...a) => {
  const ev = real(...a);
  if (kind !== ${JSON.stringify(tag)} || call++ !== Number(at)) return ev;
  const f = typeof ev.name === "string" ? "name" : "status";
  return { ...ev, [f]: flip(ev[f], ev[f].length >> 1) };
};
`;
  writeFileSync(PLANTED + "packages/middleware/package.json", `{ "type": "module" }\n`);
  writeFileSync(PLANTED + "packages/middleware/dist/index.js", wrap("mw", ROOT + "packages/middleware/dist/index.js"));
  writeFileSync(PLANTED + "packages/mcp/src/tools.mjs", wrap("mcp", ROOT + "packages/mcp/src/tools.mjs"));
  const child = (plant) => spawnSync(process.execPath, [PLANTED + "tools/presentation-diff.mjs"], { encoding: "utf8", env: { ...process.env, PD_PLANT: plant } });
  const base = child("");
  if (base.status !== 0 || !base.stdout.includes("✓ one verdict-event shape")) fail(`the unplanted child run did not pass (exit ${base.status}), so a red plant would prove nothing\n${base.stderr}`);
  console.log(`  ok         unplanted child run passes (exit 0)`);
  const mid = last >> 1;
  const runs = [
    [`cli-byte:${mid}`, `event mismatch on record ${mid}`], ["cli-lead", "event mismatch on record 0"],
    ["cli-trail", `event mismatch on record ${last}`], ["cli-blank", "record count mismatch"],
    ["cli-crlf", "event mismatch on record 0"], ["cli-drop", "record count mismatch"],
    ["mw:0", "node surfaces diverge on sample 0"], [`mw:${want - 1}`, `node surfaces diverge on sample ${want - 1}`],
    [`mcp:${want - 1}`, `node surfaces diverge on sample ${want - 1}`],
  ];
  for (const [plant, reason] of runs) {
    plants.push([`child run, ${plant}: exit 1 with "${reason}"`, () => { const r = child(plant); return r.status === 1 && r.stderr.startsWith("✗ " + reason); }]);
  }

  let missed = 0;
  for (const [what, run] of plants) {
    if (run()) console.log(`  ok caught  ${what}`);
    else { missed++; console.error(`  ✗ MISSED   ${what} — the gate called it identical`); }
  }
  rmSync(PLANTED, { recursive: true, force: true });
  if (missed) fail(`${missed} of ${plants.length} planted divergences passed as byte-identical`);
  console.log(`negative control OK: all ${plants.length} planted divergences reported (real lines agreed first, over ${ok} records).`);
  process.exit(0);
}

console.log(`✓ one verdict-event shape: CLI ≡ SDK byte-identical over ${ok} records; middleware ≡ MCP ≡ SDK confirmed.`);
console.log(`  e.g. ${sdkLines.find((l) => l.includes('"valid"')) || sdkLines[0]}`);
