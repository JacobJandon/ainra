#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The soak instrument and the thing that reads its reports must agree on the shape.
//
// They did not. `kits/soak/soak.mjs` writes
//     { body: { wall_start, wall_end, slo: { measured_p95_sec, pass }, … }, sig_ed25519_b64 }
// and `tools/declaration.mjs` read `rep.days`, `rep.p95_seconds` and `rep.signature` — three fields that have
// never existed in a report. Inside a try/catch, so a real report was not rejected, it was silently SKIPPED: the
// declaration would have gone on saying "0/3 regions passed a ≥14d soak" after three genuine fourteen-day soaks
// had been run, and the only place that discrepancy could surface is genesis day, after the fortnight is spent.
//
// It survived because the two halves had never been connected: the only thing that produces a report is a long
// run, and the smoke test never handed its output to the consumer. So this check does exactly that — synthesises
// a report in the instrument's own format and asserts the consumer counts it — plus the controls that matter:
//
//     a report that is too SHORT          must not count
//     a report whose p95 BREACHES the SLO must not count
//     a report with no SIGNATURE          must not count
//
// A gate that only proves the happy path would have passed against the broken code too, since "0 regions counted"
// looks identical to "no reports present".
//
// WITNESS: `--negative` writes copies of tools/declaration.mjs to the OS temp directory and runs this very file
// against each, as a child process (`--consumer <copy>`), so a copy is judged by the same assertions, the same
// counter and the same exit code a normal run uses. First an unchanged copy, which must pass with exit 0 and no
// failures, so the copying itself is known not to break anything. Then five broken copies. One is the historical
// defect (the consumer reads the top level of the report, not `body`, so every real report is skipped); the others
// each delete one refusal — the 14-day floor, the p95 ceiling, the signature requirement, the three-region quorum.
// Each broken copy must make the run exit 1 with exactly one failure, and that failure must be the control it owns:
// the shape check for the first, the matching refusal for the rest. A copy that crashes, or breaks more than its
// own control, does not count as caught, because it would be "caught" whatever the battery checked. A battery that
// stays green on a consumer that gates nothing is the silence this file exists to end. The tracked declaration is
// only read.

import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const SELF = fileURLToPath(import.meta.url);
let bad = 0;
const ok = (m) => console.log(`  ✓ ${m}`);
const no = (m) => { console.error(`  ✗ ${m}`); bad++; };

// The instrument's real output shape, kept here as one literal so a drift in soak.mjs shows up as a failure here
// rather than as silence in a year's time.
function report({ days = 14, p95 = 12.5, signed = true, pass = true } = {}) {
  const end = Date.parse("2026-08-01T00:00:00Z");
  const body = {
    kind: "ainra/soak-report/v1",
    challenge: "test-challenge",
    host: "gate", registrar: "http://127.0.0.1:4907", vantages: ["a", "b", "c"], now: 1776729600,
    wall_start: new Date(end - days * 86400000).toISOString(),
    wall_end: new Date(end).toISOString(),
    cycles: 100, measurements: 300,
    slo: { revocation_p95_sec: 60, measured_p95_sec: p95, pass },
    overall: { misses: 0 }, per_vantage: {}, log_head_hash: "0".repeat(64),
  };
  const r = { body, reporter_pubkey_spki_b64: "AAAA" };
  if (signed) r.sig_ed25519_b64 = "SIG";
  return r;
}

function declare(reports, consumer) {
  const ev = mkdtempSync(join(tmpdir(), "ainra-soak-"));
  try {
    for (const [region, rep] of Object.entries(reports)) {
      mkdirSync(join(ev, "soak", region), { recursive: true });
      writeFileSync(join(ev, "soak", region, "soak-report.json"), JSON.stringify(rep, null, 2));
    }
    // The declaration prints the board; we only care what it concluded about the soak rows.
    return execFileSync("node", [consumer, "--evidence", ev], {
      cwd: ROOT, encoding: "utf8",
    });
  } catch (e) { return `${e.stdout || ""}${e.stderr || ""}`; }
  finally { rmSync(ev, { recursive: true, force: true }); }
}

// Does the consumer see a valid three-region soak at all? This is the assertion that was false.
//
// The declaration fails closed and lists every unresolved claim as a TODO, so "ingested" means precisely: the
// three SOAK rows STOP appearing in that list. Counting the digit 3 in the output would have been meaningless —
// "need ≥3" contains one too, which is how a check comes to pass against the very bug it was written for.
const soakTodo = (out) => (out.match(/TODO\s+\{\{SOAK_[A-Z0-9]+\}\}/g) || []).length;

// The battery, against the consumer this run was given.
function battery(consumer) {
  const good = declare({ "region-a": report(), "region-b": report(), "region-c": report() }, consumer);
  soakTodo(good) === 0
    ? ok("three valid 14-day reports are INGESTED — all three SOAK claims resolve (the shape matches)")
    : no(`three valid reports were NOT ingested — ${soakTodo(good)} SOAK claim(s) still unproven; the instrument and the declaration disagree on the report shape`);

  // Controls. Each must be refused, and refused for its own reason — otherwise "3 counted" proves nothing.
  for (const [why, reports] of [
    ["a 3-day window", { a: report({ days: 3 }), b: report({ days: 3 }), c: report({ days: 3 }) }],
    ["a breached SLO (p95 > 60s)", { a: report({ p95: 91 }), b: report({ p95: 91 }), c: report({ p95: 91 }) }],
    ["an unsigned report", { a: report({ signed: false }), b: report({ signed: false }), c: report({ signed: false }) }],
    ["only two regions", { a: report(), b: report() }],
  ]) {
    const out = declare(reports, consumer);
    soakTodo(out) === 3
      ? ok(`refused: ${why}`)
      : no(`ACCEPTED ${why} — only ${3 - soakTodo(out)} SOAK claim(s) refused; the soak gate is not gating`);
  }
}

if (process.argv.includes("--negative")) {
  const src = readFileSync(ROOT + "tools/declaration.mjs", "utf8");
  // [what is broken, the exact text replaced, its replacement, the words the one failure must contain]
  const PLANTS = [
    ["reads the report's top level, not its body (the historical bug)", "const b = rep.body ?? rep;", "const b = rep;", "NOT ingested"],
    ["no 14-day floor", "days >= SOAK_DAYS", "days >= 0", "ACCEPTED a 3-day window"],
    ["no p95 ceiling", "p95 <= SOAK_P95_MAX", "p95 >= 0", "ACCEPTED a breached SLO"],
    ["no signature requirement", "&& signed &&", "&&", "ACCEPTED an unsigned report"],
    ["a two-region quorum", "const enough = ok >= SOAK_REGIONS;", "const enough = ok >= 2;", "ACCEPTED only two regions"],
  ];
  // Run this file as a normal run would, but against `consumer`. Failures are the "  ✗ " lines `no` prints.
  const run = (consumer) => {
    const r = spawnSync("node", [SELF, "--consumer", consumer], { cwd: ROOT, encoding: "utf8" });
    const fails = (r.stderr || "").split("\n").filter((l) => l.startsWith("  ✗ "));
    return { status: r.status, fails, said: `${r.stdout || ""}${r.stderr || ""}` };
  };
  const dir = mkdtempSync(join(tmpdir(), "ainra-soak-neg-"));
  let missed = 0;
  try {
    // The control: an unchanged copy must pass exactly as the tracked file does.
    const same = join(dir, "declaration-unchanged.mjs");
    writeFileSync(same, src);
    const c = run(same);
    const clean = c.status === 0 && c.fails.length === 0 && c.said.includes("SOAK-INGEST OK");
    console.log(`  ${clean ? "ok  passed " : "✗   FLAGGED"} an unchanged copy of the declaration (control)`);
    if (!clean) { missed++; console.error(`        exit ${c.status}\n${c.said.replace(/^/gm, "        ")}`); }

    for (const [i, [what, from, to, must]] of PLANTS.entries()) {
      // A plant whose text is no longer in the consumer would test nothing; that is a failure of the control itself.
      if (src.split(from).length !== 2) { console.error(`  ✗   STALE   ${what} — \`${from}\` no longer appears exactly once in tools/declaration.mjs`); missed++; continue; }
      const consumer = join(dir, `declaration-${i}.mjs`);
      writeFileSync(consumer, src.replace(from, to));
      const r = run(consumer);
      const caught = r.status === 1 && r.fails.length === 1 && r.fails[0].includes(must) && r.said.includes("SOAK-INGEST FAILED");
      console.log(`  ${caught ? "ok  caught " : "✗   MISSED "} ${what}`);
      if (!caught) { missed++; console.error(`        exit ${r.status}, ${r.fails.length} failure(s), wanted exactly one containing "${must}"`); for (const m of r.fails) console.error(`      ${m}`); }
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
  if (missed) { console.error(`SOAK-INGEST NEGATIVE FAILED — ${missed} control(s) did not behave.`); process.exit(1); }
  console.log(`SOAK-INGEST NEGATIVE OK — an unchanged copy passed, and all ${PLANTS.length} broken consumers were caught, each by the control it owns and no other.`);
  process.exit(0);
}

// `--consumer <file>` is how the negative mode points a run at a planted copy; a plain run reads the tracked one.
const at = process.argv.indexOf("--consumer");
if (at >= 0 && !process.argv[at + 1]) { console.error("soak-ingest-check: --consumer needs a file"); process.exit(2); }
battery(at >= 0 ? process.argv[at + 1] : ROOT + "tools/declaration.mjs");

if (bad) { console.error("\nSOAK-INGEST FAILED — the soak instrument and the declaration do not agree."); process.exit(1); }
console.log("SOAK-INGEST OK: the declaration reads what kits/soak/soak.mjs writes, and refuses short, breached, unsigned and under-replicated runs.");
