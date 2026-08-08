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

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
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

function declare(reports) {
  const ev = mkdtempSync(join(tmpdir(), "ainra-soak-"));
  try {
    for (const [region, rep] of Object.entries(reports)) {
      mkdirSync(join(ev, "soak", region), { recursive: true });
      writeFileSync(join(ev, "soak", region, "soak-report.json"), JSON.stringify(rep, null, 2));
    }
    // The declaration prints the board; we only care what it concluded about the soak rows.
    return execFileSync("node", [ROOT + "tools/declaration.mjs", "--evidence", ev], {
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
const good = declare({ "region-a": report(), "region-b": report(), "region-c": report() });
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
  const out = declare(reports);
  soakTodo(out) === 3
    ? ok(`refused: ${why}`)
    : no(`ACCEPTED ${why} — only ${3 - soakTodo(out)} SOAK claim(s) refused; the soak gate is not gating`);
}

if (bad) { console.error("\nSOAK-INGEST FAILED — the soak instrument and the declaration do not agree."); process.exit(1); }
console.log("SOAK-INGEST OK: the declaration reads what kits/soak/soak.mjs writes, and refuses short, breached, unsigned and under-replicated runs.");
