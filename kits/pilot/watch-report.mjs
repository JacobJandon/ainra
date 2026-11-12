#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// node kits/pilot/watch-report.mjs FILE — what a pilot in watch mode saw, in plain words (D-105).
//
// FILE is the observations file `pilot.mjs --watch` writes: one JSON line per request. This prints how many requests
// were seen; the share that carried any signature, a Signature-Agent header, an RFC 9421 signature and an AINRA
// presentation (of every request seen, checked or not); how many were checked, and of those how many the gate would
// have admitted and refused, with the refusals by reason; how many were not checked, and why; and how long the check
// took on this machine (p50/p95/p99, nearest rank, as the pilot's own summary computes them). It reads the file a
// piece at a time, so its size does not matter, and sends nothing anywhere. Exit 0; exit 2 when the file is missing or
// cannot be read.
import { createReadStream } from "node:fs";

const file = process.argv[2];
if (!file) { console.error("usage: node kits/pilot/watch-report.mjs FILE"); process.exit(2); }

const MAX_LINE = 1 << 20; // an observation is a few hundred bytes; a longer line is not one, and is skipped unread
const KINDS = ["signature-agent", "rfc9421", "ainra-presentation"];
let n = 0, skipped = 0, first = null, last = null;
const carrying = { any: 0, "signature-agent": 0, rfc9421: 0, "ainra-presentation": 0 };
const decided = { admit: 0, refuse: 0 }, reasons = new Map(), unchecked = new Map();
let unsignedInvalid = 0;
let times = new Float64Array(1024), timed = 0;
const bump = (m, k) => m.set(k, (m.get(k) ?? 0) + 1);

function take(text) {
  if (!text.trim()) return;
  let r;
  try { r = JSON.parse(text); } catch { skipped++; return; }
  const kind = r?.decision;
  if (!(kind === "admit" || kind === "refuse" || kind === "unchecked") || !Array.isArray(r.signatures)) { skipped++; return; }
  n++;
  if (typeof r.time === "string") { if (first === null || r.time < first) first = r.time; if (last === null || r.time > last) last = r.time; }
  if (r.signatures.length) carrying.any++;
  for (const k of KINDS) if (r.signatures.includes(k)) carrying[k]++;
  if (kind === "unchecked") return bump(unchecked, String(r.not_checked ?? "(no reason)"));
  decided[kind]++;
  if (kind === "refuse") bump(reasons, r.reason ?? "(no reason)");
  // the gate names a request with no signature at all sig_invalid too; the report says how many of those carried none,
  // so it does not read as forgeries (a first-time reader took it so, 2026-11-12)
  if (kind === "refuse" && r.reason === "sig_invalid" && !r.signatures.length) unsignedInvalid++;
  if (typeof r.check_ms === "number" && Number.isFinite(r.check_ms)) {
    if (timed === times.length) { const t = new Float64Array(times.length * 2); t.set(times); times = t; }
    times[timed++] = r.check_ms;
  }
}

try {
  let part = [], partBytes = 0, tooLong = false;
  for await (const chunk of createReadStream(file)) {
    let from = 0;
    for (let nl = chunk.indexOf(10); nl !== -1; nl = chunk.indexOf(10, from)) {
      const end = chunk.subarray(from, nl);
      if (tooLong) skipped++;
      else take((part.length ? Buffer.concat([...part, end]) : end).toString("utf8"));
      part = []; partBytes = 0; tooLong = false; from = nl + 1;
    }
    if (tooLong || from === chunk.length) continue;
    partBytes += chunk.length - from;
    if (partBytes > MAX_LINE) { tooLong = true; part = []; } else part.push(chunk.subarray(from));
  }
  if (tooLong) skipped++;
  else take(Buffer.concat(part).toString("utf8"));
} catch (e) {
  console.error(`watch-report: cannot read ${file} (${e.code ?? e.message})`);
  process.exit(2);
}

const checked = decided.admit + decided.refuse, notChecked = n - checked;
const share = (k, of) => (of ? ` ${(100 * k / of).toFixed(1).padStart(5)}%` : "");
const row = (label, value, extra = "") => console.log(`  ${label.padEnd(36)}${String(value).padStart(8)}${extra}`);
const byCount = (m) => [...m].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
const sorted = times.subarray(0, timed).sort();
const pct = (p) => sorted[Math.ceil((p * timed) / 100) - 1];

console.log(`${file}: ${n} request${n === 1 ? "" : "s"} seen${n && first ? `, ${first} to ${last}` : ""}`);
if (skipped) console.log(`  (${skipped} line${skipped === 1 ? "" : "s"} skipped: not an observation)`);
console.log("");
row("carrying any signature", `${carrying.any} of ${n}`, share(carrying.any, n));
for (const [k, label] of [["signature-agent", "  a Signature-Agent header"], ["rfc9421", "  an RFC 9421 signature"], ["ainra-presentation", "  an AINRA presentation"]])
  row(label, `${carrying[k]} of ${n}`, share(carrying[k], n));
console.log("");
row("checked", checked);
row("  the gate would admit", decided.admit);
row("  the gate would refuse", decided.refuse);
for (const [reason, c] of byCount(reasons)) { row(`    ${reason}`, c); if (reason === "sig_invalid" && unsignedInvalid) row("      of which no signature at all", unsignedInvalid); }
row("not checked", notChecked);
for (const [why, c] of byCount(unchecked)) row(`  ${why}`, c);
console.log("");
console.log(timed
  ? `  check time on this machine: p50 ${pct(50).toFixed(2)} ms · p95 ${pct(95).toFixed(2)} ms · p99 ${pct(99).toFixed(2)} ms (${timed} checks)`
  : "  check time on this machine: no checks recorded");
