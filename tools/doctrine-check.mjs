// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make doctrine — the rules that were enforced only by the author remembering them.
//
// The M32 census asked one question of every stated rule: "if a stranger with commit rights ignored this
// tomorrow, what would go red?" For ten bedrock rules the answer was "nothing", and each was proven by running
// the violation against the full board and watching it pass. This file is the answer to those probes.
//
// A pattern worth naming, because it shaped every check below. The four rules that WERE partially gated all
// failed in the same direction: they catch someone stating something WRONG, and miss someone stating NOTHING.
// The registry only inspects files that assert, so a file that quietly stops asserting drops out of the count
// instead of failing. Nobody deletes an uncomfortable zero on purpose — they reword around it. So several checks
// here are REQUIRED-PRESENCE checks, which is the unusual shape: they fail on absence.
//
// WITNESS for the file as a whole: every rule below was executed as a probe before it was written, and every one
// passed the full board while violated. `make doctrine-negative` re-runs those probes and asserts this gate now
// catches each — a gate whose negative control is the historical defect itself.

import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => { try { return readFileSync(join(ROOT, p), "utf8"); } catch { return null; } };
const tracked = () => execFileSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8" }).split("\n").filter(Boolean);

let bad = 0;
const fail = (m) => { console.error(`  ✗ ${m}`); bad++; };
const ok = (m) => console.log(`  ok    ${m}`);

// ── 1. SPECIMEN LABELLING ────────────────────────────────────────────────────────────────────────────────────
// The census's most serious finding. Relabelling the demo passport from "SPECIMEN · TEST-ROOT" to
// "VERIFIED · PRODUCTION" passed s7, claims, claims-live and link-check. The distance between an honest demo and
// a credential impersonating a production one was one careless edit, opposed by nothing.
//
// REQUIRED-PRESENCE: the labels must be THERE. Checking for the absence of the word "production" would be the
// wrong shape — it is the honest label that has to survive.
const SPECIMEN_REQUIRED = [
  { file: "site/get.html", must: ["SPECIMEN", "TEST-ROOT"],
    why: "the issuance demo mints a real credential against a test root; the passport it renders must say so on its face" },
];
for (const s of SPECIMEN_REQUIRED) {
  const t = read(s.file);
  if (t === null) { fail(`specimen: ${s.file} is missing — a page that renders a credential cannot simply disappear from this check`); continue; }
  const absent = s.must.filter((m) => !t.includes(m));
  if (absent.length) fail(`specimen: ${s.file} no longer carries ${absent.map((x) => `"${x}"`).join(" and ")} — ${s.why}`);
  else ok(`specimen labelling   ${s.file} · ${s.must.join(" + ")}`);
}
// And the inverse: a demo surface must never claim to be production.
for (const f of ["site/get.html"]) {
  const t = read(f) ?? "";
  for (const m of t.matchAll(/TYPE AP · (LIVE|PRODUCTION)|SPECIMEN · PRODUCTION|VERIFIED · PRODUCTION/gi))
    fail(`specimen: ${f} labels a demo credential "${m[0]}" — it is minted against a test root`);
}

// ── 2. THE ONE-WAY ATTRIBUTION MARK ──────────────────────────────────────────────────────────────────────────
// The Standard permits registrars to carry "Built on the AINRA open standard" and forbids the reverse: the root
// displays no one's mark. The direction IS the rule — a neutral root that advertises one registrar has stopped
// being neutral — and nothing enforced it. Probe: a page reading "Proudly powered by Meridian" passed everything.
const MARK_REVERSED = /\b(powered by|sponsored by|in partnership with|brought to you by|proudly built (?:on|with))\s+(?!the AINRA|AINRA\b)[A-Z][A-Za-z0-9-]*/g;
for (const f of tracked().filter((f) => f.startsWith("site/") && /\.(html|md|txt)$/.test(f))) {
  const t = read(f) ?? "";
  for (const m of t.matchAll(MARK_REVERSED))
    fail(`one-way mark: ${f} displays another party's mark — "${m[0].trim()}". Registrars reference the standard; the root displays no one's mark.`);
}
ok(`one-way mark        the root displays no third party's mark`);

// ── 3. MERIDIAN STAYS OUT OF EXAMPLES, DEFAULTS AND INTERFACES ───────────────────────────────────────────────
// Charter 6 / Standard §Meridian(iii). Naming it in the required disclosure is obligatory; naming it anywhere a
// user could mistake it for the default path is forbidden. Probe: a CLI usage string advertising Meridian as the
// example audience passed every gate.
//
// The allowed homes are the disclosure passages themselves, listed explicitly so adding a new one is a decision.
const MERIDIAN_ALLOWED = new Set([
  "docs/AINRA_I_The_Standard.md", "site/AINRA_I_The_Standard.md", "site/standard.md",
  "site/docs.html", "site/index.html", "docs/PLAN-M32.md",
]);
for (const f of tracked()) {
  if (MERIDIAN_ALLOWED.has(f)) continue;
  if (/^docs\/(_archive|releases)\//.test(f) || f === "CHANGELOG.md" || f === "docs/DECISIONS.md") continue;
  // The rule forbids the name in EXAMPLES, DEFAULTS and INTERFACES. Three kinds of file name it legitimately and
  // are none of those: this checker (which must contain the string to search for it), the governance texts that
  // classify the Meridian conditions as amendable charter material, and the milestone plan recording the census.
  // Found by `make succession-drill` — from a cold clone, where these files are TRACKED and therefore visible to
  // `git ls-files`; in the working tree they were still untracked when the rule was first written, so the gate
  // could not see its own source. That is the third time an untracked file has hidden a defect from a gate here.
  if (f === "tools/doctrine-check.mjs" || f === "tools/doctrine-negative.sh" || f === "GOVERNANCE-AMENDMENT.md") continue;
  const t = read(f);
  if (t === null || !/\bMeridian\b/.test(t)) continue;
  fail(`Meridian: named in ${f}, which is not one of the disclosure passages — it must never appear in examples, defaults or interfaces`);
}
ok(`Meridian scope      named only in the disclosure passages`);

// ── 4. HONEST ZERO, INCLUDING BY OMISSION ────────────────────────────────────────────────────────────────────
// The claim registry catches a zero CONTRADICTED and misses a zero OMITTED: rewording "0 OPERATORS — GAP" to the
// neutral heading "INDEPENDENT WITNESS NETWORK" passed, because the registry only inspects files that assert.
// These statements are required to be present for as long as the count they describe is zero.
const witnesses = JSON.parse(read("witnesses/candidates.json") ?? '{"candidates":[]}').candidates.length;
if (witnesses === 0) {
  const REQUIRED_WHILE_ZERO = [
    { file: "site/foundation.html", must: "0 OPERATORS — GAP" },
    { file: "site/_includes/footer.html", must: "WITNESSES: 0" },
  ];
  for (const r of REQUIRED_WHILE_ZERO) {
    const t = read(r.file);
    if (t === null) { fail(`honest zero: ${r.file} is missing`); continue; }
    if (!t.includes(r.must)) fail(`honest zero: ${r.file} no longer states "${r.must}" while the real count is 0 — an uncomfortable zero may be stated or the count changed, never quietly reworded away`);
    else ok(`honest zero         ${r.file} · "${r.must}"`);
  }
} else ok(`honest zero         not applicable — witness operators is ${witnesses}, not zero`);

// ── 5. DoD PROSE MATCHES THE DERIVED TRUTH ───────────────────────────────────────────────────────────────────
// `genesis-status` derives 7/11 from evidence and is safe. docs/DOD.md is a hand-maintained TABLE, and
// hand-maintained is future-false: flipping "≥3 external verifiers" from pending to ✓ left the derived count
// correct and the published table lying, with status-consistency reporting "in lockstep".
{
  const dod = read("docs/DOD.md") ?? "";
  const verifierDir = join(ROOT, "evidence/verifier");
  const attestations = existsSync(verifierDir)
    ? readdirSync(verifierDir).filter((f) => f.endsWith(".json")).length : 0;
  // The two rows that depend on external events nobody here can perform.
  const EXTERNAL_ROWS = [
    { needle: "≥3 external verifiers", proven: attestations >= 3 },
    { needle: "Recorded in-person ceremony", proven: false }, // no ceremony record exists; `make genesis-status` is the source
  ];
  for (const r of EXTERNAL_ROWS) {
    // The TABLE ROW, not the first line that happens to mention the phrase. The first version of this used a
    // bare `.includes` and matched a prose sentence forty lines above the table — so the probe that hand-flipped
    // the row to ✓ went unnoticed, and `make doctrine-negative` caught it. A check reading the wrong line is
    // indistinguishable from no check.
    const line = dod.split("\n").find((l) => l.trimStart().startsWith("|") && l.includes(r.needle));
    if (!line) { fail(`DoD: no row matching "${r.needle}" in docs/DOD.md — the table may not lose a criterion`); continue; }
    const claimsProven = /\|\s*✓\s*\|/.test(line);
    if (claimsProven && !r.proven)
      fail(`DoD: docs/DOD.md marks "${r.needle}" as proven (✓), but the evidence does not support it — external attestations on disk: ${attestations}`);
    else ok(`DoD row             "${r.needle}" · published status matches the evidence`);
  }
}

// ── 6. MODELLED NUMBERS CARRY THEIR TAG ──────────────────────────────────────────────────────────────────────
// Promoting a model to a measurement is a one-word edit. docs/SCALE.md is where the project reasons about numbers
// it has not measured, so every claim there must say which kind it is.
{
  const f = "docs/SCALE.md", t = read(f) ?? "";
  const promoted = [...t.matchAll(/\b(?:argument|figure|estimate|projection|model)[^.\n]{0,30},?\s+measured\b/gi)];
  for (const m of promoted) fail(`extrapolation: ${f} calls a model "${m[0].trim()}" — a modelled number must carry [extrapolated], never "measured"`);
  const tags = (t.match(/\[extrapolated\]/g) ?? []).length;
  if (!tags) fail(`extrapolation: ${f} carries no [extrapolated] tag at all — either every number there is now measured (say where) or a tag was dropped`);
  else if (!promoted.length) ok(`extrapolation tags  ${f} · ${tags} modelled claim(s) tagged`);
}

// ── 7. EVERY NEW GATE SHIPS WITH A NEGATIVE CONTROL ──────────────────────────────────────────────────────────
// The rule ABOVE the rules — the one that produced every row above, enforced until now by review alone. A gate that cannot fail is
// indistinguishable from no gate, and this repository has shipped three of those (see CONTRIBUTING § "A check
// that has never passed does not exist").
//
// The check is deliberately weak-but-real: a gate must SAY how it can fail. It cannot verify the control works —
// only that the author was made to think about it and write it down where the next reader will see it.
{
  const GATE_FILES = tracked().filter((f) => /^tools\/[a-z0-9-]+\.mjs$/.test(f));
  const EXEMPT = new Set(["tools/claims.mjs", "tools/campaign.mjs"]); // registries, not pass/fail gates in themselves
  const missing = [];
  for (const f of GATE_FILES) {
    if (EXEMPT.has(f)) continue;
    const t = read(f) ?? "";
    const isGate = /process\.exit\(1\)/.test(t);
    if (!isGate) continue;
    if (!/WITNESS|negative control|NEGATIVE_CONTROL|could this (observe|see)/i.test(t)) missing.push(f);
  }
  // A RATCHET, not a cliff. Seventeen gates predate this rule, and writing seventeen witness statements blind
  // would produce seventeen plausible sentences rather than seventeen true ones — which is worse than silence,
  // because a false witness reads as assurance. So the existing debt is frozen by name and may only SHRINK:
  //
  //   • a gate not in the baseline must name its witness  → new debt is impossible
  //   • a baseline gate that gains one must be removed    → the baseline cannot go stale in the safe direction
  //
  // The second rule is what makes this different from an ignore-list. An ignore-list quietly grows correct and
  // nobody notices; this one fails the moment it is out of date, so the file always states the real debt.
  const BASELINE = new Set(JSON.parse(read("tools/negative-control-baseline.json") ?? "[]"));
  const newDebt = missing.filter((f) => !BASELINE.has(f));
  const fixed = [...BASELINE].filter((f) => !missing.includes(f) && GATE_FILES.includes(f));
  if (newDebt.length)
    fail(`negative controls: ${newDebt.length} NEW gate(s) never say how they could fail — ${newDebt.join(", ")}.\n` +
         `        Name the witness in a comment: what would have to break for this to go red? A gate that cannot fail is not a gate.`);
  if (fixed.length)
    fail(`negative controls: ${fixed.join(", ")} now name a witness but are still listed in tools/negative-control-baseline.json — remove them. The baseline records real debt, so it may only shrink.`);
  if (!newDebt.length && !fixed.length)
    ok(`negative controls   0 new · ${missing.length} pre-existing (frozen by baseline, may only shrink)`);
}

// ── 8. NO CLAIM WITHOUT ITS EVIDENCE (the trust-deciding surfaces) ───────────────────────────────────────────
// Census probe 7: `Measured: 12,400 verifications/sec sustained across three regions (p99 4 ms)` was added to the
// README, invented entirely, and passed every gate. Nothing required a number to trace to anything.
//
// The strictest checking goes where the stakes are: the pages someone reads while deciding whether to trust the
// root. A measured-sounding claim there must name where it came from — a make target, an evidence file, a drill
// report, or a docs/ reference. This does not verify the number; it verifies that a READER CAN. That is the
// property that survives the author.
{
  const TRUST_SURFACES = ["README.md", "SECURITY.md", "site/index.html", "site/llms.txt", "site/foundation.html"];
  // A claim of MEASUREMENT — the word plus a number. Rates, percentiles and durations are the shapes that show up.
  const MEASURED = /\b(measured|sustained|benchmarked|throughput|p9[59])\b[^.\n]{0,60}?\d/gi;
  // Anything that lets a reader go and check: a make target, an evidence path, a drill report, a docs link.
  // Widened after two false positives on the first run: "revocation is measured under 60 seconds in a local
  // drill" and a pasted board row reading "measured p95, signed report" both name a real, checkable method. The
  // bar is "could a reader go and check this", not "does it contain a filename" — a check that punishes honest
  // provenance teaches writers to drop the word "measured", which is the opposite of the goal.
  const PROVENANCE = /(`?make [a-z-]+`?|evidence\/|docs\/drills\/|docs\/[A-Z-]+\.md|BENCHMARKS|\bboard\b|\bdrill\b|signed report|transcript|attestation)/i;
  for (const f of TRUST_SURFACES) {
    const t = read(f);
    if (t === null) continue;
    for (const m of t.matchAll(MEASURED)) {
      // The sentence the claim sits in — provenance may follow it, which is the normal way to write this.
      const start = t.lastIndexOf("\n", m.index) + 1;
      const end = (() => { const i = t.indexOf("\n", m.index + m[0].length); return i === -1 ? t.length : i; })();
      const sentence = t.slice(start, end);
      if (!PROVENANCE.test(sentence))
        fail(`provenance: ${f} states "${m[0].trim().replace(/\s+/g, " ")}" with nothing a reader could check it against — name the make target, evidence file or drill report, or delete the claim. Hand-maintained is future-false.`);
    }
  }
  ok(`claim provenance    ${TRUST_SURFACES.length} trust-deciding surface(s) · every measured claim names its source`);
}

if (bad) {
  console.error(`\nDOCTRINE-CHECK FAILED — ${bad} rule(s) that were previously held only by memory.`);
  console.error(`Each of these passed the entire board when violated, before this gate existed. See docs/PLAN-M32.md.`);
  process.exit(1);
}
console.log(`DOCTRINE-CHECK OK: the census's ungated rules are gated — specimen labelling, the one-way mark, Meridian scope,`);
console.log(`honest zeroes (including by omission), DoD rows against evidence, extrapolation tags, and negative controls.`);
