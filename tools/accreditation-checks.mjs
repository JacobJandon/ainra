// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make accreditation-checks — docs/ACCREDITATION-CHECKS.md says exactly what the workbench checks (PLAN-M52 R2).
//
// The document is generated from the code's own list (`ainra directory check-request --list-checks`, which prints
// `CHECKS` in crates/ainra-adapter/src/workbench.rs). A published check list that drifts from the code is worse than
// none: a filer reproduces a refusal from the document, so a row the code no longer runs, or a check the document
// does not name, sends them to the wrong place. This gate fails when the two differ, naming each check that differs.
//
//   node tools/accreditation-checks.mjs            compare the document with the code
//   node tools/accreditation-checks.mjs --write    regenerate the document from the code
//   node tools/accreditation-checks.mjs --negative prove the comparison can fail
//
// WITNESS: `--negative` takes the code's real output and plants one disagreement at a time — a check dropped from the
// document, a check the code does not have, a rule reworded, a "not built" row marked built, two rows swapped, and
// the prose around the tables edited — and each must be reported (the first four by the check's id). It also requires
// the code's output compared with itself to report nothing, so a comparison that always fails cannot pass either.
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const DOC = "docs/ACCREDITATION-CHECKS.md";
const BIN = process.env.AINRA_BIN || join(ROOT, "target/release/ainra");

function codeText() {
  const r = spawnSync(BIN, ["directory", "check-request", "--list-checks"], { encoding: "utf8" });
  if (r.status !== 0) {
    console.error(`cannot run ${BIN} directory check-request --list-checks (build it: cargo build --release -p ainra-cli-rs)`);
    console.error(r.stderr || r.error?.message || "");
    process.exit(2);
  }
  return r.stdout;
}

// Every table row, by check id, in order.
function rows(text) {
  const out = [];
  for (const line of text.split("\n")) {
    const m = /^\| `([a-z0-9-]+)` \| ([^|]+) \| (.+) \|$/.exec(line);
    if (m) out.push({ id: m[1], line });
  }
  return out;
}

function disagreements(doc, code) {
  const d = rows(doc), c = rows(code), out = [];
  const dm = new Map(d.map((r) => [r.id, r.line])), cm = new Map(c.map((r) => [r.id, r.line]));
  for (const { id } of c) if (!dm.has(id)) out.push(`${id}: the code runs this check and the document does not list it`);
  for (const { id } of d) if (!cm.has(id)) out.push(`${id}: the document lists this check and the code has no such check`);
  for (const { id, line } of c) if (dm.has(id) && dm.get(id) !== line) out.push(`${id}: the document's row differs from the code's`);
  if (!out.length && d.map((r) => r.id).join() !== c.map((r) => r.id).join()) out.push("the checks are listed in another order than the code runs them");
  if (!out.length && doc !== code) out.push("the text around the tables differs from the generated text");
  return out;
}

if (process.argv.includes("--write")) {
  writeFileSync(join(ROOT, DOC), codeText());
  console.log(`wrote ${DOC} from the code's list`);
  process.exit(0);
}

if (process.argv.includes("--negative")) {
  const code = codeText();
  const r = rows(code);
  const target = r.find((x) => x.line.includes("*not built*")) ?? r[0];
  const PLANTS = [
    ["a check dropped from the document", code.replace(r[3].line + "\n", ""), r[3].id],
    ["a check the code does not have", code.replace(r[0].line, r[0].line + "\n| `approver-quorum` | yes | A key change carries the registrar's offline approvers. |"), "approver-quorum"],
    ["a rule reworded", code.replace(r[5].line, r[5].line.replace(/ \|$/, " (usually). |")), r[5].id],
    ["a row not built marked built", code.replace(target.line, target.line.replace("*not built*", "yes")), target.id],
    ["two rows swapped", code.replace(r[1].line, "\u0000").replace(r[2].line, r[1].line).replace("\u0000", r[2].line), null],
    ["the prose edited", code.replace("Nothing here signs anything", "Little here signs anything"), null],
  ];
  let bad = 0;
  for (const [what, doc, id] of PLANTS) {
    const found = disagreements(doc, code);
    const named = id === null ? found.length > 0 : found.some((f) => f.startsWith(id + ":"));
    console.log(`  ${named ? "ok  caught " : "✗   MISSED "} ${what}${found.length ? " — " + found[0] : ""}`);
    if (!named) bad++;
  }
  const self = disagreements(code, code);
  console.log(`  ${self.length ? "✗   FLAGGED" : "ok  allowed"} the code's own output, unchanged`);
  if (self.length) bad++;
  if (bad) { console.error(`ACCREDITATION-CHECKS NEGATIVE FAILED — ${bad} case(s) judged wrongly`); process.exit(1); }
  console.log(`ACCREDITATION-CHECKS NEGATIVE OK — all ${PLANTS.length} planted disagreements caught, the true document left alone`);
  process.exit(0);
}

let doc;
try { doc = readFileSync(join(ROOT, DOC), "utf8"); } catch { console.error(`${DOC} is missing — run node tools/accreditation-checks.mjs --write`); process.exit(1); }
const code = codeText();
const found = disagreements(doc, code);
if (found.length) {
  for (const f of found) console.error(`  ✗ ${f}`);
  console.error(`ACCREDITATION-CHECKS FAILED — ${DOC} and the code disagree. Change the code, then run node tools/accreditation-checks.mjs --write.`);
  process.exit(1);
}
console.log(`ACCREDITATION-CHECKS OK — ${DOC} lists exactly the ${rows(code).length} checks the code runs, in its order and its words.`);
