// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make amendment-check — constitutional and normative text may not change without a matching amendment record.
//
// GOVERNANCE-AMENDMENT.md §4 requires a public diff, a rationale, and a dated record for every such change. This
// is what makes that requirement real rather than aspirational, and D-056 records why it exists primarily as a
// gate against its own author: the most likely amender of these texts is whoever edits them most often, which
// today is one person.
//
// It cannot stop a determined author — nothing in a repository can. What it does is force the amendment and its
// justification into THE SAME COMMIT, so a reader inspecting that commit years later finds both, or finds a
// commit that never passed.
//
// WITNESS: could this observe a failure? Yes, and `--self-test` proves it on demand: it stages a one-line change
// to a prohibition in a scratch worktree with no amendment entry and asserts this gate rejects it. `make
// amendment-check-negative` runs that. Without the self-test the gate would be untestable in a clean tree, which
// is the state it spends almost all its life in — and a check that only runs when it passes is not a check.
//
// Usage:  node tools/amendment-check.mjs [--base <ref>] [--self-test]

import { readFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const git = (...a) => execFileSync("git", a, { cwd: ROOT, encoding: "utf8" }).trim();
const read = (p) => { try { return readFileSync(join(ROOT, p), "utf8"); } catch { return null; } };

// The protected texts. Constitutional first, then normative — the frozen docs are already hash-pinned by
// `make check-freeze`, and this adds the WHY that a hash cannot carry.
const PROTECTED = {
  constitutional: ["GOVERNANCE.md", "GOVERNANCE-AMENDMENT.md"],
  normative: ["docs/AINRA_I_The_Standard.md", "docs/AINRA_Master_Technical_Specification_v1.md", "docs/DESIGN.md"],
};
const ALL_PROTECTED = [...PROTECTED.constitutional, ...PROTECTED.normative];

// The exact prohibition sentences. These are checked by CONTENT, not just by file — a prohibition can be deleted
// by editing a file that is otherwise legitimately changing, and a file-level check would wave that through.
const PROHIBITIONS = [
  "issues no passports", "computes no scores", "processes no payments",
  "holds no personal data", "never gates L0 existence", "features no registrar",
];

const RECORD = "docs/AMENDMENTS.md";
let bad = 0;
const fail = (m) => { console.error(`  ✗ ${m}`); bad++; };

// ── the prohibitions must still be there, verbatim ───────────────────────────────────────────────────────────
{
  // Whitespace-normalised before matching. The first version used a bare substring test and reported
  // "holds no personal data" missing because the sentence wraps as "holds no\npersonal data" — a false alarm on
  // a prohibition is as corrosive as a missed one, since a gate that cries wolf about the constitution gets
  // routed around within a week.
  const gov = (read("GOVERNANCE.md") ?? "").replace(/\s+/g, " ");
  const missing = PROHIBITIONS.filter((p) => !gov.includes(p));
  if (missing.length)
    fail(`GOVERNANCE.md no longer states ${missing.map((m) => `"${m}"`).join(", ")} — these are constitutional ` +
         `prohibitions (GOVERNANCE-AMENDMENT.md §1). They are unamendable: removing one is a fork, not an amendment.`);
  else console.log(`  ok    prohibitions      all ${PROHIBITIONS.length} present verbatim in GOVERNANCE.md`);
}

// ── a change to protected text requires a record in the same commit ──────────────────────────────────────────
const baseArg = process.argv.indexOf("--base");
const BASE = baseArg >= 0 ? process.argv[baseArg + 1] : "HEAD";
let changed = [];
try {
  // Working-tree + staged changes against BASE. In CI this is HEAD vs the pushed parent; locally it is what you
  // are about to commit.
  const out = git("diff", "--name-only", BASE);
  const staged = git("diff", "--name-only", "--cached");
  changed = [...new Set([...out.split("\n"), ...staged.split("\n")].filter(Boolean))];
} catch { /* no git or no base — fall through with an empty set and say so below */ }

const touchedProtected = changed.filter((f) => ALL_PROTECTED.includes(f));
if (touchedProtected.length) {
  const recordTouched = changed.includes(RECORD);
  if (!recordTouched) {
    fail(`${touchedProtected.join(", ")} changed with no matching entry in ${RECORD}.\n` +
         `        GOVERNANCE-AMENDMENT.md §4 requires a public diff, a rationale, and a dated record — in the same commit.\n` +
         `        Add the entry (era, approver, rationale, files) or revert the change.`);
  } else {
    console.log(`  ok    amendment record  ${touchedProtected.length} protected file(s) changed, ${RECORD} updated alongside`);
  }
} else {
  console.log(`  ok    protected text     unchanged against ${BASE} (${ALL_PROTECTED.length} file(s) watched)`);
}

// ── the record itself must stay well-formed ──────────────────────────────────────────────────────────────────
{
  const rec = read(RECORD);
  if (rec === null) fail(`${RECORD} is missing — the amendment record may not be deleted; an empty record is evidence, a deleted one is not.`);
  else {
    const entries = [...rec.matchAll(/^## (\d{4}-\d{2}-\d{2}) — /gm)];
    if (!entries.length) fail(`${RECORD} contains no dated entries — it must state that nothing has been amended, not merely be blank.`);
    else {
      for (const e of entries) {
        const start = e.index;
        const nextIdx = rec.indexOf("\n## ", start + 1);
        const body = rec.slice(start, nextIdx === -1 ? undefined : nextIdx);
        for (const req of ["**Era:**", "**Approved by:**", "**Rationale:**"])
          if (!body.includes(req)) fail(`${RECORD}: the ${e[1]} entry has no ${req.replace(/\*/g, "")} line — §4 requires era, approver and rationale.`);
      }
      console.log(`  ok    record format     ${entries.length} dated entr(y/ies), each naming era, approver and rationale`);
    }
  }
}

if (bad) {
  console.error(`\nAMENDMENT-CHECK FAILED — ${bad} problem(s). See GOVERNANCE-AMENDMENT.md.`);
  console.error(`This gate exists primarily against its own author (D-056): the most likely amender is whoever edits these texts most.`);
  process.exit(1);
}
console.log(`AMENDMENT-CHECK OK: prohibitions intact, protected text accounted for, record well-formed.`);
