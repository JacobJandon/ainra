// SPDX-License-Identifier: Apache-2.0 OR MIT
// M10 — the front door must not disagree with itself. README.md and docs/STATUS.md each carry one canonical status
// line marked `<!-- STATUS-LINE -->…`. This fails the build if they differ (or either is missing), so the public
// headline claim can only be changed in ONE place-of-truth-per-edit and stays honest across both.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const MARK = "<!-- STATUS-LINE -->";
const extract = (rel) => {
  const line = readFileSync(ROOT + rel, "utf8").split("\n").find((l) => l.includes(MARK));
  return line ? line.slice(line.indexOf(MARK) + MARK.length).trim() : null;
};
const a = extract("README.md");
const b = extract("docs/STATUS.md");
if (!a || !b) { console.error(`STATUS-CONSISTENCY FAILED: STATUS-LINE marker missing in ${!a ? "README.md" : "docs/STATUS.md"}`); process.exit(1); }
if (a !== b) {
  console.error("STATUS-CONSISTENCY FAILED — README and STATUS disagree:\n  README: " + a + "\n  STATUS: " + b);
  process.exit(1);
}
console.log("STATUS OK: README and STATUS.md agree on the canonical status line —\n  " + a);
