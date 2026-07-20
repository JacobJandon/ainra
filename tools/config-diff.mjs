// SPDX-License-Identifier: Apache-2.0 OR MIT
// make config-diff — the staging≡production parity gate (D-033). The production profile must differ from staging in
// ONLY the four allowed axes; anything else is a fork, and a fork is where a "production" deploy silently drifts
// from the reviewed staging one. This normalizes both compose files by masking the allowed axes, then asserts the
// remainder is byte-identical. Exit nonzero on any un-allowed divergence, naming the lines.
import fs from "node:fs";

const STAGING = "deploy/compose.staging.yml";
const PROD = "deploy/compose.production.yml";

// The FOUR allowed axes (docs/genesis-day/CUTOVER.md): name, banner env, volumes, key source. Each is a mask that
// collapses the environment-specific token to a placeholder so the structural remainder can be compared.
const MASKS = [
  [/^name: ainra-(staging|production)$/, "name: ainra-NET"],
  [/AINRA_STAGE: "1"/, "AINRA_BANNER"],                 // staging banner env …
  [/AINRA_NETWORK: "production"/, "AINRA_BANNER"],       // … vs production banner env
  [/\bprod_(reg07|reg11|witness|public)\b/g, "$1"],      // production volume names → staging names
];
// Comment lines (prose) are not structure; drop them entirely (the header prose legitimately differs).
const strip = (t) =>
  t.split("\n")
    .filter((l) => !l.trimStart().startsWith("#"))
    .map((l) => MASKS.reduce((s, [re, to]) => s.replace(re, to), l))
    .join("\n");

if (!fs.existsSync(PROD)) {
  console.error(`✗ ${PROD} missing — the production profile must exist (config, not a fork).`);
  process.exit(1);
}
const a = strip(fs.readFileSync(STAGING, "utf8"));
const b = strip(fs.readFileSync(PROD, "utf8"));
if (a === b) {
  console.log("✓ config-diff: production ≡ staging except {name, banner env, volumes, key source} — parity holds.");
  process.exit(0);
}
// Report the exact divergence.
const al = a.split("\n"), bl = b.split("\n");
console.error("✗ config-diff: production diverges from staging OUTSIDE the four allowed axes:");
const max = Math.max(al.length, bl.length);
let shown = 0;
for (let i = 0; i < max && shown < 12; i++) {
  if (al[i] !== bl[i]) {
    console.error(`  line ${i + 1}:\n    staging:    ${al[i] ?? "(none)"}\n    production: ${bl[i] ?? "(none)"}`);
    shown++;
  }
}
console.error("\nA production deploy that forks from the reviewed staging one is how trust silently drifts. Fix the");
console.error("profile to differ only in name / banner env / volumes / key source, or record a waiver as a D-0xx.");
process.exit(1);
