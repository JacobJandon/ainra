// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make deploy-current — is what production SERVES the same as what this repo BUILDS?
//
// WHY THIS EXISTS, and it is a mistake of mine rather than a hypothetical. `make claims-live` verifies that the
// tracked CLAIMS match production, and it passed green while the deployment was two milestones stale — because
// M30's site edits (llms.txt gaining a section, verify.html gaining a sentence) did not happen to touch any
// tracked claim. I then reported the site as "deployed and verified live" on the strength of a gate that was
// answering a different question.
//
// Claim parity and deploy currency are different properties. This checks the second: every built page's bytes,
// compared against what the host actually returns.
//
// Ignorable differences are named explicitly rather than hand-waved: the deploy pipeline drops build-internal
// files, and a host may re-serve HTML with different whitespace or injected analytics (we have none, but the
// comparison should fail loudly if that ever changes rather than silently tolerate it).

import { readFileSync, readdirSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SITE = join(ROOT, "site");
const argBase = process.argv.indexOf("--base");
const BASE = (argBase >= 0 ? process.argv[argBase + 1] : "https://ainra.vercel.app").replace(/\/+$/, "");

// The export pipeline (tools/export-site.sh) excludes these from the published tree.
const NOT_PUBLISHED = new Set(["_includes", "DEPLOY.md", "README.md"]);
const sha = (b) => createHash("sha256").update(b).digest("hex").slice(0, 16);

const pages = readdirSync(SITE)
  .filter((f) => !NOT_PUBLISHED.has(f))
  .filter((f) => /\.(html|txt|md|json)$/.test(f))
  .filter((f) => { try { return statSync(join(SITE, f)).isFile(); } catch { return false; } })
  .sort();

let bad = 0, checked = 0;
console.log(`deploy-current · ${BASE} · ${pages.length} built page(s)`);
for (const f of pages) {
  const local = readFileSync(join(SITE, f));
  let res;
  try { res = await fetch(`${BASE}/${f}`, { redirect: "follow" }); }
  catch (e) { console.error(`  ✗ ${f} — fetch failed: ${e.message}`); bad = 1; continue; }
  if (!res.ok) { console.error(`  ✗ ${f} — HTTP ${res.status}`); bad = 1; continue; }
  const served = Buffer.from(await res.arrayBuffer());
  checked++;
  if (sha(served) !== sha(local)) {
    console.error(`  ✗ ${f} — SERVED bytes differ from the built page (local ${sha(local)} vs served ${sha(served)}, ${local.length} vs ${served.length} bytes)`);
    bad = 1;
  } else {
    console.log(`  ok    ${f.padEnd(22)} ${sha(local)}`);
  }
}

if (bad) {
  console.error(`\nDEPLOY-CURRENT FAILED — production is not serving what this repo builds.`);
  console.error(`Run \`make site && bash tools/export-site.sh\`, wait for the host, then re-run.`);
  console.error(`A green claims-live does NOT imply this: it checks the tracked claims, not every byte.`);
  process.exit(1);
}
console.log(`DEPLOY-CURRENT OK: all ${checked} published page(s) byte-identical to the build.`);
