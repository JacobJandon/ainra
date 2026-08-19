// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make claims-live — run the claim registry against the DEPLOYED site, not the repo.
//
// `make claims-check` proves the repository is internally consistent. It cannot prove that what is SERVED matches,
// and the difference is exactly the defect this milestone exists to end: during M28 a footer edit landed in the
// built page instead of the include it is generated from, the repo-side gate passed, and production went on
// advertising the opposite for a deploy cycle. Repo-green and live-wrong is the failure mode.
//
// WITNESS: could this observe a failure? It fetches real pages over the network and compares them against the
// repository's sources of truth. Point it at a stale deployment and it goes red naming the page and both values;
// point it at a host that does not serve the page and it says so rather than passing quietly. `--base` makes that
// testable without breaking production.
//
// Usage: node tools/claims-live.mjs [--base https://ainra.vercel.app]

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const argBase = process.argv.indexOf("--base");
const BASE = (argBase >= 0 ? process.argv[argBase + 1] : "https://ainra.vercel.app").replace(/\/+$/, "");

const read = (p) => { try { return readFileSync(join(ROOT, p), "utf8"); } catch { return null; } };
const truth = {
  vectors: readdirSync(join(ROOT, "vectors/v1")).filter((f) => f.endsWith(".json") && f !== "manifest.json").length,
  witnesses: JSON.parse(read("witnesses/candidates.json")).candidates.length,
  reasons: Number(read("crates/ainra-core/src/verdict.rs").match(/const ALL: \[\(Reason, &str\); (\d+)\]/)[1]),
};

// Each entry: the page, what must be TRUE on it, and how to read the served bytes. `expect` is computed from the
// repository's source of truth — never hardcoded, or this file becomes another place a claim can go stale.
const LIVE = [
  { page: "/llms.txt", label: "corpus count (agent index)",
    read: (t) => (t.match(/\b(\d{3,4})\s+CC0 conformance vectors/) ?? [])[1], expect: () => String(truth.vectors) },
  { page: "/llms.txt", label: "browser agreement (agent index)",
    read: (t) => (t.match(/must agree (\d{3,4})\/\d{3,4}/) ?? [])[1], expect: () => String(truth.vectors) },
  { page: "/docs.html", label: "corpus agreement",
    read: (t) => (t.match(/agree on <b>(\d{3,4})\/\d{3,4}<\/b> conformance vectors/) ?? [])[1], expect: () => String(truth.vectors) },
  { page: "/foundation.html", label: "witness operators (the split-view gap)",
    read: (t) => (/0 OPERATORS — GAP/.test(t) ? "0" : "nonzero-or-absent"), expect: () => String(truth.witnesses) },
  { page: "/foundation.html", label: "footer witness statement",
    read: (t) => (/WITNESSES: 0 — SPLIT-VIEW GUARANTEE NOT IN FORCE/.test(t) ? "0" : "absent"), expect: () => String(truth.witnesses) },
  { page: "/docs.html", label: "the instance path is documented",
    read: (t) => (/id="integrate-instance"/.test(t) ? "present" : "absent"), expect: () => "present" },
  { page: "/llms.txt", label: "the agent index knows the rung",
    read: (t) => (/Running copies \(ADR-019\)/.test(t) ? "present" : "absent"), expect: () => "present" },
];

const fetchText = async (p) => {
  const res = await fetch(BASE + p, { redirect: "follow" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
};

let bad = 0;
const cache = new Map();
console.log(`claims-live · ${BASE}`);
for (const c of LIVE) {
  let text = cache.get(c.page);
  if (text === undefined) {
    try { text = await fetchText(c.page); cache.set(c.page, text); }
    catch (e) {
      console.error(`  ✗ ${c.page} — could not fetch: ${e.message}. A page we cannot read is NOT a page that passes.`);
      bad = 1; continue;
    }
  }
  const got = c.read(text), want = c.expect();
  if (got === undefined || got === null) { console.error(`  ✗ ${c.page} · ${c.label}: the claim is not present on the served page`); bad = 1; }
  else if (String(got) !== String(want)) { console.error(`  ✗ ${c.page} · ${c.label}: serves "${got}", the repository's source of truth says "${want}"`); bad = 1; }
  else console.log(`  ok    ${c.page.padEnd(18)} ${c.label.padEnd(38)} ${got}`);
}

if (bad) {
  console.error(`\nCLAIMS-LIVE FAILED — the deployment disagrees with the repository, or a page could not be read.`);
  console.error(`Repo-green and live-wrong is the failure this exists to catch: deploy (bash tools/export-site.sh) and re-run.`);
  process.exit(1);
}
console.log(`CLAIMS-LIVE OK: ${LIVE.length} claims verified against what ${BASE} actually serves.`);
