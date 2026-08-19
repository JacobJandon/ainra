// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make claims-check / make claims (regenerate docs/CLAIMS.md)
//
// THE DEFECT CLASS THIS ENDS. Three times now, a gate has checked one PLACE a claim is made rather than the CLAIM:
//
//   1. `reasons-check` compared ainra-core ↔ sdk-ts ↔ docs and never looked at the Python SDK, so D-044's
//      `registrar_distrusted` sat defined-but-missing from Python's closed set for a whole milestone.
//   2. The witness-gap gate checked site/foundation.html; the edit that mattered went to site/_includes/footer.html,
//      which is the SOURCE the built pages are generated from. The gate passed while the DEPLOYED footer still
//      advertised the opposite.
//   3. The RFC-adapter line was corrected in one file and survived in a second.
//
// Every one is the same shape: a rule enforced where someone happened to look. The fix is to make the CLAIM the
// unit — one source of truth, an explicit list of every place it is asserted, and a gate that scans BOTH generated
// output and the sources it is generated from.
//
// TWO FAILURE MODES, both required:
//   (a) a listed location disagrees with the source of truth  → the claim is wrong somewhere.
//   (b) a claim is asserted in a file the registry does not list → the claim escaped. Adding an assertion is a
//       deliberate act; it must be registered, which is also what forces someone to check that it is true.
//
// HISTORICAL RECORDS ARE EXEMPT and the exemption is load-bearing: CHANGELOG.md, docs/releases/**, docs/_archive/**
// and DECISIONS.md record what was true on a date. "Corpus 737 → 745" is a correct sentence about D-029 forever,
// and rewriting it to match today would falsify a record rather than fix a claim.

import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => { try { return readFileSync(join(ROOT, p), "utf8"); } catch { return null; } };
const json = (p) => { try { return JSON.parse(readFileSync(join(ROOT, p), "utf8")); } catch { return null; } };
const countJson = (d) => { try { return readdirSync(join(ROOT, d)).filter((f) => f.endsWith(".json") && f !== "manifest.json").length; } catch { return 0; } };

// ── the sources of truth ─────────────────────────────────────────────────────────────────────────────────────────
const TRUTH = {
  sdkVersion: () => json("packages/sdk-ts/package.json")?.version ?? "?",
  vectorsPassport: () => countJson("vectors/v1"),
  vectorsDelta: () => countJson("vectors/v1-delta"),
  vectorsDirectory: () => countJson("vectors/v1-directory"),
  reasons: () => {
    const m = read("crates/ainra-core/src/verdict.rs")?.match(/const ALL: \[\(Reason, &str\); (\d+)\]/);
    return m ? Number(m[1]) : 0;
  },
  witnesses: () => (json("witnesses/candidates.json")?.candidates ?? []).length,
  releases: () => { try { return readdirSync(join(ROOT, "docs/releases")).filter((f) => f.endsWith("-board.md")).length; } catch { return 0; } },
  implementations: () => 4, // ainra-core · sdk-ts · sdk-py · apps/cli-node (P0). WASM is core recompiled, not a 5th.
  manifestFiles: () => (read("MANIFEST.sha256") ?? "").split("\n").filter(Boolean).length,
  logsSealed: () => 0, // no genesis ceremony has happened; this is 0 until one does, and it is a claim we make loudly
};

// ── the registry ─────────────────────────────────────────────────────────────────────────────────────────────────
// `where` is an ALLOWLIST, declared on purpose. A claim appearing anywhere else is a failure, because registering
// it is what forces someone to confirm it is true in the new place.
const CLAIMS = [
  {
    id: "vectors.passport",
    what: "size of the passport conformance corpus",
    source: "vectors/v1/*.json (counted)",
    value: () => String(TRUTH.vectorsPassport()),
    // Matches "1009 vectors", "1009 conformance vectors", "1009/1009", "1009 + 17 + 9", "passport 1009".
    // The number must sit NEXT TO the thing it counts. An earlier draft also matched a bare N/N pair, which found
    // key sizes in crypto.rs, byte counts in the spec and job numbers in a workflow — coincidences, not claims.
    // A gate that cries wolf gets read as noise, which is its own way of not checking anything.
    find: () => /\b(\d{3,4})(?:\/\d{3,4})?\s*(?:CC0\s+)?(?:passport\s+)?(?:conformance\s+)?vectors?\b|(?:corpus|vectors)[^.\n]{0,40}?\b(\d{3,4})\/\d{3,4}\b|"passport"\s*:\s*(\d{3,4})|\b(\d{3,4})\s*\+\s*17\s*\+\s*9\b/gi,
    gate: "make corpus-check",
    where: ["README.md", "ROADMAP.md", "CONTRIBUTING.md", "RELEASING.md", "docs/STATUS.md", "docs/ARTIFACTS.md",
            "docs/SETTLERS.md", "docs/BEST-PRACTICES.md", "docs/WASM-DEMO.md", "docs/quickstarts/conformance.md",
            "packages/sdk-ts/README.md", "packages/sdk-py/README.md", "packages/middleware/README.md",
            "tools/conformance/CONTRACT.md", "tools/preflight.sh",
            "site/index.html", "site/docs.html", "site/foundation.html", "site/verify.html",
            "campaign/SPONSORS.md", "campaign/TEMPLATES.md", "campaign/FREE-INFRASTRUCTURE.md",
            "site/llms.txt", "packages/sdk-py/ainra/verify.py", "tools/corpus-check.mjs",
            "docs/AINRA_Master_Technical_Specification_v1.md"],
  },
  {
    id: "reasons.count",
    what: "number of frozen refusal reasons",
    source: "crates/ainra-core/src/verdict.rs → Reason::ALL length",
    value: () => String(TRUTH.reasons()),
    find: () => /(?:one of the|the)\s+(\d+)\s+(?:frozen\s+)?(?:INVALID\s+)?reason/gi,
    gate: "make reasons-check",
    where: ["docs/reasons.json", "tools/conformance/CONTRACT.md", "docs/quickstarts/sdk.md",
            "docs/quickstarts/python.md", "README.md", "docs/PRESENTATION.md", "docs/STATUS.md",
            "packages/sdk-py/README.md", "packages/sdk-py/ainra/reasons.py", "packages/sdk-py/ainra/__init__.py",
            "packages/sdk-py/tests/test_reasons.py", "packages/sdk-ts/src/index.ts",
            "crates/ainra-core/src/verdict.rs", "tools/verify-60s.mjs"],
  },
  {
    id: "witness.operators",
    what: "number of witness operators (0 ⇒ the split-view guarantee is NOT in force)",
    source: "witnesses/candidates.json → candidates[]",
    value: () => String(TRUTH.witnesses()),
    // Not preceded by a threshold marker: "≥3 witness operators reachable" is a go/no-go REQUIREMENT, not a
    // statement about how many exist. Counting it would make the gate red for saying what we intend to reach.
    find: () => /WITNESSES:\s*(\d+)|(?<![≥>]\s?)(?<!at least )(?<!least )\b(\d+)\s+witness\s+(?:operators|candidac)/gi,
    gate: "node tools/campaign.mjs check",
    where: ["site/_includes/footer.html", "site/index.html", "site/docs.html", "site/foundation.html",
            "site/get.html", "site/verify.html", "site/plan.html", "site/standard.html", "site/demo.html",
            "site/scan.html", "site/status.html", "site/404.html", "site/foundations.html",
            "ROADMAP.md", "docs/PLAN-M28.md", "docs/genesis-day/GO-NO-GO.md", "tools/campaign.mjs",
            // The live gate matches on this claim's exact wording, so it IS an assertion of it. Registering rather
            // than exempting is deliberate: when the witness count moves, the live matcher must move with it, and
            // this is what will say so. It surfaced only once the file was committed — `git ls-files` cannot see
            // an untracked file, which is the same blind spot the registry's own control ran into.
            "tools/claims-live.mjs"],
  },
  {
    id: "sdk.version",
    what: "the published @ainra/sdk version",
    source: "packages/sdk-ts/package.json → version",
    value: () => TRUTH.sdkVersion(),
    find: () => /@ainra\/sdk@(\d+\.\d+\.\d+)/g,
    gate: "node tools/status-consistency.mjs",
    where: ["docs/quickstarts/sdk.md", "docs/quickstarts/middleware.md", "site/llms.txt", "README.md",
            "packages/sdk-ts/README.md", "docs/STATUS.md", "docs/PUBLISHING.md"],
  },
  {
    id: "implementations",
    what: "independent implementations that agree over the corpus",
    source: "ainra-core · @ainra/sdk · ainra (py) · apps/cli-node — counted by `make diff`",
    value: () => String(TRUTH.implementations()),
    // "the OTHER three independent implementations" is the browser verifier describing its three peers — correct
    // English for four-minus-me, and not a claim that there are three.
    find: () => /(?<!other\s)\b(four|4|three|3|five|5)\s+independent(?:ly written)?\s+implementations?\b/gi,
    gate: "make diff",
    normalize: (raw) => ({ three: "3", four: "4", five: "5" })[String(raw).toLowerCase()] ?? String(raw),
    where: ["README.md", "ROADMAP.md", "docs/STATUS.md", "site/docs.html", "site/foundation.html",
            "campaign/SPONSORS.md", "campaign/TEMPLATES.md", "packages/sdk-py/README.md",
            "packages/sdk-ts/README.md", "packages/middleware/README.md", "CONTRIBUTING.md", "GOVERNANCE.md",
            "site/llms.txt", "examples/verify-in-browser/README.md", ".github/ISSUE_TEMPLATE/verifier_divergence.yml"],
  },
];

// Capability claims: not numbers. Their "source of truth" is a gate that PROVES them, and the registry's job is to
// make sure a capability cannot be asserted without one. This is the half that would have caught a README saying
// "fails closed" about a path where nothing tested it.
const CAPABILITIES = [
  { id: "cap.offline", what: "verification is offline — no network, no callback to the root", gate: "make verify", proof: "tools/verify-60s.mjs runs root-dark against committed artifacts" },
  { id: "cap.fail-closed", what: "every unresolvable check refuses", gate: "make diff", proof: "the corpus contains a refusal vector for every reason; a missing check flips a family" },
  { id: "cap.logged-before-valid", what: "no VALID without a Merkle inclusion proof", gate: "make diff", proof: "not-logged families across all implementations" },
  { id: "cap.hybrid", what: "both signatures or invalid", gate: "make cli-check", proof: "downgrade vectors under two policies" },
  { id: "cap.instance-bounded", what: "a running copy carries ≤1 h, narrowed, holder-bound credentials", gate: "make instance-gate", proof: "middleware accepts a copy, refuses four failure modes by name" },
  { id: "cap.zero-telemetry", what: "shipped components make no network calls and report nothing", gate: "node tools/link-check.mjs", proof: "no external request on any page; ainra-core has no network dependency" },
];

// Files that record history rather than assert current fact.
const EXEMPT = [/^CHANGELOG\.md$/, /^docs\/releases\//, /^docs\/_archive\//, /^docs\/DECISIONS\.md$/,
                /^SECURITY-ADVISORIES\.md$/, /^docs\/PLAN-M29\.md$/, /^docs\/CLAIMS\.md$/, /^tools\/claims\.mjs$/,
                /^MANIFEST\.sha256$/, /^docs\/BENCHMARKS\.md$/];

const tracked = () =>
  execFileSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8" })
    .split("\n").filter(Boolean)
    .filter((f) => /\.(md|html|txt|mjs|js|ts|py|rs|sh|json|yml)$/.test(f))
    .filter((f) => !EXEMPT.some((re) => re.test(f)))
    .filter((f) => { try { return statSync(join(ROOT, f)).size < 400_000; } catch { return false; } });

function assertionsOf(claim, files) {
  const hits = new Map(); // file → [raw values]
  for (const f of files) {
    let text = read(f);
    if (text === null) continue;
    text = text.replace(/<\/?[a-z][^>]*>/gi, " ").replace(/[*`]/g, "");
    const found = [];
    for (const m of text.matchAll(claim.find())) {
      const raw = m.slice(1).find((g) => g !== undefined);
      if (raw !== undefined) found.push(claim.normalize ? claim.normalize(raw) : String(raw));
    }
    if (found.length) hits.set(f, found);
  }
  return hits;
}

function check() {
  const files = tracked();
  let bad = 0;
  const fail = (m) => { console.error(`  ✗ ${m}`); bad = 1; };

  for (const claim of CLAIMS) {
    const truth = claim.value();
    const hits = assertionsOf(claim, files);
    const known = new Set(claim.where);
    let listedOk = 0;

    for (const [file, values] of hits) {
      if (!known.has(file)) {
        fail(`${claim.id}: asserted in ${file}, which the registry does not list — register it in tools/claims.mjs (and confirm it is true there)`);
        continue;
      }
      // A documented FLOOR ("required_minimums") is deliberately not the corpus size: an implementation may be
      // conformant on a subset. Skip those, exactly as corpus-check does.
      const text = (read(file) ?? "");
      const floors = new Set([...text.matchAll(/required_minimums[^}]*?"passport"\s*:\s*(\d+)/g)].map((m) => m[1]));
      // Values that are not this claim's number at all (e.g. 17/17 for the delta corpus) are not disagreements.
      const wrong = values.filter((v) => v !== truth && !floors.has(v) && plausible(claim, v, truth));
      if (wrong.length) fail(`${claim.id}: ${file} says ${[...new Set(wrong)].join(", ")} — the source of truth (${claim.source}) says ${truth}`);
      else listedOk++;
    }
    console.log(`  ok    ${claim.id.padEnd(22)} = ${String(truth).padEnd(6)} · ${listedOk}/${hits.size} asserting file(s) agree · ${claim.gate}`);
  }

  // Capability claims must each name a gate that exists as a make target.
  const mk = read("Makefile") ?? "";
  for (const c of CAPABILITIES) {
    const target = c.gate.replace(/^make\s+/, "").split(" ")[0];
    const isMake = c.gate.startsWith("make ");
    if (isMake && !new RegExp(`^${target}:`, "m").test(mk)) fail(`${c.id}: claims to be proven by \`${c.gate}\`, which is not a target in the Makefile`);
    else console.log(`  ok    ${c.id.padEnd(22)} proven by ${c.gate}`);
  }

  if (bad) {
    console.error("\nCLAIMS-CHECK FAILED — a public claim is wrong, or escaped the registry.");
    console.error("Fix the assertion, or register the new location in tools/claims.mjs after confirming it is true there.");
    process.exit(1);
  }
  console.log(`CLAIMS-CHECK OK: ${CLAIMS.length} tracked claims + ${CAPABILITIES.length} capability claims; every assertion agrees with its source of truth and every location is registered.`);
}

// Only compare numbers that could plausibly BE this claim — 17/17 is the delta corpus, not a wrong passport count.
function plausible(claim, v, truth) {
  if (claim.id === "vectors.passport") {
    const n = Number(v);
    if (n === 366) return false; // ADR-017's passport validity in days, not a count of anything
    return Number.isFinite(n) && n >= 100 && n !== 17 && n !== 9 && Math.abs(n - Number(truth)) < 100000 &&
           ![TRUTH.vectorsDelta(), TRUTH.vectorsDirectory(), TRUTH.manifestFiles(), Number(truth) + 26].includes(n);
  }
  return true;
}

function generate() {
  const files = tracked();
  const rows = CLAIMS.map((c) => {
    const hits = assertionsOf(c, files);
    return `| \`${c.id}\` | ${c.what} | **${c.value()}** | \`${c.source}\` | \`${c.gate}\` | ${[...hits.keys()].sort().map((f) => `\`${f}\``).join(" · ") || "—"} |`;
  });
  const caps = CAPABILITIES.map((c) => `| \`${c.id}\` | ${c.what} | \`${c.gate}\` | ${c.proof} |`);
  const md = `<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- GENERATED by tools/claims.mjs — do not edit. Regenerate: make claims -->
# The claim registry

Every factual claim this project asserts publicly, with the one source of truth it comes from, the gate that
verifies it, and **every place it is asserted**. Generated from \`tools/claims.mjs\`; \`make claims-check\` fails if
a listed location disagrees with its source, or if a claim turns up somewhere this registry does not list.

**Why the registry is the unit.** Three times a gate checked one *place* a claim was made rather than the claim
itself: \`reasons-check\` covered three of four implementations; the witness-gap gate read the built page while the
edit went to the include it is generated from; an RFC-adapter line was fixed in one file and survived in another.
A claim asserted in N places and checked in one is a claim that is wrong in N−1 places eventually.

Historical records are exempt on purpose — \`CHANGELOG.md\`, \`docs/releases/\`, \`docs/_archive/\`, \`DECISIONS.md\`,
\`SECURITY-ADVISORIES.md\`. They record what was true on a date, and rewriting them to match today would falsify a
record rather than fix a claim.

## Tracked claims

| id | claim | current value | source of truth | gate | asserted in |
|---|---|---|---|---|---|
${rows.join("\n")}

## Capability claims

These are not numbers, so their source of truth is **a gate that proves them**. The registry's job here is that a
capability cannot be claimed without one.

| id | claim | gate | what the gate actually proves |
|---|---|---|---|
${caps.join("\n")}

## Adding a claim, or asserting an existing one somewhere new

1. Add or extend the entry in \`tools/claims.mjs\`.
2. Run \`make claims-check\`. If you asserted an existing claim in a new file without registering it, it fails —
   that is the point: registering is what forces you to confirm the claim is true in the new place.
3. Run \`make claims\` to regenerate this file.
`;
  writeFileSync(join(ROOT, "docs/CLAIMS.md"), md);
  console.log(`wrote docs/CLAIMS.md — ${CLAIMS.length} tracked claims, ${CAPABILITIES.length} capability claims`);
}

process.argv.includes("--generate") ? generate() : check();
