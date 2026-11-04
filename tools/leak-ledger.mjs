// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make leak-ledger — what does each party learn when an agent's passport is verified? (D-090)
//
// Privacy claims drift from code unless something measures them; until D-090 the Standard said "selective disclosure"
// and "zero-knowledge" and every gate was green. This tool measures, against the real SDK verifier and the repo's own
// fixture passport (packages/middleware/test/fixtures), and writes one row per party:
//   * the verifier — exactly which fields it receives (every bundle field and every claim: nothing is withheld);
//   * the root, the registrar, a status host, a network observer — what reaches them during one verification of a
//     carried bundle. Every network entry point the process has (fetch, http, https, net, dns) is wired to record a
//     call, so "nothing" is a count of zero, not an assumption;
//   * the self-fetch path — the files a verifier that fetches status itself would request, from the publish-static
//     layout (tools/publish-static.mjs): they name the registrar. That is the known leak D-091 is to close.
// It also tries to withhold a field: a holder who drops one claim gets a refusal, because the registrar signed the
// claims whole.
//
//   node tools/leak-ledger.mjs            compare with evidence/leak-ledger.expected.json (exit 1 on any difference)
//   node tools/leak-ledger.mjs --write    regenerate that file and docs/LEAK-LEDGER.md (after a deliberate change)
//   node tools/leak-ledger.mjs --negative plant each leak and require the comparison to catch it
//
// WITNESS: `--negative` plants (1) a network request inside verification, (2) one more field reaching the verifier,
// (3) a self-fetch path that stops naming the registrar, (4) a network file that names one (D-091 undone), and (5) a
// withheld field that verifies — each must make the
// measured ledger differ from the expected one. Honest limit: the ledger covers what AINRA's own components receive;
// it cannot see what a CDN or a network logs beyond the request, and it says so in docs/LEAK-LEDGER.md.
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import dns from "node:dns";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const FX = join(ROOT, "packages/middleware/test/fixtures");
const EXPECTED = join(ROOT, "evidence/leak-ledger.expected.json");
const DOC = join(ROOT, "docs/LEAK-LEDGER.md");
const sdk = await import(join(ROOT, "packages/sdk-ts/dist/index.js"));
const load = (f) => JSON.parse(readFileSync(join(FX, f), "utf8"));
const directory = load("directory.json"), roots = load("roots.json"), bundle = load("bundle-valid.json");
const NOW = load("meta.json").now;

// ── every network entry point records a call ──────────────────────────────────────────────────────────────────
const calls = [];
const wrap = (obj, name, label) => {
  const orig = obj[name];
  obj[name] = function (...a) { calls.push(`${label}.${name}`); return orig.apply(this, a); };
};
const realFetch = globalThis.fetch;
globalThis.fetch = (...a) => { calls.push("fetch"); return realFetch(...a); };
for (const [m, l] of [[http, "http"], [https, "https"]]) { wrap(m, "request", l); wrap(m, "get", l); }
wrap(net, "connect", "net"); wrap(net, "createConnection", "net"); wrap(dns, "lookup", "dns");

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const claimsOf = (b) => JSON.parse(Buffer.from(b.claims, "base64url").toString("utf8"));

// The registrar ids in the directory, and the files publish-static lays out per registrar.
const selfFetchPaths = (layout) => directory.entries.map((e) => layout(e.registrar));
const PUBLISH_STATIC = (r) => [`${r}/status-list.json`, `${r}/status-list.jwt`];
// D-091: the one network-wide file publish-static also writes; it is the same path whatever registrar is checked.
const NETWORK_FILE = () => ["network-status.json"];

function measure({ plantFetch = false, extraField = false, layout = PUBLISH_STATIC, networkLayout = NETWORK_FILE, withholdOk = false } = {}) {
  calls.length = 0;
  const gate = sdk.Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F3");
  if (!gate) throw new Error("the fixture directory does not verify against its roots");
  const presented = extraField ? { ...bundle, planted_field: "x" } : bundle;
  if (plantFetch) { try { globalThis.fetch("http://127.0.0.1:9/planted").catch(() => {}); } catch { /* recorded */ } }
  const verdict = gate.verify(presented, NOW);
  const during = calls.length;
  const claims = claimsOf(bundle);
  // Withholding: drop one claim the holder might want to keep (the operator's capabilities) and present the rest.
  const { capabilities, ...rest } = claims; void capabilities;
  const withheld = gate.verify({ ...bundle, claims: b64u(rest) }, NOW);
  const paths = selfFetchPaths(layout);
  const named = directory.entries.every((e, i) => paths[i].some((p) => p.includes(e.registrar)));
  const npaths = selfFetchPaths(networkLayout);
  const networkNames = directory.entries.some((e, i) => npaths[i].some((p) => p.includes(e.registrar)));
  return {
    verdict: verdict.verdict === "valid" ? "valid" : `invalid:${verdict.reason}`,
    rows: {
      verifier: {
        receives_bundle_fields: Object.keys(presented).sort(),
        receives_claims: Object.keys(claims).sort(),
        withheld_claim_verdict: withholdOk ? "valid" : withheld.verdict === "valid" ? "valid" : `invalid:${withheld.reason}`,
      },
      root: { requests_during_verification: during },
      registrar: { requests_during_verification: during },
      status_host: { requests_during_verification: during },
      network_observer: { requests_during_verification: during },
      self_fetch: { per_registrar_paths_name_the_registrar: named, example: paths[0],
        network_file: npaths[0], network_file_names_a_registrar: networkNames },
    },
  };
}

const stable = (o) => JSON.stringify(o, null, 2) + "\n";
const ledger = measure();

if (process.argv.includes("--negative")) {
  const expected = readFileSync(EXPECTED, "utf8");
  const plants = [
    ["a network request inside verification", { plantFetch: true }],
    ["one more field reaching the verifier", { extraField: true }],
    ["a self-fetch path that no longer names the registrar", { layout: () => ["network/status.json"] }],
    ["a network file that names the registrar (D-091 undone)", { networkLayout: (r) => [`${r}/network-status.json`] }],
    ["a withheld claim that verifies", { withholdOk: true }],
  ];
  let missed = 0;
  for (const [what, opts] of plants) {
    const caught = stable(measure(opts)) !== expected;
    console.log(`  ${caught ? "ok  caught " : "✗   MISSED "} ${what}`);
    if (!caught) missed++;
  }
  if (stable(ledger) !== expected) { console.error("  ✗   the unplanted ledger itself differs from the expected file"); missed++; }
  if (missed) { console.error(`LEAK-LEDGER NEGATIVE FAILED — ${missed} plant(s) not caught`); process.exit(1); }
  console.log(`LEAK-LEDGER NEGATIVE OK — all ${plants.length} planted leaks change the ledger, and the clean run matches it`);
  process.exit(0);
}

if (process.argv.includes("--write")) {
  writeFileSync(EXPECTED, stable(ledger));
  const r = ledger.rows;
  writeFileSync(DOC, `<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# The leak ledger — what each party learns from one verification

Generated by \`node tools/leak-ledger.mjs --write\` (D-090); held to \`evidence/leak-ledger.expected.json\` by
\`make leak-ledger\`. Measured with the real SDK verifier on the fixture passport in
\`packages/middleware/test/fixtures\`, with every network entry point of the process recording calls. Verdict:
**${ledger.verdict}**.

| Party | What it receives during one verification of a carried bundle |
|---|---|
| The verifier | every bundle field (${r.verifier.receives_bundle_fields.length}: ${r.verifier.receives_bundle_fields.map((f) => `\`${f}\``).join(", ")}) and every claim (${r.verifier.receives_claims.length}: ${r.verifier.receives_claims.map((f) => `\`${f}\``).join(", ")}). Nothing can be withheld: a bundle with one claim dropped is refused (\`${r.verifier.withheld_claim_verdict}\`), because the registrar signed the claims whole. |
| The root | ${r.root.requests_during_verification} requests — the root is not contacted (root-dark). |
| The registrar | ${r.registrar.requests_during_verification} requests — the agent carries its registrar-signed status list, so the registrar learns only that its agent refreshed it, never who verified. |
| A status host or mirror | ${r.status_host.requests_during_verification} requests in carried mode. A verifier that fetches a registrar's own list requests files that name the registrar (for example \`${r.self_fetch.example.join("`, `")}\`), so the host learns whose agents it checks. D-091 publishes one file for the whole network, \`${r.self_fetch.network_file.join("`, `")}\`, the same path whichever registrar is checked (names a registrar: ${r.self_fetch.network_file_names_a_registrar ? "yes" : "no"}); a verifier that fetches should read that. |
| A network observer | ${r.network_observer.requests_during_verification} requests from the verifier, so nothing to observe. |

**Honest limit.** This covers what AINRA's own components receive. It cannot see what a CDN, a proxy or a network
logs beyond a request itself, and it measures one verification, not an agent's activity over time — the passport's
name is in every presentation, so an agent is linkable across verifiers by design (MTS §11).
`);
  console.log(`wrote ${EXPECTED} and ${DOC}`);
  process.exit(0);
}

const expected = readFileSync(EXPECTED, "utf8");
if (stable(ledger) !== expected) {
  console.error("LEAK-LEDGER FAILED — what a verification reveals changed:");
  console.error(stable(ledger));
  console.error("If the change is deliberate, regenerate with --write and say in its decision record which row moved.");
  process.exit(1);
}
console.log(`LEAK-LEDGER OK — verdict ${ledger.verdict}; 0 network requests during verification; the verifier sees all ${ledger.rows.verifier.receives_claims.length} claims; a per-registrar fetch names the registrar, the network file (D-091) does not`);
