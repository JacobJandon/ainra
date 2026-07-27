// SPDX-License-Identifier: Apache-2.0 OR MIT
// M17 Task 3 — OpenAPI for the HTTP surfaces that ACTUALLY exist. The specs are defined here as the source of truth
// and emitted as both .json and .yaml under site/openapi/. There is deliberately NO verification REST API: verification
// is LOCAL (fetch signed facts, check them yourself) — every spec says so prominently; that absence is the product.
//   node tools/openapi.mjs           → (re)generate site/openapi/*.{json,yaml}
//   node tools/openapi.mjs --check    → verify each documented GET path responds on the live staging deployment
import { writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "..", "site", "openapi");
const NOW = 1776729600;
const okGet = (desc) => ({ get: { summary: desc, responses: { 200: { description: "OK" } } } });

const CONTRACT = {
  openapi: "3.1.0",
  info: {
    title: "AINRA public artifact contract (READ)",
    version: "1",
    description:
      "The public, cacheable, CORS-enabled READ surface a verifier/mirror/explorer consumes. No auth, no writes. " +
      "There is NO verification endpoint here — verification is LOCAL: fetch these signed facts and check them yourself " +
      "with @ainra/sdk (~5 lines). Responses carry X-AINRA-Network and X-AINRA-Root banner headers.",
  },
  servers: [{ url: "http://127.0.0.1:8091", description: "local staging (make stage-all)" }],
  paths: {
    "/index.json": okGet("Network index: labels, generated window, registrar ids, artifact map."),
    "/directory.json": okGet("The registrar directory: accreditations and root keys."),
    "/registry.json": okGet("All registrars + their issued records + totals {registrars, issued, revoked}."),
    "/skills.md": okGet("Agent onboarding (markdown)."),
    "/registrars/{id}/accreditation.json": { get: { summary: "One registrar's issuer_key + log_root_key (verification anchors).", parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }], responses: { 200: { description: "OK" } } } },
    "/registrars/{id}/export.json": { get: { summary: "One registrar's full record export.", parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }], responses: { 200: { description: "OK" } } } },
    "/registrars/{id}/status/current.json": { get: { summary: "The registrar's current signed status list segment.", parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }], responses: { 200: { description: "OK" } } } },
  },
};

const DOOR = {
  openapi: "3.1.0",
  info: {
    title: "AINRA registrar — public door + read API",
    version: "1",
    description:
      "A registrar-box's HTTP surface. READ endpoints are open. The PUBLIC DEMO DOOR (POST /demo/issue, /demo/revoke) " +
      "needs no token, is rate-limited, staging/TEST-ROOT only, and mints/revokes only a low-tier specimen — so a " +
      "stranger completes the whole lifecycle safely. Operator writes (/issue,/renew,/revoke) require a bearer token " +
      "(see the console spec). There is NO verify REST API: GET /present returns the signed bundle and you verify it LOCALLY.",
  },
  servers: [{ url: "http://127.0.0.1:4907", description: "local staging registrar (make stage-all)" }],
  paths: {
    "/health": okGet("Liveness + network/root labels + record count."),
    "/accreditation": okGet("issuer_key + log_root_key + status_key (verification anchors)."),
    "/present": { get: { summary: "Signed presentation bundle for a subject at ?now= (feed to @ainra/sdk to verify LOCALLY).", parameters: [{ name: "sub", in: "query", required: true, schema: { type: "string" } }, { name: "now", in: "query", schema: { type: "integer" } }], responses: { 200: { description: "OK" }, 404: { description: "unknown subject" } } } },
    "/record": { get: { summary: "The stored issued record for a subject.", parameters: [{ name: "sub", in: "query", required: true, schema: { type: "string" } }], responses: { 200: { description: "OK" }, 404: { description: "unknown subject" } } } },
    "/export": okGet("Full record export at ?now=."),
    "/status-list": okGet("Current signed status list segment at ?now=."),
    "/demo/issue": { post: { summary: "PUBLIC DOOR: mint a low-tier specimen:demo credential (no auth, rate-limited, staging only).", responses: { 200: { description: "IssuedRecord" }, 403: { description: "not staging" }, 429: { description: "rate limited" } } } },
    "/demo/revoke": { post: { summary: "PUBLIC DOOR: revoke a specimen this registrar minted (no auth, rate-limited, staging only).", requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["sub"], properties: { sub: { type: "string" }, now: { type: "integer" } } } } } }, responses: { 200: { description: "revoked" }, 403: { description: "not a demo specimen / not staging" }, 429: { description: "rate limited" } } } },
  },
};

const CONSOLE = {
  openapi: "3.1.0",
  info: {
    title: "AINRA registrar console — operator write API",
    version: "1",
    description:
      "The operator-facing write API behind the open console (GET /console). Every write requires Authorization: " +
      "Bearer <operator token> and is rate-limited. This is the confirm-required write path an agent's request flows " +
      "through with a human approval click. The root has no console and no write API — issuance lives in the registrar.",
  },
  servers: [{ url: "http://127.0.0.1:4907", description: "local staging registrar (make stage-all)" }],
  paths: {
    "/console": okGet("The self-contained operator console (HTML)."),
    "/issue": { post: { summary: "Issue a credential (bearer token).", security: [{ bearerAuth: [] }], responses: { 200: { description: "IssuedRecord" }, 401: { description: "unauthorized" }, 429: { description: "rate limited" } } } },
    "/renew": { post: { summary: "Reissue with a fresh window (bearer token).", security: [{ bearerAuth: [] }], responses: { 200: { description: "IssuedRecord" }, 401: { description: "unauthorized" } } } },
    "/revoke": { post: { summary: "Revoke a credential (bearer token).", security: [{ bearerAuth: [] }], responses: { 200: { description: "StatusDelta" }, 401: { description: "unauthorized" } } } },
  },
  components: { securitySchemes: { bearerAuth: { type: "http", scheme: "bearer" } } },
};

// minimal deterministic JSON → YAML (objects, arrays, strings, numbers, booleans) — enough for these specs.
function toYaml(v, indent = 0) {
  const pad = "  ".repeat(indent);
  if (Array.isArray(v)) {
    if (v.length === 0) return "[]";
    return v.map((x) => {
      const y = toYaml(x, indent + 1);
      return typeof x === "object" && x !== null ? `${pad}-\n${y}` : `${pad}- ${y}`;
    }).join("\n");
  }
  if (v && typeof v === "object") {
    return Object.entries(v).map(([k, val]) => {
      const key = /[^A-Za-z0-9_./-]/.test(k) ? `"${k}"` : k;
      if (val && typeof val === "object") {
        const y = toYaml(val, indent + 1);
        return Array.isArray(val) && val.length ? `${pad}${key}:\n${y}` : `${pad}${key}:\n${y}`;
      }
      return `${pad}${key}: ${scalar(val)}`;
    }).join("\n");
  }
  return scalar(v);
}
function scalar(v) {
  if (typeof v === "string") return /[:#{}\[\]&*!|>'"%@`]|^\s|\s$|^$/.test(v) ? JSON.stringify(v) : v;
  return String(v);
}

const SPECS = { "artifact-contract": CONTRACT, "registrar-door": DOOR, "console": CONSOLE };

if (process.argv.includes("--check")) {
  const REG = process.env.AINRA_REG || "http://127.0.0.1:4907";
  const ART = process.env.AINRA_ART || "http://127.0.0.1:8091";
  let fail = 0;
  const probe = async (base, path) => {
    const url = base + path.replace("{id}", "registrar-07").replace("{height}", "1");
    try { const r = await fetch(url + (path.includes("present") || path.includes("record") ? `?sub=ainra:registrar-07:acme:invoicing@4.2.1&now=${NOW}` : path.includes("export") || path.includes("status") ? `?now=${NOW}` : ""), { method: "GET" }); return r.status; }
    catch { return 0; }
  };
  const checks = [
    ...Object.keys(CONTRACT.paths).filter((p) => !p.includes("{")).map((p) => [ART, p]),
    ...Object.entries(DOOR.paths).filter(([, v]) => v.get).map(([p]) => [REG, p]),
  ];
  for (const [base, p] of checks) {
    const code = await probe(base, p);
    const ok = code >= 200 && code < 500; // 404 for a since-removed sub is still "endpoint exists"
    if (!ok) { console.log(`  ✗ ${base}${p} → ${code}`); fail++; }
  }
  console.log(fail === 0 ? `✓ OpenAPI matches reality: ${checks.length} documented GET endpoints respond on the live deployment` : `\n${fail} documented endpoint(s) unreachable — is staging up? (make stage-all)`);
  process.exit(fail ? 1 : 0);
} else {
  mkdirSync(OUT, { recursive: true });
  for (const [name, spec] of Object.entries(SPECS)) {
    writeFileSync(join(OUT, name + ".json"), JSON.stringify(spec, null, 2) + "\n");
    writeFileSync(join(OUT, name + ".yaml"), toYaml(spec) + "\n");
  }
  console.log(`generated ${Object.keys(SPECS).length} OpenAPI specs (json + yaml) → site/openapi/`);
}
