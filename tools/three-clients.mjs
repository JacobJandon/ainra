// SPDX-License-Identifier: Apache-2.0 OR MIT
// M17 Task 4 — prove "any agent" without naming any. Three INDEPENDENT client implementations each complete the
// whole lifecycle (issue → verify → revoke → re-verify) against the same backend, with NO client-specific server code:
//   A · HTTP + the browser @ainra/sdk bundle            (the "skills / plain HTTP" path)
//   B · the MCP server over stdio JSON-RPC (ainra_verify) (the "MCP" path)
//   C · curl (shell) for the door + sdk-ts/dist for verify (a third, separate stack)
// Writes generic, redacted evidence to evidence/three-clients.json. Exits non-zero if any client fails a transition.
import { spawn, execFileSync } from "node:child_process";
import { writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const REG = process.env.AINRA_REG || "http://127.0.0.1:4907";
const REGID = "registrar-07";
const NOW = 1776729600;

const post = async (path, body) => (await fetch(REG + path, { method: "POST", headers: body ? { "Content-Type": "application/json" } : {}, body: body ? JSON.stringify(body) : undefined })).json();
const get = async (path) => (await fetch(REG + path)).json();
const present = (sub) => get(`/present?sub=${encodeURIComponent(sub)}&now=${NOW}`);
const anchors = async () => { const a = await get("/accreditation"); return { [REGID]: { issuer_key: a.issuer_key, log_root_key: a.log_root_key } }; };
const assert = (cond, msg) => { if (!cond) throw new Error(msg); };

// A · HTTP + browser SDK bundle
async function clientHTTP() {
  const { runVector } = await import("../site/vendor/ainra-sdk.js");
  const A = await anchors();
  const rec = await post("/demo/issue");
  assert(rec.sub, "issue failed");
  const v1 = runVector({ name: rec.sub, expect: {}, anchors: A, presentation: await present(rec.sub) });
  assert(v1.verdict === "valid", "verify not valid");
  await post("/demo/revoke", { sub: rec.sub, now: NOW });
  const v2 = runVector({ name: rec.sub, expect: {}, anchors: A, presentation: await present(rec.sub) });
  assert(v2.verdict === "invalid" && v2.reason === "revoked", "re-verify not revoked");
  return { sub: rec.sub, clean: "valid", revoked: "invalid:revoked" };
}

// C · curl (shell) for the door + sdk-ts/dist (a different SDK entry) for verify
async function clientCurl() {
  const curl = (args) => JSON.parse(execFileSync("curl", ["-s", "--max-time", "8", ...args], { encoding: "utf8" }));
  const { runVector } = await import("../packages/sdk-ts/dist/index.js");
  const A = await anchors();
  const rec = curl(["-X", "POST", `${REG}/demo/issue`]);
  assert(rec.sub, "issue failed");
  const p1 = curl([`${REG}/present?sub=${encodeURIComponent(rec.sub)}&now=${NOW}`]);
  const v1 = runVector({ name: rec.sub, expect: {}, anchors: A, presentation: p1 });
  assert(v1.verdict === "valid", "verify not valid");
  curl(["-X", "POST", "-H", "Content-Type: application/json", "-d", JSON.stringify({ sub: rec.sub, now: NOW }), `${REG}/demo/revoke`]);
  const p2 = curl([`${REG}/present?sub=${encodeURIComponent(rec.sub)}&now=${NOW}`]);
  const v2 = runVector({ name: rec.sub, expect: {}, anchors: A, presentation: p2 });
  assert(v2.verdict === "invalid" && v2.reason === "revoked", "re-verify not revoked");
  return { sub: rec.sub, clean: "valid", revoked: "invalid:revoked" };
}

// B · the MCP server over stdio JSON-RPC (ainra_verify tool)
function mcpSession() {
  const child = spawn("node", ["packages/mcp/src/server.mjs"], { cwd: ROOT, env: { ...process.env, AINRA_TARGET: REG }, stdio: ["pipe", "pipe", "ignore"] });
  let buf = "", nextId = 1; const waiters = new Map();
  child.stdout.on("data", (d) => {
    buf += d; let i;
    while ((i = buf.indexOf("\n")) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 1); if (!line.trim()) continue; try { const m = JSON.parse(line); if (m.id && waiters.has(m.id)) { waiters.get(m.id)(m); waiters.delete(m.id); } } catch {} }
  });
  const call = (method, params) => new Promise((res) => { const id = nextId++; waiters.set(id, res); child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n"); });
  return { call, close: () => child.stdin.end() };
}
async function clientMCP() {
  const A = await anchors();
  const m = mcpSession();
  await m.call("initialize", {});
  const verify = async (sub) => {
    const r = await m.call("tools/call", { name: "ainra_verify", arguments: { anchors: A, presentation: await present(sub) } });
    const text = r.result?.content?.map((c) => c.text).join("") ?? JSON.stringify(r.result);
    const j = JSON.parse(text);
    return { verdict: j.verdict, reason: j.reason ?? null };
  };
  const rec = await post("/demo/issue");
  assert(rec.sub, "issue failed");
  const v1 = await verify(rec.sub);
  assert(v1.verdict === "valid", "MCP verify not valid: " + JSON.stringify(v1));
  await post("/demo/revoke", { sub: rec.sub, now: NOW });
  const v2 = await verify(rec.sub);
  m.close();
  assert(v2.verdict === "invalid" && v2.reason === "revoked", "MCP re-verify not revoked: " + JSON.stringify(v2));
  return { sub: rec.sub, clean: "valid", revoked: "invalid:revoked" };
}

const CLIENTS = [
  ["client-1 (HTTP + @ainra/sdk)", clientHTTP],
  ["client-2 (MCP · stdio JSON-RPC)", clientMCP],
  ["client-3 (curl + sdk-ts)", clientCurl],
];

const main = async () => {
  if (!(await get("/health").then((h) => h.ok).catch(() => false))) { console.error("  ✗ registrar not up — run: make stage-up"); process.exit(2); }
  console.log("AINRA · any-agent proof — three independent clients, one lifecycle, no client-specific server code\n");
  const results = [];
  let failed = 0;
  for (const [label, fn] of CLIENTS) {
    try { const r = await fn(); console.log(`  ✓ ${label} — issue → VALID → revoke → INVALID:revoked`); results.push({ client: results.length + 1, transport: label.replace(/^client-\d+ \(|\)$/g, ""), result: "green", clean: r.clean, revoked: r.revoked }); }
    catch (e) { console.log(`  ✗ ${label} — ${e.message}`); results.push({ client: results.length + 1, transport: label, result: "red", error: e.message }); failed++; }
  }
  mkdirSync(join(ROOT, "evidence"), { recursive: true });
  writeFileSync(join(ROOT, "evidence", "three-clients.json"), JSON.stringify({
    claim: "3 independent client implementations completed the full lifecycle (issue → verify → revoke → re-verify) against the same registrar public door + read surface, with no client-specific server code.",
    network: "staging", root: "test-root", clients: results.length, green: results.filter((r) => r.result === "green").length, results,
  }, null, 2) + "\n");
  console.log(`\n${failed === 0 ? `✓ any-agent PROVEN — ${results.length}/${results.length} independent clients green (evidence/three-clients.json)` : `✗ ${failed} client(s) failed`}`);
  process.exit(failed ? 1 : 0);
};
main().catch((e) => { console.error("proof error:", e.message); process.exit(2); });
