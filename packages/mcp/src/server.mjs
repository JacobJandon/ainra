#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
// @ainra/mcp — a zero-dependency MCP server (JSON-RPC 2.0 over stdio, newline-delimited) exposing the AINRA tools.
// Agents are the users now; this meets them natively. No new protocol semantics — every tool wraps an existing
// surface (see tools.mjs). Zero telemetry: the only outbound calls are to the AINRA_TARGET the operator set.
//   Run: node packages/mcp/src/server.mjs   (or the `ainra-mcp` bin)
import { TOOLS, TOOL_BY_NAME, TARGET_INFO } from "./tools.mjs";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const VERSION = JSON.parse(readFileSync(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8")).version;
const PROTOCOL = "2025-06-18"; // the MCP revision this server speaks
const send = (msg) => process.stdout.write(JSON.stringify(msg) + "\n");
const reply = (id, result) => send({ jsonrpc: "2.0", id, result });
const fail = (id, code, message) => send({ jsonrpc: "2.0", id, error: { code, message } });

async function handle(msg) {
  const { id, method, params } = msg;
  if (method === "initialize")
    return reply(id, { protocolVersion: PROTOCOL, capabilities: { tools: { listChanged: false } }, serverInfo: { name: "ainra", version: VERSION }, instructions: `AINRA tools. Target: ${TARGET_INFO.target} (${TARGET_INFO.mode}). Read-only: ainra_verify/lookup/status. Write (need confirm:true): ainra_issue/renew/revoke. Never targets a registrar you don't control.` });
  if (method === "notifications/initialized" || method === "notifications/cancelled") return; // no response to notifications
  if (method === "ping") return reply(id, {});
  if (method === "tools/list")
    return reply(id, { tools: TOOLS.map((t) => ({ name: t.name, title: t.title, description: t.description, inputSchema: t.inputSchema, annotations: { title: t.title, ...t.annotations } })) });
  if (method === "tools/call") {
    const tool = TOOL_BY_NAME[params?.name];
    if (!tool) return fail(id, -32602, `unknown tool: ${params?.name}`);
    try {
      const result = await tool.handler(params.arguments || {});
      return reply(id, { content: [{ type: "text", text: JSON.stringify(result, null, 2) }], structuredContent: result, isError: false });
    } catch (e) {
      // Tool errors are reported IN-BAND (isError) so the agent sees the message and the next step, not a transport crash.
      return reply(id, { content: [{ type: "text", text: String(e.message || e) }], isError: true });
    }
  }
  if (id !== undefined) return fail(id, -32601, `method not found: ${method}`);
}

// newline-delimited JSON-RPC over stdin. Track in-flight async handlers so a closed stdin (one-shot pipes, some
// agent runners) drains pending tool calls instead of dropping their responses on the floor.
let buf = "";
let inflight = 0;
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buf += chunk;
  let nl;
  while ((nl = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, nl).trim();
    buf = buf.slice(nl + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    inflight++;
    Promise.resolve(handle(msg))
      .catch((e) => { if (msg?.id !== undefined) fail(msg.id, -32603, String(e.message || e)); })
      .finally(() => { inflight--; });
  }
});
process.stdin.on("end", () => {
  const deadline = Date.now() + 30000; // drain up to 30s of pending tool calls, then exit regardless
  const t = setInterval(() => { if (inflight === 0 || Date.now() > deadline) { clearInterval(t); process.exit(0); } }, 15);
});
process.stderr.write(`[ainra-mcp] up — ${TOOLS.length} tools, target ${TARGET_INFO.target} (${TARGET_INFO.mode}), zero telemetry\n`);
