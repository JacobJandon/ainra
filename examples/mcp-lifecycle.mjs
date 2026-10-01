// SPDX-License-Identifier: Apache-2.0 OR MIT
// Example: drive the AINRA lifecycle through the MCP tools an agent would call — issue → check (verify standing) →
// revoke → check again — against a LOCAL registrar the operator controls. Plus one pure ainra_verify to show the
// verdict tool. Run: node examples/mcp-lifecycle.mjs   (placeholder operators only; nothing leaves this machine.)
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const DIR = ROOT + "target/mcp-lifecycle-registrar";
const BIN = ROOT + "target/release/ainra";

// setup: a fresh local registrar (this is the operator's, so the write tools may touch it).
execFileSync(BIN, ["init", DIR, "registrar-07"], { encoding: "utf8" });
process.env.AINRA_TARGET = DIR; // one config field selects the target; must be set before importing the tools
const { TOOL_BY_NAME } = await import("../packages/mcp/src/tools.mjs");
const call = async (tool, args) => TOOL_BY_NAME[tool].handler(args);
const sub = "ainra:registrar-07:acme:assistant@1.0.0";

console.log("1. ainra_issue :", JSON.stringify(await call("ainra_issue", { operator: "acme", lineage: "assistant", version: "1.0.0", tier: "L2", capabilities: ["read:data"], confirm: true })));
console.log("2. ainra_lookup:", JSON.stringify(await call("ainra_lookup", { name: sub })));           // standing: active
console.log("3. ainra_revoke:", JSON.stringify(await call("ainra_revoke", { sub, confirm: true })));  // the kill-switch
console.log("4. ainra_lookup:", JSON.stringify(await call("ainra_lookup", { name: sub })));           // standing: revoked

// ainra_verify DECIDES when you give it the signed directory and the roots you trust (see docs/quickstarts/mcp.md).
// Here it replays a conformance vector instead — which carries its own anchors, clock and status on purpose — so
// the call says so by name: `fixture: true`. That mode shows the verdict + named reason + event shape; it believes
// the bundle and is never a decision about a real presenter.
const { readdirSync, readFileSync } = await import("node:fs");
const vdir = ROOT + "vectors/v1";
const vfile = readdirSync(vdir).find((f) => { try { return JSON.parse(readFileSync(vdir + "/" + f, "utf8")).expect?.verdict === "valid"; } catch { return false; } });
const vec = JSON.parse(readFileSync(vdir + "/" + vfile, "utf8"));
console.log("5. ainra_verify:", JSON.stringify(await call("ainra_verify", { anchors: vec.anchors, presentation: vec.presentation, fixture: true })));

execFileSync("rm", ["-rf", DIR]);
console.log("\nMCP-driven lifecycle complete: a valid credential was issued, its standing checked, revoked, and re-checked — all through agent-callable tools, with revoke requiring confirm:true.");
