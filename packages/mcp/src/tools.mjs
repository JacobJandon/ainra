// SPDX-License-Identifier: Apache-2.0 OR MIT
// @ainra/mcp — the AINRA tools an agent calls natively. Each tool maps 1:1 onto an EXISTING surface (the published
// @ainra/sdk verifier, the registrar's public record, the ainra CLI / registrar write API) — NO new protocol
// semantics. Read-only tools are marked; write/destructive tools require an explicit `confirm: true`. Zero telemetry:
// the only network calls are to the AINRA_TARGET the operator configured. One config field selects the target:
//   AINRA_TARGET=genesis-out           → a LOCAL registrar dir (genesis-local / `ainra init` output) via the CLI
//   AINRA_TARGET=http://127.0.0.1:8091 → a network the operator controls (lookup/status read-only; issue/renew/revoke
//                                        need AINRA_STAGE_ISSUE_TOKEN — never touch a registrar you don't hold keys for)
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { runVector, verdictEvent, serializeVerdictEvent } from "../../sdk-ts/dist/index.js";
export { verdictEvent, serializeVerdictEvent }; // one event shape across CLI, middleware, MCP (docs/PRESENTATION.md)

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const REASONS = JSON.parse(readFileSync(ROOT + "docs/reasons.json", "utf8"));
const TARGET = process.env.AINRA_TARGET || "genesis-out";
const isUrl = (t) => /^https?:\/\//.test(t);
const BIN = ROOT + "target/release/ainra";
const gloss = (v) => (v.verdict === "valid" ? REASONS.valid : REASONS[v.reason] || "");

function cli(args) {
  try { return execFileSync(BIN, args, { encoding: "utf8", timeout: 15000 }); }
  catch (e) {
    const out = (e.stderr || e.stdout || e.message || "").toString().trim();
    throw new Error(`${out}\n(the ainra CLI must be built: run \`cargo build --release -p ainra-cli-rs\`; and AINRA_TARGET must be a registrar dir you control — currently "${TARGET}")`);
  }
}
async function getJson(path) {
  let r;
  try {
    r = await fetch(TARGET.replace(/\/$/, "") + path, { signal: AbortSignal.timeout(5000) });
  } catch {
    throw new Error(`cannot reach the target at ${TARGET} — is it up? Start one with \`make stage-up\` (staging) or set AINRA_TARGET to a running network / local registrar dir.`);
  }
  if (!r.ok) throw new Error(`target ${TARGET} returned HTTP ${r.status} for ${path} — check AINRA_TARGET points at a live AINRA network.`);
  return r.json();
}
// One AINRA_TARGET, either shape: an artifact server publishes /registry.json (many registrars, read-only); a
// registrar daemon serves /export (its own records) + the write API. Agents get the SAME read surface from both.
async function readRegistry() {
  try { return await getJson("/registry.json"); } catch { /* fall through to the registrar-daemon shape */ }
  const ex = await getJson("/export");
  return {
    generated_window: { verified_at: ex.verified_at },
    registrars: [ex],
    totals: { registrars: 1, issued: (ex.records || []).length, revoked: (ex.records || []).filter((e) => e.record.revoked).length },
  };
}
async function postJson(path, body, what) {
  const token = process.env.AINRA_STAGE_ISSUE_TOKEN || "";
  const r = await fetch(TARGET.replace(/\/$/, "") + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10000),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`registrar ${what} returned HTTP ${r.status}: ${text.slice(0, 160)} — a write to a network registrar needs AINRA_STAGE_ISSUE_TOKEN (the operator's bearer token).`);
  try { return JSON.parse(text); } catch { return { raw: text }; }
}
function requireConfirm(input, tool) {
  if (input.confirm !== true)
    throw new Error(`${tool} is a WRITE operation against a registrar you control. Re-call with \`confirm: true\` to proceed. Nothing was changed.`);
}

// ── the tools (def + handler). handler(input) → a plain object; the server wraps it as MCP content. ──
export const TOOLS = [
  {
    name: "ainra_verify",
    title: "Verify an AINRA passport",
    description: "Run the real @ainra/sdk verifier over a presentation bundle (with its trust anchors) and return the verdict plus the named reason in plain words. Read-only, offline, deterministic — the same code that agrees byte-for-byte in the conformance differential. If the bundle carries an ADR-019 instance credential (a RUNNING COPY of an agent rather than the agent itself), pass your own `audience`: it is never taken from the bundle, and an empty audience refuses every instance credential.",
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    inputSchema: {
      type: "object",
      properties: {
        anchors: { type: "object", description: "Trust anchors keyed by registrar id (issuer_key + log_root_key), as published in a directory/export." },
        presentation: { type: "object", description: "The presentation bundle to verify." },
        audience: { type: "string", description: "YOUR audience (ADR-019), e.g. https://api.example. Required to accept an instance credential; a presenter can never supply it. Omit for plain passport bundles." },
      },
      required: ["anchors", "presentation"],
    },
    handler(input) {
      // The audience is the CALLER's, exactly as `now` is. It is spliced over whatever the bundle claimed, which
      // is the same override the TS Verifier and the Python Verifier apply — a presenter naming its own audience
      // would defeat audience binding entirely.
      const presentation = { ...input.presentation, audience: input.audience ?? "" };
      const v = runVector({ name: "mcp", expect: {}, anchors: input.anchors, presentation });
      const event = verdictEvent(presentation, v, presentation?.now ?? 0);
      // Report the instance layer DISTINCTLY: an agent reading this must be able to tell "the running copy is not
      // entitled" from "the lineage is not trusted", because the two have different remedies — renew the copy, or
      // stop using the passport.
      const INSTANCE_REASONS = ["instance_expired", "instance_scope_exceeds", "instance_sig_invalid", "instance_pop_invalid"];
      const inst = presentation.instance ?? null;
      return {
        verdict: v.verdict,
        reason: v.reason ?? null,
        explanation: gloss(v),
        event,
        instance: inst
          ? {
              presented: true,
              iid: inst.iid ?? null,
              expires: inst.exp ?? null,
              audience: presentation.audience || null,
              layer: v.reason && INSTANCE_REASONS.includes(v.reason) ? "instance" : v.verdict === "valid" ? "ok" : "passport",
              note: v.reason && INSTANCE_REASONS.includes(v.reason)
                ? "the RUNNING COPY is not entitled — the passport may be fine; mint a fresh instance credential"
                : v.verdict === "valid" ? null
                : "the failure is at the passport layer, not the running copy — the lineage itself did not verify",
            }
          : { presented: false },
      };
    },
  },
  {
    name: "ainra_lookup",
    title: "Look up a public record",
    description: "Resolve an AINRA name to its public record (tier, authority, standing, carried verdict) from the configured target's directory + log. Read-only.",
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    inputSchema: { type: "object", properties: { name: { type: "string", description: "The subject name, e.g. ainra:registrar-07:acme:invoicing@4.2.1" } }, required: ["name"] },
    async handler(input) {
      if (isUrl(TARGET)) {
        const reg = await readRegistry();
        for (const R of reg.registrars) for (const e of R.records)
          if (e.record.sub === input.name)
            return { name: e.record.sub, registrar: R.registrar, tier: e.record.tier, authority: e.record.auth_class, standing: e.record.revoked ? "revoked" : "active", verdict: e.verdict.verdict, reason: e.verdict.reason ?? null };
        throw new Error(`no record for "${input.name}" in the target's registry — list what exists with ainra_status, or issue it with ainra_issue.`);
      }
      const out = cli(["present", TARGET, input.name]);
      const rec = JSON.parse(out);
      return { name: rec.sub, registrar: rec.registrar, tier: rec.tier, authority: rec.auth_class, standing: rec.revoked ? "revoked" : "active" };
    },
  },
  {
    name: "ainra_status",
    title: "Status / freshness of the target",
    description: "Report the target's current head: network + root label, registrar count, and the verification window (freshness). Read-only.",
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    inputSchema: { type: "object", properties: {} },
    async handler() {
      if (isUrl(TARGET)) {
        let health = null;
        try { health = await getJson("/health"); } catch { /* artifact servers have no /health — registry totals still tell the story */ }
        const reg = await readRegistry();
        return {
          target: TARGET,
          network: health?.network ?? "staging", root: health?.root ?? "test-root",
          registrar: health?.registrar, write_auth: health?.write_auth,
          registrars: reg.totals.registrars, issued: reg.totals.issued, revoked: reg.totals.revoked,
          lineages: reg.registrars.flatMap((R) => R.records.map((e) => e.record.sub)),
          verified_at: reg.generated_window.verified_at, freshness: "F3", telemetry: "none",
        };
      }
      return { target: TARGET, mode: "local registrar dir", note: "use ainra_lookup <name> to read a record; ainra_status is fullest against a network target.", telemetry: "none" };
    },
  },
  {
    name: "ainra_issue",
    title: "Issue a passport (writes to a registrar you control)",
    description: "Issue a new passport on the configured registrar (a LOCAL dir via the ainra CLI, or a network registrar you hold the write token for). WRITE operation: requires `confirm: true`.",
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    inputSchema: {
      type: "object",
      properties: {
        operator: { type: "string" }, lineage: { type: "string" }, version: { type: "string" },
        tier: { type: "string", default: "L2" }, auth: { type: "string", default: "A2" },
        capabilities: { type: "array", items: { type: "string" } },
        confirm: { type: "boolean", description: "Must be true — this writes to your registrar." },
      },
      required: ["operator", "lineage", "version", "confirm"],
    },
    async handler(input) {
      requireConfirm(input, "ainra_issue");
      const caps = input.capabilities?.length ? input.capabilities : ["read:data"];
      if (isUrl(TARGET)) {
        const body = { operator: input.operator, lineage: input.lineage, version: input.version, tier: input.tier || "L2", auth_class: input.auth || "A2", principal_proof: "deadbeef" + input.lineage, capabilities: caps, scope_ceiling: caps, hops: [] };
        const rec = await postJson("/issue", body, "issue");
        return { issued: rec.sub ?? rec.record?.sub ?? `${input.operator}:${input.lineage}@${input.version}`, tier: rec.tier ?? body.tier, via: TARGET };
      }
      const args = ["issue", TARGET, "--operator", input.operator, "--lineage", input.lineage, "--version", input.version, "--tier", input.tier || "L2", "--auth", input.auth || "A2"];
      for (const c of caps) args.push("--cap", c);
      const out = cli(args).trim();
      return { issued: out.split("\n")[0].replace(/^issued /, ""), detail: out };
    },
  },
  {
    name: "ainra_renew",
    title: "Renew a passport (writes to a registrar you control)",
    description: "Reissue a lineage with a fresh validity window (ADR-017 renewal, prev_leaf continuity). WRITE operation: requires `confirm: true`.",
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    inputSchema: { type: "object", properties: { sub: { type: "string" }, version: { type: "string" }, confirm: { type: "boolean" } }, required: ["sub", "version", "confirm"] },
    async handler(input) {
      requireConfirm(input, "ainra_renew");
      if (isUrl(TARGET)) {
        // ADR-017 reissue over the registrar's public door — fresh window, prev_leaf continuity, new status bit.
        const out = await postJson("/renew", { sub: input.sub, new_version: input.version, now: Math.floor(Date.now() / 1000) }, "renew");
        return { renewed: input.sub, new_generation: out.sub ?? out.record?.sub ?? input.sub.replace(/@.*$/, "@" + input.version), via: TARGET };
      }
      const out = cli(["renew", TARGET, input.sub, "--version", input.version]).trim();
      return { renewed: input.sub, detail: out };
    },
  },
  {
    name: "ainra_revoke",
    title: "Revoke a passport (DESTRUCTIVE — writes to a registrar you control)",
    description: "Set a lineage's revocation bit; it fails closed everywhere within the freshness window. DESTRUCTIVE and requires `confirm: true`.",
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    inputSchema: { type: "object", properties: { sub: { type: "string" }, confirm: { type: "boolean", description: "Must be true — this revokes a live credential." } }, required: ["sub", "confirm"] },
    async handler(input) {
      requireConfirm(input, "ainra_revoke");
      if (isUrl(TARGET)) {
        await postJson("/revoke", { sub: input.sub, now: Math.floor(Date.now() / 1000) }, "revoke");
        return { revoked: input.sub, via: TARGET, note: "fails closed everywhere within the freshness window" };
      }
      const out = cli(["revoke", TARGET, input.sub]).trim();
      return { revoked: input.sub, detail: out.split("\n")[0] };
    },
  },
];

export const TOOL_BY_NAME = Object.fromEntries(TOOLS.map((t) => [t.name, t]));
export const TARGET_INFO = { target: TARGET, mode: isUrl(TARGET) ? "network" : "local-dir" };
