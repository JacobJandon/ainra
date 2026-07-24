// SPDX-License-Identifier: Apache-2.0 OR MIT
// Example: an HTTP service that GATES a path on the AINRA middleware — fail closed. Run: node examples/gate-http-service.mjs
// Self-contained: builds a Verifier from the bundled sample artifacts, starts a server, then POSTs a request WITH a
// valid passport (allowed) and one WITHOUT (denied 403), and prints both outcomes. Placeholder operators only.
// The bundle is presented in the request BODY field `ainra_passport` — AINRA bundles are tens of KB (post-quantum
// key + signature), over most header limits, so the body is the recommended envelope (see docs/PRESENTATION.md).
import http from "node:http";
import { readFileSync } from "node:fs";
import { Verifier, checkRequest, serializeVerdictEvent } from "../packages/middleware/dist/index.js";

const j = (f) => JSON.parse(readFileSync(new URL("../kits/verifier/sample-artifacts/" + f, import.meta.url), "utf8"));
const roots = j("roots.json");
const NOW = j("meta.json").now;
const verifier = Verifier.fromDirectoryB64(j("directory.json"), roots.root_ed25519, roots.root_slh);

// The gate: read the presentation bundle from the body's `ainra_passport`, verify, allow or deny (403) fail-closed.
const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const bundle = (() => { try { return JSON.parse(body).ainra_passport; } catch { return undefined; } })();
    const result = checkRequest(verifier, bundle, { now: () => NOW });
    res.setHeader("x-ainra-verdict", serializeVerdictEvent(result.event));
    if (!result.allow) { res.statusCode = 403; res.end(JSON.stringify({ error: "denied", reason: result.reason })); return; }
    res.end(JSON.stringify({ ok: true, agent: result.event.name, tier: result.event.tier }));
  });
});

await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;
const call = async (label, bundleFile) => {
  const body = bundleFile ? JSON.stringify({ ainra_passport: j(bundleFile) }) : "{}";
  const res = await fetch(`http://127.0.0.1:${port}/agent`, { method: "POST", headers: { "Content-Type": "application/json" }, body });
  console.log(`${label.padEnd(22)} → HTTP ${res.status} · ${await res.text()}`);
};
await call("valid passport", "bundle-valid.json");
await call("no passport", null);
await call("revoked passport", "bundle-revoked.json");
server.close();
