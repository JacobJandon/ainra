// SPDX-License-Identifier: Apache-2.0 OR MIT
// D-079 — the hosted verifier: signed receipts, no lookup, aggregate counters only. Real fixtures; the server runs as
// a separate process exactly as deployed, with a pinned clock so the fixtures are fresh.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifyDecisionChain } from "../../../packages/sdk-ts/dist/index.js";

const ROOT = new URL("../../../", import.meta.url);
const servers = [];
after(() => servers.forEach((p) => p.kill()));

async function start(directory, roots, nowT, port) {
  const d = mkdtempSync(join(tmpdir(), "ainra-verify-"));
  writeFileSync(join(d, "directory.json"), JSON.stringify(directory));
  writeFileSync(join(d, "roots.json"), JSON.stringify(roots));
  const server = new URL("services/verify/server.mjs", ROOT).pathname;
  await new Promise((r) => spawn("node", [server, "--new-key", join(d, "key")]).on("exit", r));
  const p = spawn("node", [server, "--directory", join(d, "directory.json"), "--roots", join(d, "roots.json"), "--key", join(d, "key"), "--port", String(port), "--now", String(nowT)]);
  servers.push(p);
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 100; i++) { try { await fetch(base + "/v1/about"); return base; } catch { await new Promise((r) => setTimeout(r, 100)); } }
  throw new Error("server did not start");
}
const post = async (base, body) => (await fetch(base + "/v1/verify", { method: "POST", body: typeof body === "string" ? body : JSON.stringify(body) })).json();
const fx = (n) => JSON.parse(readFileSync(new URL(`packages/middleware/test/fixtures/${n}`, ROOT), "utf8"));
const port = () => 20000 + Math.floor(Math.random() * 20000);

test("a passport: accept or refuse, each with a signed receipt that re-checks offline and binds the request", async () => {
  const base = await start(fx("directory.json"), fx("roots.json"), fx("meta.json").now, port());
  const about = await (await fetch(base + "/v1/about")).json();
  const key = Buffer.from(about.verifier_key, "base64url");
  const ok = await post(base, { passport: fx("bundle-valid.json") });
  assert.equal(ok.decision, "accept");
  assert.ok(ok.operator);
  assert.deepEqual(verifyDecisionChain([ok.receipt], key), { ok: true, count: 1 });
  const no = await post(base, { passport: fx("bundle-revoked.json") });
  assert.equal(no.decision, "refuse");
  assert.equal(no.reason, "revoked");
  assert.equal(JSON.parse(no.receipt).reason, "revoked");
  // the receipt is bound to the exact bytes sent: the same passport sent again with different whitespace differs
  const again = await post(base, JSON.stringify({ passport: fx("bundle-valid.json") }, null, 1));
  assert.notEqual(JSON.parse(again.receipt).request, JSON.parse(ok.receipt).request);
  // an edited receipt no longer verifies
  const edited = ok.receipt.replace('"verdict":"valid"', '"verdict":"invalid","reason":"revoked"');
  assert.equal(verifyDecisionChain([edited], key).ok, false);
});

test("nothing it cannot decide is accepted; there is no lookup; metrics are aggregate", async () => {
  const base = await start(fx("directory.json"), fx("roots.json"), fx("meta.json").now, port());
  assert.deepEqual(await post(base, "not json"), { decision: "refuse", reason: "schema_violation", receipt: null });
  for (const path of ["/v1/lookup?key=abc", "/v1/agents", "/v1/search?q=acme", "/v1/verify"]) {
    assert.equal((await fetch(base + path)).status, 404, path);
  }
  await post(base, { passport: fx("bundle-valid.json") });
  const m = await (await fetch(base + "/v1/metrics")).json();
  assert.deepEqual(Object.keys(m).sort(), ["accepted", "by_reason", "refused", "verifications"]);
  assert.equal(JSON.stringify(m).includes("ainra:"), false, "no identifiers in metrics");
});

test("a link: who stands behind a key, with a receipt", async () => {
  const v = JSON.parse(readFileSync(new URL("vectors/v1-link/l01-valid.json", ROOT), "utf8"));
  const base = await start(v.directory, v.roots, v.now, port());
  const ok = await post(base, { link: v.link, key: v.presented_key });
  assert.equal(ok.decision, "accept");
  assert.equal(ok.operator, "acme");
  assert.equal(JSON.parse(ok.receipt).kind, "link");
  const r = JSON.parse(readFileSync(new URL("vectors/v1-link/l05-link-revoked.json", ROOT), "utf8"));
  const no = await post(base, { link: r.link, key: r.presented_key });
  assert.equal(no.reason, "revoked");
});
