// SPDX-License-Identifier: Apache-2.0 OR MIT
// D-079 static half — the publisher copies a real registrar's signed artefacts into content-addressed files; a copy
// served from anywhere still verifies, because the signature travels with it.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { createServer } from "node:net";

const ROOT = new URL("../../../", import.meta.url).pathname;
const procs = [];
after(() => procs.forEach((p) => p.kill()));
const freePort = () => new Promise((r) => { const s = createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => r(p)); }); });

test("published files are what their digests say, and the status token verifies wherever it is served", async () => {
  const port = await freePort();
  const data = mkdtempSync(join(tmpdir(), "ainra-pub-reg-"));
  const p = spawn(join(ROOT, "target/release/registrar-box"), [`127.0.0.1:${port}`, "registrar-07", data], {
    env: { ...process.env, AINRA_CLOCK: "pinned", AINRA_OPEN_WRITES: "1", AINRA_STAGE_ISSUE_TOKEN: "" }, stdio: "ignore",
  });
  procs.push(p);
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 300; i++) { try { await fetch(base + "/health"); break; } catch { await new Promise((r) => setTimeout(r, 200)); } }
  const out = mkdtempSync(join(tmpdir(), "ainra-pub-out-"));
  execFileSync("node", [join(ROOT, "tools/publish-static.mjs"), "--out", out, "--registrar", base]);
  const heads = JSON.parse(readFileSync(join(out, "heads.json"), "utf8"));
  const entry = heads.registrars["registrar-07"];
  assert.ok(entry, "the registrar is in heads.json");
  for (const f of ["status-list.json", "status-list.jwt", "links.json"]) {
    const bytes = readFileSync(join(out, "registrar-07", f));
    const d = createHash("sha256").update(bytes).digest("base64url");
    assert.equal(entry[f], d, `${f} is listed under its own digest`);
    assert.deepEqual(readFileSync(join(out, "sha256", d)), bytes, `sha256/${d} holds ${f}`);
  }
  for (const d of readdirSync(join(out, "sha256")))
    assert.equal(createHash("sha256").update(readFileSync(join(out, "sha256", d))).digest("base64url"), d, `sha256/${d}`);
  // The mirror's copy of the status token verifies under the registrar's status key — nothing depends on the host.
  const acc = await (await fetch(base + "/accreditation")).json();
  const jwt = readFileSync(join(out, "registrar-07", "status-list.jwt"), "utf8");
  const [h, pl, s] = jwt.split(".");
  const { createPublicKey, verify } = await import("node:crypto");
  const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: acc.status_key.ed25519 }, format: "jwk" });
  assert.equal(verify(null, Buffer.from(`${h}.${pl}`), key, Buffer.from(s, "base64url")), true);
});
