#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make desk-drill — the steward's desk (PLAN-M53 step 2, D-099) against a real TEST-ROOT world.
//
// Runs the epoch rehearsal with AINRA_REHEARSAL_KEEP to get a signed contract, its roots and two divergent copies of
// registrar-11's log, starts the desk on loopback, and requires:
//   · the screen reads the control room, the epoch log and the incident log;
//   · the log-forked playbook builds the D-098 fork proof from the two copies and the real checker ACCEPTS the
//     emergency request; the same copy twice is REFUSED by name (adverse-proof);
//   · every other playbook drafts an incident entry; every draft lands under the desk's own drafts folder;
//   · a request filed in home/requests is checked and aged on the screen;
//   · a request with another Host is refused (421), a playbook from another origin is refused (403), an unknown
//     route is 404, and the desk refuses to bind anything but 127.0.0.1;
//   · the contract the desk reads is byte-identical afterwards — the desk wrote nothing into it.
//
// WITNESS: drop the desk's Host check and the 421 case goes red; drop the fork proof from the request it drafts and
// the checker refuses it (adverse-notice-chain), so the "ACCEPTS" case goes red; point the playbook's output at the
// contract and the byte-identical case goes red.
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, statSync, copyFileSync, existsSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const W = mkdtempSync(join(tmpdir(), "desk-drill-")), KEEP = join(W, "world"), HOME = join(W, "home");
let bad = 0; const ok = (c, m) => { if (c) console.log(`  ok    ${m}`); else { console.error(`  ✗     ${m}`); bad++; } };
const tree = (d) => readdirSync(d, { recursive: true }).filter((f) => statSync(join(d, f)).isFile()).sort().map((f) => f + ":" + createHash("sha256").update(readFileSync(join(d, f))).digest("hex")).join("\n");

console.log("desk-drill · the steward's desk against a TEST-ROOT world (the epoch rehearsal, kept)");
const reh = spawnSync("bash", ["tools/sign-epoch-rehearsal.sh"], { cwd: ROOT, env: { ...process.env, AINRA_REHEARSAL_KEEP: KEEP }, encoding: "utf8", timeout: 1200000 });
if (reh.status !== 0 || !existsSync(join(KEEP, "contract", "directory.json"))) { console.error(reh.stdout.slice(-2000), reh.stderr.slice(-2000)); console.error("DESK DRILL: the rehearsal did not leave a world"); process.exit(2); }
const before = tree(join(KEEP, "contract"));

const refuse = spawnSync("node", ["kits/steward/desk.mjs", "--net", join(KEEP, "contract"), "--roots", join(KEEP, "roots.json"), "--home", HOME, "--host", "0.0.0.0"], { cwd: ROOT, encoding: "utf8" });
ok(refuse.status === 2 && /loopback only/.test(refuse.stderr), "the desk refuses to bind 0.0.0.0");

const desk = spawn("node", ["kits/steward/desk.mjs", "--net", join(KEEP, "contract"), "--roots", join(KEEP, "roots.json"), "--home", HOME, "--site", join(ROOT, "site"), "--port", "0"], { cwd: ROOT });
const port = await new Promise((res, rej) => { let buf = ""; desk.stdout.on("data", (d) => { buf += d; const m = buf.match(/127\.0\.0\.1:(\d+)/); if (m) res(Number(m[1])); }); desk.on("exit", () => rej(new Error("desk exited"))); setTimeout(() => rej(new Error("desk did not start")), 20000); });
const call = (method, path, body, headers = {}) => new Promise((res) => {
  const data = body === undefined ? null : JSON.stringify(body);
  const r = http.request({ host: "127.0.0.1", port, method, path, headers: { host: `127.0.0.1:${port}`, ...(data ? { "content-type": "application/json" } : {}), ...headers } }, (rs) => { let b = ""; rs.on("data", (d) => (b += d)); rs.on("end", () => { let j = null; try { j = JSON.parse(b); } catch { /* html */ } res({ code: rs.statusCode, body: b, json: j }); }); });
  if (data) r.write(data); r.end();
});

try {
  const page = await call("GET", "/");
  ok(page.code === 200 && /Steward's desk/.test(page.body), "the page is served");
  const s = await call("GET", "/api/state");
  ok(s.code === 200 && s.json.ctl.lines.length > 0 && s.json.ctl.lines.some((l) => /both roots/.test(l.text)), `the screen reads the control room (ctl exit ${s.json?.ctl.exit}, ${s.json?.ctl.lines.length} lines)`);
  ok(s.json.epoch_log && s.json.epoch_log.size >= 1, `the screen reads the epoch log (size ${s.json?.epoch_log?.size})`);
  ok(s.json.incidents.length >= 7, `the screen reads the incident log (${s.json?.incidents.length} entries)`);

  const a = readFileSync(join(KEEP, "a.json"), "utf8"), b = readFileSync(join(KEEP, "b.json"), "utf8");
  const fork = await call("POST", "/api/playbook/log-forked", { registrar: "registrar-11", leaf: "1", a, b });
  ok(fork.code === 200 && fork.json.check.passes === true, `log-forked: the checker ACCEPTS the emergency stop built from two copies of registrar-11's log`);
  ok(fork.json?.drafts?.startsWith(join(HOME, "drafts")) && ["evidence.json", "request.json", "incident-draft.json"].every((f) => existsSync(join(fork.json.drafts, f))), "its drafts land in the desk's own drafts folder");
  const same = await call("POST", "/api/playbook/log-forked", { registrar: "registrar-11", leaf: "1", a, b: a });
  ok(same.code === 200 && same.json.check.passes === false && /adverse-proof/.test(same.json.check.output), "the same copy twice is REFUSED by name (adverse-proof)");
  for (const p of ["delegate-compromised", "share-lost", "site-defaced"]) {
    const r = await call("POST", `/api/playbook/${p}`, { registrar: "registrar-07" });
    ok(r.code === 200 && r.json.incident?.class && r.json.drafts?.startsWith(join(HOME, "drafts")), `${p}: an incident draft (${r.json?.incident?.class}) and its checklist`);
  }

  copyFileSync(join(fork.json.drafts, "request.json"), join(HOME, "requests", "fork.json"));
  const s2 = await call("GET", "/api/state");
  const filed = s2.json.requests.find((r) => r.file === "fork.json");
  ok(filed && filed.check === "passes" && filed.age_days === 0, `a filed request is checked and aged on the screen (${filed?.check}, day ${filed?.age_days} of 90)`);

  ok((await call("GET", "/api/state", undefined, { host: "evil.example" })).code === 421, "another Host is refused (421): no DNS rebinding");
  ok((await call("POST", "/api/playbook/site-defaced", {}, { origin: "https://evil.example" })).code === 403, "a playbook from another origin is refused (403)");
  ok((await call("POST", "/api/playbook/..%2F..%2Fetc", {})).code === 404, "an unknown route is 404");
  ok(tree(join(KEEP, "contract")) === before, "the contract the desk reads is byte-identical afterwards");
} finally { desk.kill(); if (!process.env.DESK_DRILL_KEEP) rmSync(W, { recursive: true, force: true }); }

if (bad) { console.error("DESK DRILL FAILED"); process.exit(1); }
console.log("DESK DRILL OK — the desk reads everything, drafts the emergency stop the checker accepts, and holds no key");
