// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make gate-parity — one request, three gates, one answer (D-072).
//
// AINRA ships three gates: `@ainra/middleware` (Node), `@ainra/edge` (ainra-core in WebAssembly) and `ainra.AinraGate`
// (Python, ASGI). The corpus holds their VERIFY functions to one answer, and `make policy-parity` holds the SDKs'
// defaults; neither sends an HTTP request. A gate is also the code around the verifier — which header line it reads,
// what it does with a field sent twice, what it answers when something is missing — and that code is written three
// times. This battery sends the SAME requests to all three, over real sockets, with a real passport from the live
// registrar, and requires the same status and the same named reason from each.
//
//   node tools/gate-parity.mjs node=http://127.0.0.1:P1 edge=http://127.0.0.1:P2 python=http://127.0.0.1:P3
//
// Each origin gets its own agent (a fresh passport and running copy), so nothing one gate remembers can colour
// another's answer. Headers are sent as raw lines, in order, so "the same field twice" means twice on the wire.
// `tools/gate-parity.sh` starts the three origins and runs this; `make live-up` must be running. TEST-ROOT.
//
// WITNESS: could this observe a failure? It did, twice, on its first run: the Python gate allowed a request the
// other two refused, and the edge gate stored a bundle whose status the registrar never signed. Negative control,
// run by hand and recorded in D-072: with `authenticate_status` skipped in ainra-adapter, eight of the 42 rows go
// red. A row passes only if every gate gives the same status AND reason, and that equals the stated expectation.
import http from "node:http";
import { liveAgent, hybridKey, now } from "./lib/live-agent.mjs";
import { PRESENTATION_HEADER, POP_HEADER, PRIME_PATH } from "../packages/sdk-ts/dist/index.js";

const AUD = process.env.AINRA_AUDIENCE ?? "https://shop.example";
const origins = process.argv.slice(2).map((a) => { const i = a.indexOf("="); return [a.slice(0, i), a.slice(i + 1).replace(/\/$/, "")]; });
if (origins.length < 2) { console.error("usage: node tools/gate-parity.mjs name=http://host:port name=http://host:port [...]"); process.exit(2); }

/** One request, its header lines exactly as given. Resolves to { status, reason, body }; never throws. */
function raw(origin, method, path, lines, body) {
  return new Promise((resolve) => {
    const u = new URL(origin);
    const flat = [["host", u.host], ...lines, ...(body ? [["content-length", String(body.length)]] : [])].flat();
    const req = http.request({ host: u.hostname, port: u.port, method, path, headers: flat }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        let parsed = null; try { parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { /* not JSON */ }
        resolve({ status: res.statusCode, reason: res.headers["x-ainra-reason"] ?? null, body: parsed });
      });
    });
    req.on("error", (e) => resolve({ status: 0, reason: e.code ?? String(e), body: null }));
    req.end(body);
  });
}
/** Header lines → the record `signPresentation` reads; a name sent twice becomes an array, as a server holds it. */
const record = (lines) => lines.reduce((h, [k, v]) => { (h[k] ??= []).push(v); return h; }, {});
const OTHER_INPUT = 'sig1=("@authority");created=1;expires=2;keyid="k";alg="ed25519";tag="web-bot-auth"';
const OTHER_SIG = `sig1=:${Buffer.alloc(64).toString("base64")}:`;

async function battery(origin) {
  const A = await liveAgent({ lineage: "parity", audience: AUD });
  const authority = new URL(origin).host;
  const primed = await raw(origin, "POST", PRIME_PATH, [["content-type", "application/json"]], Buffer.from(JSON.stringify(await A.presentation())));
  if (primed.status !== 201 || !primed.body?.ref) throw new Error(`${origin}: priming failed (${primed.status} ${primed.reason})`);
  const REF = primed.body.ref;
  const base = async (ref = REF) => [[PRESENTATION_HEADER, ref], [POP_HEADER, await A.popHeader()]];
  /** `lines`, signed: the signer's output replaces fields of the same name and is appended after the rest. */
  async function signed(lines, { method = "GET", path = "/orders", body, ...opts } = {}) {
    const add = await A.sign({ method, authority, path, headers: record(lines), body, ...opts });
    return [...lines.filter(([k]) => !(k in add)), ...Object.entries(add)];
  }
  const get = (lines, path = "/orders") => raw(origin, "GET", path, lines);
  const body = Buffer.from('{"sku":"A-1","qty":2}');
  const out = [];
  const run = async (name, expect, fn) => { const r = await fn(); out.push({ name, expect, got: `${r.status}${r.reason ? " " + r.reason : ""}` }); };

  // ── what must be allowed ───────────────────────────────────────────────────────────────────────────────────────
  await run("a signed GET", "200", async () => get(await signed(await base())));
  await run("a signed POST with a body", "200", async () => raw(origin, "POST", "/orders", await signed(await base(), { method: "POST", body }), body));
  await run("a path with a query", "200", async () => get(await signed(await base(), { path: "/search?q=a%20b&page=2" }), "/search?q=a%20b&page=2"));
  await run("header names in upper case", "200", async () => get((await signed(await base())).map(([k, v]) => [k.toUpperCase(), v])));
  await run("beside another signer, one line", "200", async () => get(await signed([...await base(), ["signature-input", OTHER_INPUT], ["signature", OTHER_SIG]])));
  await run("beside another signer, own lines", "200", async () => {
    const h = await signed(await base());
    const rest = h.filter(([k]) => !k.startsWith("signature"));
    return get([...rest, ["signature-input", OTHER_INPUT], ["signature", OTHER_SIG], ...h.filter(([k]) => k.startsWith("signature"))]);
  });

  // ── the request is not the one that was signed ─────────────────────────────────────────────────────────────────
  await run("moved to another path", "403 presentation_sig_invalid", async () => get(await signed(await base()), "/admin/refunds"));
  await run("the query changed", "403 presentation_sig_invalid", async () => get(await signed(await base(), { path: "/search?q=a" }), "/search?q=b"));
  await run("the body changed", "403 presentation_sig_invalid", async () => raw(origin, "POST", "/orders", await signed(await base(), { method: "POST", body }), Buffer.from('{"sku":"A-1","qty":200}')));
  await run("a body the signature never covered", "403 presentation_sig_invalid", async () => raw(origin, "POST", "/orders", await signed(await base(), { method: "POST" }), body));
  await run("signed by another key", "403 presentation_sig_invalid", async () => get(await signed(await base(), { key: hybridKey() })));
  await run("keyid names another copy", "403 presentation_sig_invalid", async () => get(await signed(await base(), { keyid: "i-00000000" })));
  await run("signed 301 s ago", "403 presentation_stale", async () => get(await signed(await base(), { created: now() - 301 })));
  await run("signed 31 s in the future", "403 presentation_stale", async () => get(await signed(await base(), { created: now() + 31 })));
  await run("the identical request, again", "403 presentation_replayed", async () => { const h = await signed(await base()); await get(h); return get(h); });

  // ── the signature fields ───────────────────────────────────────────────────────────────────────────────────────
  await run("unsigned", "403 presentation_unsigned", async () => get(await base()));
  await run("signed only by someone else", "403 presentation_unsigned", async () => get([...await base(), ["signature-input", OTHER_INPUT], ["signature", OTHER_SIG]]));
  await run("signature-input without signature", "403 presentation_unsigned", async () => get((await signed(await base())).filter(([k]) => k !== "signature")));
  await run("two ainra members", "403 presentation_sig_invalid", async () => get((await signed(await base())).map(([k, v]) => (k === "signature-input" ? [k, `${v}, ${v}`] : [k, v]))));
  await run("the signature fields sent twice", "403 presentation_sig_invalid", async () => { const h = await signed(await base()); return get([...h, ...h.filter(([k]) => k.startsWith("signature"))]); });

  // ── the presentation headers ───────────────────────────────────────────────────────────────────────────────────
  await run("a digest this gate was never sent", "428 presentation_unknown", async () => get(await signed(await base(`sha-256=:${Buffer.alloc(32).toString("base64")}:`))));
  await run("the presentation header sent twice", "403 schema_violation", async () => get(await signed([[PRESENTATION_HEADER, REF], [PRESENTATION_HEADER, REF], [POP_HEADER, await A.popHeader()]])));
  await run("no presentation header", "403 schema_violation", async () => get([]));
  await run("a presentation header that is not one", "403 schema_violation", async () => get(await signed([[PRESENTATION_HEADER, "not-a-presentation"], [POP_HEADER, await A.popHeader()]])));
  await run("the digest without a proof of possession", "403 schema_violation", async () => get(await signed([[PRESENTATION_HEADER, REF]])));
  await run("a proof of possession that is not one", "403 schema_violation", async () => get(await signed([[PRESENTATION_HEADER, REF], [POP_HEADER, "AAAA"]])));
  await run("another copy's proof of possession", "403 instance_pop_invalid", async () => {
    const B = await liveAgent({ lineage: "parity-other", audience: AUD });
    return get(await signed([[PRESENTATION_HEADER, REF], [POP_HEADER, await B.popHeader()]]));
  });

  // ── send-once ──────────────────────────────────────────────────────────────────────────────────────────────────
  const prime = (text) => raw(origin, "POST", PRIME_PATH, [["content-type", "application/json"]], Buffer.from(text));
  await run("send-once: not JSON", "403 schema_violation", async () => prime("{not json"));
  await run("send-once: JSON that is not a bundle", "403 schema_violation", async () => prime('{"hello":"world"}'));
  await run("send-once: a JSON array", "403 schema_violation", async () => prime("[1,2,3]"));
  await run("send-once: an empty body", "403 schema_violation", async () => raw(origin, "POST", PRIME_PATH, [["content-type", "application/json"]]));
  await run("send-once: the bundle without its proof of possession", "403 schema_violation", async () => { const p = await A.presentation(); delete p.instance.pop; return prime(JSON.stringify(p)); });
  // ── status the registrar did not sign (D-072) ──────────────────────────────────────────────────────────────────
  // Every one of these is a presenter editing the status material it hands over. A gate that does not authenticate
  // the registrar's signature over it believes them; all three must answer stale_status — status that cannot be
  // authenticated is status that is not available.
  const edited = async (edit, b) => { const p = await A.presentation(b); edit(p); return prime(JSON.stringify(p)); };
  await run("status: the list changed", "403 stale_status", () => edited((p) => { p.status_list = p.status_list.slice(0, -2) + (p.status_list.endsWith("AA") ? "BB" : "AA"); }));
  await run("status: a byte appended to the list", "403 stale_status", () => edited((p) => { p.status_list += "A"; }));
  await run("status: the issue time moved", "403 stale_status", () => edited((p) => { p.status_issued_at += 1; }));
  await run("status: the signature removed", "403 stale_status", () => edited((p) => { delete p.status_sig_ed25519; delete p.status_sig_mldsa65; }));
  await run("status: one half of the signature removed", "403 stale_status", () => edited((p) => { delete p.status_sig_mldsa65; }));
  await run("status: published under another URI", "403 stale_status", () => edited((p) => { p.status_uri = "status://someone-else/1"; }));
  await run("status: the declared length changed", "403 stale_status", () => edited((p) => { p.status_len += 8; }));
  await run("a mandate-revocation set from the presenter", "201", () => edited((p) => { p.mandate_revocations = ["m-anything"]; }));
  const before = { ...A.bundle };
  await A.revoke();
  await run("send-once: after revocation", "403 revoked", async () => prime(JSON.stringify(await A.presentation(await A.fetchBundle()))));
  // THE attack this section exists for: a revoked agent keeps the list from before its revocation and claims it was
  // issued just now. Before D-072 the edge gate stored that bundle and then allowed its signed requests.
  await run("REVOKED, presenting its old status as issued now", "403 stale_status", () => edited((p) => { p.status_issued_at = now(); }, before));
  return out;
}

const results = [];
for (const [name, origin] of origins) results.push([name, await battery(origin)]);

let bad = 0;
const names = origins.map(([n]) => n);
console.log(`\n${"case".padEnd(52)} ${names.map((n) => n.padEnd(30)).join(" ")}`);
for (let i = 0; i < results[0][1].length; i++) {
  const row = results.map(([, r]) => r[i]);
  const same = row.every((r) => r.got === row[0].got);
  const asExpected = row[0].expect === null || row.every((r) => r.got === r.expect);
  if (!same || !asExpected) bad++;
  const mark = !same ? "DIFFER" : !asExpected ? `WANT ${row[0].expect}` : "";
  console.log(`${(same && asExpected ? "  " : "✗ ") + row[0].name.padEnd(50)} ${row.map((r) => r.got.padEnd(30)).join(" ")} ${mark}`);
}
console.log(bad
  ? `\nGATE-PARITY FAILED: ${bad} of ${results[0][1].length} requests were not answered the same way, or not as expected.`
  : `\nGATE-PARITY OK: ${results[0][1].length} requests, ${names.length} gates (${names.join(", ")}) — the same status and the same reason from each. TEST-ROOT.`);
process.exit(bad ? 1 : 0);
