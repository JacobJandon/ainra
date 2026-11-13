// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make record-agrees — do the published record and every registrar agree on every passport?  (PLAN-M53 R3, D-107)
//
// The record on the site is a copy; a registrar answers from its own state. Until 13 November 2026 nothing compared
// the two passport by passport: `make site-net-check` compared files with the artifact server and asked one
// registrar for one subject. So the site showed four passports as VALID that their registrar would not vouch for,
// and a registrar's log held a different first leaf than the record published at the same size, and both checks
// were green. This one asks about every passport, at its own registrar:
//
//   · the directory the record ships is anchored in the roots it ships;
//   · every stored passport, verified again by the published SDK, gets exactly the verdict stored beside it;
//   · its own registrar can present it, and what it presents is THE SAME passport (the same claims, the same issuer
//     signature, the same leaf — not another one under the same name);
//   · where the registrar's log is the size the record published, it has the root the record published;
//   · that presentation, verified against the published directory, gets the same verdict the record shows;
//   · the registrar holds no passport the record does not list, and the record lists none the registrar lacks.
//
//   node tools/record-agrees.mjs              the committed site/net/ against the registrars on this machine
//   AINRA_RECORD=https://ainra.org/net …      the record a visitor is reading now, against the same registrars
//   AINRA_DOORS=registrar-07=http://…,…       where each registrar answers (default 127.0.0.1:49NN for registrar-NN)
//   node tools/record-agrees.mjs --drill      the witness; offline
//
// Exit 0: they agree. Exit 1: they do not, and each disagreement is named. Exit 2: it could not ask (the record is
// unreadable or a registrar is not answering) — no network, no verdict; it never guesses.
//
// WITNESS: --drill builds a one-passport record from the committed sample bundles (kits/verifier/sample-artifacts:
// one passport as issued, and the same passport after its registrar revoked it) and a registrar that answers from
// them, then plants, one at a time: a record that says VALID over a passport its registrar has revoked; a record
// that says revoked over one its registrar presents as valid; a registrar that does not know the passport; a
// registrar presenting another passport under the same name; a registrar whose log has another root at the same
// size; a registrar holding a passport the record does not list; a record listing one the registrar lacks; a stored
// verdict edited to VALID beside a revoked passport; and roots with one byte flipped. Each must be refused with its
// own line. The two untouched worlds must pass, so a check that refuses everything cannot.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Verifier } from "../packages/sdk-ts/dist/index.js";
import { runVector } from "../packages/sdk-ts/dist/conformance.js";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const b64u = (s) => Buffer.from(s, "utf8").toString("base64url");
const said = (v) => (v?.verdict === "valid" ? "VALID" : `INVALID · ${v?.reason ?? "no reason"}`);
const same = (a, b) => a?.verdict === b?.verdict && (a?.verdict === "valid" || a?.reason === b?.reason);

// A stored record as the vector the SDK's conformance runner verifies (the shape tools/verify-60s.mjs and the
// site's own scan page use).
function toWire(rec, R, now) {
  return {
    name: rec.sub, expect: {},
    anchors: { [R.registrar]: { issuer_key: R.accreditation.issuer_key, log_root_key: R.accreditation.log_root_key } },
    presentation: {
      claims: b64u(rec.claims),
      issuer_sig: { ed25519: rec.issuer_sig_ed25519, mldsa65: rec.issuer_sig_mldsa65 },
      now, chain_keys: rec.chain_keys, hop_proofs: rec.hop_proofs,
      status_list: R.status_list.status_list_b64, status_len: R.status_list.bit_len, status_issued_at: R.status_list.issued_at,
      freshness: "F3",
      checkpoint: { origin: rec.log_origin, size: rec.checkpoint_size, root: rec.checkpoint_root },
      checkpoint_sig: rec.checkpoint_sig, leaf_index: rec.leaf_index, inclusion_proof: rec.inclusion_proof,
      mandate_revocations: [], revoked_delegates: [],
    },
  };
}

// The comparison itself. `door(id)` gives a registrar: { records(): [{sub, revoked}], present(sub, now): bundle|null }.
// A door that cannot be reached throws; that is "could not ask", never a disagreement.
export async function agree({ registry, directory, roots, door }) {
  const bad = [], now = registry?.generated_window?.verified_at;
  let passports = 0;
  if (!now || !Array.isArray(registry?.registrars)) return { bad: ["the record is not a published record (no verify time, or no registrars)"], passports };
  const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F3");
  if (!verifier) return { bad: ["the record's directory is not anchored in the record's roots"], passports };
  for (const R of registry.registrars) {
    const d = door(R.registrar), listed = new Set();
    for (const e of R.records || []) {
      const rec = e.record, who = rec.sub; passports++; listed.add(who);
      const stored = e.verdict;   // { verdict: "valid" } or { verdict: "invalid", reason }
      let again;
      try { again = runVector(toWire(rec, R, now)); } catch (x) { again = { verdict: "invalid", reason: `could not be verified (${String(x.message).slice(0, 60)})` }; }
      if (!same(stored, again)) bad.push(`${who}: the record shows ${said(stored)}, and its own stored passport verifies as ${said(again)}`);
      const b = await d.present(who, now);
      if (!b || typeof b.claims !== "string") { bad.push(`${who}: the record lists it, and ${R.registrar} cannot present it`); continue; }
      const claims = Buffer.from(b.claims, "base64url").toString("utf8");
      if (claims !== rec.claims || b.issuer_sig?.ed25519 !== rec.issuer_sig_ed25519 || b.leaf_index !== rec.leaf_index) {
        bad.push(`${who}: ${R.registrar} presents another passport under this name (the claims, the issuer signature or the leaf differ from the record's)`); continue; }
      if (b.checkpoint?.size === rec.checkpoint_size && b.checkpoint?.root !== rec.checkpoint_root)
        bad.push(`${who}: ${R.registrar}'s log has another root at size ${rec.checkpoint_size} than the record published — a forked log`);
      let live;
      try { live = verifier.verify(b, now); } catch (x) { live = { verdict: "invalid", reason: `could not be verified (${String(x.message).slice(0, 60)})` }; }
      if (!same(stored, live)) bad.push(`${who}: the record shows ${said(stored)}, and ${R.registrar} presents it as ${said(live)}`);
    }
    const held = await d.records();
    for (const h of held) if (!listed.has(h.sub)) bad.push(`${h.sub}: ${R.registrar} holds it, and the record does not list it`);
    for (const who of listed) if (!held.some((h) => h.sub === who)) bad.push(`${who}: the record lists it, and ${R.registrar} does not hold it`);
  }
  return { bad, passports };
}

// ── the real run ──
async function readRecord(src) {
  const get = async (f) => {
    if (/^https?:\/\//.test(src)) { const r = await fetch(`${src.replace(/\/$/, "")}/${f}`, { signal: AbortSignal.timeout(15000) }); if (!r.ok) throw new Error(`${f}: HTTP ${r.status}`); return r.json(); }
    return JSON.parse(readFileSync(`${src.replace(/\/$/, "")}/${f}`, "utf8"));
  };
  return { registry: await get("registry.json"), directory: await get("directory.json"), roots: await get("roots.json") };
}

function doors() {
  const named = Object.fromEntries((process.env.AINRA_DOORS || "").split(",").filter(Boolean).map((p) => p.split("=")));
  return (id) => {
    const base = (named[id] || `http://127.0.0.1:49${id.slice(-2)}`).replace(/\/$/, "");
    const ask = async (p) => fetch(base + p, { signal: AbortSignal.timeout(10000) });
    return {
      async records() { const r = await ask("/records"); if (!r.ok) throw new Error(`${id}: /records answered HTTP ${r.status}`); return (await r.json()).records || []; },
      async present(sub, now) { const r = await ask(`/present?sub=${encodeURIComponent(sub)}&now=${now}`); if (r.status >= 500) throw new Error(`${id}: /present answered HTTP ${r.status}`); try { return await r.json(); } catch { return null; } },
    };
  };
}

async function main() {
  const src = process.env.AINRA_RECORD || ROOT + "site/net";
  const shown = src.startsWith(ROOT) ? src.slice(ROOT.length) + "/" : src;
  let world;
  try { world = await readRecord(src); } catch (x) { console.error(`record-agrees: could not read the record at ${shown} (${x.message}) — no record, no verdict`); process.exit(2); }
  let out;
  try { out = await agree({ ...world, door: doors() }); }
  catch (x) { console.error(`record-agrees: could not ask a registrar (${x.cause?.code || x.message}) — run 'make stage-install'; no network, no verdict`); process.exit(2); }
  if (out.bad.length) {
    for (const b of out.bad) console.error(`  ✗ ${b}`);
    console.error(`RECORD DISAGREES: ${out.bad.length} disagreement(s) between ${shown} and the registrars over ${out.passports} passports`);
    process.exit(1);
  }
  const n = world.registry.registrars.length;
  console.log(`record-agrees OK: ${shown} and ${n} registrar${n === 1 ? "" : "s"} agree on all ${out.passports} passports — each one is the same passport at its registrar, with the verdict the record shows`);
}

// ── the witness ──
async function drill() {
  const S = ROOT + "kits/verifier/sample-artifacts/", j = (f) => JSON.parse(readFileSync(S + f, "utf8"));
  const directory = j("directory.json"), roots = j("roots.json"), entry = directory.entries[0];
  const world = (file, verdict) => {
    const b = j(file), claims = Buffer.from(b.claims, "base64url").toString("utf8"), c = JSON.parse(claims);
    const rec = { sub: c.sub, claims, issuer_sig_ed25519: b.issuer_sig.ed25519, issuer_sig_mldsa65: b.issuer_sig.mldsa65, chain_keys: b.chain_keys, hop_proofs: b.hop_proofs,
      log_origin: b.checkpoint.origin, checkpoint_size: b.checkpoint.size, checkpoint_root: b.checkpoint.root, checkpoint_sig: b.checkpoint_sig, leaf_index: b.leaf_index, inclusion_proof: b.inclusion_proof };
    const R = { registrar: entry.registrar, accreditation: { issuer_key: { ed25519: entry.issuer_ed25519, mldsa65: entry.issuer_mldsa65 }, log_root_key: entry.log_root_slh },
      status_list: { status_list_b64: b.status_list, bit_len: b.status_len, issued_at: b.status_issued_at }, records: [{ record: rec, verdict }] };
    return { registry: { generated_window: { verified_at: b.now }, registrars: [R] }, bundle: b, sub: c.sub, revoked: verdict.verdict !== "valid" };
  };
  const V = world("bundle-valid.json", { verdict: "valid" }), X = world("bundle-revoked.json", { verdict: "invalid", reason: "revoked" });
  const doorOf = (w, over = {}) => () => ({ records: async () => over.records ?? [{ sub: w.sub, revoked: w.revoked }], present: async () => ("present" in over ? over.present : w.bundle) });
  const run = (w, door, r = roots) => agree({ registry: w.registry, directory, roots: r, door });
  const flip = (s) => { const b = Buffer.from(s, "base64url"); b[b.length >> 1] ^= 1; return b.toString("base64url"); };
  const edited = structuredClone(X); edited.registry.registrars[0].records[0] = { record: edited.registry.registrars[0].records[0].record, verdict: { verdict: "valid" } };
  let missed = 0;
  for (const [name, w] of [["the passport as issued", V], ["the passport after its registrar revoked it", X]]) {
    const o = await run(w, doorOf(w));
    if (o.bad.length || o.passports !== 1) { console.error(`  ✗ MISSED control: ${name} must agree — ${o.bad[0] ?? "no passport was compared"}`); missed++; } else console.log(`  ok    ${name}: the record and the registrar agree`);
  }
  const plants = [
    ["a record that says VALID over a passport its registrar has revoked", () => run(V, doorOf(V, { present: X.bundle })), "presents it as INVALID · revoked"],
    ["a record that says revoked over a passport its registrar presents as valid", () => run(X, doorOf(X, { present: V.bundle })), "presents it as VALID"],
    ["a registrar that does not know the passport", () => run(V, doorOf(V, { present: { error: "unknown subject" } })), "cannot present it"],
    ["a registrar presenting another passport under the same name", () => run(V, doorOf(V, { present: { ...V.bundle, issuer_sig: { ...V.bundle.issuer_sig, ed25519: flip(V.bundle.issuer_sig.ed25519) } } })), "presents another passport under this name"],
    ["a registrar whose log has another root at the same size", () => run(V, doorOf(V, { present: { ...V.bundle, checkpoint: { ...V.bundle.checkpoint, root: flip(V.bundle.checkpoint.root) } } })), "a forked log"],
    ["a registrar holding a passport the record does not list", () => run(V, doorOf(V, { records: [{ sub: V.sub }, { sub: "ainra:registrar-07:drill:unlisted@1.0.0" }] })), "the record does not list it"],
    ["a record listing a passport the registrar does not hold", () => run(V, doorOf(V, { records: [] })), "does not hold it"],
    ["a stored verdict edited to VALID beside a revoked passport", () => run(edited, doorOf(X)), "its own stored passport verifies as INVALID · revoked"],
    ["roots with one byte flipped", () => run(V, doorOf(V), { ...roots, root_ed25519: flip(roots.root_ed25519) }), "not anchored in the record's roots"],
  ];
  for (const [name, go, want] of plants) {
    const o = await go(), hit = o.bad.find((b) => b.includes(want));
    if (hit) console.log(`  ok    ${name} — refused: ${hit.slice(0, 150)}`);
    else { console.error(`  ✗ MISSED ${name} — wanted "${want}", got ${o.bad.length ? o.bad[0] : "agreement"}`); missed++; }
  }
  if (missed) { console.error(`RECORD-AGREES DRILL FAILED (${missed})`); process.exit(1); }
  console.log(`RECORD-AGREES DRILL OK — both untouched worlds agree, and all ${plants.length} planted disagreements are refused by name`);
}

if (import.meta.url === `file://${process.argv[1]}`) await (process.argv.includes("--drill") ? drill() : main());
