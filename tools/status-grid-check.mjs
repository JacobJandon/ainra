// SPDX-License-Identifier: Apache-2.0 OR MIT
// Status-list grid proof (site concept, FIG. 04). The home page draws a registrar's 4,096-bit status list as a grid.
// A wrong picture of a revocation list is worse than none, so this proves — with the repository's own SDK
// (packages/sdk-ts), not a decode of our own invention — that what the page draws is what a verifier reads:
//
//   1. the list in net/registry.json is signed by the registrar's status key (hybrid Ed25519 + ML-DSA-65 over the
//      canonical {bit_len, issued_at, status_list, uri}, the same body the SDK's authenticateStatus checks);
//   2. the SDK's verdict for every published record equals the verdict the record states;
//   3. decoding the list LSB-first (the SDK's statusBit: packed[idx >> 3] >> (idx & 7)) gives set bits EXACTLY equal
//      to the status_idx of the records marked revoked;
//   4. bit order is pinned by mutation: setting a valid record's bit makes the SDK refuse it as revoked, and clearing
//      a revoked record's bit makes it valid — so the bit the page lights red is the bit the SDK reads;
//   5. the per-registrar copies in net/registrars/<r>/status/current.json are checked the same way and REPORTED: they
//      are a different publication (their own seq and signature). Where their set bits do not match the records,
//      they must not be drawn as "the" list, and the page does not draw them.
//
//   node tools/status-grid-check.mjs [--net <dir>]   → exit 0 when the registry lists are provably right (1–4); prints 5.
//
// WITNESS (negative control, executed): a copy of site/net whose registrar-07 list in registry.json is replaced by the
// one in registrars/registrar-07/status/current.json (a real, validly signed list whose set bit is 1, not 2) turns
// this red at step 3 and step 2 — the SDK then refuses invoicing@4.2.1 and accepts data-export@2.0.0, against the
// record's own verdicts. That is exactly the wrong picture this gate exists to keep off the page.
import { readFileSync, existsSync } from "node:fs";
import { inflateSync, deflateSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ai = process.argv.indexOf("--net");
const NET = ai > 0 ? process.argv[ai + 1] : join(ROOT, "site", "net");
const SDK = join(ROOT, "packages", "sdk-ts", "dist");
if (!existsSync(join(SDK, "index.js"))) { console.error("✗ packages/sdk-ts/dist is not built — run `make site` (it builds the SDK) first"); process.exit(2); }
const { runVector, canonicalize, headHash } = await import(join(SDK, "index.js"));
const { verifyHybrid, b64uDecode, b64uEncode } = await import(join(SDK, "crypto.js"));

const j = (p) => JSON.parse(readFileSync(join(NET, p), "utf8"));
const reg = j("registry.json");
const NOW = reg.generated_window?.verified_at ?? 0;
let fail = 0;
const bad = (m) => { console.log("  ✗ " + m); fail++; };
const ok = (m) => console.log("  ✓ " + m);

const setBits = (b64, len) => {
  const packed = inflateSync(b64uDecode(b64));
  const out = [];
  for (let i = 0; i < len; i++) if ((packed[i >> 3] >> (i & 7)) & 1) out.push(i);
  return { packed, bits: out };
};
const withBit = (packed, idx, on) => {
  const p = Uint8Array.from(packed);
  if (on) p[idx >> 3] |= 1 << (idx & 7); else p[idx >> 3] &= ~(1 << (idx & 7));
  return b64uEncode(deflateSync(p));
};
const enc = (s) => b64uEncode(new TextEncoder().encode(s));
const wire = (rec, R, list) => ({
  name: rec.sub, expect: {},
  anchors: { [R.registrar]: { issuer_key: R.accreditation.issuer_key, log_root_key: R.accreditation.log_root_key } },
  presentation: {
    claims: enc(rec.claims), issuer_sig: { ed25519: rec.issuer_sig_ed25519, mldsa65: rec.issuer_sig_mldsa65 },
    now: NOW, chain_keys: rec.chain_keys, hop_proofs: rec.hop_proofs,
    status_list: list, status_len: R.status_list.bit_len, status_issued_at: R.status_list.issued_at,
    freshness: "F3", checkpoint: { origin: rec.log_origin, size: rec.checkpoint_size, root: rec.checkpoint_root },
    checkpoint_sig: rec.checkpoint_sig, leaf_index: rec.leaf_index, inclusion_proof: rec.inclusion_proof,
    mandate_revocations: [], revoked_delegates: [],
  },
});
const key = (k) => ({ ed25519: b64uDecode(k.ed25519), mldsa65: b64uDecode(k.mldsa65) });
const sigOk = (k, sl) => verifyHybrid(key(k),
  new TextEncoder().encode(canonicalize({ bit_len: sl.bit_len, issued_at: sl.issued_at, status_list: sl.status_list_b64, uri: sl.uri })),
  { ed25519: b64uDecode(sl.sig_ed25519), mldsa65: b64uDecode(sl.sig_mldsa65) });

for (const R of reg.registrars || []) {
  const sl = R.status_list, recs = (R.records || []).map((e) => ({ rec: e.record, want: e.verdict }));
  console.log(`\n${R.registrar} · net/registry.json · status seq ${R.status_seq} · ${sl.bit_len} bits · ${sl.uri}`);
  // 1. signature
  const s = sigOk(R.accreditation.status_key, sl);
  s === null ? ok("status list signed by the registrar's status key (Ed25519 + ML-DSA-65)") : bad(`status list signature: ${s}`);
  if (sl.uri !== R.accreditation.status_uri) bad(`status uri ${sl.uri} ≠ accreditation ${R.accreditation.status_uri}`);
  // 2. SDK verdicts equal the stated verdicts
  for (const { rec, want } of recs) {
    const v = runVector(wire(rec, R, sl.status_list_b64));
    const got = v.verdict + (v.reason ? "·" + v.reason : ""), exp = want.verdict + (want.reason ? "·" + want.reason : "");
    got === exp ? null : bad(`${rec.sub}: SDK says ${got}, record says ${exp}`);
  }
  ok(`SDK verdicts equal the record's stated verdicts for all ${recs.length} records`);
  // 3. decoded set bits == revoked status_idx
  const { packed, bits } = setBits(sl.status_list_b64, sl.bit_len);
  const revoked = recs.filter((r) => r.rec.revoked).map((r) => r.rec.status_idx).sort((a, b) => a - b);
  JSON.stringify(bits) === JSON.stringify(revoked)
    ? ok(`set bits (LSB-first) [${bits}] = status_idx of revoked records [${revoked}]`)
    : bad(`set bits [${bits}] ≠ revoked status_idx [${revoked}]`);
  // 4. mutation pins the bit order
  for (const { rec } of recs) {
    const flipped = withBit(packed, rec.status_idx, !rec.revoked);
    const v = runVector(wire(rec, R, flipped));
    const expect = rec.revoked ? "valid" : "invalid";
    if (v.verdict !== expect || (!rec.revoked && v.reason !== "revoked")) bad(`mutation at bit ${rec.status_idx} (${rec.sub}): SDK said ${v.verdict}${v.reason ? "·" + v.reason : ""}, expected ${expect}`);
  }
  ok(`flipping each record's bit flips the SDK's verdict (${recs.length} mutations) — the page's bit is the SDK's bit`);

  // 5. the per-registrar publication (reported, never drawn unless it agrees)
  const p = join(NET, "registrars", R.registrar, "status", "current.json");
  if (existsSync(p)) {
    const c = JSON.parse(readFileSync(p, "utf8"));
    const cs = sigOk(R.accreditation.status_key, c);
    const cb = setBits(c.status_list_b64, c.bit_len).bits;
    let head = "";
    const fh = join(NET, "registrars", R.registrar, "fresh-head.json");
    if (existsSync(fh)) {
      const h = JSON.parse(readFileSync(fh, "utf8"));
      head = b64uEncode(headHash(c.uri, c.bit_len, c.status_list_b64)) === h.status_hash ? ` · matches fresh-head seq ${h.seq}` : ` · does NOT match fresh-head`;
    }
    const agrees = JSON.stringify(cb) === JSON.stringify(revoked);
    console.log(`  · registrars/${R.registrar}/status/current.json: signature ${cs === null ? "valid" : cs}${head} · set bits [${cb}] · ${agrees ? "agrees with" : "DISAGREES with"} the records' revoked status_idx [${revoked}]${agrees ? "" : " — a different publication; not drawn"}`);
  }
}
console.log(fail ? `\nSTATUS-GRID FAIL: ${fail} problem(s) — the page must not draw the grid` : `\nSTATUS-GRID OK: every list the page draws is signed, and its red bits are exactly the revoked records the SDK refuses.`);
process.exit(fail ? 1 : 0);
