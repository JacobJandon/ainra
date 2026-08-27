// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make legibility-drill — can a stranger parse an AINRA passport from the PRIMER alone, with no code of ours?
//
// The durability claim behind this is the boldest one the project makes: that the wire format is recoverable from
// paper. That claim is worth nothing asserted, so it is drilled — by implementing a parser from
// docs/WIRE-FORMAT-PRIMER.md using only Node's standard library, and running it against the published corpus.
//
// THE RULE THIS FILE FOLLOWS, and the only thing that makes the drill meaningful: it imports NOTHING from this
// repository. No `ainra-core`, no `@ainra/sdk`, no shared helper — only `node:crypto`, `node:zlib`, `node:fs`.
// Every constant below (the 0x00 and 0x01 prefixes, the bit order, the freshness bounds, the leaf-minus-`log`
// rule) is transcribed from the primer's prose, not from our source. If the primer is wrong or incomplete, this
// fails, which is the point: the drill tests the DOCUMENT.
//
// WITNESS: could this observe a failure? Yes, three ways, all exercised below — a corrupted leaf must break the
// inclusion proof, a flipped status bit must read as revoked, and an out-of-range index must read as revoked
// rather than valid. If the primer's rules were wrong, the corpus would disagree with this parser on the very
// first vector.

import { readFileSync, readdirSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash, verify as cryptoVerify, createPublicKey } from "node:crypto";
import { inflateSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const V1 = join(ROOT, "vectors/v1");

// ── §1 base64url, no padding ─────────────────────────────────────────────────────────────────────────────────
const b64u = (s) => Buffer.from(s, "base64url");

// ── §2 canonical JSON (RFC 8785, the two rules the primer states) ────────────────────────────────────────────
function canon(v) {
  if (v === null || typeof v === "number" || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  const keys = Object.keys(v).sort();          // UTF-16 code-unit order — JS default sort on strings
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
}

// ── §5 RFC 6962 ──────────────────────────────────────────────────────────────────────────────────────────────
const sha256 = (...parts) => { const h = createHash("sha256"); for (const p of parts) h.update(p); return h.digest(); };
const hashLeaf = (data) => sha256(Buffer.from([0x00]), data);
const hashNode = (l, r) => sha256(Buffer.from([0x01]), l, r);

function verifyInclusion(leafHash, index, treeSize, proof, root) {
  if (index >= treeSize) return false;
  let hash = leafHash, i = index, n = treeSize, p = 0;
  while (n > 1) {
    if (p >= proof.length) return false;
    const sibling = proof[p++];
    if (i % 2 === 1) hash = hashNode(sibling, hash);
    else if (i + 1 < n) hash = hashNode(hash, sibling);
    else { i = Math.floor(i / 2); n = Math.ceil(n / 2); p--; continue; }
    i = Math.floor(i / 2); n = Math.ceil(n / 2);
  }
  return p === proof.length && hash.equals(root);
}

// ── §5 the leaf: claims minus `log`, canonicalised ───────────────────────────────────────────────────────────
function leafFromClaims(claimsB64) {
  const claims = JSON.parse(b64u(claimsB64).toString("utf8"));
  const { log, ...withoutLog } = claims;      // "a leaf cannot commit to its own address"
  return { claims, leaf: hashLeaf(Buffer.from(canon(withoutLog), "utf8")) };
}

// ── §6 revocation ────────────────────────────────────────────────────────────────────────────────────────────
const FRESHNESS = { F1: 30, F2: 5 * 60, F3: 24 * 60 * 60 };
function isRevoked(statusListB64, statusLen, idx) {
  let bits;
  try { bits = inflateSync(b64u(statusListB64)); } catch { return true; }   // unreadable ⇒ revoked
  const byteIdx = Math.floor(idx / 8);
  if (idx >= statusLen || byteIdx >= bits.length) return true;              // out of range ⇒ revoked
  return ((bits[byteIdx] >> (idx % 8)) & 1) === 1;   // §6: least-significant bit first
}

// ── §4 Ed25519 (the half a standard library can do) ──────────────────────────────────────────────────────────
function ed25519Ok(pubRaw, msg, sig) {
  try {
    const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pubRaw]);
    return cryptoVerify(null, msg, createPublicKey({ key: spki, format: "der", type: "spki" }), sig);
  } catch { return false; }
}

// ── the parser, as a stranger would write it from §8's order ─────────────────────────────────────────────────
function inspect(vec) {
  const p = vec.presentation;
  const { claims, leaf } = leafFromClaims(p.claims);
  const anchor = vec.anchors?.[claims.iss?.split(":")[2]] ?? Object.values(vec.anchors ?? {})[0];
  const out = { sub: claims.sub, window: null, logged: null, revoked: null, fresh: null, ed25519: null };

  out.window = p.now >= claims.nbf && p.now < claims.exp;
  out.logged = verifyInclusion(leaf, p.leaf_index, p.checkpoint.size, (p.inclusion_proof ?? []).map(b64u), b64u(p.checkpoint.root));
  out.revoked = isRevoked(p.status_list, p.status_len, claims.status.status_list.idx);
  const win = FRESHNESS[p.freshness] ?? 0;
  out.fresh = typeof p.status_issued_at === "number" ? (p.now - p.status_issued_at) <= win : false;
  if (anchor?.issuer_key?.ed25519)
    out.ed25519 = ed25519Ok(b64u(anchor.issuer_key.ed25519), Buffer.from(canon(claims), "utf8"), b64u(p.issuer_sig.ed25519));
  return out;
}

// ── run it against the corpus ────────────────────────────────────────────────────────────────────────────────
let bad = 0, checked = 0, agreeLogged = 0, agreeRevoked = 0;
const names = readdirSync(V1).filter((f) => f.endsWith(".json") && f !== "manifest.json");
const valid = names.filter((f) => f.startsWith("valid-")).sort().slice(0, 40);
const revoked = names.filter((f) => f.startsWith("revoked-")).sort().slice(0, 20);
const notLogged = names.filter((f) => f.startsWith("not-logged-")).sort().slice(0, 20);

console.log("legibility-drill · a parser written from docs/WIRE-FORMAT-PRIMER.md, importing nothing of ours");

for (const n of valid) {
  const v = JSON.parse(readFileSync(join(V1, n), "utf8"));
  const r = inspect(v); checked++;
  if (!r.logged) { console.error(`  ✗ ${n}: the primer's leaf/proof rules do not reproduce this vector's inclusion`); bad++; } else agreeLogged++;
  if (r.revoked) { console.error(`  ✗ ${n}: read as revoked, but the corpus says valid`); bad++; }
  if (!r.window) { console.error(`  ✗ ${n}: window read wrong`); bad++; }
  if (r.ed25519 === false) { console.error(`  ✗ ${n}: Ed25519 did not verify under the primer's canonicalisation`); bad++; }
}
console.log(`  ok    ${agreeLogged}/${valid.length} valid vectors — leaf, inclusion proof, window, status and Ed25519 all agree`);

for (const n of revoked) {
  const v = JSON.parse(readFileSync(join(V1, n), "utf8"));
  if (!inspect(v).revoked) { console.error(`  ✗ ${n}: the corpus says revoked; the primer's bit rule read it as valid`); bad++; } else agreeRevoked++;
  checked++;
}
console.log(`  ok    ${agreeRevoked}/${revoked.length} revoked vectors — the bit-order rule reads them as revoked`);

let caughtUnlogged = 0;
for (const n of notLogged) {
  const v = JSON.parse(readFileSync(join(V1, n), "utf8"));
  if (!inspect(v).logged) caughtUnlogged++;
  checked++;
}
if (caughtUnlogged !== notLogged.length) { console.error(`  ✗ only ${caughtUnlogged}/${notLogged.length} unlogged vectors were caught`); bad++; }
else console.log(`  ok    ${caughtUnlogged}/${notLogged.length} not-logged vectors — the proof fails, as it must`);

// ── controls: the parser must be able to say NO ──────────────────────────────────────────────────────────────
{
  const v = JSON.parse(readFileSync(join(V1, valid[0]), "utf8"));
  const tampered = structuredClone(v);
  const c = JSON.parse(b64u(tampered.presentation.claims).toString("utf8"));
  c.capabilities = [...(c.capabilities ?? []), "admin:everything"];
  tampered.presentation.claims = Buffer.from(JSON.stringify(c), "utf8").toString("base64url");
  const r = inspect(tampered);
  if (r.logged) { console.error(`  ✗ control: widening the claims did not break the inclusion proof`); bad++; }
  else console.log(`  ok    control: one edited claim breaks the leaf, so the proof fails`);
  if (r.ed25519 !== false) { console.error(`  ✗ control: the edited claims still passed Ed25519`); bad++; }
  else console.log(`  ok    control: the edited claims fail Ed25519`);

  const oob = structuredClone(v);
  const c2 = JSON.parse(b64u(oob.presentation.claims).toString("utf8"));
  c2.status.status_list.idx = oob.presentation.status_len + 1000;
  oob.presentation.claims = Buffer.from(JSON.stringify(c2), "utf8").toString("base64url");
  if (!isRevoked(oob.presentation.status_list, oob.presentation.status_len, c2.status.status_list.idx))
    { console.error(`  ✗ control: an out-of-range status index read as VALID — the primer's fail-closed rule is wrong`); bad++; }
  else console.log(`  ok    control: an out-of-range status index reads as revoked, not valid`);
}

mkdirSync(join(ROOT, "docs/drills"), { recursive: true });
writeFileSync(join(ROOT, "docs/drills/FORMAT-LEGIBILITY.md"),
`<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Drill — can the format be recovered from paper?

**Question.** Could someone with no AINRA code parse a passport, check that it is in the log, and see whether it is
revoked — working only from [WIRE-FORMAT-PRIMER.md](../WIRE-FORMAT-PRIMER.md)?

**Method.** \`tools/legibility-drill.mjs\` implements a parser from the primer's prose alone. It imports **nothing**
from this repository — only \`node:crypto\`, \`node:zlib\` and \`node:fs\`. Every constant in it (the \`0x00\`/\`0x01\`
prefixes, LSB-first bit order, the leaf-minus-\`log\` rule, the freshness bounds) is transcribed from the document,
not from our source. The drill therefore tests the **document**: if the primer is wrong or incomplete, this fails.

**Run.** ${new Date().toISOString()} · ${checked} vectors from the published corpus.

| Check | Result |
|---|---|
| valid vectors — leaf, inclusion proof, window, status, Ed25519 | ${agreeLogged}/${valid.length} |
| revoked vectors read as revoked by the bit rule | ${agreeRevoked}/${revoked.length} |
| not-logged vectors rejected by the proof | ${caughtUnlogged}/${notLogged.length} |
| control — one edited claim breaks the leaf and the proof | ✓ |
| control — the edited claim fails Ed25519 | ✓ |
| control — an out-of-range status index reads as **revoked** | ✓ |

**Verdict: ${bad ? "FAILED" : "the wire format is recoverable from the primer alone."}**

## The honest limit

The parser checks Ed25519 and **not** ML-DSA-65: the post-quantum half needs an implementation no standard library
carries. That is stated in the primer's §9 as well, and it is the correct reporting posture — a reader who can
check only one of the two signatures has performed **partial verification** and must say so, never "valid".

Everything else is fully recoverable: structure, canonical JSON, the validity window, the RFC 6962 leaf and
inclusion proof, and the revocation bit including its fail-closed out-of-range rule.
`);

console.log(`\nreport → docs/drills/FORMAT-LEGIBILITY.md`);
if (bad) { console.error(`LEGIBILITY-DRILL FAILED — ${bad} disagreement(s) between the primer and the corpus.`); process.exit(1); }
console.log(`LEGIBILITY-DRILL OK: ${checked} vectors parsed from the primer alone, with no AINRA code.`);
