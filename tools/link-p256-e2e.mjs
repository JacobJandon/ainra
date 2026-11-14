#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make link-p256-e2e — AINRA Link for a P-256 key, live (D-108, PLAN-M55 step 1).
//
// Most identity systems sign with NIST P-256: the key in an agent's certificate, in a signed agent card, in a
// platform keystore. This is the whole path for one such key, against the running registrar, with the key made and
// used by the platform's own signer (WebCrypto ECDSA) the way a keystore would:
//
//   1. the operator: a passport from the live registrar
//   2. a P-256 key from the platform's signer, exported the way it already travels (65 bytes, uncompressed)
//   3. the key signs its consent. The platform returns either twin of an ECDSA signature; Link takes the low-S one.
//      The high-S twin is refused; so is the compressed form of the key, and a consent by another key.
//   4. a gate that has verified a signature with that key asks who stands behind it → the operator, by name
//   5. a P-256 key nobody linked → not linked
//   6. revoke the link → the same gate refuses the same key
//
// TEST-ROOT, loopback. It proves the mechanism; it is not evidence that any operator runs it.
//
// WITNESS: could this observe a failure? Yes — step 4 is the positive control (a `valid` that names the operator),
// step 5 the negative one (a real key with no link must not be attributed), and step 3 must see three refusals from
// the registrar itself, each for its own reason. With the registrar built before D-108 step 3 already fails: it
// answers 400 for every ES256 key.
import { readFileSync } from "node:fs";
import { Verifier, jwkThumbprintEs256, linkPopSigningBytes, linkFromIndex } from "../packages/sdk-ts/dist/index.js";
import { b64uEncode } from "../packages/sdk-ts/dist/crypto.js";

const REG = process.env.AINRA_REGISTRAR ?? "http://127.0.0.1:4970";
const ART = process.env.AINRA_ARTIFACTS ?? "http://127.0.0.1:8093";
const now = () => Math.floor(Date.now() / 1000);

let bad = 0;
const ok = (m) => console.log(`  ok    ${m}`);
const fail = (m) => { console.error(`  ✗     ${m}`); bad = 1; };
const step = (m) => console.log(`\n${m}`);
async function j(url, init) {
  const r = await fetch(url, init);
  const t = await r.text();
  let body; try { body = JSON.parse(t); } catch { body = t; }
  return { status: r.status, body };
}

try { await fetch(`${REG}/accreditation`, { signal: AbortSignal.timeout(3000) }); }
catch { console.error(`link-p256-e2e: no live registrar at ${REG} — run \`make live-up\` first`); process.exit(2); }
// Linking and revoking are operator writes. The token goes into a request header only — never onto stdout.
let TOKEN;
try { TOKEN = readFileSync(new URL("../live/.issue-token", import.meta.url), "utf8").trim(); }
catch { console.error("link-p256-e2e: live/.issue-token missing — start the registrar with `make live-up`"); process.exit(2); }
const write = (path, body) => j(`${REG}${path}`, {
  method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" }, body: JSON.stringify(body),
});

// ── 1 · the operator's passport ──────────────────────────────────────────────────────────────────────────────────
step("1 · the operator: a passport from the live registrar");
const issued = await j(`${REG}/demo/issue`, { method: "POST", body: JSON.stringify({ operator: "specimen", lineage: "p256" }) });
if (issued.status !== 200) { fail(`issue failed: ${issued.status} ${JSON.stringify(issued.body)}`); process.exit(1); }
const passport = issued.body;
const directory = (await j(`${ART}/directory.json`)).body;
const roots = (await j(`${ART}/roots.json`)).body;
const gate = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F1");
if (!gate) { fail("could not build a verifier from the published directory"); process.exit(1); }
ok(`${passport.sub}`);

// ── 2 · a P-256 key, as a platform keystore holds one ────────────────────────────────────────────────────────────
step("2 · a P-256 key from the platform's own signer");
const N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;   // the order of the P-256 group
const big = (b) => BigInt("0x" + Buffer.from(b).toString("hex"));
const be32 = (n) => Uint8Array.from(Buffer.from(n.toString(16).padStart(64, "0"), "hex"));
async function platformKey() {
  const k = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", k.publicKey));       // 0x04 || x || y
  // What the platform returns: r || s, with s on either side of n/2. Both twins, so the drill can send each.
  const signTwins = async (msg) => {
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, k.privateKey, msg));
    const r = sig.slice(0, 32), s = big(sig.slice(32));
    const lowS = s > N / 2n ? N - s : s;
    return { low: Uint8Array.from([...r, ...be32(lowS)]), high: Uint8Array.from([...r, ...be32(N - lowS)]) };
  };
  return { pub, tp: jwkThumbprintEs256(pub), signTwins };
}
const K = await platformKey(), OTHER = await platformKey(), UNLINKED = await platformKey();
K.pub.length === 65 && K.pub[0] === 4 && K.tp ? ok(`65 bytes, uncompressed · thumbprint ${K.tp.slice(0, 12)}… (the private key cannot be exported)`) : fail("the platform did not give an uncompressed P-256 key");

// ── 3 · consent, and what the registrar refuses ──────────────────────────────────────────────────────────────────
step("3 · the key signs its consent; the registrar takes the low-S form and nothing else");
const nbf = passport.nbf, exp = Math.min(passport.exp, now() + 3600);
const consent = linkPopSigningBytes(passport.registrar, passport.sub, K.tp, nbf);
const twins = await K.signTwins(consent);
const body = (key, pop) => ({ passport: passport.sub, alg: "ES256", key: b64uEncode(key), pop: b64uEncode(pop), nbf, exp });
{
  const r = await write("/link", body(K.pub, twins.high));
  r.status === 400 ? ok(`the high-S twin of its own consent → refused: ${String(r.body.error).split(":")[0]}`) : fail(`high-S consent: ${r.status} ${JSON.stringify(r.body)}`);
}
{
  const compressed = Uint8Array.from([2 + (K.pub[64] & 1), ...K.pub.slice(1, 33)]);
  const r = await write("/link", body(compressed, twins.low));
  r.status === 400 ? ok(`the same key in compressed form (33 bytes names another curve) → refused: ${String(r.body.error).split(":")[0]}`) : fail(`compressed key: ${r.status} ${JSON.stringify(r.body)}`);
}
{
  const r = await write("/link", body(K.pub, (await OTHER.signTwins(consent)).low));
  r.status === 400 ? ok(`a consent signed by another P-256 key → refused: ${String(r.body.error).split(":")[0]}`) : fail(`another key's consent: ${r.status} ${JSON.stringify(r.body)}`);
}
{
  const r = await write("/link", body(K.pub, twins.low));
  r.status === 200 && r.body.thumbprint === K.tp ? ok(`linked · log leaf ${r.body.leaf_index}`) : fail(`link: ${r.status} ${JSON.stringify(r.body)}`);
}

// ── 4–6 · the gate ───────────────────────────────────────────────────────────────────────────────────────────────
// A gate that has ALREADY verified a signature with `key` (in whatever protocol it speaks) asks the next question.
async function whoStandsBehind(key) {
  const [index, publication] = await Promise.all([j(`${REG}/links`).then((r) => r.body), j(`${REG}/status-list`).then((r) => r.body)]);
  const link = linkFromIndex(index, publication, jwkThumbprintEs256(key));
  if (!link) return { verdict: "not_linked" };
  return gate.verifyLink(link, key, now(), "demo:specimen");
}
step("4 · a gate asks who stands behind the key");
{
  const v = await whoStandsBehind(K.pub);
  v.verdict === "valid" && v.operator === "specimen" && v.passport === passport.sub
    ? ok(`valid · operator ${v.operator} · ${v.passport}`) : fail(`linked key: ${JSON.stringify(v)}`);
}
step("5 · a P-256 key nobody linked");
{
  const v = await whoStandsBehind(UNLINKED.pub);
  v.verdict === "not_linked" ? ok("not linked — a key that verifies is not, by itself, an accountable operator") : fail(`unlinked key: ${JSON.stringify(v)}`);
}
step("6 · revoke the link");
{
  const rv = await write("/link/revoke", { thumbprint: K.tp, kind: "link" });
  rv.status === 200 ? ok(`revoked (kind link) · log leaf ${rv.body.leaf_index}`) : fail(`revoke: ${rv.status} ${JSON.stringify(rv.body)}`);
  const v = await whoStandsBehind(K.pub);
  v.verdict === "invalid" && v.reason === "revoked" ? ok("the same gate, the same key → refused: revoked") : fail(`after revocation: ${JSON.stringify(v)}`);
}

console.log(bad ? "\nLINK P-256 E2E FAILED" : "\nLINK P-256 E2E OK: a P-256 key from a platform signer, attributed to its operator and revoked — live");
process.exit(bad);
