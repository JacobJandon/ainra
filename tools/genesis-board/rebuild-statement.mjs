// SPDX-License-Identifier: Apache-2.0 OR MIT
// A REBUILD STATEMENT (PLAN-M50 step 5) — what an outsider signs after rebuilding a release from public artifacts, so
// the genesis board's "an outsider rebuilds a release" row can move on evidence instead of on our word.
//
//   git checkout v0.6.0 && make repro       # on YOUR machine; writes MANIFEST.sha256 from what you rebuilt
//   node tools/genesis-board/rebuild-statement.mjs --tag v0.6.0 --key my-rebuild.pem --builder "<who you are>" \
//        [--manifest MANIFEST.sha256] [--keygen] [--out rebuild-statement.json]
//
// The statement names the tag and the digest of YOUR manifest's lines sorted bytewise — so the locale your rebuild
// ran under cannot change it — and is signed with YOUR Ed25519 key (--keygen makes one, 0600). The board counts it
// only if the digest equals the one it computes from MANIFEST.sha256 at that tag and the key is not one the project
// signs with (witnesses/project-keys.json). Submit it as evidence/rebuild/<you>.json. It proves your rebuild produced
// the published artifacts byte for byte; it does not prove your toolchain was independent of ours.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "node:crypto";

const A = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : d; };
const tag = A("tag"), keyPath = A("key"), builder = A("builder");
if (!tag || !/^v\d+\.\d+\.\d+$/.test(tag) || !keyPath || !builder) {
  console.error('usage: rebuild-statement.mjs --tag vX.Y.Z --key <ed25519.pem> --builder "<who>" [--manifest MANIFEST.sha256] [--keygen] [--out f]');
  process.exit(2);
}
if (!existsSync(keyPath)) {
  if (!process.argv.includes("--keygen")) { console.error(`no key at ${keyPath} — pass --keygen to make one`); process.exit(2); }
  const { privateKey } = generateKeyPairSync("ed25519");
  writeFileSync(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
}
function canonicalJSON(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalJSON).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalJSON(v[k])).join(",") + "}";
}
// The same digest tools/genesis-board/board.mjs computes from the tag: lines sorted bytewise, newline-terminated.
const manifestDigest = (text) =>
  createHash("sha256").update(text.split("\n").filter(Boolean).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)).join("\n") + "\n").digest("hex");

const priv = createPrivateKey(readFileSync(keyPath));
const body = {
  statement: "ainra-rebuild-1",
  tag,
  manifest_sha256: manifestDigest(readFileSync(A("manifest", "MANIFEST.sha256"), "utf8")),
  rebuilt_at: new Date().toISOString(),
  builder,
  builder_pubkey_spki_b64: createPublicKey(priv).export({ type: "spki", format: "der" }).toString("base64"),
};
const out = A("out", "rebuild-statement.json");
writeFileSync(out, JSON.stringify({ body, sig_ed25519_b64: sign(null, Buffer.from(canonicalJSON(body)), priv).toString("base64") }, null, 2) + "\n");
console.log(`wrote ${out} — ${tag}, manifest digest ${body.manifest_sha256.slice(0, 16)}…, signed by your key`);
