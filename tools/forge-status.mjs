// SPDX-License-Identifier: Apache-2.0 OR MIT
// Adversarial test tool (NOT a product) — forge the exact revocation bypass the M5 review found: rewrite a
// presentation bundle's status list to an all-clear bitmap and re-stamp it fresh, WITHOUT re-signing (the attacker
// has no status key). A correct verifier must still reject this (the status signature no longer covers the bits) —
// so running `ainra-verify` over the output must print INVALID. This exists only to PROVE the gate is closed.
//
//   node tools/forge-status.mjs --in bundle.json --out forged.json --now T [--mode clear|strip|swap-uri]
//
//   clear     (default) all-zero status bitmap + fresh issued_at, keep the (now-stale) signature
//   strip     remove the status signature entirely (a bundle that carries no authenticated status)
//   swap-uri  point the signed publication at a different URI than the passport/directory claim

import { readFileSync, writeFileSync } from "node:fs";
import { deflateSync } from "node:zlib";

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : def;
}
const inPath = arg("in");
const outPath = arg("out");
const now = Number(arg("now", `${Math.floor(Date.now() / 1000)}`));
const mode = arg("mode", "clear");
if (!inPath || !outPath) {
  console.error("usage: forge-status --in B --out F --now T [--mode clear|strip|swap-uri]");
  process.exit(2);
}

const bundle = JSON.parse(readFileSync(inPath, "utf8"));

if (mode === "clear") {
  // An all-zero (nobody-revoked) bitmap of the SAME declared length, zlib-compressed exactly like the real codec.
  const nBytes = Math.ceil(Number(bundle.status_len) / 8);
  const clear = deflateSync(Buffer.alloc(nBytes)); // zlib-wrapped DEFLATE, matches Rust flate2 ZlibEncoder
  bundle.status_list = clear.toString("base64url");
  bundle.status_issued_at = now; // re-stamp fresh so it sails through any freshness window
  bundle.freshness = "F1";
} else if (mode === "strip") {
  delete bundle.status_sig_ed25519;
  delete bundle.status_sig_mldsa65;
} else if (mode === "swap-uri") {
  bundle.status_uri = `${bundle.status_uri}-attacker`;
} else {
  console.error(`forge-status: unknown mode ${mode}`);
  process.exit(2);
}

writeFileSync(outPath, JSON.stringify(bundle));
console.error(`forge-status: wrote ${mode}-forged bundle → ${outPath}`);
