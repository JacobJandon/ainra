#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make ainrascan [SERVE=1] [PORT=8090] — build the AINRAscan explorer against a real AINRA network.
#
# AINRAscan is an INDEPENDENT, client-verifying explorer: it renders public artifacts and recomputes every verdict
# in the browser with the real @ainra/sdk. The committed app is ainrascan/index.html (self-contained: no CDN, no web
# fonts, zero telemetry). This step derives the two things the app reads, both from CANONICAL sources, so nothing is
# stale or hand-authored:
#   1. ainrascan/vendor/ainra-sdk.js — the real SDK bundled for the browser (esbuild; @noble inlined; node:zlib →
#      fflate; the shipped file is fully self-contained). Proven: it agrees with core on all conformance vectors.
#   2. ainrascan/data/registry.json — a REAL signed network, seeded through the real RegistrarBox pipeline (real
#      hybrid signing, real RFC 6962 log inclusion, real status deltas, a real ADR-017 renewal), labeled TEST-ROOT.
# Both are gitignored (derived). Run this, then open/serve ainrascan/.
set -euo pipefail
cd "$(dirname "$0")/.."
SDK=packages/sdk-ts
APP=ainrascan

# 1. bundle the real SDK for the browser (build-time deps only; the OUTPUT is self-contained).
[ -x "$SDK/node_modules/.bin/esbuild" ] || { echo "→ installing build-time bundler (esbuild, fflate)…"; ( cd "$SDK" && npm install --prefer-offline --no-audit --no-fund --silent >/dev/null 2>&1 ); }
mkdir -p "$APP/vendor" "$APP/data"
( cd "$SDK" && node_modules/.bin/esbuild src/index.ts --bundle --format=esm --platform=browser \
    --alias:node:zlib=./browser/zlib-shim.js \
    --banner:js="$(cat browser/buffer-banner.js)" \
    --outfile=../../"$APP"/vendor/ainra-sdk.js >/dev/null )
echo "✓ browser SDK bundle → $APP/vendor/ainra-sdk.js ($(wc -c < "$APP/vendor/ainra-sdk.js") bytes, self-contained)"

# 2. seed a real staging network (real crypto; the seed self-checks every verdict with the core verifier).
cargo build --release -q -p ainra-cli-rs
./target/release/ainra seed "$APP/data" | sed 's/^/  /'

# 3. proof the browser bundle reproduces the CLI verdicts over the seeded data (no dummy verdicts trusted).
node --input-type=module -e '
import { runVector } from "./'"$APP"'/vendor/ainra-sdk.js";
import fs from "node:fs";
const enc=(u)=>Buffer.from(u).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const norm=(v)=>JSON.stringify({verdict:v.verdict,reason:v.reason??null});
const reg=JSON.parse(fs.readFileSync("'"$APP"'/data/registry.json","utf8")); const now=reg.generated_window.verified_at;
const wire=(rec,R)=>({name:rec.sub,expect:{},anchors:{[R.registrar]:{issuer_key:R.accreditation.issuer_key,log_root_key:R.accreditation.log_root_key}},
 presentation:{claims:enc(new TextEncoder().encode(rec.claims)),issuer_sig:{ed25519:rec.issuer_sig_ed25519,mldsa65:rec.issuer_sig_mldsa65},now,
 chain_keys:rec.chain_keys,hop_proofs:rec.hop_proofs,status_list:R.status_list.status_list_b64,status_len:R.status_list.bit_len,status_issued_at:R.status_list.issued_at,
 freshness:"F3",checkpoint:{origin:rec.log_origin,size:rec.checkpoint_size,root:rec.checkpoint_root},checkpoint_sig:rec.checkpoint_sig,leaf_index:rec.leaf_index,inclusion_proof:rec.inclusion_proof,mandate_revocations:[],revoked_delegates:[]}});
let ok=0,tot=0; for(const R of reg.registrars) for(const e of R.records){tot++; if(norm(runVector(wire(e.record,R)))===norm(e.verdict)) ok++;}
if(ok!==tot){console.error(`✗ browser bundle disagrees with CLI on ${tot-ok}/${tot}`);process.exit(1);}
console.log(`✓ browser SDK reproduces all ${tot} CLI verdicts from the public export (client-side verify is real)`);
'

if [ "${SERVE:-0}" = "1" ]; then
  PORT="${PORT:-8090}"
  echo "→ serving AINRAscan at http://127.0.0.1:$PORT  (Ctrl-C to stop)"
  cd "$APP" && exec python3 -m http.server "$PORT" --bind 127.0.0.1
fi
