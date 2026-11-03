#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Witness one registrar's log and keep the evidence (PLAN-M51 witness work). Zero dependencies.
//
//   node kits/witness/submit.mjs --registrar <url> --witness <url> --out evidence/cosignatures/<you>.json
//
// `--now <unix>` is for hermetic drills only: it is sent to the witness (which ignores it unless that witness runs
// with AINRA_CLOCK=pinned) and recorded as the observation time. Never pass it against a real network.
//
// It asks YOUR witness where it last left this log (GET /seen), asks the registrar for its current signed checkpoint
// and the consistency proof from there (GET /witness-feed?from=N), hands both to your witness (POST /consider), and
// — only if your witness cosigned — writes the cosignature file the genesis board counts: your witness key, the
// checkpoint exactly as the log signed it, its signature, your cosignature over it, and when you observed it.
//
// Nothing here decides anything. Your witness decides whether the log only grew; the board decides whether the
// checkpoint is one the log's accredited key signed and whether your key is independent (`make genesis-status`).
// Run it on a schedule: a witness that cosigned once has said one thing; one that keeps cosigning is the guarantee.
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

const A = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : d; };
const registrar = (A("registrar") || "").replace(/\/$/, "");
const witness = (A("witness") || "").replace(/\/$/, "");
const out = A("out");
const pinnedNow = A("now") === undefined ? undefined : Number(A("now"));
if (!registrar || !witness || !out) {
  console.error("usage: submit.mjs --registrar <url> --witness <url> --out evidence/cosignatures/<you>.json");
  process.exit(2);
}
const get = async (u) => {
  const r = await fetch(u);
  const j = await r.json().catch(() => null);
  if (!r.ok || !j) throw new Error(`GET ${u} → HTTP ${r.status}${j?.error ? ` · ${j.error}` : ""}`);
  return j;
};

try {
  const { ed25519: witnessKey } = await get(`${witness}/key`);
  const acc = await get(`${registrar}/accreditation`);
  const seen = await get(`${witness}/seen`);
  const last = seen[acc.log_origin]?.size;
  // From where this witness left the log, or the whole log on first sight.
  const feed = await get(`${registrar}/witness-feed${Number.isSafeInteger(last) ? `?from=${last}` : ""}`);
  if (feed.checkpoint.origin !== acc.log_origin) throw new Error(`the feed's origin ${feed.checkpoint.origin} is not ${acc.log_origin}`);
  const r = await fetch(`${witness}/consider`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      origin: feed.checkpoint.origin, size: feed.checkpoint.size, root_b64: feed.checkpoint.root,
      checkpoint_sig: feed.checkpoint_sig, consistency_proof_b64: feed.consistency_proof,
      // Used only by a witness with no directory configured, and only the first time it meets this log.
      log_root_key_b64: acc.log_root_key,
      ...(pinnedNow === undefined ? {} : { now: pinnedNow }),
    }),
  });
  const v = await r.json().catch(() => ({}));
  if (!v.cosignature) {
    console.error(`your witness did not cosign: ${v.outcome ?? v.error ?? `HTTP ${r.status}`} (${acc.log_origin} at size ${feed.checkpoint.size}${Number.isSafeInteger(last) ? `, last cosigned at ${last}` : ""})`);
    process.exit(1);
  }
  const evidence = {
    witness_key: witnessKey,
    checkpoint: feed.checkpoint,
    checkpoint_sig: feed.checkpoint_sig,
    cosignature: v.cosignature,
    observed_at: pinnedNow ?? Math.floor(Date.now() / 1000),
    outcome: v.outcome,
  };
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, JSON.stringify(evidence, null, 2) + "\n");
  console.log(`${v.outcome}: ${acc.log_origin} at size ${feed.checkpoint.size}${Number.isSafeInteger(last) ? ` (grew from ${last}, consistency proven)` : " (first sight)"} → ${out}`);
} catch (e) {
  console.error(`submit: ${e.message}`);
  process.exit(1);
}
