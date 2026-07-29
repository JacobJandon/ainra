// SPDX-License-Identifier: Apache-2.0 OR MIT
// ADR-018 advisory announcer (M23 Task 5) — the OPTIONAL push transport.
//
// A thin bridge that turns a registrar's pull surface into a push feed: it polls /deltas and emits an SSE-shaped
// ADVISORY frame for each new status delta. The frame is UNSIGNED and carries no trust — it only says "something
// changed, pull now". A subscriber MUST react by doing the normal signed pull + validation (see the `subscriber`
// note in each frame); it must never treat the announcement itself as authority. Suppressing this feed cannot hide
// a revocation (the verifier's scheduled pull enforces freshness) and forging it cannot inject one (the pulled
// bytes are validated). Proven by tools/push-advisory-threat.mjs.
//
//   node tools/push-announce.mjs <registrar-url> [--once]     e.g. http://127.0.0.1:4907
import process from "node:process";

const base = (process.argv[2] || "http://127.0.0.1:4907").replace(/\/$/, "");
const once = process.argv.includes("--once");
let since = 0;

async function poll() {
  let arr = [];
  try {
    const r = await fetch(`${base}/deltas?since=${since}`, { signal: AbortSignal.timeout(2000) });
    const j = await r.json();
    arr = Array.isArray(j) ? j : j.deltas || [];
  } catch (e) {
    process.stderr.write(`# announcer: registrar unreachable at ${base} (${e.message})\n`);
    return false;
  }
  for (const d of arr) {
    if (d.seq <= since) continue;
    since = d.seq;
    // SSE frame — advisory only. Note the mandatory subscriber reaction: PULL then VALIDATE, never trust this frame.
    const frame = {
      advisory: true,
      unsigned: true,
      kind: "status-delta",
      seq: d.seq,
      uri: d.uri,
      pull: `${base}/fresh-head + ${base}/deltas?since=${d.from_seq}`,
      subscriber: "on receipt, run the normal signed pull + validate (verifyFreshHead / verifyDelta); do NOT trust this frame",
    };
    process.stdout.write(`event: status-delta\ndata: ${JSON.stringify(frame)}\n\n`);
  }
  return arr.length > 0;
}

await poll();
if (!once) {
  // Poll-to-push bridge. A native SSE/webhook deployment replaces the loop with the registrar's own event stream;
  // the frame contract (advisory, unsigned, pull-to-validate) is identical.
  process.stderr.write("# announcing (Ctrl-C to stop) — advisory frames only; the pull remains sovereign\n");
  const tick = () => poll().then(() => setTimeout(tick, 2000));
  setTimeout(tick, 2000);
}
