// SPDX-License-Identifier: Apache-2.0 OR MIT
// The NEGATIVE CONTROL for kits/probe/probe.mjs — a transparent proxy in front of a real registrar that breaks
// exactly one accreditation invariant, so we can watch the probe catch it.
//
//   node dishonest-registrar.mjs --upstream <url> --port <p> --sabotage drop-log|suppress-revocation|rewind-seq|open-write-door
//
// This exists because of a failure this project keeps repeating: writing a check, watching it print PASS, and never
// asking whether it COULD have printed FAIL. A probe that cannot observe a dishonest registrar is decoration, and the
// only way to know is to build the dishonest registrar and point the probe at it.
//
// Every mode is a real behaviour that a real registrar could exhibit, not a synthetic error:
//
//   drop-log            serves presentations with the inclusion proof removed — "logged before valid" in words only.
//   suppress-revocation accepts the revoke, answers 200, and keeps serving the pre-revocation snapshot forever.
//                       This is the failure mode of every soft-fail revocation system ever shipped.
//   rewind-seq          reports a status sequence lower than it already published — an older history served after an
//                       outage, which is a split view wearing the clothes of a recovery.
//   open-write-door     answers an unauthenticated write, so the probe is silently an insider. P0 must abort the run.

import { createServer } from "node:http";

const A = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : d; };
const upstream = (A("upstream") || "").replace(/\/$/, "");
const port = Number(A("port", "4949"));
const mode = A("sabotage");
const MODES = ["drop-log", "suppress-revocation", "rewind-seq", "open-write-door"];
if (!upstream || !MODES.includes(mode)) {
  console.error(`usage: dishonest-registrar.mjs --upstream <url> --port <p> --sabotage ${MODES.join("|")}`);
  process.exit(2);
}

const frozen = new Map(); // suppress-revocation: sub → the first presentation body we ever served
let revokeSeen = false;
let servedMaxSeq = 0;     // rewind-seq: the highest status_seq this server has already published to a caller

const server = createServer(async (req, res) => {
  const body = await new Promise((resolve) => { let b = ""; req.on("data", (d) => (b += d)); req.on("end", () => resolve(b)); });
  const path = req.url;

  // open-write-door: answer the unauthenticated write ourselves, before it reaches an upstream that would refuse it.
  if (mode === "open-write-door" && req.method === "POST" && path.startsWith("/issue")) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ sub: "ainra:registrar-07:whoever:whatever@1.0.0", note: "no token required here" }));
    return;
  }

  // suppress-revocation: take the revoke, sound cheerful, publish nothing.
  if (mode === "suppress-revocation" && req.method === "POST" && (path.startsWith("/revoke") || path.startsWith("/demo/revoke"))) {
    revokeSeen = true;
    let sub = null; try { sub = JSON.parse(body)?.sub ?? null; } catch { /* keep going; the shape is the caller's problem */ }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ revoked: sub, now: JSON.parse(body || "{}")?.now ?? null }));
    return;
  }

  let up;
  try {
    up = await fetch(`${upstream}${path}`, {
      method: req.method,
      headers: req.method === "POST" ? { "content-type": "application/json" } : undefined,
      body: req.method === "POST" ? body : undefined,
    });
  } catch (e) {
    res.writeHead(502, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: `upstream unreachable: ${String(e.message || e)}` }));
    return;
  }
  let text = await up.text();

  if (path.startsWith("/present")) {
    const sub = new URLSearchParams(path.split("?")[1] || "").get("sub");
    if (mode === "suppress-revocation") {
      // Freeze the first genuine snapshot and serve it forever. Note what this proxy does NOT do: it does not forge
      // anything. Every byte it serves was signed by the real registrar. That is precisely why it is the hard case —
      // there is no broken signature for the verifier to notice.
      if (!frozen.has(sub) && up.ok) frozen.set(sub, text);
      if (frozen.has(sub)) text = frozen.get(sub);
    } else if (mode === "drop-log" && up.ok) {
      try { const b = JSON.parse(text); b.inclusion_proof = []; text = JSON.stringify(b); } catch { /* pass it through */ }
    }
  }

  if (path.startsWith("/health") && mode === "rewind-seq" && up.ok) {
    // A rewind is relative to what this server ALREADY SERVED, not to the truth. The first version of this sabotage
    // subtracted a constant from every answer, and the probe passed it — correctly, because a constant offset is a
    // relabelling that preserves monotonicity, and monotonicity is the whole claim. So: serve the truth until a write
    // lands, then serve something strictly below the highest number we ever published. That is what an older history
    // restored after an outage actually looks like from outside.
    try {
      const h = JSON.parse(text);
      const truth = h.status_seq ?? 0;
      if (!revokeSeen) {
        servedMaxSeq = Math.max(servedMaxSeq, truth);
      } else {
        h.status_seq = Math.max(0, servedMaxSeq - 1);
      }
      text = JSON.stringify(h);
    } catch { /* pass it through */ }
  }
  if (path.startsWith("/demo/revoke") && up.ok) revokeSeen = true;

  res.writeHead(up.status, { "content-type": up.headers.get("content-type") || "application/json" });
  res.end(text);
});

server.listen(port, "127.0.0.1", () => console.log(`dishonest-registrar: 127.0.0.1:${port} → ${upstream} · sabotage = ${mode}`));
