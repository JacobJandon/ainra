// SPDX-License-Identifier: Apache-2.0 OR MIT
// D-079 — the gate keeps a signed, chained record of what it decided. Real fixtures (a valid passport and a revoked
// one, captured from a live registrar), a gate with a decision log, real requests through it; then the log is
// checked the way an auditor would, with nothing but the gate's public key.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { Verifier, createDecisionLog, verifyDecisionChain } from "@ainra/sdk";
import { ainraGate } from "../dist/index.js";

const fx = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8"));
const NOW = 1776729600;
const directory = fx("directory.json");
const roots = fx("roots.json");
const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh);
const sdkRequire = createRequire(new URL("../../sdk-ts/package.json", import.meta.url));
const { ed25519 } = await import(pathToFileURL(sdkRequire.resolve("@noble/curves/ed25519")).href);

function gateWithLog() {
  const secret = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(secret);
  const lines = [];
  const decisions = createDecisionLog({ gatePublic: pub, sign: (m) => ed25519.sign(m, secret), append: (l) => lines.push(l), freshness: "F2", audience: "https://shop.example" });
  return { gate: ainraGate(verifier, { now: () => NOW, decisions }), lines, pub, decisions };
}
function send(gate, bundle, path = "/orders") {
  const req = { method: "GET", url: path, headers: { host: "shop.example", "x-ainra-passport": Buffer.from(JSON.stringify(bundle)).toString("base64url") } };
  let status = 200;
  const res = { status(c) { status = c; return res; }, json() {}, setHeader() {} };
  gate(req, res, () => {});
  return status;
}

test("every decision about a named passport is recorded, signed and chained; the log holds", () => {
  const { gate, lines, pub, decisions } = gateWithLog();
  assert.equal(send(gate, fx("bundle-valid.json")), 200);
  assert.equal(send(gate, fx("bundle-revoked.json")), 403);
  assert.equal(send(gate, fx("bundle-valid.json"), "/refunds"), 200);
  assert.equal(lines.length, 3);
  assert.deepEqual(verifyDecisionChain(lines, pub), { ok: true, count: 3 });
  const recs = lines.map((l) => JSON.parse(l));
  assert.equal(recs[0].verdict, "valid");
  assert.equal(recs[1].verdict, "invalid");
  assert.equal(recs[1].reason, "revoked");
  assert.equal(recs[1].operator, undefined, "an invalid decision does not take the presenter's word for the operator");
  assert.ok(recs[0].operator, "a valid decision names the operator");
  assert.notEqual(recs[0].request, recs[2].request, "a different path is a different request digest");
  assert.ok(recs[0].status && recs[0].checkpoint, "it records what the decision relied on");
  assert.equal(decisions.head().length, 43, "a head digest to publish");
});

test("the record holds no request body and no field outside the closed set", () => {
  const { gate, lines } = gateWithLog();
  send(gate, fx("bundle-valid.json"));
  const keys = Object.keys(JSON.parse(lines[0])).sort();
  assert.deepEqual(keys, ["at", "checkpoint", "gate", "kind", "operator", "policy", "prev", "request", "seq", "sig", "status", "subject", "v", "verdict"]);
});

test("an edited, deleted or forged record is found by anyone with the gate's public key", () => {
  const { gate, lines, pub } = gateWithLog();
  for (let i = 0; i < 3; i++) send(gate, fx(i === 1 ? "bundle-revoked.json" : "bundle-valid.json"));
  const edited = [...lines];
  edited[1] = edited[1].replace('"reason":"revoked"', '"reason":"stale_status"');
  assert.deepEqual(verifyDecisionChain(edited, pub), { ok: false, index: 1, problem: "signature" });
  assert.deepEqual(verifyDecisionChain([lines[0], lines[2]], pub), { ok: false, index: 1, problem: "sequence" });
  const other = ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
  assert.deepEqual(verifyDecisionChain(lines, other), { ok: false, index: 0, problem: "gate" });
});

test("a request naming no parseable passport is decided but not recorded: it has no subject", () => {
  const { gate, lines } = gateWithLog();
  assert.equal(send(gate, { claims: "AAAA" }), 403);
  assert.equal(lines.length, 0);
});
